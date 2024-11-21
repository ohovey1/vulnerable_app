import sys, html, json, os, pickle, random, re, sqlite3, string, subprocess, time, traceback
import urllib.parse, urllib.request, io
import socket, socketserver, http.server, http.client
import threading
from urllib.parse import unquote
import xml.etree.ElementTree
try:
    from flask import Flask, request, jsonify, render_template, redirect, url_for, Response, make_response
    app = Flask(__name__)
except ImportError:
    app = None
    print("Please install 'flask' to run this vulnerable app")
    sys.exit(1)
try:
    import lxml.etree
except ImportError:
    lxml = None
    print("Please install 'lxml' to get access to XML vulnerabilities")
    sys.exit(1)

# Disable cache, friendly for test
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
USERS_XML = """<?xml version="1.0" encoding="utf-8"?>
<users>
<user id="0"><username>admin</username><name>admin</name><surname>admin</surname><password>123456789!</password></user>
<user id="1"><username>brian</username><name>brian</name><surname>kernighan</surname><password>12345</password></user>
<user id="2"><username>ken</username><name>ken</name><surname>thompson</surname><password>passwd</password></user>
<user id="3"><username>dennis</username><name>dennis</name><surname>ritchie</surname><password>getin</password></user>
</users>"""
VERSION = "v<b>0.1</b>"

connection = sqlite3.connect(":memory:", check_same_thread=False)
cursor = connection.cursor()
cursor.execute("CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, name TEXT, surname TEXT, password TEXT)")
cursor.executemany("INSERT INTO users(id, username, name, surname, password) VALUES(NULL, ?, ?, ?, ?)", ((_.findtext("username"), _.findtext("name"), _.findtext("surname"), _.findtext("password")) for _ in xml.etree.ElementTree.fromstring(USERS_XML).findall("user")))
cursor.execute("CREATE TABLE comments(id INTEGER PRIMARY KEY AUTOINCREMENT, comment TEXT, time TEXT)")

@app.route('/')
def index():
    params = request.args
    cursor = connection.cursor()
    try:
        if 'id' in params:
            user_id = params.get('id')
            query = f"SELECT id, username, name, surname FROM users WHERE id={user_id}"
            cursor.execute(query)
            content = cursor.fetchall()
            return render_template('payload.html', content=content)
        elif 'v' in params:
            content = re.sub(r"(v<b>)[^<]+(</b>)", r"\g<1>%s\g<2>" % params["v"], VERSION)
            return render_template('payload.html', html_content=content)
        elif 'path' in params:
            if '://' in params['path']:
                response = urllib.request.urlopen(params['path'])
                content = response.read().decode()
            else:
                with open(os.path.abspath(params['path']), "r") as f:
                    content = f.read()
            return render_template('payload.html', content=content)
        elif 'domain' in params:
            content = subprocess.check_output("nslookup " + params['domain'], shell=True).decode()
            return render_template('payload.html', content=content)
        elif 'xml' in params and lxml:
            parser = lxml.etree.XMLParser(load_dtd=True, no_network=False, resolve_entities=True)
            xml_content = params['xml']
            content = lxml.etree.tostring(lxml.etree.parse(io.BytesIO(xml_content.encode()), parser), pretty_print=True).decode()
            return render_template('payload.html', html_content=content)
        elif 'comment' in params:
            comment_param = params.get("comment")
            if comment_param:
                cursor.execute("INSERT INTO comments VALUES(NULL, ?, ?)", (params['comment'], time.ctime()))
                content = "Please click here <a href=\"/?comment=\">here</a> to see all comments"
                return render_template('payload.html', html_content=content)
            else:
                cursor.execute("SELECT id, comment, time FROM comments")
                content = cursor.fetchall()
                return render_template('payload.html', html_content=content)
        elif 'redir' in params:
            content = "<head><meta http-equiv=\"refresh\" content=\"0; url=%s\"/>" % params["redir"]
            return render_template('payload.html', html_content=content)
        elif "include" in params:
            backup, sys.stdout, program = sys.stdout, io.StringIO(), (open(params["include"], "rb") if not "://" in params["include"] else urllib.request.urlopen(params["include"])).read()
            envs = {
                    "DOCUMENT_ROOT": os.getcwd(),
                    "HTTP_USER_AGENT": request.headers.get("User-Agent"),
                    "REMOTE_ADDR": request.remote_addr,
                    "REMOTE_PORT": request.environ.get("REMOTE_PORT"),
                    "PATH": request.path,
                    "QUERY_STRING": request.query_string.decode()
            }
            exec(program, envs)
            content = sys.stdout.getvalue()
            sys.stdout = backup
            return render_template('payload.html', content=content)
        return render_template('index.html')

    except Exception as ex:
        content = traceback.format_exc()
        return render_template('error.html', content=content)


def generate_session_id(length=20):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

@app.route('/login', methods=['GET', 'POST'])
def login():
    params = request.args
    username = params.get("username")
    password = params.get("password")

    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE username='" + re.sub(r"[^\w]", "", params.get("username", "")) + "' AND password='" + params.get("password", "") + "'")
    user = cursor.fetchone()
    if user:
        session_id = generate_session_id()
        response = make_response(f"Welcome <b>{user}</b>")
        response.set_cookie("SESSIONID", session_id, path='/')
        response.headers["Refresh"] = "1; url=/"
        return response
    else:
        return render_template('index.html', error="The username and/or password is incorrect")
    return render_template('index.html', error="The username and/or password is incorrect")

class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        http.server.HTTPServer.server_bind(self)

class ReqHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        content = "Hello from internal_service"
        self.send_response(200)
        self.send_header("Connection", "close")
        self.send_header("X-XSS-Protection", "0")
        self.send_header("Content-Type", "%s" % ( "text/plain"))
        self.end_headers()
        self.wfile.write(("%s" % (content)).encode())
        self.wfile.flush()

def run_flask_server():
    print("Flask server running on port 5000")
    app.run(host='127.0.0.1', port=5000)

# Mimic a internal service
def run_internal_service():
    try:
        ThreadingServer(('127.0.0.1', 8989), ReqHandler).serve_forever()
    except KeyboardInterrupt:
        pass
    except Exception as ex:
        print("[x] exception occurred ('%s')" % ex)

if __name__ == "__main__":
    # Start the threading server in a new thread
    threading_server_thread = threading.Thread(target=run_internal_service)
    threading_server_thread.daemon = True
    threading_server_thread.start()

    # Start the Flask server in the main thread
    run_flask_server()
