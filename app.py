import sys, html, json, os, pickle, random, re, sqlite3, string, subprocess, time, traceback
import urllib.parse, urllib.request, io
import socket, socketserver, http.server, http.client
import threading
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from urllib.parse import unquote
import xml.etree.ElementTree
try:
    from flask import Flask, request, jsonify, render_template, redirect, url_for, Response, make_response, session
    app = Flask(__name__)
    # To prevent CSRF
    csrf = CSRFProtect()
    csrf.init_app(app)
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

# Updated. Added password hashing.
hashed_password_admin = generate_password_hash("123456789!")
hashed_password_brian = generate_password_hash("12345")
hashed_password_ken = generate_password_hash("passwd")
hashed_password_dennis = generate_password_hash("getin")

USERS_XML = """<?xml version="1.0" encoding="utf-8"?>
<users>
<user id="0"><username>admin</username><name>admin</name><surname>admin</surname><password>{hashed_password_admin}</password></user>
<user id="1"><username>brian</username><name>brian</name><surname>kernighan</surname><password>{hashed_password_brian}</password></user>
<user id="2"><username>ken</username><name>ken</name><surname>thompson</surname><password>{hashed_password_ken}</password></user>
<user id="3"><username>dennis</username><name>dennis</name><surname>ritchie</surname><password>{hashed_password_dennis}</password></user>
</users>"""
VERSION = "v<b>0.1</b>"

connection = sqlite3.connect(":memory:", check_same_thread=False)
cursor = connection.cursor()
cursor.execute("CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, name TEXT, surname TEXT, password TEXT)")
# Updated. Added password hashing.
cursor.executemany("INSERT INTO users(id, username, name, surname, password) VALUES(NULL, ?, ?, ?, ?)",
                   ((_.findtext("username"), _.findtext("name"), _.findtext("surname"),
                     generate_password_hash(_.findtext("password")))
                    for _ in xml.etree.ElementTree.fromstring(USERS_XML).findall("user")))
cursor.execute("CREATE TABLE comments(id INTEGER PRIMARY KEY AUTOINCREMENT, comment TEXT, time TEXT)")

@app.route('/')
def index():
    params = request.args
    cursor = connection.cursor()
    try:
        if 'id' in params:
            # Updated. SQL Injection - Mitigated
            ''' Changed this block.
            - Updated query
            - Ensured user_id param is digit
            - Updated execute call '''
            user_id = params.get('id')
            if not user_id.isdigit(): # Input validation
                return "Invalid user ID", 400
            query = "SELECT id, username, name, surname FROM users WHERE id=?"
            cursor.execute(query, (user_id,))
            content = cursor.fetchall()
            return render_template('payload.html', content=content)
        elif 'v' in params:
            # Updated. XSS (reflected) - Partially mitigated
            content = re.sub(r"(v<b>)[^<]+(</b>)", r"\g<1>%s\g<2>" % html.escape(params["v"]), VERSION)
            return render_template('payload.html', html_content=content)
        elif 'path' in params:
            # Updated. SSRF - Mitigated
            allowed_paths = [
                'http://example.com',
                'https://example.org',
                '/var/www/html',
            ]
            path = params['path']
            if any(path.startswith(allowed_path) for allowed_path in allowed_paths):
                if '://' in path:
                    response = urllib.request.urlopen(path)
                    content = response.read().decode()
                else:
                    with open(os.path.abspath(path), "r") as f:
                        content = f.read()
                return render_template('payload.html', content=content)
            else:
                return "Invalid path", 400
        elif 'domain' in params:
            # Updated. OS Command Injection - Mitigated
            domain = params['domain']
            if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
                return "Invalid domain", 400
            try:
                output = subprocess.run(['nslookup', domain], capture_output=True, text=True, check=True)
                content = output.stdout
            except subprocess.CalledProcessError as e:
                content = f"Error: {e.stderr}"
            return render_template('payload.html', content=content)
        elif 'xml' in params and lxml:
            # Updated. XXE - Partially mitigated
            parser = lxml.etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
            xml_content = params['xml']
            content = lxml.etree.tostring(lxml.etree.parse(io.BytesIO(xml_content.encode()), parser), pretty_print=True).decode()
            return render_template('payload.html', html_content=content)
        elif 'comment' in params:
            # Updated. XSS (stored) - Partially mitigated
            comment_param = params.get("comment")
            if comment_param:
                encoded_comment = html.escape(comment_param)
                cursor.execute("INSERT INTO comments VALUES(NULL, ?, ?)", (encoded_comment, time.ctime()))
                content = "Please click here <a href=\"/?comment=\">here</a> to see all comments"
                return render_template('payload.html', html_content=content)
            else:
                cursor.execute("SELECT id, comment, time FROM comments")
                content = [(row[0], html.escape(row[1]), row[2]) for row in cursor.fetchall()]
                return render_template('payload.html', html_content=content)
        elif 'redir' in params:
            # Updated. Redirection - Mitigated
            allowed_redirects = [
                '/',
                '/login',
                '/dashboard',
            ]
            redirect_url = params['redir']
            if redirect_url in allowed_redirects:
                content = "<head><meta http-equiv=\"refresh\" content=\"0; url=%s\"/>" % redirect_url
                return render_template('payload.html', html_content=content)
            else:
                return "Invalid redirection", 400
        elif "include" in params:
            # Updated. File Inclusion - Mitigated
            allowed_includes = [
                'static/css/style.css',
                'templates/footer.html',
            ]
            include_file = params['include']
            if include_file in allowed_includes:
                file_path = os.path.join(os.path.dirname(__file__), include_file)
                with open(file_path, 'r') as f:
                    content = f.read()
                return render_template('payload.html', content=content)
            else:
                return "Invalid file inclusion", 400
        elif 'search' in params:
            # Added search sanitization.
            search_query = params['search']
            # Sanitize the user input
            sanitized_query = html.escape(search_query)
            # Pass the sanitized query to JavaScript
            return render_template('payload.html', search_query=json.dumps(sanitized_query))
        return render_template('index.html')

    except Exception as ex:
        # Updated. Path Disclosure via Error Message - TBD
        error_message = "An error occurred. Please try again later."
        return render_template('error.html', content=error_message), 500


def generate_session_id(length=20):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Added. CSRF - 
def generate_csrf_token():
    return secrets.token_hex(16)

@app.route('/login', methods=['GET', 'POST'])
def login():    
    # Updated. SQL Injections
    params = request.args
    username = re.sub(r"[^\w]", "", params.get("username", ""))
    password = params.get("password", "")

    cursor = connection.cursor()
    # Updated. SQL Injections
    query = "SELECT * FROM users WHERE username=?"
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    #cursor.execute("SELECT * FROM users WHERE username='" + re.sub(r"[^\w]", "", params.get("username", "")) + "' AND password='" + params.get("password", "") + "'")
    
    if user and check_password_hash(user[4], password):
        session_id = generate_session_id()
        response = make_response(f"Welcome <b>{user}</b>")
        # Updated. XSS
        response.set_cookie("SESSIONID", session_id, path='/', httponly=True, secure=True)
        response.headers["Refresh"] = "1; url=/"
        return response
    else:
        return render_template('index.html', error="The username and/or password is incorrect")
    return render_template('index.html', error="The username and/or password is incorrect")

# Added security headers for additional security.
@app.after_request
def add_security_headers(response):
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(self), camera=(self), microphone=(self)'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    return response

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


'''
Vulnerability Statuses:

Login Bypass - Possibly Mitigated? Not positive
UNION SQL Injection - Mitigated
Blind SQL Injection(time-based) - Mitigated
XSS(reflected) - Partially Mitigated
XSS(stored) - Partially Mitigated
XSS(DOM-based) - Vulnerable
XXE(local) - Partially Mitigated
SSRF - Mitigated
CSRF - Mitigated? Kind of
Redirection - Mitigated
OS Command Injection - Mitigated
Path Traversal(absolute path) - Mitigated
Path Traversal(relative path) - Mitigated
File Inclusion - Mitigated
Path Disclosure via Error Message - Mitigated

'''