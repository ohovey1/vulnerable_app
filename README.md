# INFO 558 Final Project

This project involves implementing various security protocols to defend against multiple vulnerabilities present in a Flask web application.

⚠️ **WARNING: This is a deliberately vulnerable web application intended for educational purposes only.** ⚠️

Currently the application is vulnerable to the following:

1. SQL Injection
2. Cross-Site Scripting (XXS)
3. XML External Entity (XXE)
4. Server-Side Request Forgery (SSRF)
5. Cross-Site Request Forgery (CSRF)
6. Open Redirection
7. Command Injection
8. Path Traversal
9. File Inclusion

The goal is to defend against each of the above threats to create a secure and stable web application. Each threat will be outlined specifically along with the approach taken to mitigate the vulnerability.

----

## Initial Security Analysis

By quickly scanning the application, the following architecture issues are apparent:

- The application uses an in-memory SQLite database with a simeple user management system
- Multiple endpoints handle various types of user input without proper security controls
- Mixing of different functionalities in single routes increase the attack surface
- No proper session management
- Dangerous system calls and file operations are exposed directly to user input

## Implementation Strategy

1. Start w/ highest risk vulnerabilites (SQL injection, Command injection)
2. Implement basic security infrastructure (input validation, CSRF protection)
3. Address each vulnerbility individually
4. Add comprehensive logging and error handling
5. Implement proper session management
6. Add security headers and CSP

----

### Implemented Mitigations

1. **SQL Injection:**

- Used parameterized queries with placeholders instead of string concatenation when constructing SQL queries. This ensures that user input is treated as data rather than executable code.
- Validated and sanitized user input before using it in SQL queries. This includes checking for valid data types, removing special characters, and enforcing input constraints.
- Used the ? placeholder syntax in SQL queries and passed user input as separate arguments to the execute() method.

2. **Cross-Site Scripting (XXS):**

- Used the html.escape() function to encode user input before rendering it in HTML responses. This converts special characters like <, >, &, ', and " to their corresponding HTML entities, preventing them from being interpreted as HTML or JavaScript code.
- Implemented a Content Security Policy (CSP) to restrict the sources of scripts and other resources that can be loaded and executed in the application.
- Set the HttpOnly and Secure flags for sensitive cookies to prevent them from being accessed by JavaScript.

3. **XML External Entity (XXE):**

- Set resolve_entities=False to disable the resolution of external entities.
- Set no_network=True to prevent the XML parser from accessing network resources.
- Set load_dtd=False to disable the loading of external Document Type Definitions (DTDs)

4. **Server-Side Request Forgery (SSRF):**

- Validated and restricted the allowed URLs and paths that can be accessed by user input.
- Defined an allowlist of permitted URLs and paths and checked user input against this allowlist before making requests or accessing resources.

5. **Cross-Site Request Forgery (CSRF):**

- Used the flask_wtf.csrf extension to enable CSRF protection in the application.
- Generated and included CSRF tokens in forms and validated them on the server-side for each request that modifies data.
- Note: Robust CSRF Mitigation would require modifying templates, which was not allowed in this project

6. **Open Redirection:**

- Validated and restricted the allowed redirection URLs using an allowlist approach.
- Checked the requested redirection URL against a predefined list of permitted URLs before performing the redirection.
- Returned an error response if the requested redirection URL is not in the allowlist.

7. **Command Injection:**

- Validated and restricted the allowed redirection URLs using an allowlist approach.
- Checked the requested redirection URL against a predefined list of permitted URLs before performing the redirection.
- Returned an error response if the requested redirection URL is not in the allowlist.

8. **Path Traversal:**

- Validated and restricted the allowed file paths using an allowlist approach.
- Checked the requested file path against a predefined list of permitted paths before accessing files.
- Used os.path.abspath() to resolve file paths and prevent path traversal attempts.

9. **File Inclusion:**

- Validated and restricted the allowed file paths using an allowlist approach.
- Checked the requested file path against a predefined list of permitted paths before including files.
- Used os.path.join() and os.path.dirname() to construct file paths securely and prevent path traversal attempts.

### Additional Security Measures

In addition to the specific vulnerability mitigations, the following security measures were implemented to enhance the overall security of the application:

1. **Secure Password Hashing:**

- Used the werkzeug.security module to generate secure password hashes using the generate_password_hash() function.
- Stored the hashed passwords in the database instead of plain-text passwords.
- Used the check_password_hash() function to compare the provided password with the stored hashed password during authentication

2. **Added Security Headers:**

- Implemented various security headers using the @app.after_request decorator to add an extra layer of protection.
- Added headers such as X-XSS-Protection, X-Content-Type-Options, Strict-Transport-Security, X-Frame-Options, Referrer-Policy, Permissions-Policy, Cache-Control, and Pragma to enhance browser security and prevent common attacks.

3. **Error Handling:**

- Implemented custom error handling to provide generic error messages without disclosing sensitive information.
- Returned appropriate HTTP status codes for different types of errors.

-----------

## Conclusion

These security measures collectively contribute to the overall security posture of the application, making it more resilient against common web vulnerabilities and attacks. However, it's important to note that security is an ongoing process, and regular security testing, code reviews, and updates are necessary to maintain a secure application.
