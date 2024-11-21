# INFO 558 Final Project

This project involves implementing various security protocols to defend against multiple vulnerabilities present in a Flask web application. Currently the application is vulnerable to the following:

⚠️ **WARNING: This is a deliberately vulnerable web application intended for educational purposes only.** ⚠️

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

### Step 1: SQL Injection



