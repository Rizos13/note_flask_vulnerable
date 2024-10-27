# Note_flask_vulnerable

## Description
This project is a simple Flask-based to-do application that intentionally contains multiple security vulnerabilities for educational purposes, specifically for penetration testing and ethical hacking practice. The vulnerabilities include issues such as SQL injection, weak password hashing, and other security flaws.

## Vulnerabilities and Solutions

### 1. SQL-injection

#### Description:

The application is vulnerable to SQL injection because it constructs SQL queries using Python f-strings, such as:

``` 
query = f"SELECT id FROM users WHERE username='{username}' AND password= '{hashed_password}'"
```
A user can input data that includes SQL commands, potentially altering the behavior of the query.

#### How to test:

 • Try entering ' OR '1'='1 in the login field. If the query is not properly escaped, this will make the condition always true, allowing login without correct credentials.
 
• Use automated tools like BurpSute or SQLMap to detect SQL injection vulnerabilities.

#### Solution:
Use parameterized queries, which safely handle user inputs:

````
query = "SELECT id FROM users WHERE username=? AND password=?"
self.c.execute(query, (username, hashed_password))
````

This prevents malicious SQL commands from being injected into the query.

## 2. Use of Weak Hashing Algorithm (MD5)

#### Description:
The application uses MD5 for password hashing:

````
hashed_password = hashlib.md5(password.encode()).hexdigest()
````

MD5 is considered outdated and insecure for password hashing due to its vulnerability to collision attacks and brute force.

#### How to test:

 • Attempt to generate a hash using common password dictionaries (e.g. using tools like hashcat) and check if you can recover the password.

#### Solution:
Use stronger algorithms like bcrypt, passlib or argon2:

````
from bcrypt import hashpw, gensalt, checkpw

hashed_password = hashpw(password.encode(), gensalt())
````
bcrypt automatically adds a salt, making brute force attacks much more difficult.

## 3. XSS (Cross-Site Scripting)

#### Description:
The application renders user-provided data (such as notes and posts content) without proper escaping:

````
return render_template('dashboard.html', notes=notes)
````

If a user enters malicious scripts like <script> alert('XSS') </script> , they can be executed in another user’s browser.

``````
<script> alert('XSS') </script>
``````

#### How to test:

 • Enter scripts in a note or post field and see if an alert box appears on the page.

#### Solution:
Escape user inputs before displaying them, or use Flask’s built-in template engine, which automatically escapes outputs:

``````
return render_template('dashboard.html', notes=notes | escape)
``````

## 4. CSRF (Cross-Site Request Forgery)

#### Description:
The application lacks CSRF protection, making it possible for attackers to forge requests. For example, an attacker could create a form on another website that sends a POST request to /delete_note/1 if the user is logged in.

#### How to test:

 • Create a simple HTML form on another server that sends a POST request to /delete_note/<note_id> and see if it executes when the user is logged in.

#### Solution:
Implement CSRF tokens using libraries like Flask-WTF:

````
from flask_wtf import CSRFProtect
csrf = CSRFProtect(app)
````

This will add a hidden token field in forms and verify it on the server, preventing CSRF attacks.

## 5. Improper Session and Authorization Handling

#### Description:
The application does not properly enforce access control. For instance, the is_admin check is done through session data without additional server-side verification, which could be tampered with by an attacker.

#### How to test:

 • Modify the is_admin value in the session using the browser’s developer tools and attempt to access the /admin/posts endpoint.

#### Solution:

• Enforce access control checks on the server side before performing actions that require admin privileges.
 
• Use a secure session storage solution like Flask-Session.

• Implement Role-Based Access Control (RBAC):

Define user roles in the database and verify the user’s role at every access point. This ensures only users with the correct role can access specific functionality.
 
• Secure Session Management:

Use secure cookies with secure and httponly flags to protect session data from being accessed through client-side scripts. Configure the session cookie settings in your Flask app:

````
app.config['SESSION_COOKIE_SECURE'] = True  
app.config['SESSION_COOKIE_HTTPONLY'] = True  
````

 • Audit Logs:
 
Implement logging of authorization events, such as failed access attempts and role changes. This will help in monitoring suspicious activities related to authorization handling.
 
• Regular Security Reviews:

Regularly review and test your authorization logic as part of your security audits to ensure that no vulnerabilities have been introduced over time.

## 6. Improper Input Handling

#### Description:
Direct usage of user input in the get_all_posts method:

````
query = f"SELECT id, title, content, created_at FROM posts WHERE visible = 1 AND {user_input} ORDER BY created_at DESC"
````

allows attackers to inject arbitrary SQL code through the user_input parameter.

#### How to test:
• In the URL, try passing a value for user_input, such as user_input=1 OR 1=1, and see if it returns all records.

#### Solution:

 • Avoid using user input directly in SQL queries.
 • Rewrite the code to use safe parameterized queries:

````
query = "SELECT id, title, content, created_at FROM posts WHERE visible = 1 ORDER BY created_at DESC"
````

and filter parameters before running the query.

## 7. Hardcoded Secret Key

#### Description:
The application uses a hardcoded secret_key:

````
app.secret_key = 'ef1b7f45ed011a3fbe6790873b6bed1283be3c42d5ddb7633acd9cff8d287031'
````

If this code is exposed, an attacker could decrypt session data or forge their own session tokens.

#### How to test:

 • Check if it’s possible to decode session data using this key.

#### Solution:

 • Use environment variables to store secrets:

````
import os
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')
````

 • Generate the secret_key randomly and store it in a secure environment.

## Conclusion

These vulnerabilities make the application insecure and open to exploitation. Addressing each one of them will improve the application’s security and protect it from various attacks.