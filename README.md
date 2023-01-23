# Flask-authentication
The project aims to build a login/registration page that, in addition to basic functionality, also has server load protection and a password reset option.

## Functionalities

* user registration
* password reset using e-mail and JWT authentication
* logging in with appropriate rules and logging out of the system
* user login without assigning to a user group
* counting the number of incorrect logins and blocking logins for a certain period of time,
* logging of the last n passwords so that you cannot repeat any of them.
* logging in and out of the system.

## Account rules
The example account rules are divided into two groups possibly to be used.
1. password rules, under which you should:
* Enable the Password rule must meet the complexity requirements.
* Specify the maximum password validity period, i.e. the number of days after which it
* Specify the maximum period of validity of the password, i.e. the number of days after which it must be changed; passwords should be changed at least every three months.
at least every three months.
* Set a minimum, even one-day password validity period; in this way
prevent users from quickly changing their password so many times,
so that they can use the previous one back.
* Enforce a long password history of up to 20 entries.
- this rule in combination with the previous one will force users to actually
changing passwords.
2. account lockout rules, which should:
* Specify at least a period of several minutes for which the account will be
automatically blocked.
* Set a high account lockout threshold; the risk that a submitted password will be
guessed in five and fifteen attempts is practically the same.
- setting the lockout threshold too low will only make your job more difficult.

## Installation
To install the application, follow these steps:
1. clone the repository to your computer.
```
git clone https://github.com/MrZeleq/flask-authentication.git
```
2. install the required libraries
3. create a "flask_auth" database in SQL Server
4. open the copied folder in VS Code
5. run the main.py file
6. Open the application in a browser via the address displayed in the console
