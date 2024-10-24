# CS302-MasterVault
MasterVault is a Flask-based password management application designed for secure storage and management of passwords. It features functionalities like user authentication, 
password generation, encryption, and two-factor authentication (2FA).


## Features
* **Secure Login & Registration:** Users can create accounts and log in securely.

* **Password Management:** Add, view, edit, or delete stored passwords.

* **Password Generation:** Generate strong, unique passwords based on user-defined criteria.

* **Password Strength Checker:** Evaluates the strength of passwords in real time.

* **Two-Factor Authentication (2FA):** Enhance security with optional 2FA.

* **Account Locking:** Ability to lock accounts for specified durations.

* **Encryption:** Sensitive data is encrypted using AES-256 for additional security.

* **Email Notifications:** Sends emails for verification, 2FA PINs and Add Family notifications.

* **Personal and Family Accounts:** Flexible account options to suit individual and family needs.

* **Animal ID Verification:** Adds an additional layer of security using unique identifiers.



## Setup & Installation
1. **Clone the Repository:** Start by cloning this repository to your local machine.
   
2. **Install Dependencies:** Use **'pip install -r requirements.txt'** to install the necessary Python packages.
   
3. **Run the Application:** Execute **'app.py'** to start the Flask server.

## Usage
* **Register:** Create a new account by providing a username, email, and password.

* **Animal ID Verification:** Set up and use Animal ID for an additional security measure.
  
* **Login:** Access your account using your credentials.
  
* **Password Management:** Add new passwords, view saved ones, or modify existing entries.
  
* **Generate Password:** Use the built-in tool to create strong passwords.
  
* **Account Settings:** Enable/disable 2FA, lock your account, or reset your password.

* **Family Accounts:** Add family memmbers and manage them under a single family account.


## Security Features
* **Encryption:** All sensitive data is encrypted using AES-256 encryption.

* **Master Password:** Provides an additional layer of security by requiring a master password to access all saved passwords.
  
* **2FA:** Optional two-factor authentication adds an extra layer of security.
  
* **Account Locking:** Temporarily lock your account to prevent unauthorized access.

* **Animal ID Verification:** Adds an additional layer of security with unique identifiers.

## Email Integration
* **Verification Emails:** Sent upon account creation.
  
* **2FA Emails:** Sent when 2FA is enabled, containing a PIN for verification.

* **Add Family Member Emails:** Sent to invite family members to join the family account, containing instructions for account setup.
   



