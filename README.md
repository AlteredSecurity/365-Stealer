# 365-Stealer

<h1 align="center">
   <a href="https://github.com/AlteredSecurity/365-Stealer"><img src="https://github.com/AlteredSecurity/365-Stealer/blob/master/Images/365-Stealers.png" alt="365-Stealer" border="0"></a>
</h1>

## Table of Contents

- [About 365-Stealer](#About)
- [About Illicit Consent Grant Attack](#Understanding-the-Illicit-Consent-Grant-Attack)
- [Key Features of 365-Stealer](#Key-Features-of-365-Stealer)
- [Setup Attacking Environment](#Setting-Up-the-Attack-Environment)
  - [Automated Azure App Registration](#Automated-Azure-App-Registration)
  - [Manual Azure App Registration](#Manual-Azure-App-Registration)
  - [Configuring the Application](#Configuring-the-Application)
    - [Creating Client Secrets](#Creating-Client-Secrets)
    - [Adding API Permissions](#Adding-API-Permissions)
- [Setting Up 365-Stealer](#Setting-Up-365-Stealer)
  - [Enabling SQLite3 on the Apache Server](#Enabling-SQLite3-on-the-Apache-Server)
- [Configuring the 365-Stealer Management Portal](#Configuring-the-365-Stealer-Management-Portal)
  - [Modifying Paths](#modifying-paths)
  - [Enabling IP Whitelisting for the 365-Stealer Management Portal](#Enabling-IP-Whitelisting-for-the-365-Stealer-Management-Portal)
- [OPSEC Consideration](#OPSEC-Consideration)
- [Command Line Help](#Command-Line-Help)
- [Blog](#Blog)
- [Bugs and Feature Requests](#Bugs-and-Feature-Requests)
- [Contributing](#Contributing)

## About

**365-Stealer** is a Python3-based tool designed to automate illicit consent grant attacks. When a target user unknowingly grants permission to an attacker's application, the attacker gains access to the victim's refresh token. This refresh token can then be used to generate other tokens, allowing the attacker to access sensitive data such as emails, files on OneDrive, and notes—without needing further input from the victim. Manually exploiting this can be time-consuming, but 365-Stealer simplifies and automates the process.

#### 365-Stealer comes with 2 interfaces:

1. **CLI (Command Line Interface)** - Built entirely in Python3, the CLI provides direct access to the tool’s features.
2. **Web UI** - The Web User Interface is developed using PHP, while Python3 operates in the background to execute commands.

## Understanding the Illicit Consent Grant Attack

An illicit consent grant attack occurs when an attacker registers a malicious application within Azure, requesting access to sensitive data like contacts, emails, or documents. The attacker deceives a user into consenting to the app, usually by presenting it as legitimate. Once the victim clicks "Accept," they unknowingly provide access to the attacker, allowing them to act on behalf of the victim without needing the victim’s organizational credentials.

To explain more clearly, once the user grants permission, Entra ID sends a token to the attacker's server. This token gives the attacker the ability to read emails, send emails, access files on OneDrive, and perform other malicious activities using the victim's credentials. Unlike phishing attacks that rely on stealing passwords, illicit consent grant attacks bypass authentication entirely by abusing the permissions system of cloud applications.

## Key Features of 365-Stealer

- **Steals Refresh Tokens:** The tool captures refresh tokens from victims, which can be used to generate new access tokens for at least 90 days, providing ongoing access to their accounts..
- **Send Emails on Behalf of Victims:** 365-Stealer can send emails with attachments from the victim’s account to other users without their knowledge.
- **Create Malicious Outlook Rules:** It can create harmful rules in the victim’s Outlook, such as forwarding any incoming mail to an attacker-controlled email.
- **Upload Files to OneDrive:** The tool can upload any file into the victim's OneDrive account.
- **Steal Data from OneDrive, OneNote, and Email:** 365-Stealer can extract files from OneDrive, OneNote, and dump all emails, including attachments, from the victim’s account.
- **Manage Stolen Data:** The 365-Stealer Management Portal allows attackers to manage all compromised data, including refresh tokens, emails, files, and users.
- **Backdoor OneDrive Documents:** The tool can backdoor a .docx file stored in OneDrive by injecting malicious macros and replacing the file extension with .doc.
- **Store Compromised Data:** All collected information, such as refresh tokens, emails, files, and user data from the victim’s tenant, along with configurations, are stored in a database.
- **Customizable Delay for Data Theft:** Attackers can delay requests by specifying a time in seconds to avoid detection while stealing data.
- **Host a Phishing Application:** The tool can host a fake application for performing illicit consent grant attacks using the `--run-app` command in the terminal or via the 365-Stealer Management portal.
- **Selective Token Theft:** Using the `--no-stealing` flag, the tool can steal only the tokens without further actions, allowing attackers to exploit them later.
- **Request New Access Tokens:** The tool allows attackers to request new access tokens for all users or specific users within the compromised tenant.
- **Generate Access Tokens Using Credentials:** With the --refresh-token, `--client-id`, and `--client-secret` flags, attackers can easily obtain new access tokens.
- **Automate Azure App Registration:** The `--app-registration` flag automates the process of Azure app registration, making it easier to set up the attack infrastructure without manual intervention.
- **Selective Data Theft:** With the `--custom-steal` flag, attackers can selectively steal data from specific sources like OneDrive, Outlook, etc.
- **Shared Data:** All compromised data is saved in a database.db file, which can be shared with our team to leverage the existing stolen tokens and data.
- **Search and Filter Emails:** Attackers can search for specific emails by keyword, subject, user’s email address, or filter emails with attachments using the 365-Stealer Management portal.
- **Export User Data:** The tool allows attackers to dump user information from the compromised tenant and export the data to a CSV file for further analysis or use.

## Setting Up the Attack Environment

### Automated Azure App Registration

To automatically register an application in Azure using the provided Python script, follow these steps:

1. Ensure you have Python3 installed on your machine.
2. Clone the 365-Stealer repository:
   ```bash
   git clone https://github.com/AlteredSecurity/365-Stealer.git
   cd 365-Stealer
   ```
3. Install the required Python modules:

   ```bash
   pip install -r requirements.txt
   ```

4. Run the automated Azure app registration script:

   ```bash
   python 365-Stealer.py --app-registration
   ```

- The script will prompt you to provide your Azure tenant ID, the desired application name, and the redirect URI.
- You will also choose an authentication method (OAuth with Client Secret or Device Code Flow) and set API permissions (either default, LowImpact or custom permissions).
- Follow the prompts to complete the app registration process.

### Manual Azure App Registration

If you prefer to manually register an Azure application, follow these steps:

1. **Log in to the Azure Portal:** Go to `https://portal.azure.com` and sign in to your account.
2. **Navigate to Microsoft Entra ID:** From the portal, navigate to Microsoft Entra ID.
3. **Go to App Registrations:** Click on `App registrations` in the left-hand menu.`
4. **Create a New Registration:** Click on `New registration` to begin the process of registering a new application.
5. **Provide Application Details:**
   - **Name:** Enter a name for your application. This name will be shown to the user during the consent process.
   - **Supported Account Types:** Select `Accounts in any organizational directory (Any Microsoft Entra ID tenant - Multitenant)`.
6. **Set the Redirect URI:**
   - Provide the redirect URI that points to your 365-Stealer phishing page. The format should be `https://<DOMAIN/IP>:<PORT>/login/authorized`, where your domain or IP corresponds to where you will host the 365-Stealer application.
7. **Complete the Registration:**
   - Once all details are entered, click `Register` to create the application.

<h1 align="center">
<img src="https://github.com/AlteredSecurity/365-Stealer/blob/master/Images/registration.png" alt="app registration" width=720 border="0">

<img src="https://github.com/AlteredSecurity/365-Stealer/blob/master/Images/registration1.png" alt="app registration" width=720  border="0">
</h1>

### Configuring the Application

#### Creating Client Secrets

1. **Navigate to Certificates & Secrets:**
   - In the Azure portal, go to the `Certificates & secrets` section under your registered application.
2. **Create a New Client Secret:**
   - Click on `New client secret`, provide a description for the secret, and then click Add.
3. **Save the Secret Value:**
   - Once created, copy and store the secret's value in a safe location, as you won’t be able to retrieve it again after you leave the page.

<img src="https://github.com/AlteredSecurity/365-Stealer/blob/master/Images/secrets.png" alt="Client Secrets" border="0">

#### Adding API Permissions

1. **Go to API Permissions:**
   - In the Azure portal, click on the `API permissions` tab under your application.
2. **Add Permissions:**
   - Click `Add a permission` to begin selecting the necessary permissions.
3. **Select Microsoft Graph:**
   - Under the available APIs, select `Microsoft Graph`.
4. **Choose Delegated Permissions:**
   - In the next step, click on `Delegated permissions` to assign permissions that will act on behalf of the signed-in user.
5. **Select Required Permissions:**
   1. Contacts.Read
   2. Mail.Read
   3. Notes.Read.All
   4. Mailboxsettings.ReadWrite
   5. Files.ReadWrite.All
   6. Mail.Send
   7. User.ReadBasic.All

<img src="https://github.com/AlteredSecurity/365-Stealer/blob/master/Images/API-Permissions.png" alt="Client Secrets" border="0">

## Setting Up 365-Stealer

### Step-by-Step Instructions

1. **Clone the 365-Stealer Repository:**

   > git clone https://github.com/AlteredSecurity/365-Stealer.git

2. **Install Required Applications:**
   > [Python3](https://www.python.org/downloads/)

   > [XAMPP](https://www.apachefriends.org/index.html)

3. **Extract and Save the Files:**
   - After cloning, copy the **365-Stealer** folder and place them in `C:\xampp\htdocs\` that allows you to host the PHP application and run Python.

4. **Install Python Dependencies:** Run the following command to install the necessary Python libraries.
   ```
   cd C:\xampp\htdocs\365-Stealer
   pip install -r requirements.txt
   ```

5. **Follow Additional Setup Instructions:** After installing the required applications and dependencies, make sure to follow the instructions provided in the `yoursVictims/Readme.md` file. This will guide you through setting up the necessary databases and tables for 365-Stealer to function properly.


## Configuring the 365-Stealer Management Portal

### Modifying Paths
1. Adjust the Script Paths:

   - If necessary, modify the paths for `365-Stealer.py`, the database, and python3 in the index.php file located at `C:/xampp/htdocs/yourvictims/`.

<img src="https://github.com/AlteredSecurity/365-Stealer/blob/master/Images/Management-config-1.png" alt="Managemeent Config" border="0">

2. Handling Spaces in File Paths:

   - If Python is installed in a directory with spaces in the path (e.g., "Program Files"), make sure to enclose the path in quotes. For example:
   ```"C:/Program Files/Python/python.exe"```

<img src="https://github.com/AlteredSecurity/365-Stealer/blob/master/Images/Management-config-2.png" alt="Managemeent Config" border="0">

### Enabling IP Whitelisting for the 365-Stealer Management Portal

1. Default Whitelisting:

   - By default, IP whitelisting is enabled, and the Management Portal can only be accessed from localhost.

2. Adding Remote IPs:

   - If you want to allow access from a remote IP, you can add the desired IP address in the configuration.

3. Disabling IP Whitelisting:

   - If you wish to disable IP whitelisting entirely, set $enableIpWhiteList = false; in the configuration file.

<img src="https://github.com/AlteredSecurity/365-Stealer/blob/master/Images/management-config-3.png" alt="Managemeent Config" border="0">

## OPSEC Consideration

**Access Restrictions:** For security reasons, always restrict access to the 365-Stealer Management Portal to infrastructure that you control.

**Avoid Public Exposure:** Never expose the 365-Stealer Management Portal directly to the internet. Ensure it is only accessible through secure, private networks to avoid potential compromise.

## Command Line Help

```
usage: 365-Stealer.py [-h] [--app-registration] [--set-config] [--get-config] [--code CODE] [--token TOKEN] [--client-id CLIENT_ID]
                      [--client-secret CLIENT_SECRET] [--refresh-token REFRESH_TOKEN] [--token-path TOKEN_PATH]
                      [--refresh-all] [--refresh-user REFRESH_USER] [--redirect-url REDIRECT_URL]
                      [--database-path DATABASE_PATH] [--no-stealing] [--upload UPLOAD] [--create-rules CREATE_RULES]
                      [--send-mail SEND_MAIL] [--delete-all-data] [--delete-user-data DELETE_USER_DATA] [--run-app]
                      [--no-ssl] [--port PORT] [--disable-logs]
                      [--injection]
                      [--custom-steal {listusers,checklicence,outlook,onedrive,onenote} [{listusers,checklicence,outlook,onedrive,onenote} ...]]
                      [--delay DELAY]
optional arguments:
  -h, --help            show this help message and exit
  --app-registration    Azure App Registration
  --set-config          Set 365-Stealer Configuration
  --get-config          Get 365-Stealer Configuration
  --code CODE           Provide Authorization Code
  --token TOKEN         Provide Access Token
  --client-id CLIENT_ID
                        Provide Application Client ID
  --client-secret CLIENT_SECRET
                        Provide Application Client Secret
  --refresh-token REFRESH_TOKEN
                        Provide Refresh Token
  --token-path TOKEN_PATH
                        Provide Access Token file path
  --refresh-all         Steal all user's data again.
  --refresh-user REFRESH_USER
                        Steal particular user's data again.(Provide EmailID)
  --redirect-url REDIRECT_URL
                        Redirect Url
  --database-path DATABASE_PATH
                        Provide Database Path
  --no-stealing         Steal only Tokens
  --upload UPLOAD       Add files in victim's OneDrive(Provide File Path)
  --create-rules CREATE_RULES
                        Provide json file containing outlook rules
  --send-mail SEND_MAIL
                        Provide json file to send email
  --delete-all-data     Delete all data from the database!
  --delete-user-data DELETE_USER_DATA
                        Delete specific user data from the database!
  --run-app             Host the Phising App
  --no-ssl              Use http(port 80)
  --port PORT           Provide custom port to Host the Phishing App
  --disable-logs        Disable all http access logs
  --custom-steal {listusers,checklicence,outlook,onedrive,onenote} [{listusers,checklicence,outlook,onedrive,onenote} ...]
                        Steal specific data
  --injection           Enable Macro Injection
  --delay DELAY         Delay the request by specifying time in seconds while stealing
```

## Blog
### [Initial Access Attack in Azure – Understanding and Executing the Illicit Consent Grant Attack in 2025](https://www.alteredsecurity.com/post/initial-access-attack-in-azure-understanding-and-executing-the-illicit-consent-grant-attack-in-202) 
Blog post for the new version of 365-stealder, which is a ground-up rewrite of the older one. This post explores how Illicit Consent Grant (ICG) attack works in Microsoft 365.

#### [Introduction to 365-Stealer](https://www.alteredsecurity.com/post/introduction-to-365-stealer)
The old blog post.

## Bugs and Feature Requests

Please raise an issue if you encounter a bug or have a feature request.

## Contributing

If you want to contribute to a project and make it better, your help is very welcome.
