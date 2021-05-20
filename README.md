# 365-Stealer
<h1 align="center">
  <a href="https://github.com/AlteredSecurity/365-Stealer"><img src="https://github.com/AlteredSecurity/365-Stealer/blob/master/Images/365-Stealer.png" alt="365-Stealer" border="0"></a>
</h1>


## Table of Contents
- [About 365-Stealer](#About)
- [About Illicit Consent Grant Attack](#About-Illicit-Consent-Grant-Attack)
- [Features](#Features)
- [Setup Attacking Environment](#Setup-Attacking-Environment) 
	- [Register Application](#Register-Application)
	- [Configure Application](#Configure-Application)
		- [Create Client Secrets ](#Create-Client-Secrets )
		- [Add API Permissions](#Add-API-Permissions)
- [Setup 365-Stealer](#Setup-365-Stealer)
	- [ Enable sqlite3 in apache server](#Enable-sqlite3-in-apache-server)
- [Configure 365-Stealer Management portal](#Configure-365-Stealer-Management-portal)
	- [Enable IP whitelisting for 365-Stealer Management portal](#Enable-IP-whitelisting-for-365-Stealer-Management-portal)
- [OPSEC Consideration](#OPSEC-Consideration)
- [Command Line Help](#Command-Line-Help)
- [Blog](#Blog)
- [Video](#Video)
- [Bugs and Feature Requests](#Bugs-and-Feature-Requests)
- [Contributing](#Contributing)
- [Credits](#Credits)

## About
365-Stealer is a tool written in Python3 which can be used in illicit consent grant attacks. When the victim grant his consent we get their Refresh Token which can be used to request multiple Tokens that can help us in accessing data like Mails, Notes, Files from OneDrive etc. Doing this manually will take a lot of time so this tool helps in automating the process.

365-Stealer comes with 2 interfaces:
1. CLI - The CLI is purely written in python3. 
2. Web UI - The Web UI is written in PHP and it also leverages python3 for executing commands in background.

## About Illicit Consent Grant Attack
In an illicit consent grant attack, the attacker creates an Azure-registered application that requests access to data such as contact information, email, or documents. The attacker then tricks an end user into granting consent to the application so that the attacker can gain access to the data that the target user has access to. After the application has been granted consent, it has user account-level access to the data without the need for an organizational account.

In simple words when the victim clicks on that beautiful blue button of "Accept", Azure AD sends a token to the third party site which belongs to an attacker where attacker will use the token to perform actions on behalf the victims like accessing all the Files, Read Mails, Send Mails etc. 

## Features
- Steals Refresh Token which can be used to grant new Access Tokens for at least 90 days.
- Can send mails with attachments from the victim user to another user.
- Creates Outlook Rules like forwarding any mail that the victim receives.
- Upload any file in victims OneDrive.
- Steal's files from OneDrive, OneNote and dump all the Mails including the attachments.
- 365-Stealer Management portal allows us to manage all the data of the victims.
- Can backdoor .docx file located in OneDrive by injecting macros and replace the file extension with .doc.
- All the data like Refresh Token, Mails, Files, Attachments, list of all the users in the victim's tenant and our Configuration are stored in database.
- Delay the request by specifying time in seconds while stealing the data
- Tool also helps in hosting the dummy application for performing illicit consent grant attack by using `--run-app` in the terminal or by using 365-Stealer Management.
- By using `--no-stealing` flag 365-Stealer will only steal token's that can be leverage to steal data.
- We can also request New Access Tokens for all the user’s or for specific user.
- We can easily get a new access token using `--refresh-token`, `--client-id`, `--client-secret` flag.
- Configuration can be done from 365-Stealer CLI or Management portal.
- The 365-Stealer CLI gives an option to use it in our own way and set up our own Phishing pages.
- Allow us to steal particular data eg, OneDrive, Outlook etc. by passing a `--custom-steal` flag.
- All the stolen data are saved in database.db file which we can share with our team to leverage the existing data, tokens etc.
- We can search emails with specific keyword, subject, user's email address or by filtering the emails containing attachments from the 365-Stealer Management portal.
- We can dump the user info from the target tenant and export the same to CSV.

## Setup Attacking Environment

### Register Application
Follow the below mentioned steps to register an application in Azure 
1. Login to `https://portal.azure.com`
2. Navigate to `Azure Active Directory`
3. Click on `App registrations`
4. Click `New registration`
5. Enter the Name for our application (The same name will be displayed to the victim while granting consent)
6. Under support account types select `Accounts in any organizational directory (Any Azure AD directory - Multitenant)`
7. Enter the Redirect URL. This URL should be pointed towards our 365-Stealer application that we will host for hosting our phishing page. Make sure the endpoint is `https://<DOMAIN/IP>:<PORT>/login/authorized`.
8. Click `Register`

<h1 align="center">
<img src="https://github.com/AlteredSecurity/365-Stealer/blob/master/Images/registration.png" alt="app registration" width=720 border="0">

<img src="https://github.com/AlteredSecurity/365-Stealer/blob/master/Images/registration1.png" alt="app registration" width=720  border="0">
</h1>

### Configure Application
#### Create Client Secrets 

1. Click on `Certificates & secrets`
2. Click on `New client secret` then enter the `Description` and click on `Add`.
3.  Save the secret's value somewhere in a safe place.

<img src="https://github.com/AlteredSecurity/365-Stealer/blob/master/Images/secrets.png" alt="Client Secrets" border="0">

#### Add API Permissions

1. Click on `API permissions`
2. Click `Add a permission`
3. Click on `Microsoft Graph`
4. Click on  `Delegated permissions`
5. Search and select the below mentioned permissions and click on Add permission (This depends upon what permissions we want from the victim)
    1. Contacts.Read 
    2. Mail.Read
    3. Notes.Read.All
    4. Mailboxsettings.ReadWrite
    5. Files.ReadWrite.All
    6. Mail.Send
    7. User.ReadBasic.All

## Setup 365-Stealer

1. Clone 365-Stealer from [https://github.com/AlteredSecurity/365-Stealer](https://github.com/AlteredSecurity/365-Stealer)

> git clone https://github.com/AlteredSecurity/365-Stealer.git

2. Save the extracted in `C:\xampp\htdocs\` or at any location that can help us to host the PHP application and run Python.

3. Install the required application 
> Python3
> PHP CLI or Xampp server

4. Install the required python modules
> pip install -r requirements.txt 

### Enable sqlite3 in apache server

1. Open Xampp server, click on config of Apache and select `PHP (php.ini)`
2. Search for `extension=sqlite3` and remove `;` from the begining as it is considered as a comment and then save the file.(File location: `C:\xampp\php\php.ini`)
3. Start the Apache server.

<span style="font-size:20px">Note: </span> 365-Stealer will by default run on Port 443 (that can be changed by using `--port` flag) so we need to run apache server on another Port. This can be done by changing Port in Xampp server to avoid conflict between our 365-Stealer Phishing application & Management portal. We can also use PHP CLI command from the "./yourVictims/" directory as mentioned below.

```
php -S localhost:8000
```

<img src="https://github.com/AlteredSecurity/365-Stealer/blob/master/Images/365-Stetaler-home-page.png" alt="365 Stealer Home" border="0">

## Configure 365-Stealer Management portal

Modify the path of 365-Stealer.py, database and python3 in C:/xampp/htdocs/yourvictims/index.php if needed.

<img src="https://github.com/AlteredSecurity/365-Stealer/blob/master/Images/Management-config-1.png" alt="Managemeent Config" border="0">

If our python.exe is installed in "Program Files" or some directory that contains space in the path then we need to use quotes as shown below screenshot.

<img src="https://github.com/AlteredSecurity/365-Stealer/blob/master/Images/Management-config-2.png" alt="Managemeent Config" border="0">


### Enable IP whitelisting for 365-Stealer Management portal
By default whitelisting is enabled and the portal can only be accessed from localhost.
We can add a Remote IP or disable whitelisting ( $enableIpWhiteList = false; )

<img src="https://github.com/AlteredSecurity/365-Stealer/blob/master/Images/management-config-3.png" alt="Managemeent Config" border="0">

## OPSEC Consideration

Access to the 365-Stealer Management portal shall only be allowed from the infrastructure that you own. Don't expose the 365-Stealer Management portal on the Internet.

## Command Line Help
```
usage: 365-Stealer.py [-h] [--set-config] [--get-config] [--code CODE] [--token TOKEN] [--client-id CLIENT_ID]
                      [--client-secret CLIENT_SECRET] [--refresh-token REFRESH_TOKEN] [--token-path TOKEN_PATH]
                      [--refresh-all] [--refresh-user REFRESH_USER] [--redirect-url REDIRECT_URL]
                      [--database-path DATABASE_PATH] [--no-stealing] [--upload UPLOAD] [--create-rules CREATE_RULES]
                      [--send-mail SEND_MAIL] [--delete-all-data] [--delete-user-data DELETE_USER_DATA] [--run-app]
                      [--no-ssl] [--port PORT] [--disable-logs]
                      [--custom-steal {listusers,checklicence,outlook,onedrive,onenote} [{listusers,checklicence,outlook,onedrive,onenote} ...]]
                      [--delay DELAY]

optional arguments:
  -h, --help            show this help message and exit
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
  --delay DELAY         Delay the request by specifying time in seconds while stealing
 ```

## Blog

[Introduction To 365-Stealer](https://www.alteredsecurity.com/post/Introduction-To-365-Stealer)

## Video
<h1 align="center">
<span style="color:#00A1FF">1. 365-Stealer Introduction/Guide Video.</span>
<a href="https://youtu.be/22ku67tElkI">
<img src="https://github.com/AlteredSecurity/365-Stealer/blob/master/Images/thumbnail.png" alt="thumbnail" border="0" width="90%">
</a>
</h1>

<h2 align="center">
Author: 
<a href="https://twitter.com/trouble1_raunak" target="_blank"> 
@trouble1_raunak <img src="https://github.com/AlteredSecurity/365-Stealer/blob/master/Images/twitter-icon.png" width="35px"></a>
</h2>
<h2 align="center">
Being used in <a href="https://bootcamps.pentesteracademy.com/course/ad-azure-jun-21">Attacking and Defending Azure AD Cloud</a>
</h2>

## Bugs and Feature Requests

Please raise an issue if you encounter a bug or have a feature request. 

## Contributing

If you want to contribute to a project and make it better, your help is very welcome.

## Credits

Thanks to [0x09AL](https://twitter.com/0x09AL) for writing [office365-attack-toolkit](https://github.com/mdsecactivebreach/o365-attack-toolkit).
