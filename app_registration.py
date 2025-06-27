#!/usr/bin/env python3
"""
Azure App Registration Automation Tool

"""
import msal
import requests
import json
import crayons
import argparse
import sys
import re

class AzureAppRegistration:
    def __init__(self, tenant_id, app_name, redirect_uri):
        self.tenant_id = tenant_id
        self.app_name = app_name
        self.redirect_uri = redirect_uri
        self.selected_permissions = []

    def get_access_token_with_username_password(self, UserName, Password):
        """
        Get an access token using the ROPC flow.

        Args:
            username (str): The username.
            password (str): The password.

        Returns:
            str: The access token.

        Raises:
            Exception: If the access token cannot be acquired.
        """
        authority_url = "https://login.microsoftonline.com/"
        scope = ["https://graph.microsoft.com/.default"]
        client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Microsoft's Public Client ID for PowerShell/Azure CLI
        username = UserName
        password = Password

        app = msal.PublicClientApplication(client_id=client_id, authority=authority_url + self.tenant_id)
        token_response = app.acquire_token_by_username_password(username=username, password=password, scopes=scope)

        if "access_token" in token_response:
            return token_response["access_token"]
        else:
            error_message = f"Failed to acquire token: {json.dumps(token_response)}"
            raise Exception(error_message)

    def get_access_token_with_client_secret(self, client_id, client_secret):
        """
        Get an access token using client credentials flow.

        Args:
            client_id (str): The client ID.
            client_secret (str): The client secret.

        Returns:
            str: The access token.

        Raises:
            Exception: If the access token cannot be acquired.
        """
        authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        app = msal.ConfidentialClientApplication(
            client_id=client_id,
            authority=authority,
            client_credential=client_secret
        )
        token_response = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])

        if "access_token" in token_response:
            return token_response["access_token"]
        else:
            error_message = f"Failed to acquire token: {json.dumps(token_response)}"
            raise Exception(error_message)


    def get_access_token_via_device_code(self):
        """
        Get an access token using the device code flow.

        Args:
            None
        
        Returns:
            str: The access token

        Raises:
            Exception: If the access token cannot be acquired.
        """
        client_id = "d3590ed6-52b3-4102-aeff-aad2292ab01c"  # Microsoft Graph client ID for public client applications
        authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        scope = ["https://graph.microsoft.com/.default"]

        app = msal.PublicClientApplication(client_id, authority=authority)

        flow = app.initiate_device_flow(scopes=scope)
        if "user_code" not in flow:
            raise ValueError("Failed to create device flow. Err: %s" % json.dumps(flow, indent=4))

        print(crayons.yellow(flow["message"]))
        result = app.acquire_token_by_device_flow(flow)

        if "access_token" in result:
            return result["access_token"]
        else:
            raise Exception("Failed to acquire token: " + json.dumps(result, indent=2))


    def get_default_permissions(self):
        # Display default API permissions required by 365-Stealer.
        print(crayons.blue("┌────────────────────────────┐"))
        print(crayons.blue("│ Default API Permissions    │"))
        print(crayons.blue("├────────────────────────────┤"))
        print(crayons.blue("│ Contacts.Read              │"))
        print(crayons.blue("│ Files.ReadWrite.All        │"))
        print(crayons.blue("│ Mail.Read                  │"))
        print(crayons.blue("│ Mail.Send                  │"))
        print(crayons.blue("│ MailboxSettings.ReadWrite  │"))
        print(crayons.blue("│ Notes.Read.All             │"))
        print(crayons.blue("│ User.Read                  │"))
        print(crayons.blue("│ User.ReadBasic.All         │"))
        print(crayons.blue("└────────────────────────────┘"))

    
    def map_permission_name_to_id(self, permission_name):
        # Define a dictionary mapping permission names to their corresponding IDs
        permission_ids = {
            "Contacts.Read": "ff74d97f-43af-4b68-9f2a-b77ee6968c5d",
            "Files.ReadWrite.All": "863451e7-0667-486c-a5d6-d135439485f0",
            "Mail.Read": "570282fd-fa5c-430d-a7fd-fc8dc98a9dca",
            "Mail.Send": "e383f46e-2787-4529-855e-0e479a3ffac0",
            "MailboxSettings.ReadWrite": "818c620a-27a9-40bd-a6a5-d96f7d610b4b",
            "Notes.Read.All": "dfabfca6-ee36-4db2-8208-7a28381419b3",
            "User.Read": "e1fe6dd8-ba31-4d61-89e7-88639da4683d",
            "User.ReadBasic.All": "b340eb25-3456-403f-be2f-af7a0d370277"
        }

        # Return the corresponding ID for the given permission name
        return permission_ids.get(permission_name)


    def create_app_registration(self, access_token, resource_access=None):
        """
        Create a new app registration in Azure AD.

        Args:
            access_token (str): The access token.
            resource_access (list): List of resource access objects.
        
        Returns:
            dict: The app registration data.

        Raises:
            Exception: If the app registration cannot be created.
        """
        url = "https://graph.microsoft.com/v1.0/applications"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        if resource_access is None:
            permissions = [
            "Contacts.Read",
            "Files.ReadWrite.All",
            "Mail.Read",
            "Mail.Send",
            "MailboxSettings.ReadWrite",
            "Notes.Read.All",
            "User.Read",
            "User.ReadBasic.All"
            ]
            resource_access = [
                {"id": self.map_permission_name_to_id(permission), "type": "Scope"} for permission in permissions
            ]

        app_data = {
            "displayName": self.app_name,
            "signInAudience": "AzureADMultipleOrgs",  # Multitenant
            "web": {
                "redirectUris": [self.redirect_uri]
            },
            "requiredResourceAccess": [
                {
                    "resourceAppId": "00000003-0000-0000-c000-000000000000",  # Microsoft Graph
                    "resourceAccess": resource_access
                }
            ]
        }

        response = requests.post(url, headers=headers, json=app_data)

        if response.status_code == 201:
            return response.json()
        else:
            raise Exception(f"Failed to create app registration: {response.status_code} {response.text}")


    def create_client_secret(self, access_token, app_id):
        """
        Create a new client secret for the app registration.

        Args:
            access_token (str): The access token.
            app_id (str): The app registration ID.

        Returns:
            dict: The client secret data.

        Raises:
            Exception: If the client secret cannot be created
        """
        url = f"https://graph.microsoft.com/v1.0/applications/{app_id}/addPassword"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        secret_data = {
            "passwordCredential": {
                "displayName": "default"
            }
        }

        response = requests.post(url, headers=headers, json=secret_data)

        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to create client secret: {response.status_code} {response.text}")


    def create_app_with_secret(self, auth_method, resource_access=None, client_id=None, client_secret=None, username=None, password=None):
        """
        Create a new app registration with a client secret.

        Args:
            auth_method (str): The authentication method.
            resource_access (list): List of API's Permissions IDs.
            client_id (str): The client ID.
            client_secret (str): The client secret.
            username (str): The username.
            password (str): The password.

        Returns:
            tuple: The client ID and client secret.

        Raises:
            ValueError: If the authentication method is invalid.
        """
        if auth_method == 'client_secret':
            if not all([client_id, client_secret]):
                raise ValueError("Client ID and Client Secret are required for OAuth with Client Secret.")
            access_token = self.get_access_token_with_client_secret(client_id, client_secret)
        elif auth_method == 'device_code':
            access_token = self.get_access_token_via_device_code()
        elif auth_method == 'ROPC_flow':
            print(crayons.red("\n[!] Note: After Microsoft's mandatory MFA enforcement, ROPC (Resource Owner Password Credential) flow will not work."))
            access_token = self.get_access_token_with_username_password(username, password)
        else:
            raise ValueError("Invalid authentication method.")

        app = self.create_app_registration(access_token, resource_access)
        client_id = app["appId"]
        secret = self.create_client_secret(access_token, app["id"])
        return client_id, secret['secretText']


    def display_permissions_and_select(self):
        """
        Display API permissions and allow the user to select permissions.

        Args:
            None

        Returns:
            list: List of selected API's permissions.

        Raises:
            FileNotFoundError: If the API-Permissions.json file is not found.
        """
        try:
            with open("API-Permissions.json", "r") as f:
                permissions = json.load(f)
        except FileNotFoundError:
            print(crayons.red("Error: API-Permissions.json file not found."))
            return None

        all_permissions = permissions
        self.selected_permissions = []

        try:
            while True:
                starting_letter = input(crayons.green("Enter the starting letter(A-Z) of the API permissions (or 'done' to finish): ")).upper()
                if starting_letter.lower() == "done":
                    break

                filtered_permissions = {k: v for k, v in all_permissions.items() if k.startswith(starting_letter)}
                if not filtered_permissions:
                    print(crayons.red(f"No API permissions found starting with '{starting_letter}'\n"))
                    continue

                while True:
                    print(crayons.yellow(f"\nAPI Permissions starting with '{starting_letter}':"))
                    for idx, category in enumerate(filtered_permissions.keys(), 1):
                        print(crayons.green(f"{idx}. {category}"))

                    print(crayons.green("99. Done"))

                    try:
                        category_choice = int(input(crayons.green("Select the category: ")))
                    except ValueError:
                        print(crayons.red("Invalid input. Please enter a number."))
                        continue

                    if category_choice == 99:
                        break

                    if category_choice < 1 or category_choice > len(filtered_permissions):
                        print(crayons.red("Invalid choice. Please try again."))
                        continue

                    selected_category = list(filtered_permissions.keys())[category_choice - 1]
                    selected_permissions = filtered_permissions[selected_category]

                    while True:
                        print(crayons.yellow(f"\nPermissions for {selected_category}:"))
                        for idx, perm in enumerate(selected_permissions, 1):
                            print(crayons.green(f"{idx}. {perm['name']}"))

                        print(crayons.green("99. Go Back"))

                        try:
                            permission_choice = int(input(crayons.green("Select the permission: ")))
                        except ValueError:
                            print(crayons.red("Invalid input. Please enter a number."))
                            continue

                        if permission_choice == 99:
                            break

                        if permission_choice < 1 or permission_choice > len(selected_permissions):
                            print(crayons.red("Invalid choice. Please try again."))
                            continue

                        selected_permission = selected_permissions[permission_choice - 1]
                        self.selected_permissions.append({"id": selected_permission["id"], "type": "Scope"})
                        print(crayons.green(f"Selected: {selected_permission['name']}"))
        
        except KeyboardInterrupt:
            print(crayons.red("\nKeyboardInterrupt occurred. Exiting..."))
            exit(1)

        print(crayons.blue("\nSelected Permissions:"))
        for perm in self.selected_permissions:
            print(crayons.blue(perm))

        return self.selected_permissions

def create_parser():
    parser = argparse.ArgumentParser(description="Automate Azure App Registration.")

    parser.add_argument('--tenant-id', type=str, required=True, help="Azure Tenant ID")
    parser.add_argument('--app-name', type=str, required=True, help="New App registration name")
    parser.add_argument('--redirect-uri', type=str, required=True, help="Redirect URI")

    # API permissions
    parser.add_argument('--low-impact', action='store_true', help="Use low-impact permissions (User.ReadBasic.All)")
    parser.add_argument('--default-permissions', action='store_true', help="Use default API permissions (required by 365-Stealer)")
    parser.add_argument('--custom-permissions', type=str, help="Comma-separated list of custom permission IDs")

    # Authentication method
    parser.add_argument('--auth-method', type=str, choices=['ROPC_flow', 'oauth'], required=True,
                        help="Choose authentication method: 'ROPC_flow' or 'oauth'")
    parser.add_argument('--username', type=str, help="Username (required for ROPC flow)")
    parser.add_argument('--password', type=str, help="Password (required for ROPC flow)")
    parser.add_argument('--client-id', type=str, help="Client ID (required if using OAuth)")
    parser.add_argument('--client-secret', type=str, help="Client Secret (required if using OAuth)")

    return parser

def main():
    print(crayons.green("""Welcome to Azure App Registration Automation Tool!\n"""))
    regex_url = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    def get_input(prompt_message):
        """ Prompts the user until they provide a non-empty input """
        while True:
            user_input = input(prompt_message)
            if user_input.strip():  # Check if input is not empty or only whitespace
                return user_input
            print(crayons.red("Input cannot be empty. Please try again."))

    def get_valid_url():
        """ Prompts the user until they provide a valid URL """
        while True:
            url = input("Enter the redirect URI: ")
            if regex_url.match(url):
                return url
            print(crayons.red("Invalid URL format. Make sure to include 'http://' or 'https://'."))

    if len(sys.argv) > 1: # Non-interactive mode
        import codecs

        # Set UTF-8 encoding
        sys.stdout = codecs.getwriter("utf-8")(sys.stdout.detach())

        parser = create_parser()
        args = parser.parse_args()
        if args.tenant_id and args.app_name and args.redirect_uri:
            tenant_id = args.tenant_id
            app_name = args.app_name
            redirect_uri = args.redirect_uri
        else: 
            print(crayons.red("Error: You must provide --tenant-id, --app-name, and --redirect-uri"))
            sys.exit(1)

        azure_app = AzureAppRegistration(tenant_id, app_name, redirect_uri)

        if args.low_impact:
            resource_access = [
            {"id": "b340eb25-3456-403f-be2f-af7a0d370277", "type": "Scope"},  # User.ReadBasic.All
            {"id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "type": "Scope"}   # User.Read
            ]
        elif args.default_permissions:
            azure_app.get_default_permissions()
            resource_access = None
        elif args.custom_permissions:
            resource_access = [{"id": perm_id, "type": "Scope"} for perm_id in args.custom_permissions.split(',')]
        else:
            print(crayons.red("Error: You must provide either --low-impact ,--default-permissions or--custom-permissions"))
            

        if args.auth_method == 'oauth':
            if not args.client_id or not args.client_secret:
                print(crayons.red("Error: Both --client-id and --client-secret are required for OAuth."))
                sys.exit(1)
            azure_app = AzureAppRegistration(tenant_id, app_name, redirect_uri)
            client_id, secret = azure_app.create_app_with_secret('client_secret', resource_access=resource_access, client_id=args.client_id, client_secret=args.client_secret)
        elif args.auth_method == 'ROPC_flow':
            if not args.username or not args.password:
                print(crayons.red("Error: Both --username and --password are required for ROPC flow."))
                sys.exit(1)
            azure_app = AzureAppRegistration(tenant_id, app_name, redirect_uri)
            client_id, secret = azure_app.create_app_with_secret('ROPC_flow', resource_access=resource_access, username=args.username, password=args.password)
        else:
            print(crayons.red("Error: Invalid authentication method."))
            sys.exit(1)
        
        print(crayons.green("\nApp Registration Successful!"))
        print(crayons.cyan(f"Application (client) ID: {client_id}"))
        print(crayons.cyan(f"Client Secret: {secret}"))
    else: # Interactive mode
        try:
            tenant_id = get_input("Enter your tenant ID: ")
            app_name = get_input("Enter the new app registration name: ")
            redirect_uri = get_valid_url()

            azure_app = AzureAppRegistration(tenant_id, app_name, redirect_uri)

            print(crayons.green("\nSelect permission method:"))
            print(crayons.green("1. Low Impact (User.ReadBasic.All)"))
            print(crayons.green("2. Default API permissions (required by 365-Stealer)"))
            print(crayons.green("3. Custom API permissions"))

            while True:
                permission_choice = get_input("Enter the number of your choice (1, 2 or 3): ")
                if permission_choice == '1':
                    resource_access = [
                    {"id": "b340eb25-3456-403f-be2f-af7a0d370277", "type": "Scope"},
                    {"id": "e1fe6dd8-ba31-4d61-89e7-88639da4683d", "type": "Scope"}] # User.Read and User.ReadBasic.All
                    break
                elif permission_choice == '2':
                    azure_app.get_default_permissions()
                    resource_access = None
                    break
                elif permission_choice == '3':
                    resource_access = azure_app.display_permissions_and_select()
                    break
                else:
                    print(crayons.red("Invalid choice. Please select 1, 2, or 3."))

            try:
                print(crayons.green("\nSelect authentication method:"))
                print(crayons.green("1. ROPC Flow (requires Username and Password)."))
                print(crayons.green("2. OAuth with Client Secret (requires Client ID and Client Secret)."))
                print(crayons.green("3. Device Code Flow."))

                while True:
                    choice = get_input("Enter the number of your choice (1, 2 or 3): ")
                    if choice in ['1', '2', '3']:
                        break
                    print(crayons.red("Invalid choice. Please select 1, 2 or 3."))

            except KeyboardInterrupt:
                print(crayons.red("\nKeyboardInterrupt occurred. Exiting..."))
                sys.exit(1)

            try:
                if choice == '2':
                    print(crayons.yellow("\n[*] Note: The App needs 'Application.ReadWrite.All' API permission (Application) with admin consent.\n"))
                    client_id = get_input("Enter your client ID: ")
                    client_secret = get_input("Enter your client secret: ")
                    client_id, secret = azure_app.create_app_with_secret('client_secret', resource_access=resource_access, client_id=client_id, client_secret=client_secret)
                elif choice == '3':
                    client_id, secret = azure_app.create_app_with_secret('device_code', resource_access=resource_access)
                elif choice == '1':
                    print(crayons.yellow("\n[*] Note: User is required to have 'Application Administrator' RBAC role in Azure AD.\n"))
                    username = get_input("Enter your username: ")
                    password = get_input("Enter your password: ")
                    client_id, secret = azure_app.create_app_with_secret('ROPC_flow', resource_access=resource_access, username=username, password=password)

                print(crayons.green("\nApp Registration Successful!"))
                print(crayons.cyan(f"Application (client) ID: {client_id}"))
                print(crayons.cyan(f"Client Secret: {secret}"))

            except Exception as e:
                print(crayons.red(str(e)))

        except KeyboardInterrupt:
            print(crayons.red("\nKeyboardInterrupt occurred. Exiting..."))
            sys.exit(1)

if __name__ == "__main__":
    main()