# Python script to check Active Directory emails and NTLM hashes against haveibeenpwned for pwnage
# Haveibeenpwned uses a paid api key. Blocks normal means of scraping. (mechanize, selenium, and requests)
# Api_Key, Receiving_Email, Sender_Address, and Sender_Password can be hardcoded if need be

# These are part of the python standard library
import os
import gc
import sys
import ssl
import time
import shutil
import ctypes
import smtplib
import subprocess
import urllib.parse
from os import path
from getpass import getpass


# Function to install packages via pip (aka Pip Cheat)
def install_library(package):
    # Run pip as a subprocess
    subprocess.call(['pip', 'install', package])
    return

# Install pypiwin32 to access windows api services
install_library("pypiwin32")

# Install missing packages
while True:
    try:
        # Import packages here
        import psutil
        import binascii
        import requests
        import win32crypt
        import pandas as pd
        from py7zr import unpack_7zarchive
        break
    except Exception as e:
        Missing_Library = str(e).strip('No module named ')
        Missing_Library = Missing_Library.strip("'")
        install_library(Missing_Library)


# Print important information to screen
def acknowledgements(*args):
    # Change fucntion based on automation
    Auto_Bit = 0
    if (len(args) > 0) and ("auto" in args):
        Auto_Bit = 1      

    print("""
        This script makes a couple assumptions...\n
        1.) Pip is installed.
        2.) You have administrator credentials for this machine and for the Domain Controller.
        3.) You have an api key for HaveIBeenPwned.
        4.) You have sender email credentials (Assuming you chose to email results).
       
        Current versions of python automatically install pip,
        however you can also install it using the following commands:
       
        To download pip: curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
       
        To install pip: python get-pip.py
       
        Any dependencies will automatically be installed via pip
        if they are not present. This is purely for ease of use,
        however, they can also be installed manually:
        
        pip install -r requirements.txt
       
        The script will auto escalate, but will give you a UAC
        prompt to allow for admin access. It will then run an admin
        instance of itself for the rest of the duration.
       
        Beyond that, the script will check to see if the current
        machine is connected to an active directory instance.
        If so, it will pull all user emails, and sumbit them to
        HaveIBeenPwned to check if they have been compromised.
        Then it will replicate the NTLM hash database, and check
        those locally against HaveIBeenPwned's NTLM hash file,
        and return compromised emails and usernames.
        
        Results can be emailed or printed to screen.
        
        (Hashes do not exist outside of memory for protection purposes,
        so only the username will be returned if that user's password hash
        is identified as compromised.)""")
    if Auto_Bit == 0:    
        # Prompt user for acknowledgement
        Initial_Prompt = input("\nPress enter if you want to continue. Otherwise enter q to quit. ")
        if Initial_Prompt.lower() == 'q':
            print("Exiting...")
            exit()
        else:
            pass
    else:
        pass
       
    return
   

# Function to run script as admin
# In essence, checks to see if the current script is being
# Run with admin priveledges. If not, spawn a UAC prompt,
# And create new elevated window.
# Everything from there on runs in the new window
def run_as_admin(argv=None, debug=False):

    shell32 = ctypes.windll.shell32
    if argv is None and shell32.IsUserAnAdmin():
        return True

    if argv is None:
        acknowledgements()
        argv = sys.argv

    if hasattr(sys, '_MEIPASS'):
        arguments = map(str, argv[1:])
    else:
        arguments = map(str, argv)
       
    argument_line = u' '.join(arguments)
    executable = str(sys.executable)
   
    if debug:
        print('Command line: ', executable, argument_line)
    ret = shell32.ShellExecuteW(None, u"runas", executable, argument_line, None, 1)

    if int(ret) <= 32:
        return False
        
    return
    

# Function to export credentials to xml file and encrypt using windows dpapi
def export_credentials(username, password):
    # Encrypt the password using dpapi
    encrypted_password = win32crypt.CryptProtectData(password.encode("utf-16-le"))
    
    # Convert password to secure string format used by powershell
    password_secure_string = binascii.hexlify(encrypted_password).decode()

    # Use the same xml format as for powershells Export-Clixml, just replace values for username and password.
    xml = f"""<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">{username}</S>
      <SS N="Password">{password_secure_string}</SS>
    </Props>
  </Obj>
</Objs>"""
    
    # Write encrypted xml data to file
    file = open("clixml.xml", "w", encoding='utf-16')
    file.write(xml)
    file.close()
    
    # Print ending message
    print("Credentials saved to: clixml.xml")

    return


# Function to import credentials from xml file
def import_credentials(filename):
    # Import file and get credentials
    with open(filename, 'r', encoding='utf-16') as f:
        xml = f.read()

        # Extract username and password from the XML since thats all we care about.
        username = xml.split('<S N="UserName">')[1].split("</S>")[0]
        password_secure_string = xml.split('<SS N="Password">')[1].split("</SS>")[0]

        # CryptUnprotectDate returns two values, description and the password, 
        # we dont care about the description, so we use _ as variable name.
        _, decrypted_password_string = win32crypt.CryptUnprotectData(
            binascii.unhexlify(password_secure_string), None, None, None, 0
        )

        # Decode password string to get rid of unknown characters
        decrypted_password_string = decrypted_password_string.decode("utf-16-le")

        return username, decrypted_password_string


# Function to install active directory tools via powershell
def install_tools():
    # Get current admin state
    Admin_State = run_as_admin()
    # (Local) Administrator privileges are needed for installing AD tools
    if Admin_State is True:
        # Install active directory tools
        print("Installing Active Directory Tools. This may take a few minutes. Please wait...")
        
        try: 
            # Check to see if the NuGet package is installed
            # Will return an error if it can't find it
            nuget_check = subprocess.check_output(["powershell.exe", "Find-Package -Name 'nuget' -Force"]).decode("utf-8")
        except subprocess.CalledProcessError:
            # Install NuGet package provider
            NuGet = subprocess.check_output(["powershell.exe", "Install-PackageProvider -Name 'nuget' -Force"])#; Import-PackageProvider -Name 'nuget'"])
        
        # Check to see if tools are already installed
        ad_module_check = subprocess.check_output(["powershell.exe", "Get-InstalledModule -Name 'ActiveDirectory'"]).decode("utf-8")
        ds_module_check = subprocess.check_output(["powershell.exe", "Get-InstalledModule -Name 'DSInternals'"]).decode("utf-8")
        
        # Set boolean value if the modules exist or not
        if "No match was found for the specified search criteria" in ad_module_check:
            AD_Exists = False
        else:
            AD_Exists = True
            
        if "No match was found for the specified search criteria" in ds_module_check:
            DS_Exists = False
        else:
            DS_Exists = True
       
        # Check to see if OS is a server version of windows or not
        os_check = subprocess.check_output(["powershell.exe", "$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem; $osInfo.ProductType"])
        os_check = str(os_check.decode("utf-8"))
        os_check = os_check.replace('\n', '')
        os_check = os_check.replace('\r', '')

        # If 1, this is a normal windows version
        if os_check == '1':
            if AD_Exists == False:
                # Install AD Tools, with specific version
                powershell = subprocess.check_output(["powershell.exe", "Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'"])
            else:
                # They are already installed
                pass
            if DS_Exists == False:
                # Install DSInternals
                powershell = subprocess.check_output(["powershell.exe", "Install-Module -Name DSInternals -Force"])
            else:
                # They are already installed
                pass
        # If 2 or 3, we are on windows server
        elif (os_check == '2') or (os_check == '3'):
            if AD_Exists == False:
                # These two work, but only on windows server editions
                powershell_install = subprocess.check_output(["powershell.exe", "Import-Module ServerManager"])
                powershell_install = subprocess.check_output(["powershell.exe", "Add-WindowsFeature -Name 'RSAT-AD-PowerShell' -IncludeAllSubFeature"])
            else:
                # They are already installed
                pass
            if DS_Exists == False:
                # Install DSInternals
                powershell = subprocess.check_output(["powershell.exe", "Install-Module -Name DSInternals -Force"])
            else:
                # They are already installed
                pass
        # Don't know what this would be. Just try to install the default windows 10 way
        else:
            if AD_Exists == False:
                # Install AD Tools, with specific version
                powershell = subprocess.check_output(["powershell.exe", "Add-WindowsCapability -Online -Name 'Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'"])
            else:
                # They are already installed
                pass
            if DS_Exists == False:
                # Install DSInternals
                powershell = subprocess.check_output(["powershell.exe", "Install-Module -Name DSInternals -Force"])
            else:
                # They are already installed
                pass
        print("Done installing tools.")
    elif Admin_State is None:
        print('Elevating privleges and moving to admin window.')
    else:
        print('Error: cannot elevate privileges.')
    
    return


# Function to pull all emails from active directory
def get_emails(*args):
    # Change fucntion based on automation
    Auto_Bit = 0
    if (len(args) > 0) and ("auto" in args):
        Auto_Bit = 1 

    # List of emails pulled from active directory
    email_list = []
   
    # Install AD Tools
    install_tools()

    # Call powershell process and pull email accounts from all users
    powershell = subprocess.check_output(["powershell.exe", "Import-Module ActiveDirectory"])
    Output_Message = powershell.decode("utf-8")
    if "Error initializing default drive" in Output_Message:
        if Auto_Bit == 0:
            input("No active directory found running. Press enter to quit.")
            exit()
        else:
            exit()
    else:
        pass

    # Get user emails via powershell
    powershell = subprocess.check_output(["powershell.exe", "Get-ADUser -Filter * -Properties EmailAddress, DisplayName, samaccountname | select EmailAddress | Format-List"])
    powershell = powershell.decode("utf-8")
    powershell = powershell.split(':')
   
    # Convert powershell list to list of strings
    # Remove all unnecessary characters
    for email in powershell:
        current_email = str(email)
        current_email = current_email.replace("EmailAddress", '')
        current_email = current_email.strip()
       
        # Create new list of clean email addresses
        if len(current_email) > 0:
            current_email = current_email.replace('\n', '')
            current_email = current_email.replace('\r', '')
            email_list.append(current_email)

    print(str(len(email_list)) + " email addresses found in current active directory.")
   
    return email_list
 

# Function to submit email address for checking
def check_email(email_list, api_key):
    # Url for getting all breaches for an account (takes an account) (This is the main one to use)
    Breached_Acount_Url = "https://haveibeenpwned.com/api/v3/breachedaccount/"
    # Url for getting alll breached sites in a system (takes a domain)
    #All_Sites_Url = "https://haveibeenpwned.com/api/v3/breaches/"
    # Url for getting a single breached site (takes a site)
    #Single_Site_Url = "https://haveibeenpwned.com/api/v3/breach/"
    # Url for all pastes for an account (takes an email)
    #Paste_Url = "https://haveibeenpwned.com/api/v3/pasteaccount/"

    # Header to send with request
    Header = {
      'hibp-api-key': str(api_key),
      'format': 'application/json',
      'timeout': '2.5',
      'HIBP': str(api_key),
    }
   
    # Save results to list
    Results = []
   
    # If there are emails addresses present, check them.
    if len(email_list) > 0:
        i = 0
        while i < len(email_list):
            # Concatenate to create full search url
            Full_Url = Breached_Acount_Url + email_list[i]
           
            # Default time in between requests. (To try and not get rate limited.) (in seconds)
            Default_Rate = 1.3

            # Get page and response
            Get_Page = requests.get(Full_Url, headers=Header)
            # Check response code
            Response_Status = Get_Page.status_code
           
            # Good response
            if Response_Status == 200:
                # Parse through results and get all sites the email has been compromised on
                Page_Repsonse = Get_Page.text
                Page_Repsonse = Page_Repsonse.replace('[', '')
                Page_Repsonse = Page_Repsonse.replace(']', '')
                Page_Repsonse = Page_Repsonse.replace('{', '')
                Page_Repsonse = Page_Repsonse.replace('}', '')
                Page_Repsonse = Page_Repsonse.replace('"', '')
                Page_Repsonse = Page_Repsonse.replace('Name:', '')
                Page_Repsonse = Page_Repsonse.split(',')
                print("Email address: " + str(email_list[i]) + " has been compromised on " + str(len(Page_Repsonse)) + " site(s).")
                Results.append([str(email_list[i]), Page_Repsonse])
               
            # Bad request - possible incorrect format
            elif Response_Status == 400:
                print("Bad request. Potentially empty string or incorect formatting.")
            # Unauthorized - Invalid api key
            elif Response_Status == 401:
                print("Invalid or Expired api key.")
            # Forbidden - No user agent specified
            elif Response_Status == 403:
                print("No user agent specified.")
            # Not found - Account could not be found (Clean. This is ideal)
            elif Response_Status == 404:
                print("No results for " + str(email_list[i]) + ". Email address doesn't appear to be compromised.")
                Results.append([str(email_list[i]), 'Clean'])
            # Too many requests - Implement rate limiting
            elif Response_Status == 429:
                print("Time in betwen requests being increased due to rate limiting.")
                Default_Rate += 0.2
                i -= 1
            # Service Unavailable - Possibly being blocked by cloudflare, or the site is down
            elif Response_Status == 503:
                print("Service Unavailable. Make sure requests aren't geting blocked by firewall.")
            # Unknown
            else:
                print("Unknown response code: " + str(Response_Status))
           
            # Sleep in between requests
            time.sleep(Default_Rate)
           
            i += 1
   
    return Results
   
   
# Function to send email
def send_mail(to_address, message, *args):
    # Change fucntion based on automation
    Auto_Bit = 0
    if (len(args) > 0) and ("auto" in args):
        Auto_Bit = 1 

    # Default server for gmail
    Smtp_Server = "smtp.gmail.com"
    # Subject for email header
    Subject = "Subject: HaveIBeenPwned Results\n"
    
    # Email account to send email from
    Sender_Address = ""
    Sender_Password = ""
    
    # Get current working directory
    Current_Directory = os.getcwd()
    # Default text file to save authentication email for sending from
    Email_File = "authentication_address.txt"
    # Full path to credential file
    Full_Path = str(Current_Directory) + "\\" + str(Email_File)
    # Check to see if file exists, if so, load credentials
    Authentication = path.exists(Full_Path)
   
    if Auto_Bit == 0:
        # Check to see if sender credentials are hard coded above
        print("Checking to see if a sender email and password already exists...")
        if len(Sender_Address) == 0 and len(Sender_Password) == 0:
            # If the length is zero, the variables are empty.
            # Check files to see if there are credentials saved.
            if Authentication == True:
                print("Save file found. Checking for credentials...")
                # Load in credentials
                # Saved as emailaddress:emailpassword
                with open(Full_Path, 'r') as file:
                    File_Contents = file.readlines()
                    file.close()
                    if len(File_Contents) > 0:
                        File_Contents = File_Contents[0].split(':')
                        Sender_Address = File_Contents[0]
                        Sender_Password = File_Contents[1]
                        #file.close()
                        print("Email credentials found in save file.")
                    else:
                        # If file is empty, ask for credentials
                        print("Save file empty.")
                        # Don't use credentials. Ask for new ones.
                        Sender_Address = input("Please enter an email address to send results from (Make sure Less Secure Apps are allowed): ")
                        Sender_Password = getpass("Enter password for above email address previously entered (Characters will not be printed): ")
                        # Save if warranted
                        while True:
                            Save_Credentials = input("Would you like to save these credentials for future use? (y/n) ").lower()
                            if (Save_Credentials == 'y') or (Save_Credentials == "yes"):
                                # Save credentials as emailaddress:emailpassword
                                print("Saving to file...")
                                with open(Full_Path, 'w+') as file:
                                    Credential_Write = (str(Sender_Address) + ':' + str(Sender_Password))
                                    file.write(Credential_Write)
                                    file.close()
                                print("Saved!")
                                break
                            elif (Save_Credentials == 'n') or (Save_Credentials == "no"):
                                print("Continuing...")
                                break
                            else:
                                # Other character entered.
                                print("Invalid response entered. Use y/Y for yes, and n/N for no.")
                # This should be yes, but just in case
                while True:
                    Continue = input("Continue using " + str(Sender_Address) + "? (y/n) ").lower()
                    if (Continue == 'y') or (Continue == "yes"):
                        # Continue using credentials already found.
                        pass
                        break
                    elif (Continue == 'n') or (Continue == "no"):
                        # Don't use credentials. Ask for new ones.
                        Sender_Address = input("Please enter an email address to send results from (Make sure Less Secure Apps are allowed): ")
                        Sender_Password = getpass("Enter password for above email address previously entered (Characters will not be printed): ")
                        # Save if warranted
                        while True:
                            Save_Credentials = input("Would you like to save these credentials for future use? (y/n) ").lower()
                            if (Save_Credentials == 'y') or (Save_Credentials == "yes"):
                                # Save credentials as emailaddress:emailpassword
                                print("Saving to file...")
                                with open(Full_Path, 'w+') as file:
                                    Credential_Write = (str(Sender_Address) + ':' + str(Sender_Password))
                                    file.write(Credential_Write)
                                    file.close()
                                print("Saved!")
                                break
                            elif (Save_Credentials == 'n') or (Save_Credentials == "no"):
                                print("Continuing...")
                                break
                            else:
                                # Other character entered.
                                print("Invalid response entered. Use y/Y for yes, and n/N for no.")
                        break
                    else:
                        # Other character entered.
                        print("Invalid response entered. Use y/Y for yes, and n/N for no.")
                print("Continuing...")
            else:
                print("No previous sender credentials exist.")
                # Ask user for credentials
                Sender_Address = input("Please enter an email address to send results from (Make sure Less Secure Apps are allowed): ")
                Sender_Password = getpass("Enter password for above email address previously entered (Characters will not be printed): ")
                # Save if warranted
                while True:
                    Save_Credentials = input("Would you like to save these credentials for future use? (y/n) ").lower()
                    if (Save_Credentials == 'y') or (Save_Credentials == "yes"):
                        # Save credentials as emailaddress:emailpassword
                        print("Saving to file...")
                        with open(Full_Path, 'w+') as file:
                            Credential_Write = (str(Sender_Address) + ':' + str(Sender_Password))
                            file.write(Credential_Write)
                            file.close()
                        print("Saved!")
                        break
                    elif (Save_Credentials == 'n') or (Save_Credentials == "no"):
                        print("Continuing...")
                        break
                    else:
                        # Other character entered.
                        print("Invalid response entered. Use y/Y for yes, and n/N for no.")
                print("Continuing...")
        else:
            # Both sender fields have atleast something in them.
            # Try those credentials. If there is an authentication error,
            # Ask to re-enter credentials
            print("Email credentials found hardcoded in system.")
            while True:
                Continue = input("Continue using " + str(Sender_Address) + "? (y/n) ").lower()
                if (Continue == 'y') or (Continue == "yes"):
                    # Continue using credentials already found.
                    pass
                    break
                elif (Continue == 'n') or (Continue == "no"):
                    # Don't use hardcoded credentials. Ask for new ones.
                    Sender_Address = input("Please enter an email address to send results from (Make sure Less Secure Apps are allowed): ")
                    Sender_Password = getpass("Enter password for above email address previously entered (Characters will not be printed): ")
                    Save_Credentials = input("Would you like to save these credentials for future use? (y/n) ")
                    # save
                    break
                else:
                    # Other character entered.    
                    print("Invalid response entered. Use y/Y for yes, and n/N for no.")
            print("Continuing...")
    else:
        # Pull from file and continue (this assumes they exist)
        with open(Full_Path, 'r') as file:
            File_Contents = file.readlines()
            file.close()
            if len(File_Contents) > 0:
                File_Contents = File_Contents[0].split(':')
                Sender_Address = File_Contents[0]
                Sender_Password = File_Contents[1]
            else:
                # WELL
                pass
       
    # Email address to send to
    Receiving_Address = to_address
    # Message to send via email
    Message = Subject + message
    # Create a secure SSL context
    Context = ssl.create_default_context()

    # Log in to google server and send email
    try:
        server = smtplib.SMTP(Smtp_Server, 587)
        server.ehlo()
        server.starttls(context=Context)
        server.ehlo()
        server.login(Sender_Address, Sender_Password)
        # Once logged in, send email
        server.sendmail(Sender_Address, Receiving_Address, Message)
    except Exception as e:
        # Catch any errors
        print(e)
    finally:
        # Close connection
        server.quit()

    return


# Function to run script as normal, with user interation
def run_normal():
    # Get current admin state
    Admin_State = run_as_admin()
    
    # API Key
    Api_Key = ""
    # Receiving email
    Receiving_Email = ""

    if Admin_State is True:
        # Move to admin window
        print('Continuing in admin window...')
       
        # The rest of the script will run in the elevated window
        # List to hold email addresses
        Email_Addresses = []
 
        # Call function to get all emails from active directory
        Email_Addresses = get_emails()
       
        # Check to see if api key is saved
        print("Checking to see if api key already exists...")
        # If the length is zero, the variable is empty.
        if len(Api_Key) == 0:
            # Check files to see if there is a save file.
            # Get current working directory
            Current_Directory = os.getcwd()
            # Default text file to save authentication email for sending from
            Api_File = "api_key.txt"
            # Full path to credential file
            Full_Path = str(Current_Directory) + "\\" + str(Api_File)
            # Check to see if file exists
            Api_File_Existence = path.exists(Full_Path)
           
            # If file exists, get key
            if Api_File_Existence == True:
                print("Save file found. Checking for key...")
                # Load in key
                with open(Full_Path, 'r') as file:
                    File_Contents = file.readlines()
                    file.close()
                # Make sure there is a key in file
                if len(File_Contents) > 0:
                    print("Api key found in save file.")
                    Api_Key = str(File_Contents[0])
                else:
                    # If file is empty, ask for key
                    print("Save file empty.")
                    Api_Key = input("Please enter an Api Key to access HaveIBeenPwned's api: ")
                    # Save if warranted
                    while True:
                        Save_Key = input("Would you like to save this key for future use? (y/n) ").lower()
                        if (Save_Key == 'y') or (Save_Key == "yes"):
                            # Save key
                            print("Saving to file...")
                            with open(Full_Path, 'w+') as file:
                                file.write(str(Api_Key))
                                file.close()
                            print("Saved!")
                            break
                        elif (Save_Key == 'n') or (Save_Key == "no"):
                            print("Continuing...")
                            break
                        else:
                            # Other character entered.
                            print("Invalid response entered. Use y/Y for yes, and n/N for no.")
            # No key file found
            else:
                Api_Key = input("Please enter an Api Key to access HaveIBeenPwned's api: ")
                # Save if warranted
                while True:
                    Save_Key = input("Would you like to save this key for future use? (y/n) ").lower()
                    if (Save_Key == 'y') or (Save_Key == "yes"):
                        # Save key
                        print("Saving to file...")
                        with open(Full_Path, 'w+') as file:
                            file.write(str(Api_Key))
                            file.close()
                        print("Saved!")
                        break
                    elif (Save_Key == 'n') or (Save_Key == "no"):
                        print("Continuing...")
                        break
                    else:
                        # Other character entered.
                        print("Invalid response entered. Use y/Y for yes, and n/N for no.")
       
        # Send email list to api for checking
        HIBP_Results = check_email(Email_Addresses, Api_Key)
        
        # Create a dataframe of the compromised emails and site, and then save as csv file
        Simplified_Results = []
        for result in HIBP_Results:
            Current_Result = []
            Current_Result.append(result[0])
            for site in result[1]:
                Current_Result.append(site)
            Simplified_Results.append(Current_Result)
                
        # Write to csv file
        with open("Compromised_Emails.csv", 'a') as file:
            for result in Simplified_Results:
                for item in result:
                    file.write(str(item))
                    file.write(',')
                file.write('\n')
            file.close()
       
        # Beautify results (Results come back as a list of lists, after I get ahold of them anyway)
        The_End_Result = ''
        # Create massive string of results, neatly organized
        for email in HIBP_Results:
            Current_Address = email[0]
            Site_List = email[1]
            if len(Site_List) > 0:
                The_End_Result += ('\n' + str(Current_Address) + " has been compromised on " + str(len(Site_List)) + " site(s), listed below: \n\n\t")
                i = 0
                while i < len(Site_List):
                    # Check if i is an exact multiple of 4.
                    The_End_Result += (str(Site_List[i]) + ', ')
                    # Check if i is an exact multiple of 4.
                    if (i != 0) and (i % 4 == 0):
                        # Start new line after every 4 sites printed
                        The_End_Result += '\n\t'
                    i += 1
            # Ad another newline for readability
            The_End_Result += '\n'
        
        while True:
            To_Send_Or_To_Not_To = input("Send results via email? (y/n) ").lower()
            # Print to screen, email, or save as CSV (Maybe a way to do multiple)
            if (To_Send_Or_To_Not_To == 'y') or (To_Send_Or_To_Not_To == "yes"):
                # Save email
                if len(Receiving_Email) == 0:
                    # Check files to see if there is a save file.
                    # Get current working directory
                    Current_Directory = os.getcwd()
                    # Default text file to save authentication email for sending from
                    Receive_File = "receiving_address.txt"
                    # Full path to email file
                    Full_Path = str(Current_Directory) + "\\" + str(Receive_File)
                    # Check to see if file exists
                    Receive_File_Existence = path.exists(Full_Path)
                   
                    # If file exists, get email
                    if Receive_File_Existence == True:
                        print("Save file found. Checking for email address...")
                        # Load in key
                        with open(Full_Path, 'r') as file:
                            File_Contents = file.readlines()
                            file.close()
                        # Make sure there is an email in file
                        if len(File_Contents) > 0:
                            print("Receving email found in save file.")
                            Receiving_Email = str(File_Contents[0])
                            
                            while True:
                                Continue = input("Continue using " + str(Receiving_Email) + "? (y/n) ").lower()
                                if (Continue == 'y') or (Continue == "yes"):
                                    # Continue using credentials already found.
                                    pass
                                    break
                                else:
                                    # If file is empty, ask for email
                                    print("Save file empty.")
                                    Receiving_Email = input("Please enter an email to send results to: ")
                                    # Save if warranted
                                    while True:
                                        Save_Email = input("Would you like to save this email for future use? (y/n) ").lower()
                                        if (Save_Email == 'y') or (Save_Email == "yes"):
                                            # Save email
                                            print("Saving to file...")
                                            with open(Full_Path, 'w+') as file:
                                                file.write(str(Receiving_Email))
                                                file.close()
                                            print("Saved!")
                                            break
                                        elif (Save_Email == 'n') or (Save_Email == "no"):
                                            print("Continuing...")
                                            break
                                        else:
                                            # Other character entered.
                                            print("Invalid response entered. Use y/Y for yes, and n/N for no.")
                                    break
                            print("Continuing...")
                        else:
                            # If file is empty, ask for email
                            print("Save file empty.")
                            Receiving_Email = input("Please enter an email to send results to: ")
                            # Save if warranted
                            while True:
                                Save_Email = input("Would you like to save this email for future use? (y/n) ").lower()
                                if (Save_Email == 'y') or (Save_Email == "yes"):
                                    # Save email
                                    print("Saving to file...")
                                    with open(Full_Path, 'w+') as file:
                                        file.write(str(Receiving_Email))
                                        file.close()
                                    print("Saved!")
                                    break
                                elif (Save_Email == 'n') or (Save_Email == "no"):
                                    print("Continuing...")
                                    break
                                else:
                                    # Other character entered.
                                    print("Invalid response entered. Use y/Y for yes, and n/N for no.")
                    # No key file found
                    else:
                        Receiving_Email = input("Please enter an email to send results to: ")
                        # Save if warranted
                        while True:
                            Save_Email = input("Would you like to save this email for future use? (y/n) ").lower()
                            if (Save_Email == 'y') or (Save_Email == "yes"):
                                # Save key
                                print("Saving to file...")
                                with open(Full_Path, 'w+') as file:
                                    file.write(str(Receiving_Email))
                                    file.close()
                                print("Saved!")
                                break
                            elif (Save_Email == 'n') or (Save_Email == "no"):
                                print("Continuing...")
                                break
                            else:
                                # Other character entered.
                                print("Invalid response entered. Use y/Y for yes, and n/N for no.")
                    # Send to email  
                    send_mail(Receiving_Email, The_End_Result)             
                break
            elif (To_Send_Or_To_Not_To == 'n') or (To_Send_Or_To_Not_To == "no"):
                # Dont email, just print to screen
                print(The_End_Result)
                break
            else:
                # Other character entered.
                print("Invalid response entered. Use y/Y for yes, and n/N for no.")
                
        # Save to csv file as well (default)
        
                
        # Exit
        input("Done. Press enter to exit or continue...")
                
    elif Admin_State is None:
        print('Elevating privleges and moving to admin window.')
    else:
        print('Error: cannot elevate privileges.')
    
    return
    

# Function to run script automated (only the email portion)
def run_automated():
    # Get current admin state
    Admin_State = run_as_admin()
    
    # API Key
    Api_Key = ""
    # Receiving email
    Receiving_Email = ""

    if Admin_State is True:
        # The rest of the script will run in the elevated window
        # List to hold email addresses
        Email_Addresses = []
 
        # Call function to get all emails from active directory
        Email_Addresses = get_emails("auto")
       
        # If the length is zero, the variable is empty.
        if len(Api_Key) == 0:
            # Check files to see if there is a save file.
            # Get current working directory
            Current_Directory = os.getcwd()
            # Default text file to save authentication email for sending from
            Api_File = "api_key.txt"
            # Full path to credential file
            Full_Path = str(Current_Directory) + "\\" + str(Api_File)
            # Check to see if file exists
            Api_File_Existence = path.exists(Full_Path)
           
            # If file exists, get key
            if Api_File_Existence == True:
                with open(Full_Path, 'r') as file:
                    File_Contents = file.readlines()
                    file.close()
                # Make sure there is a key in file
                if len(File_Contents) > 0:
                    Api_Key = str(File_Contents[0])
                else:
                    # Fail
                    exit()
            # No key file found
            else:
                # Fail
                exit()
       
        # Send email list to api for checking
        HIBP_Results = check_email(Email_Addresses, Api_Key)
        
        # Create a dataframe of the compromised emails and site, and then save as csv file
        Simplified_Results = []
        for result in HIBP_Results:
            Current_Result = []
            Current_Result.append(result[0])
            for site in result[1]:
                Current_Result.append(site)
            Simplified_Results.append(Current_Result)
                
        # Write to csv file
        with open("Compromised_Emails.csv", 'a') as file:
            for result in Simplified_Results:
                for item in result:
                    file.write(str(item))
                    file.write(',')
                file.write('\n')
            file.close()
       
        # Beautify results (Results come back as a list of lists, after I get ahold of them anyway)
        The_End_Result = ''
        # Create massive string of results, neatly organized
        for email in HIBP_Results:
            Current_Address = email[0]
            Site_List = email[1]
            if len(Site_List) > 0:
                #print('\n' + str(Current_Address) + " has been compromised on " + str(len(Site_List)) + " site(s), listed below.")
                The_End_Result += ('\n' + str(Current_Address) + " has been compromised on " + str(len(Site_List)) + " site(s), listed below: \n\n\t")
                i = 0
                while i < len(Site_List):
                    # Check if i is an exact multiple of 4.
                    The_End_Result += (str(Site_List[i]) + ', ')
                    # Check if i is an exact multiple of 4.
                    if (i != 0) and (i % 4 == 0):
                        # Start new line after every 4 sites printed
                        The_End_Result += '\n\t'
                    i += 1
            # Ad another newline for readability
            The_End_Result += '\n'
            
        # Get current working directory
        Current_Directory = os.getcwd()
        # Default text file to save authentication email for sending from
        Receive_File = "receiving_address.txt"
        # Full path to email file
        Full_Path = str(Current_Directory) + "\\" + str(Receive_File)
        # Check to see if file exists
        Receive_File_Existence = path.exists(Full_Path)
       
        # If file exists, get email
        if Receive_File_Existence == True:
            print("Save file found. Checking for email address...")
            # Load in key
            with open(Full_Path, 'r') as file:
                File_Contents = file.readlines()
                file.close()
            # Make sure there is an email in file
            if len(File_Contents) > 0:
                print("Receving email found in save file.")
                Receiving_Email = str(File_Contents[0])
            else:
                # Fail
                exit()
        # File not found
        else:
            # Fail
            exit() 
        # Email results    
        # Send results via email
        send_mail(Receiving_Email, The_End_Result, "auto")

    elif Admin_State is None:
        print('Elevating privleges and moving to admin window.')
    else:
        print('Error: cannot elevate privileges.')
    
    return
    
    
# Function to download a file from a given url
def download_and_unzip():
    # Url to HIBP hash file
    HIBP_Hashes = "https://downloads.pwnedpasswords.com/passwords/pwned-passwords-ntlm-ordered-by-hash-v7.7z"

    # Get current directory
    Current_Directory = os.getcwd() + '\\'

    # Split url at the last slash, and get whatever is after (the complete filename)
    File_Name = HIBP_Hashes.rsplit('/', 1)[1]

    # Full path to file save directory
    Full_Path = Current_Directory + File_Name

    print("Starting file download...")
    print("**WARNING** - This will take a significant amount of time to download...")
    # Get file url and download in sections
    # Also filter out anything that isn't actual data (ie. keep alive requests)
    r = requests.get(HIBP_Hashes, stream=True)
    with open(Full_Path, 'wb') as file:
        for chunk in r.iter_content(chunk_size=1024):
            if chunk:
                file.write(chunk)
    # Close file
    file.close()
    
    print("File downloaded.")
    # Unzip file in the current directory
    print("Starting file unzip...")
    print("**WARNING** - This will take a significant amount of time to unzip...")
    # Unzip file to current directory (specify the archive type here as well)
    shutil.register_unpack_format('7zip', ['.7z'], unpack_7zarchive)
    shutil.unpack_archive(File_Name, Current_Directory)
    print("File unzipped.")
    # Delete archive file once it has been unzipped
    print("Cleaning up...")
    
    if os.path.exists(Full_Path):
        os.remove(File_Name)
    else:
        # Silently pass if there is no file to delete (Shouldn't ever be the case)
        pass
    input("Done, press enter to exit or continue...")
    
    return


def check_ntlm_hashes():
    # Get current admin state
    Admin_State = run_as_admin()
    # (Local) Administrator privileges are needed for installing AD tools
    if Admin_State is True:
        # Install AD Tools
        install_tools()
    
        # Call powershell to get current domain name
        # Strip all other characters to isolate the domain name as a string
        domain_name = subprocess.check_output(["powershell.exe", "Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Domain | Format-List"]).decode("utf-8")
        domain_name = domain_name.replace('\n', '')
        domain_name = domain_name.replace('\r', '')
        domain_name = domain_name.replace("Domain :", '')
        domain_name = domain_name.strip()
        print("Current domain name: " + str(domain_name))

        try:
            # Get hostname of Domain Controller
            hostname = subprocess.check_output(["powershell.exe", "Get-ADDomainController | select HostName"]).decode("utf-8")
            hostname = str(hostname)
            hostname = hostname.strip()
            hostname = hostname.split('\n')
            hostname = hostname[2]
            hostname = hostname.replace(("." + domain_name), '')

            # Check to see if a valid hostname was found
            if "Cannot find DC" in hostname:
                print("Cannot find domain controller.")
                # Exit
                input("Done. Press enter to exit...")
                quit()
            else:
                print("Domain controller hostname: " + str(hostname))
            
            while True:
                try:
                    # Get admin DC credentials from user
                    DC_Username = input("Please enter the administrator username for the domain controller: ")
                    DC_Password = getpass("Please enter the administrator password for the domain controller (Characters will not be printed): ")
                    
                    # Get current user execution policy, so that we can revert it later
                    User_Policy = subprocess.check_output(["powershell.exe", "Get-ExecutionPolicy -Scope CurrentUser"]).decode("utf-8")
                    User_Policy = User_Policy.strip()
                    User_Policy = User_Policy.replace('\r', '')
                    User_Policy = User_Policy.replace('\n', '')
                    
                    # Allow scripting for the current process
                    powershell = subprocess.check_output(["powershell.exe", "Set-ExecutionPolicy Bypass -Scope CurrentUser -Force"])
                    
                    # Import DSInternals module
                    powershell = subprocess.check_output(["powershell.exe", "Import-Module DSInternals"])
                        
                    # Get all NTLM hashes
                    hash_list = subprocess.check_output(["powershell.exe", "$Username = '" + str(DC_Username) + "'; $Password = ConvertTo-SecureString -String '" + str(DC_Password) + "' -AsPlainText -Force; $Credentials = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $Password; Get-ADReplAccount -all -Server '" + str(hostname) + "' -Credential $Credentials | Format-Custom -View HashcatNT"])
                    hash_list = hash_list.decode("utf-8")
                    hash_list = hash_list.strip()
                    hash_list = hash_list.replace('\r', '')
                    hash_list = hash_list.split('\n')
                    
                    # Split NTLM hash data frame powershell and convert into dataframe
                    i = 0
                    while i < len(hash_list):
                        hash_list[i] = hash_list[i].split(':')
                        i += 1
                    
                    User_Frame = pd.DataFrame(hash_list)
                    
                    # Powershell returns hashes in all lowercase
                    # HIBP gives us the hashes in all caps
                    User_Frame.iloc[:][1] = User_Frame.iloc[:][1].str.upper()
                    
                    print("Hashes replicated. Checking against database...")
                    break
                except subprocess.CalledProcessError as e:
                    print("Error. Possible invalid credentials used.")
            
        except subprocess.CalledProcessError as e:
            if domain_name == "WORKGROUP":
                print("Default domain being used, possible that this machine isn't connected to an Active Directory.")
                input("Done. Press enter to exit...")
                quit()
            else:
                print("Unknown failure.")

        # Pandas big data related stuff
        # Get start time
        Start_Time = time.time()

        # Get current working directory
        Current_Directory = os.getcwd()
        # Default text file for compromised hashes (Find a way in the future to not card code this)
        Hash_File = "pwned-passwords-ntlm-ordered-by-hash-v7.txt"
        # Full path to email file
        Full_Path = str(Current_Directory) + "\\" + str(Hash_File)

        # Check if hash file exists
        Hash_Existence = path.exists(Full_Path)
        if Hash_Existence == False:
            print("Cannot find Compromised NTLM Hash File.")
            
            # Download has file if warranted
            while True:
                Download_File = input("Would you like to download HIBP's hash file now? (y/n) ").lower()
                if (Download_File == 'y') or (Download_File == "yes"):
                    # Download and unzip
                    download_and_unzip()
                    break
                elif (Download_File == 'n') or (Download_File == "no"):
                    # Else exit
                    print("File can be downloaded using the -d or --download arguments.")
                    input("Done. Press enter to exit...")
                    quit()
                else:
                    # Other character entered.
                    print("Invalid response entered. Use y/Y for yes, and n/N for no.")
        else:
            pass

        # Get total number of users
        User_Count = str(len(User_Frame))

        # 613,584,246 lines in hash file
        # 7 million hashes per gigabyte of ram used seems to be a safe amount
        # Utilize 8% of unused memory (Figure out how many hashes that allows for)
        # Get total machine memory and convert to gigabytes
        #Bytes = psutil.virtual_memory().total
        #print("Total memory:", Gigs)

        # Get total memory used
        #Bytes = psutil.virtual_memory().used

        #print("Total memory used:", Gigs)

        # Get total memory free
        Bytes = psutil.virtual_memory().free
        #print("Total memory free:", Gigs)

        # Calculate memory usage of dataframe and subtract that from the allocated memory (in bytes)
        #User_Frame_Bytes = User_Frame.memory_usage(index=True, deep=True).sum()
        #Bytes = Bytes - User_Frame_Bytes

        # Convert bytes to gigs
        Gigs = Bytes/1073741824

        # Only allow 80% of memory to be used by python
        Allowed_Usage = 0.8

        # Get number of gigabytes allowed
        Allowed_Gigs = Allowed_Usage * Gigs

        # Determine number of hashes that can be read into dataframe at once
        Split_Limit = round(Allowed_Gigs * 7000000)

        # Offset starting point, so that old hashes aren't checked again
        Start_Offset = 0

        # Create final dataframe of users that have compromised passwords
        Compromised_Users = pd.DataFrame()

        # Compare each piece of the file against the user hashes
        while True:
            if len(User_Frame) > 0:
                print("Reading in portion of compromised hash file...")

                # Create a dataframe of compromised hashes (This reads everything into memory...)
                # With format Hash:Number
                Hash_Frame = pd.read_csv(Full_Path, sep=':', skiprows=Start_Offset, nrows=Split_Limit, header=None, index_col=False)

                if len(Hash_Frame) == Split_Limit:
                    print("Checking against compromised hashes...")
                    # Check to see if user hashes appear in compromised hashes
                    # Returns a new dataframe containing True or False for each user
                    Overlap = User_Frame[1].isin(Hash_Frame[0])

                    # Make a list of compromised users by index
                    Drop_Index = []

                    # Return users with compromised passwords
                    i = 0
                    while i < len(Overlap):
                        if Overlap[i] == True:
                            # Print each row, column 0
                            print(" * User " + str(User_Frame.iloc[i][0]) + "'s password has been identified as compromised.")
                            Compromised_Users = Compromised_Users.append([User_Frame.iloc[i][0]])
                            Drop_Index.append(i)
                        i += 1

                    # Drop those usernames from the dataframe
                    User_Frame.drop(Drop_Index, inplace=True)

                    # Reset index in dataframe
                    User_Frame.reset_index(drop=True, inplace=True)
                    
                    # Start where we left off
                    Start_Offset += Split_Limit
                    
                    # Delete dataframe to remove it from memory, and make room for new dataframe
                    # This is in an effort to keep from using massive amounts of memory,
                    # as python does not normally release memory back to the OS
                    del Hash_Frame
                    gc.collect()

                    print("Portion done, continuing...")
                        
                # Run once more, then quit
                else:
                    print("Checking against compromised hashes...")
                    # Check to see if user hashes appear in compromised hashes
                    # Returns a new dataframe containing True or False for each user
                    Overlap = User_Frame[1].isin(Hash_Frame[0])

                    # Return users with compromised passwords
                    i = 0
                    while i < len(Overlap):
                        if Overlap[i] == True:
                            # Print each row, column 0
                            print("User " + str(User_Frame.iloc[i][0]) + "'s password has been identified as compromised.")
                            Compromised_Users = Compromised_Users.append([User_Frame.iloc[i][0]])
                        i += 1
                        
                    # Delete dataframe to remove it from memory, and make room for new dataframe
                    # This is in an effort to keep from using massive amounts of memory,
                    # as python does not normally release memory back to the OS
                    del Hash_Frame
                    gc.collect()
                
                    print("Portion done, continuing...")  
                    break
            else:
                print("All user passwords have been compromised. Exiting...")
                break
                
        # Set execution policy back to what it was
        Policy_Revert = subprocess.check_output(["powershell.exe", "Set-ExecutionPolicy '" + str(User_Policy) + "' -Scope CurrentUser -Force"])

        # Get time elapsed
        End_Time = time.time()
        Elapsed_Time = (End_Time - Start_Time)
        Elapsed_Time = round(Elapsed_Time, 2)
        print("\nTotal elapsed time taken to check hashes: " + str(Elapsed_Time) + " (seconds)")

        # Print total number of compromises
        print(str(len(Compromised_Users)) + " out of " + User_Count + " users have compromised passwords.")
        
        # Save compromised users as csv file (only usernames in this file)
        Compromised_Users.to_csv('Compromised_Users.csv', index=False)
        
        # Exit
        input("Done. Press enter to exit...")
    
    elif Admin_State is None:
        print('Elevating privleges and moving to admin window.')
    else:
        print('Error: cannot elevate privileges.')
    
    # Probably export usernames as csv for future use
    return


# Function to print help screen
def print_help():
    # Print help screen
    print("ADACCT is a command line tool to check user email addresses and NTLM hashes for compromise against HaveIBeenPwned's database.")
    
    print("\n  Arguments: ")
    print(" -h, --help for help. (This screen)")
    print(" -d, --download Downloads and unzips the HIBP hash file to the current directory.")
    print(" -e, --email Checks emails addresses found in the current active directory for compromise.")
    print(" -n, --ntlm Checks NTLM hashes pulled from active directory against compromised hash list.")
    print(" -A for running this script in the background, completely automated (Only applies to -e argument).")
    
    print("\n -A argument makes a few assumptions listed below: ")
    print("\t- The script will not ask for any user input.")
    print("\t- The script has to be run with Administrator privileges.")
    print("\t- The results will automatically be emailed.")
    print("\t- The sender address credentials, the api key, and the")
    print("\t  receiving email address need to be hardcoded or saved in a file.")
    print("\t  as the script cannot ask the user to input them.")
    
    print("\n -n, --ntlm argument makes one assumption: ")
    print("\t- HIBP's hash file has been already downloaded and is in the same directory as this script.")
    print("\t- (As the hash file is just too large to download from the script)")
    
    return
    

# Run script with or without user interaction, based on arguements given.
def main(args):
    # Sort through arguments given in the command line    
    if len(args) >= 1:
        if '-h' in args:
            # Print help screen
            print_help()
        elif "--help" in args:
            # Print help screen
            print_help()
        elif '-d' in args:
            # Download and unzip HIBP file
            # HIBP hash file, ordered by hash
            download_and_unzip()
        elif "--download" in args:
            # Download and unzip HIBP file
            download_and_unzip()
        elif '-e' in args:
            if '-A' in args:
                # Run script without user input
                # This has to be run as admin.
                # Results wil be automatically emailed.
                # Credentials must be hard coded, or saved in file.
                run_automated()
            else:
                # Run script as normal
                run_normal()
        elif "--email" in args:
            if '-A' in args:
                # Run script without user input
                # This has to be run as admin.
                # Results wil be automatically emailed.
                # Credentials must be hard coded, or saved in file.
                run_automated()
            else:
                # Run script as normal
                run_normal()
        elif '-n' in args:
            # Check NTLM hashes
            check_ntlm_hashes()
        elif "--ntlm" in args:
            # Check NTLM hashes
            check_ntlm_hashes()
        else:
            print("Unknown arguement given.")
            print("Use -h or --help command for more help.")
    # If no arguments are given, continue as if script has never been run
    else:
        # Get current admin state
        Admin_State = run_as_admin()

        if Admin_State is True:
            # Run script as normal with all options
            run_normal()
            #download_and_unzip()
            check_ntlm_hashes()
        elif Admin_State is None:
            print('Elevating privleges and moving to admin window.')
        else:
            print('Error: cannot elevate privileges.')
            
    return


# Beginning of main
if __name__ == '__main__':
    # Call main function
    main(sys.argv[1:])


