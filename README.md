# ADACCT - Active Directory Account Compromise Checking Tool

![AD_Logo](https://user-images.githubusercontent.com/33561466/138386605-36291c2a-c68f-4390-84a7-5567d8b624e1.png)

#### A Python script to check Acitve Directory User emails and NTLM password hashes for compromise against HaveIBeenPwned
#### Prounounced /ˈadikt/ - an enthusiastic devotee of a specified thing or activity.

## Features
- Pulls all user's email addresses from the Active Directory
- Uses HaveIBeenPwned's api to check each email address for compromise
- Compromised users can be exported as a csv file or emailed
- (Ab)Uses AD Replication to pull all NTLM hashes from the Domain Controller (Requires Admin credentials for DC)
- Compares user hashes against HaveIBeenPwned's compromised hash file
- The script checks system memory and aims for 70-80% usage so that a single machine doesn't crash
- Option to save API key and Email address credentials to file instead of entering them manually each time

## Dependencies
- [Psutil](https://pypi.org/project/psutil/) - Cross-platform library for process and system monitoring
- [Requests](https://pypi.org/project/requests/) - HTTP Library
- [Pandas](https://pypi.org/project/pandas/) - A Powerful data analysis toolkit

## Notes
### HaveIBeenPwned
- [Api Key](https://haveibeenpwned.com/API/Key) - HIBP uses a paid API key, needed for using their API
- [Compromised Hash File](https://haveibeenpwned.com/Passwords) - Download the Compromised hash file (Decompressed it is about 21 gigabytes)
- If results are to be emailed, the script needs an email address and credentials to send from (If using Gmail, less secure apps needs to be enabled)
- Api key, email addresses, and email credentials can be saved to text file, instead of manually typed each time

## Installation
**Download the latest release of python below:**

[![Python](https://www.python.org/static/community_logos/python-powered-w-100x40.png)](https://www.python.org/downloads/)

REMINDER - If using a Python version greater than 3.10.0, make sure Pandas supports it

**Download and install Pip using the following commands:**
```
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py
```
**Dependencies can manually be installed using requirements.txt:**
```
pip install -r requirements.txt
```
**Or individually installed via Pip:**
```
pip install psutil
pip install pandas
```

## To Do:

- [x] Pull user emails
- [x] Check emails against HIBP
- [x] Pull all NTLM hashes
- [x] Check hashes against HIBP
- [x] Allow for emailing of results
- [ ] Download HIBP Hash file
- [ ] Find a way to protect saved API key and Email credentials (Currently saved as plain text)
- [ ] Add option to specify location of Hash File (Defaults to the same directory the script is in)
- [ ] Add better protection of python processes running in memory (Don't want hash leaks)
- [ ] Add support for new Active Directory Checks



