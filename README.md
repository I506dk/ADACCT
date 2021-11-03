# ADACCT - Active Directory Account Compromise Checking Tool

![AD_Logo](https://user-images.githubusercontent.com/33561466/138386605-36291c2a-c68f-4390-84a7-5567d8b624e1.png)

#### A Python script to check Acitve Directory User emails and NTLM password hashes for compromise against HaveIBeenPwned's database
#### Prounounced /ˈadikt/ - an enthusiastic devotee of a specified thing or activity.

## Features
- Pulls all user's email addresses from the Active Directory
- Uses HaveIBeenPwned's api to check each email address for compromise
- Compromised users can be printed to the screen or emailed
- (Ab)Uses AD Replication to pull all NTLM hashes from the Domain Controller (Requires Admin credentials for Domain Controller)
- Compares user hashes against HaveIBeenPwned's compromised hash file
- The script checks system memory and aims for 70-80% usage so that a single machine doesn't crash
- Option to save API key and Email address credentials to file instead of entering them manually each time

## Dependencies 
[![Known Vulnerabilities](https://snyk.io/test/github/I506dk/ADACCT/badge.svg)](https://snyk.io/test/github/I506dk/ADACCT)
- [Psutil](https://pypi.org/project/psutil/) - Cross-platform library for process and system monitoring
- [Requests](https://pypi.org/project/requests/) - HTTP Library
- [Pandas](https://pypi.org/project/pandas/) - A Powerful data analysis toolkit
- [py7zr](https://pypi.org/project/py7zr/) - 7zip library for python

## Notes
- [Api Key](https://haveibeenpwned.com/API/Key) - HaveIBeenPwned uses a paid API key, needed for using their API
- [Compromised Hash File](https://haveibeenpwned.com/Passwords) - Compromised hash file (Decompressed it is about 21 gigabytes) (Can be manually downloaded if needed)
- If results are to be emailed, the script needs an email address and credentials to send from (If using Gmail, less secure apps needs to be enabled)
- Api key, email addresses, and email credentials can be saved to text file, instead of manually typed each time

## Installation
**Download the recommended version of python below (3.9.7):**

[![Python 3.9.7](https://img.shields.io/badge/python-3.9.7-blue.svg)](https://www.python.org/downloads/release/python-397/)

**Or download the latest release of python:**

[![Python Latest](https://img.shields.io/badge/python-latest-blue.svg)](https://www.python.org/downloads/windows/)

**REMINDER** - *If using a Python version greater than 3.9.7, make sure Pandas and other libraries support it*

**Download and install Pip using the following commands:**
- *Newer versions of Python automatically install pip*
```
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py
```

**Download from Github**

Click the download as zip button at the top right or click [HERE](https://github.com/I506dk/ADACCT/archive/refs/heads/main.zip) to download the repository.

Or instead of downloading the compressed source, you may instead want to clone the GitHub repository: 
```
git clone https://github.com/I506dk/ADACCT.git
```


**Dependencies can manually be installed using requirements.txt:**
```
pip install -r requirements.txt
```
**Or individually installed via Pip:**
```
pip install psutil
pip install pandas
pip install requests
pip install py7zr
```

## Usage
To run ADACCT for the first time:
```
python ADACCT.py
```
This will check for compromised emails, download the HIBP hash database file, then check user password hashes against that database.

Arguments can be specified to the script if only specific portions of the script are needed:

(***-h or --help***) - will display the help screen.

Examples: ```python ADACCT.py -h``` or ```python ADACCT.py --help```

(***-d or --download***)  - will download and unzip the HIBP hash file.

Examples: ```python ADACCT.py -d``` or ```python ADACCT.py --download```

(***-e or --email***) - will check email addresses found in the current active directory for compromise.

Examples: ```python ADACCT.py -e``` or ```python ADACCT.py --email```

(***-n or --ntlm***) - will check NTLM hashes pulled from active directory against compromised hash list.

Examples: ```python ADACCT.py -n``` or ```python ADACCT.py --ntlm```

(***-A***) - will run the script completely automated, without user interaction (Only applies to email argument).

Examples: ```python ADACCT.py -e -A``` or ```python ADACCT.py --email -A```

REMINDER - You can use multiple arguments as long as they aren't -h or --help (Those will default to showing the help screen then exiting)

## To Do:

- [x] Pull user emails
- [x] Check emails against HIBP
- [x] Pull all NTLM hashes
- [x] Check hashes against HIBP
- [x] Allow for emailing of results
- [x] Download HIBP Hash file
- [ ] Find a way to protect saved API key and Email credentials (Currently saved as plain text)
- [ ] Add option to specify location of Hash File (Defaults to the same directory the script is in)
- [ ] Add better protection of python processes running in memory (Don't want hash leaks)
- [ ] Add support for new Active Directory Checks



