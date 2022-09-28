# ADACCT - Active Directory Account Compromise Checking Tool

![AD_Logo](https://user-images.githubusercontent.com/33561466/138386605-36291c2a-c68f-4390-84a7-5567d8b624e1.png)

#### A Python script to check Active Directory User emails and NTLM password hashes for compromise against HaveIBeenPwned's database
#### Prounounced /ˈadikt/ - an enthusiastic devotee of a specified thing or activity.

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![CodeQL](https://github.com/I506dk/ADACCT/workflows/CodeQL/badge.svg)
![Known Vulnerabilities](https://snyk.io/test/github/I506dk/ADACCT/badge.svg)

## Features
- Pulls all user's email addresses from the Active Directory
- Uses HaveIBeenPwned's api to check each email address for compromise
- Compromised users can be printed to the screen or emailed
- (Ab)Uses AD Replication to pull all NTLM hashes from the Domain Controller (Requires Domain Admin credentials)
- Compares user hashes against HaveIBeenPwned's compromised hash file
- The script checks free system memory and only allocates 75% of that memory for script utilization
- Option to save API key, Email address credentials, and Domain Admin credentials to file using Windows DPAPI
- Import_credentials and Export_credentials fucntions are pythonic implementations of Powershell's Import-Clixml and Export-Clixml commandlets

## Dependencies 
- [Psutil](https://pypi.org/project/psutil/) - Cross-platform lib for process and system monitoring in Python
- [Requests](https://pypi.org/project/requests/) - Python HTTP for Humans
- [BeautifulSoup4](https://pypi.org/project/beautifulsoup4/) - Screen-scraping library
- [PypiWin32](https://pypi.org/project/pywin32/) - Python for Window Extensions
- [Pandas](https://pypi.org/project/pandas/) - Powerful data structures for data analysis, time series, and statistics
- [Dask](https://pypi.org/project/dask/) - Parallel PyData with Task Scheduling
- [Py7zr](https://pypi.org/project/py7zr/) - 7zip library for python

## Notes
- [Api Key](https://haveibeenpwned.com/API/Key) - HaveIBeenPwned uses a paid API key, needed for using their API
- [Compromised Hash File](https://haveibeenpwned.com/Passwords) - Compromised hash file (Decompressed it is about 21 gigabytes) (Can be manually downloaded if needed)
- If results are to be emailed, the script needs an email address and credentials to send from (If using Gmail, less secure apps needs to be enabled)
- Api key, email addresses, and email credentials can be saved to xml file, instead of manually typed each time

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


**Dependencies can be installed manually using requirements.txt:**
```
pip install -r requirements.txt
```
**Or individually installed via Pip:**
```
pip install psutil
pip install requests
pip install beautifulsoup4
pip install pypiwin32
pip install pandas
pip install dask[dataframe]
pip install py7zr
```

## System Requirements
These were the system requirements during testing, and the script can likely run on less, however this will affect script run time.

**CPU**
- At least 2 vCpus
  - Dask.dataframe works in parallel to read in hashes from the csv file.

**Memory**
- At least 8gb of system memory
  - All dataframes are read into memory for processing.
  - Dataframes will get split based on the amount of free memory.

**Disk Space**
- At least 35gb disk space
  - The HaveIBeenPwned hash file takes up ~22gb of disk space once unzipped, and zipped file takes up ~8gb.

## Account Permissions
A domain admin account is easiest to use if running the script once or on an ad-hoc basis.
If running the script automated or as a scheduled task, it is recommended to create a service account.
Only three privileges are required for the script:
- Domain User - Allows for reading user data (specifically usernames and email addresses)
- Replicate Directory Changes - Allows for replicating data from a domain controller
- Replicate Directory Changes All - Allows for replicating all data from a domain controller

## Usage
To run ADACCT for the first time:
```
python ADACCT.py
```
This will check for compromised emails, download the HIBP hash database file, then check user password hashes against that database.

Arguments can be specified to the script if only specific portions of the script are needed:

(***-h or --help***) - will display the help screen.

- Examples: ```python ADACCT.py -h``` or ```python ADACCT.py --help```

(***-d or --download***)  - will download and unzip the HIBP hash file.

- Examples: ```python ADACCT.py -d``` or ```python ADACCT.py --download```

(***-e or --email***) - will check email addresses found in the current active directory for compromise.

- Examples: ```python ADACCT.py -e``` or ```python ADACCT.py --email```

(***-n or --ntlm***) - will check NTLM hashes pulled from active directory against compromised hash list.

- Examples: ```python ADACCT.py -n``` or ```python ADACCT.py --ntlm```

(***-A***) - will run the script completely automated, without user interaction (Only applies to email argument).

- Examples: ```python ADACCT.py -e -A``` or ```python ADACCT.py --email -A```

REMINDER - You can use multiple arguments as long as they aren't -h or --help (Those will default to showing the help screen then exiting)

## To Do:

- [x] Pull user emails
- [x] Check emails against HIBP
- [x] Pull all NTLM hashes
- [x] Check hashes against HIBP
- [x] Allow for emailing of results
- [x] Download HIBP Hash file
- [x] Find a way to protect saved API key and Email credentials (Everything is saved using windows dpapi)
- [ ] Add option to specify location of Hash File (Defaults to the same directory the script is in)
- [ ] Implement a Trusted Execution Environment to prevent memory dumping attacks
- [x] Determine minimum privileges required for domain object data replication
- [ ] Implement a pip cleanup to remove packages or libraries installed by the script
- [ ] Add support for running script in cloud environments (Specifically Azure)
- [ ] Add support for new Active Directory Checks



