# Conversor — HTB Walkthrough

**Status:** Completed  
**Difficulty:** Easy  
**OS:** Linux

## TL;DR
Discover XML converter web application, analyze source code, exploit XSLT injection with malicious .exslt file to gain reverse shell, extract database credentials, crack hash, SSH as user, exploit sudo binary for root flag.

## Target / Access
**Target IP:** `10.10.11.92`  
**Attacker IP:** `10.10.14.120`

---

## Enumeration

### Step 1: Port Scanning with Nmap

**Command:**
```bash
nmap -sC -sV -p- 10.10.11.92
```

**Raw Log:** [nmap.txt](nmap.txt), [nmap.xml](nmap.xml)

**Output Excerpt:**
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1
80/tcp   open  http    nginx
```

**Analysis:** SSH and nginx web server identified.

![Nmap scan results](nmap.png)

### Step 2: Web Application Access

**Action:** Add target to /etc/hosts and browse to application

**Command:**
```bash
echo "10.10.11.92 conversor.htb" >> /etc/hosts
```

**Analysis:** XML converter application with user registration.

![Hosts file configuration](etc_hosts.png)

![Web application interface](site.png)

![Conversor application](conversor.png)

### Step 3: Source Code Analysis

**Action:** Download and analyze application source code

**Analysis:** Application processes XML files with XSLT transformations, potential for XSLT injection.

![Source code download](source_code.png)

![Source code structure](source_code_tree.png)

---

## Foothold / Initial Access

### Step 4: XSLT Injection Exploitation

**Vulnerability:** XSLT Injection allowing Remote Code Execution

**Preparation:**
1. Create malicious EXSLT file with reverse shell payload
2. Prepare XML file (can use nmap.xml from scan)
3. Set up netcat listener

**Commands:**
```bash
# Set up listener
nc -lvnp 4444

# Create malicious EXSLT file (shell.exslt)
# Upload XML + EXSLT to trigger RCE
```

**Raw Logs:**
- [shell.exslt](shell.exslt) — Malicious XSLT payload
- [nmap.xml](nmap.xml) — XML file used for injection

![XSLT injection payload](shell.png)

**Output:** Reverse shell obtained.

![Shell received](exploit_done.png)

### Step 5: Shell Stabilization

**Commands:**
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z
stty raw -echo; fg
```

**Analysis:** Shell stabilized for better interaction.

### Step 6: Database Credential Extraction

**Commands:**
```bash
# Search for database files
find / -name "*.db" 2>/dev/null

# Read users.db
cat /path/to/users.db
```

**Analysis:** Found hash for user `fismathack`.

**Hash Found:** `5b5c3ac3a1c897c94caad48e6c71fdec`

![User hash in database](user_hash.png)

### Step 7: Password Cracking

**Command:**
```bash
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** Password successfully cracked: `fismathack123`

![Password cracking result](user_pass.png)

### Step 8: SSH Access and User Flag

**Command:**
```bash
ssh fismathack@10.10.11.92
cat ~/user.txt
```

**Output:** User flag captured.

![User flag](user_flag.png)

---

## Privilege Escalation

### Step 9: Sudo Privilege Enumeration

**Command:**
```bash
sudo -l
```

**Output:**
```
User fismathack may run the following commands:
    (root) NOPASSWD: /path/to/binary
```

**Analysis:** Can run specific binary as root without password.

### Step 10: Binary Exploitation for Root Flag

**Research:** Online research revealed command execution capability in the binary.

**Command:**
```bash
# Execute command to read root flag via sudo binary
sudo /path/to/binary [parameters to execute cat /root/root.txt]
```

**Output:** Root flag successfully obtained.

![Root flag capture](root_flag.png)

---

## Summary

This machine involved XSLT injection for initial access and privilege escalation through a sudo-enabled binary.

### Attack Chain
1. **Nmap Scan** — Discovered nginx web server
2. **Web Reconnaissance** — Identified XML converter application
3. **Source Code Analysis** — Found XSLT processing vulnerability
4. **XSLT Injection** — Exploited with malicious .exslt file for RCE
5. **Credential Extraction** — Retrieved hash from users.db
6. **Password Cracking** — Cracked fismathack's password with hashcat
7. **SSH Access** — Authenticated as fismathack, captured user flag
8. **Privilege Escalation** — Exploited sudo binary to read root flag

### Tools Used
- Nmap — Port scanning and service detection
- Web Browser — Application testing
- Netcat — Reverse shell listener
- Hashcat — Password cracking
- Custom XSLT payload — XSLT injection exploitation

---

## Cleanup / Notes / References

### Mitigation Recommendations
1. **Input Validation:** Strictly validate and sanitize XML/XSLT input.
2. **Disable XSLT Features:** Disable dangerous XSLT functions (document(), system-property()).
3. **Sandboxing:** Run XSLT transformations in isolated environment.
4. **Database Security:** Use strong password hashing (bcrypt, Argon2), encrypt sensitive data.
5. **Sudo Restrictions:** Limit sudo privileges to necessary commands only.
6. **Code Review:** Regular security audits of application code.
7. **WAF:** Implement Web Application Firewall to detect injection attempts.

### References
- [OWASP: XSLT Injection](https://owasp.org/www-community/vulnerabilities/XSLT_Injection)
- [XSLT Security Considerations](https://www.w3.org/TR/xslt-30/#security)
- [Linux Privilege Escalation](https://book.hacktricks.xyz/)


