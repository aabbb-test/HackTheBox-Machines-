# HackTheBox Machines

This repository contains my personal collection of Hack The Box machine walkthroughs and writeups. The collection includes machines I've completed independently, as well as Starting Point machines (which feature official writeups created by HTB employees).

Each writeup provides detailed step-by-step guidance through the exploitation process, including reconnaissance, enumeration, initial access, privilege escalation, and flag capture. All writeups follow a consistent structure with organized screenshots, raw logs, and comprehensive documentation to help others learn penetration testing techniques.

---

# HTB Walkthroughs Summary

| Machine | Tools Used | Attack Techniques |
|---------|-----------|-------------------|
| Appointment | nmap, gobuster, dirb, php | SQL injection, default credentials, RCE |
| Archetype | nmap, smbclient, impacket, psexec, netcat | SMB misconfiguration, RCE, privilege escalation |
| Base | nmap, gobuster, burp, john, linpeas | Type juggling, file upload, brute force, sudo privesc |
| Bike | nmap, burp, python, netcat | SSTI, template injection, RCE, reverse shell |
| CodePartTwo | nmap, dirsearch, nuclei, hashcat, netcat | CVE-2024-28397, SQL injection, password cracking, sudo privesc |
| Conversor | nmap, netcat, hashcat, python | XSLT injection, password cracking, sudo privesc, reverse shell |
| Crocodile | nmap, ftp, gobuster, metasploit | FTP misconfiguration, RCE |
| Dancing | nmap, smbclient, netcat | SMB misconfiguration, RCE |
| Explosion | nmap, ftp, telnet, ssh | FTP misconfiguration, sudo privesc |
| Fawn | ftp, ssh, netcat | FTP misconfiguration, RCE |
| Funnel | nmap, ftp, hydra, ssh | Brute force, sudo privesc |
| Ignition | nmap, gobuster, curl | Brute force, default credentials, LFI |
| Imagery | nmap, dirsearch, nuclei, burp, linpeas | CVE-2023-37582, XSS, path traversal, command injection, cron exploitation |
| Included | nmap, ftp, curl, python, ssh | LFI, RCE, privilege escalation, reverse shell |
| Markup | nmap, burp, python, netcat | XXE, default credentials, CSRF, privilege escalation |
| Mongod | nmap, curl, ssh | Misconfiguration, RCE |
| Oopsie | nmap, gobuster, burp, ftp | IDOR, privilege escalation, SUID exploit, reverse shell |
| Pennyworth | nmap, netcat | RCE, reverse shell |
| Preignition | nmap, gobuster, ffuf, php | Default credentials, RCE, sudo privesc |
| Redeemer | nmap, netcat | Misconfiguration, RCE, sudo privesc |
| Responder | nmap, ftp, responder, evil-winrm, john | LFI, RFI, hash cracking, sudo privesc |
| Sequel | nmap, netcat | SQL misconfiguration, RCE, sudo privesc |
| Synced | nmap, ftp, netcat | FTP misconfiguration, RCE |
| Tactics | nmap, smbclient, impacket, psexec | SMB misconfiguration, cron exploitation, sudo privesc |
| Three | nmap, gobuster, feroxbuster, php, python | RCE, reverse shell, sudo privesc |
| Unified | nmap, burp, tcpdump, wireshark, netcat | CVE-2021-44228, command injection, password cracking, privilege escalation |
| Vaccine | nmap, ftp, burp, john, hashcat | SQL injection, command injection, password cracking, sudo privesc |
