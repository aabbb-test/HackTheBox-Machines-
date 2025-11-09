#!/bin/bash
# Script to copy images from main branch to images/ directory

echo "Checking out main branch temporarily..."
git fetch origin main:main 2>/dev/null || echo "Note: Fetch may require authentication"

echo "Copying images from main branch..."
for img in aesdecrypt.png burp.png burp2.png burp3.png db_results.png dirseach.png \
           gettingRootFlag.png login.png markpass.png nmap.png nuclei.png \
           php_receiver.png poc.png pwn.png rev_shell.png testuserpass.png user_flag.png; do
    git show main:"$img" > "images/$img" 2>/dev/null && echo "  ✓ Copied $img" || echo "  ✗ Failed $img"
done

echo "Done! Images copied to images/ directory"
