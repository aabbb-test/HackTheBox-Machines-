# Browsed - HackTheBox Machine

![Difficulty](https://img.shields.io/badge/Difficulty-Medium-yellow)
![OS](https://img.shields.io/badge/OS-Linux-blue)

## Quick Info

- **User Flag:** `3432d629b8871b5a2d5ce5bbf78561cf`
- **Root Flag:** `da58174fdde035fa04575f567f176992`

## Attack Path

1. **SSRF via Chrome Extension** → Access internal Flask app
2. **Bash Arithmetic Injection** → RCE and reverse shell (user: larry)
3. **Python Cache Poisoning** → Privilege escalation to root

## Key Techniques

- Chrome Extension SSRF
- Bash arithmetic expansion exploitation
- Python bytecode cache poisoning with size/timestamp matching

## Files

- [`WRITEUP.md`](./WRITEUP.md) - Complete detailed writeup
- [`exploits/pwn_cache.py`](./exploits/pwn_cache.py) - Python cache poisoning exploit
- [`exploits/malicious_extension/`](./exploits/malicious_extension/) - Chrome extension for SSRF

## Quick Start

See [WRITEUP.md](./WRITEUP.md) for full exploitation details.

---

**Author:** Master Miyagi 🥋  
**Date:** January 28, 2026
