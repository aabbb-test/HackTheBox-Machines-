# HackTheBox Machines

This repository contains writeups and imagery for HackTheBox machines you've completed.

Structure
- <machine-name>/README.md — machine walkthrough
- <machine-name>/images/ — screenshots and images
- <machine-name>/raw-logs/ — raw textual logs (nmap, gobuster, exploit output, PDFs)
- tools/convert_pdf_to_md.py — script to convert PDF writeups to markdown format

Workflow
1. Create a folder for a machine (e.g., MachineName/)
2. Put textual logs into MachineName/raw-logs/ (nmap.txt, gobuster.txt, document.pdf, etc.)
3. Put screenshots into MachineName/images/
4. Create or generate a README.md with the machine walkthrough

Security / publishing
- Only publish machines you are allowed to publish (HTB policy). Remove or redact any sensitive credentials before committing.
- If you use the automated generation, ensure you do not send secrets to any external API.
