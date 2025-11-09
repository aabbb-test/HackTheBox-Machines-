# HackTheBox Machines

This repository contains writeups and imagery for HackTheBox machines you've completed.

Structure
- machines/<difficulty>/<machine-name>/README.md — machine walkthrough
- machines/<difficulty>/<machine-name>/images/ — screenshots and images
- machines/<difficulty>/<machine-name>/raw-logs/ — raw textual logs (nmap, gobuster, exploit output)
- templates/writeup-template.md — template to create new writeups
- .github/workflows/generate-writeup.yml — optional automation that generates writeups from raw-logs

Workflow
1. Create a folder for a machine under machines/Medium/<MachineName>
2. Put textual logs into machines/Medium/<MachineName>/raw-logs/ (nmap.txt, gobuster.txt, etc.)
3. Put screenshots into machines/Medium/<MachineName>/images/
4. If you want automatic generation, push files and the Action will attempt to generate a first-draft README.md for the machine using the template (requires API key secret; manual review recommended).

Security / publishing
- Only publish machines you are allowed to publish (HTB policy). Remove or redact any sensitive credentials before committing.
- If you use the automated generation, ensure you do not send secrets to any external API.
