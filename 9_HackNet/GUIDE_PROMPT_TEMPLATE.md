# HTB Machine Walkthrough Guide - Prompt Template

## Use This Prompt for Future HTB Machines:

```
Create a complete step-by-step walkthrough for the HTB machine [MACHINE_NAME].

CRITICAL REQUIREMENTS:

1. STRUCTURE - Every step must follow this exact format:
   - Step Number and Title
   - WHY: Explain why we're doing this step
   - COMMAND: Show the exact command (if applicable)
   - EXPLANATION: Explain what each flag/parameter does
   - OUTPUT: Show the REAL output from running the command
   - ANALYSIS: Explain what the output means
   - NEXT STEP: Explain how this leads to the next action

2. DISCOVERY FLOW - Show the natural progression:
   - Start with nmap
   - Explain why we chose the next tool based on nmap results
   - Show browser exploration (clicking around, network tab inspection)
   - Demonstrate how we discovered endpoints/vulnerabilities organically
   - Include both successful AND unsuccessful attempts when relevant

3. COMMANDS:
   - Every single command executed with full syntax
   - Explain ALL flags and parameters
   - Show complete, unedited output
   - Include both automated scripts AND manual commands
   - Show browser actions when GUI interaction was used

4. THOUGHT PROCESS:
   - Explain the reasoning behind each decision
   - "Since we found X, we should try Y because..."
   - Show how one finding leads to the next step
   - Include the "why not Z?" when ruling out approaches

5. NO FLUFF:
   - Do NOT include CVSS scores
   - Do NOT include CVE references (unless directly exploited)
   - Do NOT include theoretical "prevention" sections
   - Do NOT include generic security advice
   - Focus ONLY on practical execution

6. INCLUDE:
   - Browser discoveries (Developer Tools, Network tab, clicking links)
   - How we found hidden endpoints/pages
   - Manual exploration before automation
   - Script creation (show the code with explanations)
   - Full attack chain diagram at the end

7. FORMAT:
   - Use markdown
   - Code blocks for all commands and outputs
   - Clear section headers for each phase (Enumeration, Exploitation, Privilege Escalation)
   - Number all steps sequentially

8. SAVE AS:
   - WALKTHROUGH.md - The complete guide
   - README.md - Copy of WALKTHROUGH.md (shows when opening folder)

EXAMPLE STRUCTURE:

### Step 1: Initial Port Scan

**Why?** First step in any pentest is discovering what services are running.

**Command:**
```bash
nmap -sC -sV -oN nmap_scan.txt 10.10.10.X
```

**Flags Explained:**
- `-sC`: Run default nmap scripts
- `-sV`: Detect service versions
- `-oN`: Save output to file
- `10.10.10.X`: Target IP

**Output:**
```
[paste actual nmap output here]
```

**Analysis:**
- Port 22 (SSH): OpenSSH 8.2 - recent version, unlikely vulnerable
- Port 80 (HTTP): Apache 2.4.41 - web server running
- The web server redirects to domain.htb

**Next Step:** Add domain.htb to /etc/hosts and explore the website

---

REMEMBER: The goal is to teach someone the METHODOLOGY and THOUGHT PROCESS, not just give them commands to copy. Show them HOW you think through a pentest, step by step.

Machine Details:
- Name: [MACHINE_NAME]
- IP: [IP_ADDRESS]
- Difficulty: [DIFFICULTY]
- OS: [OPERATING_SYSTEM]

Start with nmap and guide me through the complete exploitation path.
```

---

## Quick Reference Checklist:

Before finalizing the guide, verify:

- [ ] Every command has explanation of why we run it
- [ ] Every command output is shown in full
- [ ] Browser actions are documented (not just CLI)
- [ ] Discovery flow is natural (not "use this exploit")
- [ ] Thought process connects each step
- [ ] No CVSS/CVE unless directly used
- [ ] Attack chain diagram at the end
- [ ] Both WALKTHROUGH.md and README.md created
- [ ] Step numbers are sequential
- [ ] Scripts include code + explanation

---

## Example Phrases to Use:

**Good:**
- "Why? We need to find what services are running"
- "Since this is a web server, let's enumerate directories"
- "The output shows port 80 is open, so we should check the website"
- "Clicking 'View Likes' in the browser takes us to /likes/6"
- "This didn't work, so let's try another approach"

**Bad:**
- "Run this command" (no explanation)
- "The vulnerability has CVSS score 9.8"
- "To prevent this, developers should..."
- "Just use this exploit"
- "I found the vulnerability" (how did you find it?)

---

## Template Variables to Replace:

When using this prompt, replace:
- `[MACHINE_NAME]` - Name of the HTB box
- `[IP_ADDRESS]` - Target IP (e.g., 10.129.232.4)
- `[DIFFICULTY]` - Easy/Medium/Hard/Insane
- `[OPERATING_SYSTEM]` - Linux/Windows

---

## Pro Tips:

1. **Document as you go** - Don't wait until the end
2. **Save all outputs** - Easier to paste real output than recreate
3. **Screenshot browser actions** - Shows the discovery process
4. **Keep notes.txt** - Track your thought process during the box
5. **Save all scripts** - Include them in the guide with explanations

---

## File Organization:

```
MachineName/
├── README.md              # Copy of walkthrough (shows on GitHub)
├── WALKTHROUGH.md         # Complete guide
├── notes.txt              # Your raw notes during exploitation
├── scripts/
│   ├── exploit_script.py
│   ├── credential_extract.py
│   └── ...
└── outputs/
    ├── nmap_scan.txt
    ├── credentials.json
    └── ...
```

---

**Save this file for future reference!**
