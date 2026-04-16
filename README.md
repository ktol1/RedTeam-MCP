# RedTeam-Agent

<div align="center">

<img src="assets/logo.png" alt="RedTeam-Agent" width="200"/>

### AI-Powered Autonomous Red Team Framework

**Let AI become your security audit hacker**

[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge)](https://www.python.org/)
[![Skill](https://img.shields.io/badge/Workflow-Skill--First-brightgreen?style=for-the-badge)](./.github/skills/redteam/SKILL.md)
[![Stars](https://img.shields.io/github/stars/ktol1/RedTeam-Agent?style=for-the-badge)](https://github.com/ktol1/RedTeam-Agent/stargazers)

[English](./README.md) | [Chinese](./README_zh.md) | [Documentation](./.github/skills/redteam/SKILL.md) | [Quick Start](#quick-start)

</div>

---

## Overview

RedTeam-Agent is an AI-powered red team framework using a skill-first terminal workflow. AI reads project skills, discovers tools, executes commands in terminal, and summarizes high-signal findings.

Core philosophy: no manual tool-by-tool operation. Let AI orchestrate the workflow end-to-end.

## Key Features

- Plug and play: 15+ tools with automated setup
- AI-driven workflow: Skill + terminal execution
- Token optimized: output filtering and file-first strategy
- AD coverage: BloodHound + impacket + Responder chain
- Multi-client support: Cursor, Claude Desktop, VS Code/Cline

---

## Tool Matrix

### Network

- gogo: fast asset discovery
- fscan: comprehensive host/service scan

### Web

- httpx: HTTP probing and fingerprinting
- nuclei: template-based vulnerability validation
- ffuf: directory and parameter fuzzing

### Active Directory

- SharpHound / bloodhound-python
- impacket (GetNPUsers, GetUserSPNs, secretsdump, ntlmrelayx, etc.)
- pywerview, ldapdomaindump

### Lateral Movement

- nxc (NetExec)
- impacket-wmiexec
- impacket-psexec

---

## Quick Start

### 1. Requirements

```text
Python 3.8+
Windows 10/11 or Linux/macOS
8GB+ RAM recommended
```

### 2. Installation

```bash
git clone https://github.com/ktol1/RedTeam-Agent.git
cd RedTeam-Agent

python -m venv venv
# Windows PowerShell
.\venv\Scripts\Activate.ps1
# Linux/macOS
source venv/bin/activate

# Windows
python scripts/install_tools.py

# Linux/macOS
python scripts/install_tools_linux.py
```

### 3. Enable Skills Terminal Mode

No extra server setup is required.

```bash
cd RedTeam-Agent
dir .\tools
```

AI will read the repository skill and `.github/copilot-instructions.md`, then execute terminal commands directly.

### 4. Example Prompts

```text
First load the redteam skill, then scan 192.168.1.0/24 in terminal,
write output to scan.txt, and summarize high-value findings.

Use SharpHound to collect corp.local data and summarize attack paths.

Set up a chisel proxy and provide upload/run commands.
```

---

## AD Attack Flow

1. Recon: gogo / fscan / kerbrute / pywerview
2. Collection: SharpHound or bloodhound-python
3. Analysis: BloodHound GUI or scripts/bloodhound_analysis.py
4. Attack: Kerberoast / AS-REP Roast / secretsdump / relay
5. Lateral: nxc / wmiexec / psexec / getST

---

## Terminal Commands (Skill-driven)

| # | Tool | Function | Command |
|---|------|----------|---------|
| 1 | gogo | Fast asset probe | `gogo -t 100 -l hosts.txt -q -f gogo.txt` |
| 2 | fscan | Network scanner | `fscan -h 192.168.1.0/24 -np -silent -nocolor -o fscan.txt` |
| 3 | httpx | Web fingerprinting | `httpx -l urls.txt -sc -title -server -td -silent -o httpx.txt` |
| 4 | nuclei | POC scanner | `nuclei -l urls.txt -tags cve,rce -s high,critical -nc -o nuclei.txt` |
| 5 | ffuf | Directory fuzzing | `ffuf -u http://target/FUZZ -w wordlist.txt -mc 200,301,302 -s -o ffuf.txt` |
| 6 | nxc | Lateral movement | `nxc smb 192.168.1.0/24 -u user -p pass --shares` |
| 7 | kerbrute | Kerberos enum | `kerbrute userenum -d corp.local --dc 192.168.1.10 users.txt -o valid_users.txt` |
| 8 | SharpHound | Data collection | `SharpHound.exe -c Default -d corp.local` |
| 9 | pywerview | Domain enum | `pywerview.py get-domain-user -d corp.local --dc-ip 192.168.1.10 -u user -p pass` |
| 10 | ldapdomaindump | LDAP dump | `ldapdomaindump ldap://192.168.1.10 -u 'corp\\user' -p 'password' -o .\\ldapdump` |
| 11 | responder | LLMNR spoofing | `responder -I eth0 -v` |
| 12 | wmiexec | WMI exec | `impacket-wmiexec domain/user:pass@target 'whoami'` |
| 13 | psexec | Service exec | `impacket-psexec domain/user:pass@target cmd.exe` |
| 14 | secretsdump | Credential dump | `impacket-secretsdump corp.local/user:pass@dc -just-dc` |
| 15 | ntlmrelayx | NTLM relay | `impacket-ntlmrelayx -t ldap://dc --smb2support` |

---

## Output Optimization

- Remove ANSI colors
- Compress blank lines
- Truncate excessive output
- Prefer file-first output for large scans
- Summarize only high-signal findings

---

## Documentation

- [SKILL.md](./.github/skills/redteam/SKILL.md)
- [.github/copilot-instructions.md](./.github/copilot-instructions.md)

## Contributing

Issues and pull requests are welcome.

<div align="center">

MIT License - Copyright (c) 2024-2026 ktol1

</div>

