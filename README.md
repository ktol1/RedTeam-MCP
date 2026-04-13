# RedTeam-Agent

<div align="center">

<img src="assets/logo.png" alt="RedTeam-Agent" width="200"/>

### AI-Powered Autonomous Red Team Framework

**Let AI Become Your Security Audit Hacker**

[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge)](https://www.python.org/)
[![Skill](https://img.shields.io/badge/Workflow-Skill--First-brightgreen?style=for-the-badge)](./.github/skills/redteam/SKILL.md)
[![Stars](https://img.shields.io/github/stars/ktol1/RedTeam-Agent?style=for-the-badge)](https://github.com/ktol1/RedTeam-Agent/stargazers)

[English](./README.md) 路 [涓枃](./README_zh.md) 路 [Documentation](./.github/skills/redteam/SKILL.md) 路 [Quick Start](#-quick-start)

</div>

---

## 馃幆 Overview

RedTeam-Agent is an AI-powered red team penetration testing framework now uses a **Skill-first terminal workflow**. AI reads the project skill, discovers tools, and executes commands directly in terminal to complete internal network penetration testing, Active Directory attacks, vulnerability exploitation, and other red team tasks.

> **Core Philosophy**: No manual operation required. AI takes over all penetration tools for truly automated security testing.

### 鉁?Key Features

| Feature | Description |
|---------|-------------|
| 馃殌 **Plug & Play** | 15+ tools auto-install, one-click Windows deployment |
| 馃 **AI-Driven** | AI calls penetration tools directly via Skill + terminal |
| 馃挵 **Token Optimized** | Smart output compression, saves 80% tokens |
| 馃洝锔?**Full AD Coverage** | BloodHound + impacket + Responder full chain |
| 馃寪 **Multi-Client** | Cursor, Claude Desktop, VS Code Cline |

---

## 馃洜锔?Tool Matrix

### Network Scanning

| Tool | Function | Use Case |
|------|----------|----------|
| [gogo](./.github/skills/redteam/SKILL.md#tool-1-gogo-fast-asset-probe) | Fast asset discovery | Internal host detection |
| [fscan](./.github/skills/redteam/SKILL.md#tool-2-fscan-comprehensive-scanner) | Comprehensive scanner | Port/vulnerability/weak password |

### Web Security

| Tool | Function | Use Case |
|------|----------|----------|
| [httpx](./.github/skills/redteam/SKILL.md#tool-3-httpx-web-fingerprinting) | Web fingerprinting | Tech stack identification |
| [nuclei](./.github/skills/redteam/SKILL.md#tool-4-nuclei-vulnerability-poc-scanner) | POC batch scanning | Known vulnerability detection |
| [ffuf](./.github/skills/redteam/SKILL.md#tool-5-ffuf-directory-fuzzing) | Directory fuzzing | Web directory brute force |

### Active Directory Attacks 馃弳

| Tool | Function | Use Case |
|------|----------|----------|
| [SharpHound](./.github/skills/redteam/SKILL.md#tool-8-sharphound-ad-permission-graph-windows) | Windows collector | Domain data collection |
| [bloodhound-python](./.github/skills/redteam/SKILL.md#tool-7-bloodhound) | Cross-platform collector | Linux/macOS data collection |
| [GetNPUsers](./.github/skills/redteam/SKILL.md#impacket-getnpusersas-rep-roasting) | AS-REP Roast | Enumerate no-preauth users |
| [GetUserSPNs](./.github/skills/redteam/SKILL.md#impacket-getuserspnskerberoasting) | Kerberoasting | Request SPN ticket cracking |
| [secretsdump](./.github/skills/redteam/SKILL.md#impacket-secretsdump-lsass-dump) | LSASS Dump | Extract plaintext and hashes |
| [ntlmrelayx](./.github/skills/redteam/SKILL.md#impacket-ntlmrelayx) | NTLM Relay | Relay attacks |
| [pywerview](./.github/skills/redteam/SKILL.md#tool-9-powerview-domain-enumeration) | Domain enumeration | Users/computers/groups |
| [ldapdomaindump](./.github/skills/redteam/SKILL.md#tool-10-ldapdomaindump-ldap-domain-dump) | LDAP dump | Domain info snapshot |

### Lateral Movement

| Tool | Function | Use Case |
|------|----------|----------|
| [nxc](./.github/skills/redteam/SKILL.md#tool-6-netexec-nxc-lateral-movement) | NetExec | SMB/WinRM/SSH |
| [wmiexec](./.github/skills/redteam/SKILL.md#impacket-wmiexec) | WMI execution | Fileless lateral |
| [psexec](./.github/skills/redteam/SKILL.md#impacket-psexec) | PSEXEC | Service execution |

### Proxy & Credentials

| Tool | Function | Use Case |
|------|----------|----------|
| [chisel](./.github/skills/redteam/SKILL.md#proxy-automation-proxy-setup) | HTTP tunnel | Port forwarding |
| [responder](./.github/skills/redteam/SKILL.md#tool-11-responder-llmnrntbns-spoofing) | LLMNR spoofing | Hash collection |

---

## 馃殌 Quick Start

### 1锔忊儯 Requirements

```
Python 3.8+
Windows 10/11 or Linux/macOS
8GB+ RAM (recommended)
```

### 2锔忊儯 Installation

```bash
# Clone repository
git clone https://github.com/ktol1/RedTeam-Agent.git
cd RedTeam-Agent

# Create virtual environment
python -m venv venv

# Activate venv
# Windows PowerShell
.\venv\Scripts\Activate.ps1
# Linux/macOS
source venv/bin/activate

# Download binary tools (auto-downloads gogo, fscan, httpx, nuclei, etc.)
python scripts/install_tools.py
```

### 3锔忊儯 Enable Skills Terminal Mode

No extra server setup is required. Just do:

```bash
# Enter repo root (ensure .github/skills/redteam/SKILL.md is visible)
cd RedTeam-Agent

# Verify tools directory exists
dir .\redteam-tools
```

AI will read the repository skill and `copilot-instructions.md`, then execute commands directly in terminal and parse outputs.

### 4锔忊儯 Start Using

Tell your AI:

```
馃幆 First load the redteam skill, then scan 192.168.1.0/24 in terminal, write output to scan.txt, and summarize high-value findings

馃幆 Scan 192.168.1.0/24, find all Windows hosts and identify open services

馃幆 Use SharpHound to collect corp.local domain info, analyze attack paths

馃幆 Set up chisel proxy on 192.168.1.100 to access 10.10.10.0/24 network

馃幆 Perform Kerberoasting attack on 192.168.1.50
```

---

## 馃搳 Architecture (Skills + Terminal)

```
鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
鈹?                                                                鈹?
鈹?   鈻堚枅鈻堚枅鈻堚枅鈺?鈻堚枅鈻堚枅鈻堚枅鈺?鈻堚枅鈻堚枅鈻堚枅鈻堚晽鈻堚枅鈻堚晽   鈻堚枅鈻堚晽鈻堚枅鈻堚枅鈻堚枅鈻堚晽 鈻堚枅鈻堚枅鈻堚枅鈺?鈻堚枅鈺?   鈹?
鈹?   鈻堚枅鈺斺晲鈺愨枅鈻堚晽鈻堚枅鈺斺晲鈺愨枅鈻堚晽鈻堚枅鈺斺晲鈺愨晲鈺愨暆鈻堚枅鈻堚枅鈺?鈻堚枅鈻堚枅鈺戔枅鈻堚晹鈺愨晲鈺愨晲鈺濃枅鈻堚晹鈺愨晲鈺愨枅鈻堚晽鈻堚枅鈺?   鈹?
鈹?   鈻堚枅鈻堚枅鈻堚枅鈺斺暆鈻堚枅鈻堚枅鈻堚枅鈺斺暆鈻堚枅鈻堚枅鈻堚枅鈻堚晽鈻堚枅鈺斺枅鈻堚枅鈻堚晹鈻堚枅鈺戔枅鈻堚枅鈻堚枅鈺? 鈻堚枅鈺?  鈻堚枅鈺戔枅鈻堚晳    鈹?
鈹?   鈻堚枅鈺斺晲鈺愨晲鈺?鈻堚枅鈺斺晲鈺愨枅鈻堚晽鈺氣晲鈺愨晲鈺愨枅鈻堚晳鈻堚枅鈺戔暁鈻堚枅鈺斺暆鈻堚枅鈺戔枅鈻堚晹鈺愨晲鈺? 鈻堚枅鈺?  鈻堚枅鈺戔暁鈺愨暆    鈹?
鈹?   鈻堚枅鈺?    鈻堚枅鈺? 鈻堚枅鈺戔枅鈻堚枅鈻堚枅鈻堚枅鈺戔枅鈻堚晳 鈺氣晲鈺?鈻堚枅鈺戔枅鈻堚枅鈻堚枅鈻堚枅鈺椻暁鈻堚枅鈻堚枅鈻堚枅鈺斺暆鈻堚枅鈺?   鈹?
鈹?   鈺氣晲鈺?    鈺氣晲鈺? 鈺氣晲鈺濃暁鈺愨晲鈺愨晲鈺愨晲鈺濃暁鈺愨暆     鈺氣晲鈺濃暁鈺愨晲鈺愨晲鈺愨晲鈺?鈺氣晲鈺愨晲鈺愨晲鈺?鈺氣晲鈺?   鈹?
鈹?                                                                鈹?
鈹?                Skill-first Terminal Execution                   鈹?
鈹?                                                                鈹?
鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
                              鈹?
              鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹尖攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
              鈹?              鈹?              鈹?
              鈻?              鈻?              鈻?
       鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?  鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?  鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
       鈹? Cursor   鈹?  鈹? Claude  鈹?  鈹? Cline   鈹?
       鈹?   IDE    鈹?  鈹? Desktop 鈹?  鈹?(VS Code)鈹?
       鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?  鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?  鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
              鈹?              鈹?              鈹?
              鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹尖攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
                              鈹?
              鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹粹攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
              鈹?                              鈹?
              鈻?                              鈻?
    鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
    鈹?                      Skill Layer                           鈹?
    鈹?                                                            鈹?
    鈹? .github/copilot-instructions.md                            鈹?
    鈹? .github/skills/redteam/SKILL.md                            鈹?
    鈹?                                                            鈹?
    鈹? Rules: non-interactive commands / file-first long output   鈹?
    鈹?        summarize only high-signal findings                 鈹?
    鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
              鈹?
              鈻?
    鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
    鈹?                    Tool Layer                              鈹?
    鈹? 鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹? 鈹?
    鈹? 鈹? gogo  鈹?鈹? fscan  鈹?鈹? httpx  鈹?鈹?nuclei  鈹?鈹?Sharp  鈹? 鈹?
    鈹? 鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?鈹侶ound.exe鈹? 鈹?
    鈹? 鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹? 鈹?
    鈹? 鈹?nxc    鈹?鈹?chisel  鈹?鈹俰mpacket 鈹?鈹俽esponder鈹?           鈹?
    鈹? 鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?              鈹?
    鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
```

---

## 馃幆 AD Attack Flow

```
     鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
     鈹?                     Attack Flow                                 鈹?
     鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?

  鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?     鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?     鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
  鈹?   Recon      鈹?鈹€鈹€鈹€鈻?鈹?  Collection  鈹?鈹€鈹€鈹€鈻?鈹?  Analysis    鈹?
  鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?     鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?     鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹攢鈹€鈹€鈹€鈹€鈹€鈹€鈹?
         鈹?                                              鈹?
         鈻?                                              鈻?
  鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?                           鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
  鈹?gogo/fscan    鈹?                           鈹?BloodHound GUI鈹?
  鈹?kerbrute      鈹?                           鈹?attack_paths  鈹?
  鈹?pywerview     鈹?                           鈹?analysis.py  鈹?
  鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?                           鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
                                                        鈹?
  鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?     鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?           鈹?
  鈹?   Attack     鈹?鈼勨攢鈹€鈹€ 鈹?   Lateral    鈹?鈼勨攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
  鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?     鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
         鈹?                      鈹?
         鈻?                      鈻?
  鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?     鈹屸攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
  鈹?Kerberoast    鈹?     鈹?nxc smb       鈹?
  鈹?AS-REP Roast  鈹?     鈹?wmiexec       鈹?
  鈹?secretsdump   鈹?     鈹?psexec        鈹?
  鈹?ntlmrelayx    鈹?     鈹?getST         鈹?
  鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?     鈹斺攢鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹?
```

---

## 馃摝 Terminal Commands (Skill-driven)

| # | Tool | Function | Command |
|---|------|----------|---------|
| 1 | `gogo` | Fast asset probe | `gogo -t 100 -l hosts.txt -q -f gogo.txt` |
| 2 | `fscan` | Network scanner | `fscan -h 192.168.1.0/24 -np -silent -nocolor -o fscan.txt` |
| 3 | `httpx` | Web fingerprinting | `httpx -l urls.txt -sc -title -server -td -silent -o httpx.txt` |
| 4 | `nuclei` | POC scanner | `nuclei -l urls.txt -tags cve,rce -s high,critical -nc -o nuclei.txt` |
| 5 | `ffuf` | Directory fuzzing | `ffuf -u http://target/FUZZ -w wordlist.txt -mc 200,301,302 -s -o ffuf.txt` |
| 6 | `nxc` | Lateral movement | `nxc smb 192.168.1.0/24 -u user -p pass --shares` |
| 7 | `kerbrute` | Kerberos enum | `kerbrute userenum -d corp.local --dc 192.168.1.10 users.txt -o valid_users.txt` |
| 8 | `SharpHound` | BloodHound collection | `SharpHound.exe -c Default -d corp.local` |
| 9 | `pywerview` | Domain enumeration | `pywerview.py get-domain-user -d corp.local --dc-ip 192.168.1.10 -u user -p pass` |
| 10 | `ldapdomaindump` | LDAP dump | `ldapdomaindump ldap://192.168.1.10 -u 'corp\\user' -p 'password' -o .\\ldapdump` |
| 11 | `responder` | LLMNR spoofing | `responder -I eth0 -v` |
| 12 | `wmiexec` | WMI execution | `impacket-wmiexec domain/user:pass@target 'whoami'` |
| 13 | `psexec` | PSEXEC | `impacket-psexec domain/user:pass@target cmd.exe` |
| 14 | `secretsdump` | LSASS dump | `impacket-secretsdump corp.local/user:pass@dc -just-dc` |
| 15 | `ntlmrelayx` | NTLM relay | `impacket-ntlmrelayx -t ldap://dc --smb2support` |

---

## 鈿?Token Optimization

| Optimization | Description | Savings |
|-------------|-------------|---------|
| ANSI Removal | Strip terminal colors | ~15% |
| Whitespace | Merge blank lines | ~10% |
| Truncation | Max 8000 chars | ~50% |
| Progress Filter | Remove progress bars | ~20% |
| **Total** | | **~80%** |

---

## 馃摎 Documentation

| Document | Description |
|----------|-------------|
| [SKILL.md](./.github/skills/redteam/SKILL.md) | Complete tool docs for AI agents |
| [.github/copilot-instructions.md](./.github/copilot-instructions.md) | Repository terminal execution rules |

---

## 馃 Contributing

Issues and Pull Requests welcome!

[![Stars](https://img.shields.io/github/stars/ktol1/RedTeam-Agent?style=social)](https://github.com/ktol1/RedTeam-Agent)
[![Forks](https://img.shields.io/github/forks/ktol1/RedTeam-Agent?style=social)](https://github.com/ktol1/RedTeam-Agent)

---

<div align="center">

**MIT License** 路 Copyright 漏 2024-2026 **ktol1**

**If you find this useful, give it a 猸?Star!**

</div>

