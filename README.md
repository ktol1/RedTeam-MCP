# RedTeam-MCP

<div align="center">

![RedTeam-MCP Logo](assets/logo.png)

**AI-Powered Autonomous Red Team Framework via Model Context Protocol**

[English](README.md) · [中文](README_zh.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-Protocol-green.svg)](https://modelcontextprotocol.io/)

</div>

---

## Overview

RedTeam-MCP 让 AI 直接化身安全审计黑客！通过 Model Context Protocol (MCP)，AI 能够自主执行内网渗透测试、活动目录攻击、漏洞利用等红队任务。

**15+ 渗透工具开箱即用**：gogo、fscan、httpx、nuclei、impacket、BloodHound、SharpHound、chisel、pywerview 等。

## Features

| Category | Tools |
|----------|-------|
| **Network Scanner** | gogo, fscan |
| **Web Fingerprint** | httpx, nuclei |
| **Directory Bruteforce** | ffuf, dirsearch |
| **AD Enumeration** | SharpHound, bloodhound-python, pywerview |
| **AD Attacks** | GetNPUsers, GetUserSPNs, secretsdump, ntlmrelayx |
| **Lateral Movement** | nxc, wmiexec, psexec, dcomexec |
| **Proxy Setup** | chisel, nc, PowerShell |
| **Credential Harvest** | responder, ldapdomaindump |
| **Browser Automation** | playwright |

## Quick Start

### 1. Clone & Install

```bash
# Clone repository
git clone https://github.com/ktol1/RedTeam-MCP.git
cd RedTeam-MCP/redteam-server

# Create virtual environment
python -m venv venv

# Activate (Windows)
.\venv\Scripts\Activate.ps1
# Or (Linux/macOS)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Download binary tools (gogo, fscan, httpx, nuclei, etc.)
python install_tools.py
```

### 2. Configure MCP Client

#### Cursor IDE

Add to `settings.json`:

```json
{
  "mcpServers": {
    "RedTeam-MCP": {
      "command": "D:\\mcp\\redteam-server\\venv\\Scripts\\python.exe",
      "args": ["D:\\mcp\\redteam-server\\server.py"]
    }
  }
}
```

#### Claude Desktop

Add to `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "RedTeam-MCP": {
      "command": "D:\\mcp\\redteam-server\\venv\\Scripts\\python.exe",
      "args": ["D:\\mcp\\redteam-server\\server.py"]
    }
  }
}
```

#### VS Code (Cline/Roo Code)

Add to MCP settings in the extension config.

### 3. Start Using

Tell your AI:

> *"扫描 192.168.1.0/24 网段，发现所有 Windows 主机并识别开放服务。"*

> *"使用 SharpHound 收集域信息，然后分析攻击路径找到域管。"*

> *"在 192.168.1.100 上搭建 chisel 代理，通过它访问 10.10.10.0/24 网段。"*

## MCP Tools

| Tool | Description |
|------|-------------|
| `invoke_gogo` | 极速资产与协议指纹探针 |
| `invoke_fscan` | 内网综合扫描 (主机发现/端口/漏洞) |
| `invoke_httpx` | Web 指纹识别与可用性探测 |
| `invoke_nuclei` | 漏洞 POC 批量扫描 |
| `invoke_ffuf` | Web 目录/参数 fuzzing |
| `invoke_nxc` | NetExec 内网横向渗透 |
| `invoke_bloodhound_analysis` | BloodHound AD 权限图谱分析 |
| `invoke_powerview` | pywerview 域信息枚举 |
| `invoke_ldapdomaindump` | LDAP 域信息转储 |
| `invoke_responder` | LLMNR/NBT-NS 欺骗哈希收集 |
| `invoke_proxy_setup` | 自动化代理搭建 (chisel/nc/powershell) |
| `invoke_kerbrute` | Kerberos 用户枚举 |
| `invoke_ntlmrelayx` | NTLM Relay 攻击 |
| `invoke_playwright` | Playwright 浏览器自动化 |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AI Agent (Cursor/Claude)                 │
└─────────────────────────────┬───────────────────────────────┘
                              │ MCP Protocol
┌─────────────────────────────▼───────────────────────────────┐
│                    RedTeam-MCP Server                       │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    server.py                         │   │
│  │  - Tool definitions (17+ tools)                     │   │
│  │  - Output optimization & truncation                  │   │
│  │  - Token cost control                                │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                  Python Libraries                    │   │
│  │  impacket · bloodhound · pywerview · ldapdomaindump │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│                    Binary Tools                              │
│  gogo.exe · fscan.exe · httpx.exe · nuclei.exe · chisel.exe │
│  SharpHound.exe · nxc.exe                                   │
└─────────────────────────────────────────────────────────────┘
```

## AD Attack Workflow

```
┌──────────────┐    ┌────────────────┐    ┌──────────────────┐
│   Discovery  │───►│   Collection   │───►│    Analysis      │
│              │    │                │    │                  │
│ gogo/fscan   │    │ SharpHound     │    │ BloodHound GUI   │
│ kerbrute     │    │ bloodhound-py  │    │ bloodhound_      │
│ pywerview    │    │ ldapdomaindump │    │ analysis.py      │
└──────────────┘    └────────────────┘    └────────┬─────────┘
                                                    │
┌──────────────┐    ┌────────────────┐    ┌────────▼─────────┐
│   Lateral    │◄───│   Movement     │◄───│    Attack Path   │
│   Movement   │    │                │    │                  │
│              │    │ nxc smb        │    │ Golden/Silver    │
│ wmiexec      │    │ secretsdump    │    │ Kerberoast       │
│ psexec       │    │ ntlmrelayx     │    │ AS-REP Roast     │
└──────────────┘    └────────────────┘    └──────────────────┘
```

## Token Optimization

RedTeam-MCP includes intelligent output optimization:

- **ANSI Code Removal**: Strips terminal colors and formatting
- **Whitespace Compression**: Removes excessive blank lines
- **Output Truncation**: Max 8,000 characters per result
- **Smart Filtering**: Removes progress bars and non-critical errors

## Documentation

- [SKILL.md](.github/skills/redteam/SKILL.md) - Complete tool documentation for AI agents
- [redteam-server/README.md](redteam-server/README.md) - Server deployment guide

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please read the contribution guidelines first.

---

<div align="center">

**Star this repo if you find it useful!**

</div>
