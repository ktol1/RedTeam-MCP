# RedTeam-MCP

<div align="center">

![RedTeam-MCP Logo](assets/logo.png)

**AI 红队与内网渗透自动化框架**

通过 Model Context Protocol (MCP) 让 AI 直接化身安全审计黑客

[English](README.md) · [中文](README_zh.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-Protocol-green.svg)](https://modelcontextprotocol.io/)

</div>

---

## 简介

RedTeam-MCP 让 AI 拥有如黑客般真实的扫描、横向移动、活动目录攻击能力。通过 MCP 协议，AI 能够自主执行内网渗透测试任务。

**15+ 渗透工具开箱即用**：gogo、fscan、httpx、nuclei、impacket、BloodHound、SharpHound、chisel、pywerview 等。

## 核心功能

| 类别 | 工具 |
|------|------|
| **网络扫描** | gogo, fscan |
| **Web 指纹** | httpx, nuclei |
| **目录爆破** | ffuf, dirsearch |
| **域内枚举** | SharpHound, bloodhound-python, pywerview |
| **域内攻击** | GetNPUsers, GetUserSPNs, secretsdump, ntlmrelayx |
| **横向移动** | nxc, wmiexec, psexec, dcomexec |
| **代理搭建** | chisel, nc, PowerShell |
| **凭据收集** | responder, ldapdomaindump |
| **浏览器自动化** | playwright |

## 快速开始

### 1. 克隆与安装

```bash
# 克隆仓库
git clone https://github.com/ktol1/RedTeam-MCP.git
cd RedTeam-MCP/redteam-server

# 创建虚拟环境
python -m venv venv

# 激活虚拟环境 (Windows)
.\venv\Scripts\Activate.ps1
# 或 (Linux/macOS)
source venv/bin/activate

# 安装依赖
pip install -r requirements.txt

# 下载二进制工具 (gogo, fscan, httpx, nuclei 等)
python install_tools.py
```

### 2. 配置 MCP 客户端

#### Cursor IDE

添加到 `settings.json`:

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

添加到 `%APPDATA%\Claude\claude_desktop_config.json`:

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

添加到插件的 MCP 设置中。

### 3. 开始使用

告诉 AI：

> *"扫描 192.168.1.0/24 网段，发现所有 Windows 主机并识别开放服务。"*

> *"使用 SharpHound 收集域信息，然后分析攻击路径找到域管。"*

> *"在 192.168.1.100 上搭建 chisel 代理，通过它访问 10.10.10.0/24 网段。"*

## MCP 工具列表

| 工具 | 功能 |
|------|------|
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

## 架构图

```
┌─────────────────────────────────────────────────────────────┐
│                    AI Agent (Cursor/Claude)                  │
└─────────────────────────────┬───────────────────────────────┘
                              │ MCP Protocol
┌─────────────────────────────▼───────────────────────────────┐
│                    RedTeam-MCP Server                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    server.py                         │   │
│  │  - 工具定义 (17+ 工具)                                │   │
│  │  - 输出优化与截断                                      │   │
│  │  - Token 成本控制                                     │   │
│  └─────────────────────────────────────────────────────┘   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                  Python 库                            │   │
│  │  impacket · bloodhound · pywerview · ldapdomaindump │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────┬───────────────────────────────┘
                              │
┌─────────────────────────────▼───────────────────────────────┐
│                    二进制工具                                 │
│  gogo.exe · fscan.exe · httpx.exe · nuclei.exe · chisel.exe │
│  SharpHound.exe · nxc.exe                                   │
└─────────────────────────────────────────────────────────────┘
```

## 域渗透攻击流程

```
┌──────────────┐    ┌────────────────┐    ┌──────────────────┐
│   发现探测   │───►│   信息收集     │───►│    攻击分析      │
│              │    │                │    │                  │
│ gogo/fscan   │    │ SharpHound     │    │ BloodHound GUI   │
│ kerbrute     │    │ bloodhound-py  │    │ bloodhound_      │
│ pywerview    │    │ ldapdomaindump │    │ analysis.py      │
└──────────────┘    └────────────────┘    └────────┬─────────┘
                                                    │
┌──────────────┐    ┌────────────────┐    ┌────────▼─────────┐
│   横向移动   │◄───│   凭据利用     │◄───│    攻击路径     │
│   Movement   │    │                │    │                  │
│              │    │ nxc smb        │    │ 黄金/白银票据    │
│ wmiexec      │    │ secretsdump    │    │ Kerberoast       │
│ psexec       │    │ ntlmrelayx     │    │ AS-REP Roast     │
└──────────────┘    └────────────────┘    └──────────────────┘
```

## Token 优化

RedTeam-MCP 内置智能输出优化：

- **ANSI 颜色去除**: 清除终端颜色和格式代码
- **空白压缩**: 去除多余的空行
- **输出截断**: 每个结果最多 8,000 字符
- **智能过滤**: 移除进度条和不重要的错误信息

## 文档

- [SKILL.md](.github/skills/redteam/SKILL.md) - AI Agent 完整工具文档
- [redteam-server/README.md](redteam-server/README.md) - 服务器部署指南

## 许可证

MIT License - 详见 [LICENSE](LICENSE)

## 贡献

欢迎提交 Issue 和 Pull Request！

---

<div align="center">

**如果对你有帮助，请给个 Star！**

</div>
