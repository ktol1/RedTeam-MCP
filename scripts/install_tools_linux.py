#!/usr/bin/env python3
"""
RedTeam-Agent Linux 工具自动化部署脚本
自动从 GitHub Releases 下载 Linux amd64 版本的二进制工具，并安装 Python 渗透包。
"""

import os
import platform
import stat
import sys
import urllib.request
import json
import zipfile
import tarfile
import shutil
import subprocess

# 工具存放目录（相对于脚本位置）
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "tools")

# Go 编译的核心工具列表与 GitHub 仓库
TOOLS_LIST = {
    "fscan": "shadow1ng/fscan",
    "gogo": "chainreactors/gogo",
    "httpx": "projectdiscovery/httpx",
    "nuclei": "projectdiscovery/nuclei",
    "ffuf": "ffuf/ffuf",
    "dnsx": "projectdiscovery/dnsx",
    "kerbrute": "ropnop/kerbrute",
    # nxc 在 Linux 上通过 pip 安装 netexec，不需要独立二进制
}

# Python 工具包
PYTHON_PACKAGES = [
    "impacket",       # wmiexec / psexec / secretsdump / GetNPUsers / GetUserSPNs / getST / ntlmrelayx
    "bloodhound",     # bloodhound-python：AD 权限图谱收集
    "netexec",        # nxc：内网横向渗透控制台
    "playwright",     # Playwright 无头浏览器：动态页面信息读取
]


def get_arch_keywords():
    """根据当前系统架构返回匹配关键词"""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return ["amd64", "x86_64", "linux64"]
    elif machine in ("aarch64", "arm64"):
        return ["arm64", "aarch64"]
    else:
        return ["amd64", "x86_64"]  # 默认 x86_64


def download_and_extract_latest(repo, tool_name):
    """从 GitHub Releases 下载最新的 Linux 版本"""
    print(f"\n[*] 正在准备安装 {tool_name} (来自 {repo})...")

    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(api_url, headers={"User-Agent": "Mozilla/5.0"})

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read().decode())
    except Exception as e:
        print(f"[!] 无法拉取 {repo} 的最新发布数据: {e}")
        return

    arch_keywords = get_arch_keywords()
    target_url = None
    archive_type = None  # "zip", "tar.gz", "binary"

    for asset in data.get("assets", []):
        name = asset["name"].lower()

        # 跳过非 Linux 平台
        if "windows" in name or "darwin" in name or "macos" in name:
            continue
        # 跳过不匹配的架构
        if "arm" in name and "arm64" not in name and "aarch64" not in name:
            continue
        if "386" in name or "i686" in name:
            continue

        # 必须包含 linux 关键词
        is_linux = "linux" in name
        # 必须匹配目标架构
        is_arch = any(kw in name for kw in arch_keywords)

        if is_linux and is_arch:
            if name.endswith(".tar.gz") or name.endswith(".tgz"):
                target_url = asset["browser_download_url"]
                archive_type = "tar.gz"
                break
            elif name.endswith(".zip"):
                target_url = asset["browser_download_url"]
                archive_type = "zip"
                break
            elif not name.endswith(".txt") and not name.endswith(".sha256"):
                target_url = asset["browser_download_url"]
                archive_type = "binary"

    if not target_url:
        print(f"[!] 没有找到适用于 Linux {platform.machine()} 的发布文件，跳过。")
        return

    # 确定临时文件扩展名
    ext_map = {"tar.gz": ".tar.gz", "zip": ".zip", "binary": ""}
    temp_path = os.path.join(TOOLS_DIR, f"{tool_name}_temp{ext_map[archive_type]}")

    print(f"[-] 正在从 Github 拉取文件: {target_url}")
    try:
        req = urllib.request.Request(target_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=120) as response, open(temp_path, "wb") as out_file:
            shutil.copyfileobj(response, out_file)
    except Exception as e:
        print(f"[!] 下载失败: {e}")
        return

    target_bin = os.path.join(TOOLS_DIR, tool_name)

    if archive_type == "tar.gz":
        print(f"[-] 正在解压 tar.gz 至 {TOOLS_DIR}")
        try:
            with tarfile.open(temp_path, "r:gz") as tar:
                for member in tar.getmembers():
                    basename = os.path.basename(member.name)
                    # 查找可执行文件（工具名匹配或无扩展名的非目录文件）
                    if member.isfile() and (
                        basename == tool_name
                        or basename.startswith(tool_name)
                        and not basename.endswith((".txt", ".md", ".yml", ".yaml"))
                    ):
                        source = tar.extractfile(member)
                        if source:
                            with open(target_bin, "wb") as target:
                                shutil.copyfileobj(source, target)
                            break
                else:
                    # 如果没找到精确匹配，提取第一个可执行文件
                    for member in tar.getmembers():
                        if member.isfile() and not member.name.endswith(
                            (".txt", ".md", ".yml", ".yaml", ".1")
                        ):
                            source = tar.extractfile(member)
                            if source:
                                with open(target_bin, "wb") as target:
                                    shutil.copyfileobj(source, target)
                                break
            os.remove(temp_path)
        except Exception as e:
            print(f"[!] 解压发生错误: {e}")
            return

    elif archive_type == "zip":
        print(f"[-] 正在解压 zip 至 {TOOLS_DIR}")
        try:
            with zipfile.ZipFile(temp_path, "r") as zip_ref:
                for member in zip_ref.namelist():
                    basename = os.path.basename(member)
                    if basename and not basename.endswith(
                        (".txt", ".md", ".yml", ".yaml")
                    ):
                        source = zip_ref.open(member)
                        with open(target_bin, "wb") as target:
                            shutil.copyfileobj(source, target)
                        break
            os.remove(temp_path)
        except Exception as e:
            print(f"[!] 解压发生错误: {e}")
            return

    else:  # binary
        os.replace(temp_path, target_bin)

    # 赋予可执行权限
    os.chmod(target_bin, os.stat(target_bin).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    print(f"[+] {tool_name} 安装成功！-> {target_bin}")


def install_python_packages():
    """安装 Python 渗透工具包"""
    print("\n" + "=" * 50)
    print("安装 Python 渗透工具包 (impacket / bloodhound / netexec)")
    print("=" * 50)

    for pkg in PYTHON_PACKAGES:
        print(f"\n[*] 正在安装 Python 包: {pkg} ...")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", pkg, "--upgrade", "-q"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print(f"[+] {pkg} 安装/升级成功")
        else:
            print(f"[!] {pkg} 安装失败:\n{result.stderr.strip()}")

    # 验证关键入口点
    print("\n[*] 验证工具入口点...")
    checks = [
        ("impacket-wmiexec", "impacket"),
        ("nxc", "netexec"),
        ("bloodhound-python", "bloodhound"),
    ]
    for cmd, pkg_name in checks:
        result = subprocess.run(
            [cmd, "--help"], capture_output=True, text=True
        )
        if result.returncode == 0 or "usage" in (result.stdout + result.stderr).lower():
            print(f"[+] {cmd} 入口点可用")
        else:
            print(f"[~] {cmd} 不在 PATH，请确认 {pkg_name} 正确安装且 pip bin 目录在 PATH 中")

    # 安装 Playwright 浏览器引擎
    print("\n[*] 安装 Playwright Chromium 浏览器引擎...")
    result = subprocess.run(
        [sys.executable, "-m", "playwright", "install", "chromium"],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        print("[+] Playwright Chromium 浏览器引擎安装成功")
    else:
        print(f"[!] Playwright 浏览器安装失败:\n{result.stderr.strip()}")
        print("[~] Linux 可能需要先安装系统依赖: playwright install-deps chromium")
            print(f"[~] {cmd} 不在 PATH，请确认 {pkg_name} 正确安装且 pip bin 目录在 PATH 中")


if __name__ == "__main__":
    print("=" * 50)
    print("RedTeam-Agent Linux 依赖工具自动化部署脚本")
    print(f"平台: {platform.system()} {platform.machine()}")
    print("=" * 50)

    if platform.system() != "Linux":
        print("[!] 警告：此脚本专为 Linux 设计。Windows 用户请使用 install_tools.py")
        sys.exit(1)

    if not os.path.exists(TOOLS_DIR):
        print(f"[*] 创建工具统一存放目录: {TOOLS_DIR}")
        os.makedirs(TOOLS_DIR)

    # 下载 Go 二进制工具
    for tool_name, repo in TOOLS_LIST.items():
        download_and_extract_latest(repo, tool_name)

    # 安装 Python 包
    install_python_packages()

    print("\n" + "=" * 50)
    print("[+] 所有工具安装完成！")
    print(f"    二进制工具目录: {TOOLS_DIR}")
    print(f"    Python 工具: impacket-* / nxc / bloodhound-python")
    print()
    print("[*] 别忘了把工具目录加入 PATH:")
    print(f'    echo \'export PATH="{TOOLS_DIR}:$PATH"\' >> ~/.bashrc')
    print(f"    source ~/.bashrc")
    print("=" * 50)

