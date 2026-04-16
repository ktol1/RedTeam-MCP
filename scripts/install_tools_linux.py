#!/usr/bin/env python3
"""Linux 工具安装脚本（精简版）"""

import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "tools")

TOOLS_LIST = {
    "fscan": "shadow1ng/fscan",
    "gogo": "chainreactors/gogo",
    "httpx": "projectdiscovery/httpx",
    "nuclei": "projectdiscovery/nuclei",
    "ffuf": "ffuf/ffuf",
    "dnsx": "projectdiscovery/dnsx",
    "kerbrute": "ropnop/kerbrute",
}

PYTHON_PACKAGES = [
    "impacket",
    "bloodhound",
    "netexec",
    "pywerview",
    "ldapdomaindump",
    "bloodyAD",
]

IMPACKET_REPO = "https://github.com/fortra/impacket.git"
DNSTOOL_URL = "https://raw.githubusercontent.com/dirkjanm/krbrelayx/master/dnstool.py"

SKIP_SUFFIX = (
    ".txt",
    ".md",
    ".sha256",
    ".sha512",
    ".sig",
    ".asc",
    ".pem",
    ".yaml",
    ".yml",
)


def arch_keywords():
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return ["amd64", "x86_64", "linux64"]
    if machine in ("aarch64", "arm64"):
        return ["arm64", "aarch64"]
    return ["amd64", "x86_64"]


def github_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode())


def choose_asset(assets):
    keys = arch_keywords()
    selected = None
    selected_kind = None
    priority = {"tar.gz": 3, "zip": 2, "binary": 1}

    for asset in assets:
        name = asset["name"].lower()

        if "linux" not in name:
            continue
        if any(x in name for x in ("windows", "darwin", "macos", "freebsd")):
            continue
        if not any(k in name for k in keys):
            continue
        if any(name.endswith(s) for s in SKIP_SUFFIX):
            continue
        if "386" in name or "i686" in name:
            continue

        kind = "binary"
        if name.endswith(".tar.gz") or name.endswith(".tgz"):
            kind = "tar.gz"
        elif name.endswith(".zip"):
            kind = "zip"

        if selected is None or priority[kind] > priority[selected_kind]:
            selected = asset
            selected_kind = kind

    return selected, selected_kind


def find_candidate_name(names, tool_name):
    lowered = [n for n in names if n and not n.endswith("/")]

    for n in lowered:
        base = os.path.basename(n).lower()
        if base == tool_name:
            return n

    for n in lowered:
        base = os.path.basename(n).lower()
        if base.startswith(tool_name) and not base.endswith(SKIP_SUFFIX):
            return n

    for n in lowered:
        base = os.path.basename(n).lower()
        if not base.endswith(SKIP_SUFFIX):
            return n

    return None


def download_tool(tool_name, repo):
    print(f"\n[*] 安装 {tool_name} ({repo})")
    api = f"https://api.github.com/repos/{repo}/releases/latest"

    try:
        data = github_json(api)
    except Exception as exc:
        print(f"[!] 获取发布信息失败: {exc}")
        return

    asset, kind = choose_asset(data.get("assets", []))
    if not asset:
        print(f"[!] 未找到 Linux {platform.machine()} 对应资源，已跳过")
        return

    ext = ".tar.gz" if kind == "tar.gz" else ".zip" if kind == "zip" else ""
    temp_path = os.path.join(TOOLS_DIR, f"{tool_name}.download{ext}")
    target_bin = os.path.join(TOOLS_DIR, tool_name)
    url = asset["browser_download_url"]

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=120) as response, open(temp_path, "wb") as out_file:
            shutil.copyfileobj(response, out_file)
    except Exception as exc:
        print(f"[!] 下载失败: {exc}")
        return

    try:
        if kind == "tar.gz":
            with tarfile.open(temp_path, "r:gz") as tar:
                names = [m.name for m in tar.getmembers() if m.isfile()]
                candidate = find_candidate_name(names, tool_name)
                if not candidate:
                    raise RuntimeError("压缩包内未找到可执行候选文件")
                member = tar.getmember(candidate)
                source = tar.extractfile(member)
                if not source:
                    raise RuntimeError("无法提取目标文件")
                with open(target_bin, "wb") as target:
                    shutil.copyfileobj(source, target)
        elif kind == "zip":
            with zipfile.ZipFile(temp_path, "r") as archive:
                names = archive.namelist()
                candidate = find_candidate_name(names, tool_name)
                if not candidate:
                    raise RuntimeError("压缩包内未找到可执行候选文件")
                with archive.open(candidate) as source, open(target_bin, "wb") as target:
                    shutil.copyfileobj(source, target)
        else:
            os.replace(temp_path, target_bin)

        if os.path.exists(temp_path):
            os.remove(temp_path)

        current_mode = os.stat(target_bin).st_mode
        os.chmod(target_bin, current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        print(f"[+] 安装完成: {target_bin}")
    except Exception as exc:
        print(f"[!] 解包或安装失败: {exc}")
        if os.path.exists(temp_path):
            os.remove(temp_path)


def install_python_packages():
    print("\n" + "=" * 50)
    print("安装 Python 依赖")
    print("=" * 50)

    for pkg in PYTHON_PACKAGES:
        print(f"[*] pip install --upgrade {pkg}")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", pkg],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            print(f"[+] {pkg} 安装成功")
        else:
            print(f"[!] {pkg} 安装失败: {result.stderr.strip()}")


def ensure_impacket_scripts_dir():
    impacket_dir = os.path.join(TOOLS_DIR, "impacket")
    if os.path.isdir(impacket_dir):
        print(f"[*] 已存在本地 impacket 脚本目录: {impacket_dir}")
        return

    print(f"[*] 拉取 impacket 脚本目录到 {impacket_dir}")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", IMPACKET_REPO, impacket_dir],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        print("[+] impacket 脚本目录准备完成")
    else:
        print(f"[!] impacket 脚本目录拉取失败: {result.stderr.strip()}")


def ensure_dnstool_script():
    dnstool_path = os.path.join(TOOLS_DIR, "dnstool.py")
    if os.path.exists(dnstool_path):
        print(f"[*] 已存在 dnstool.py: {dnstool_path}")
        return

    print(f"[*] 下载 dnstool.py 到 {dnstool_path}")
    try:
        req = urllib.request.Request(DNSTOOL_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=60) as response, open(dnstool_path, "wb") as out_file:
            shutil.copyfileobj(response, out_file)
        mode = os.stat(dnstool_path).st_mode
        os.chmod(dnstool_path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        print("[+] dnstool.py 下载完成")
    except Exception as exc:
        print(f"[!] dnstool.py 下载失败: {exc}")


def print_path_hint():
    print("\n[*] 建议将 tools 目录加入 PATH")
    print(f'    echo \'export PATH="{TOOLS_DIR}:$PATH"\' >> ~/.bashrc')
    print("    source ~/.bashrc")


def main():
    print("=" * 50)
    print("RedTeam-Agent Linux 工具安装脚本")
    print(f"平台: {platform.system()} {platform.machine()}")
    print("=" * 50)

    if platform.system() != "Linux":
        print("[!] 当前不是 Linux 平台，请改用 scripts/install_tools.py")
        sys.exit(1)

    os.makedirs(TOOLS_DIR, exist_ok=True)

    for tool_name, repo in TOOLS_LIST.items():
        download_tool(tool_name, repo)

    install_python_packages()
    ensure_impacket_scripts_dir()
    ensure_dnstool_script()

    print("\n" + "=" * 50)
    print("[+] 安装流程完成")
    print(f"    二进制目录: {TOOLS_DIR}")
    print("    Python 工具: impacket-* / nxc / bloodhound-python / pywerview / ldapdomaindump / bloodyAD")
    print("    额外脚本: ./tools/impacket/* 与 ./tools/dnstool.py")
    print("=" * 50)
    print_path_hint()


if __name__ == "__main__":
    main()

