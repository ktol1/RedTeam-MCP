# RedTeam MCP Server 

这是一个专为 AI / LLM（大语言模型）设计的红队与内网渗透自动编排 MCP (Model Context Protocol) 插件。
它让 AI 拥有如黑客般真实的扫描、横向移动、活动目录提权能力。本项目致力于**配置极致简单**，所有组件在 Windows 环境下皆可两步初始化完成。

## 🚀 极速部署指南 (Windows)

为了提供“开箱即用”的最佳体验，我们移除了那些需要复杂底层库或手动装驱动的庞大软件，全部采用轻量级的原生代码或 Go 语言独立编译工具。

### 第一步：创建虚拟环境并安装 Python 依赖库
为了避免和系统的 Python 环境冲突，请在当前项目文件夹下打开终端，并运行以下命令创建一个虚拟环境（如果报错无法运行脚本，请用 CMD 而非 PowerShell）：

```bash
# 1. 创建虚拟环境
python -m venv venv

# 2. 激活虚拟环境 (Windows CMD)
venv\Scripts\activate.bat
# 或者 (Windows PowerShell)
# .\venv\Scripts\Activate.ps1

# 3. 安装所需依赖库
pip install -r requirements.txt
```
*(这将为你自动安装：`mcp` 和 `impacket`。等工具)*

### 第二步：一键下载红队二进制引擎
本包包含大量用 Go 编写的高性能极速扫描核心工具（如 `fscan`, `httpx`, `nuclei`）。为了免去你到处找资源的痛苦，我们编写了一个自动化小脚本。
**请在虚拟环境激活的状态下，直接运行：**
```bash
python install_tools.py
```
这会在自动在你的 `d:\mcp\redteam-tools` 下抓取全部最新版二进制工具并解压排期！

### 第三步：配置环境变量
以上安装的 exe 存放于 `D:\mcp\redteam-tools`。
请按 `Win + S` 搜索“环境变量”，将其加入系统的 `PATH` 路径中。重启终端或电脑。

### 第四步：测试 MCP Server 是否可用

> ⚠️ **重要：以下命令必须在 Python 虚拟环境中运行！**  
> 如果你看到 `ModuleNotFoundError: No module named 'mcp'` 类似报错，请确认已激活虚拟环境（终端提示符前出现 `(venv)` 字样）。

```bash
# ① 先确保已激活虚拟环境
# Windows CMD:
venv\Scripts\activate.bat
# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Linux/macOS:
source venv/bin/activate

# ② 启动 MCP Inspector 调试模式
mcp dev server.py
```

如果在终端输出以下内容，说明启动成功：

```
Starting MCP inspector...
⚙️ Proxy server listening on localhost:6277
🔑 Session token: xxxxxxxx...
🚀 MCP Inspector is up and running at:
   http://localhost:6274/?MCP_PROXY_AUTH_TOKEN=xxxxxxxx...
🌐 Opening browser...
```

浏览器会自动打开 MCP Inspector 网页。在左侧填入 Command（虚拟环境的 python.exe 路径）和 Arguments（server.py 路径）后点击 **Connect**，即可看到所有工具已成功加载：

<div align="center">
<img src="../assets/mcp_inspector_tools.png" alt="MCP Inspector 运行成功截图" width="700"/>

*↑ MCP Inspector 连接成功，显示全部 14 个工具已加载（包含 Playwright 浏览器工具）*
</div>

然后对 AI 说：*"扫描 192.168.1.0/24 网段，发现所有 Windows 主机并识别开放服务。"*

---

---

## 🤖 接入 AI Agent 客户端使用指南

所有的红队工具都已经通过 `server.py` 包装成了标准的 MCP 协议节点，下一步就是让你的 AI 客户端（如 Cline、Claude Desktop 或 Cursor）连上它！

*注意：下方配置中的 `command` 部分必须是你刚刚创建的那个虚拟环境内的 Python 完整路径（而不是系统全局 Python）。这里的演示路径假定项目在 `D:/mcp/redteam-server`，请根据你的实际磁盘存放路径进行调整。*

### 1. 在 VS Code (通过 Cline 或 Roo Code 插件) 中使用
如果你在 VS Code 中使用强大的 AI 编码与安全助手插件（如 Cline），将下方配置加入到插件的 MCP 设置文件中。
1. 点击 VS Code 侧边栏的 Cline (或 Roo) 插件图标。
2. 找到配置或设置 (⚙️) 页面中的 "MCP Servers"。
3. 将以下 JSON 代码复制进去并保存：

```json
{
  "mcpServers": {
    "RedTeamAgent": {
      "command": "D:\\mcp\\redteam-server\\venv\\Scripts\\python.exe",
      "args": [
        "D:\\mcp\\redteam-server\\server.py"
      ]
    }
  }
}
```
*此时在此聊天窗口对 AI 说：“帮我使用内网资产扫描工具扫一下 192.168.1.1”，它便会立刻接管你系统里的 fscan！*

### 2. 在 Claude Desktop（桌面版客户端）中使用
Claude 官方桌面版原生支持所有的本地系统破坏性/探测性工具调用。
1. 在电脑任意文件夹的地址栏输入 `%APPDATA%\Claude` 回车进入该配置目录。
2. 找到（或新建）并编辑 `claude_desktop_config.json` 文件：

```json
{
  "mcpServers": {
    "RedTeamServer": {
      "command": "D:\\mcp\\redteam-server\\venv\\Scripts\\python.exe",
      "args": [
        "D:\\mcp\\redteam-server\\server.py"
      ]
    }
  }
}
```
3.  **完全退出并重启** Claude Desktop。重启后在聊天界面的输入框附件，你应该能看到代表 "Tools (+12)" 的锤子小图标，这就说明装备已挂载！

### 3. 在 Cursor IDE 中使用
Cursor 作为目前最顶级的 AI 编译器之一，也在底部特性中整合了 MCP。
1. 打开 Cursor。
2. 点击右上角或设置中的 "Cursor Settings" -> "Features" -> 找到 "MCP Servers"。
3. 点击 "Add New MCP Server"（添加新服务器）：
   *   **Type（类型）**: 选择 `command`。
   *   **Name（名称）**: 填 `RedTeamServer`。
   *   **Command（命令）**: 填入能够完整拉起虚拟环境执行脚本的绝对命令：
       `D:/mcp/redteam-server/venv/Scripts/python.exe D:/mcp/redteam-server/server.py`
4. 保存后，在对话框 (Ctrl+L/Cmd+L) 里请求它帮你进行漏洞探查即可。

## 🛠️ 被替代的复杂工具清单 (为什么它这么容易安装？)

*   ❌ **WhatWeb** (Windows 不自带环境，运行需要配置复杂的 Ruby 语言)。
    ✅ **被替换为**： 直接指示 AI 在信息收集时转为调用我们更现代的 `httpx` 工具配合其自带的 `-tech-detect`（Web 指纹分析技术）。

## 💡 核心设计：极致的 Token 成本优化
对于 AI Agent 编排渗透测试来说，工具返回的结果往往伴随着大量的“杂音”（几百行的跑马灯或进度条，终端 ANSI 颜色代码，不重要的错误回显等）。大模型一旦吃下这些：
1. **费用极速飙升**：按 Token 计费立刻爆炸。
2. **上下文遗忘**：超长内容会直接把模型初期的行动目标冲刷掉。

因此，本项目在底层通过 `server.py` 内设了精巧的**信息降噪和自动截断**机制：
*   **消灭 ANSI 颜色与特殊符号**：底层的 `optimize_output` 会利用正则一键抹除所有终端界面元素相关的不可见或杂色代码。
*   **压缩空行与排版**：对原工具生成的长间隔进行了瘦身优化。
*   **防爆窗截断**：所有命令默认最大截取前 **8,000 字符**（约合不到两千 Token）。多余部分舍弃并在底部附带 `[警告：输出过长已被截断，请要求AI缩小范围]`。强制引导 AI 改变大广角探测的坏习惯，像真正的黑客一样定向查询细节。

## 🌐 扩展高级能力：赋予 AI 操作真实浏览器的能力
如果你的红队 AI 在渗透时遇到了复杂的带防机器人的登录后台界面或被 JS 混淆加密的前端（此时依靠 `httpx` 已失效），你需要给 AI 添加**第二个并列的 MCP 服务器**，赋予它打开无头浏览器甚至截取浏览器画面的能力。

### 安装 Playwright MCP 桥接库 (依靠 Node.js 包管理器)
```bash
npm install -g @playwright/mcp
```
*(如果没有安装 Node.js 请先下载配置 Node.js 环境)*

在刚才介绍的任何一个 AI 客户端（如 Cline 或 Claude 的 JSON 配置文件中）与我们编写好的 Python 节点 **放在一起（组建多武器库）**：

```json
{
  "mcpServers": {
    "RedTeamServer": {
      "command": "D:\\mcp\\redteam-server\\venv\\Scripts\\python.exe",
      "args": [
        "D:\\mcp\\redteam-server\\server.py"
      ]
    },
    "PlaywrightBrowser": {
      "command": "npx",
      "args": [
        "-y",
        "@playwright/mcp@latest"
      ]
    }
  }
}
```
**火力全开：** 如此配置后，你的 AI 不仅能利用底层协议和 Go 极速跑数据包进行渗透，遇到有验证码的网页还会*自动召唤 Chrome 内核截图发给你看*进行高级互动！