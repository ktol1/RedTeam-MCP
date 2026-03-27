#!/usr/bin/env python3
"""Check delegation settings via LDAP"""
from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
import sys

conn = ldap.LDAPConnection('ldap://10.129.8.87', 'dc=pirate,dc=htb', '10.129.8.87')
conn.login('pentest', 'p3nt3st2025!&', 'pirate.htb', '', '')

searchFilter = '(|(samAccountName=gMSA_ADFS_prod$)(samAccountName=gMSA_ADCS_prod$)(samAccountName=a.white_adm))'
attrs = ['samAccountName','msDS-AllowedToDelegateTo','userAccountControl','servicePrincipalName']

result = conn.search(
    searchBase='DC=pirate,DC=htb',
    searchFilter=searchFilter,
    attributes=attrs
)

for entry in result:
    if not hasattr(entry, 'getComponentByName'):
        continue
    name = None
    for attr in entry['attributes']:
        attrType = str(attr['type'])
        vals = [str(v) for v in attr['vals']]
        if attrType == 'sAMAccountName':
            name = vals[0]
            break
    
    print(f"\n=== {name} ===")
    for attr in entry['attributes']:
        attrType = str(attr['type'])
        vals = [str(v) for v in attr['vals']]
        print(f"  {attrType}: {vals}")
