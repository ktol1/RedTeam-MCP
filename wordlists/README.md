# Wordlists Overview

This folder contains two groups of lists:

## 1) Existing project custom lists (small, scenario-specific)

- `iis_wordlist.txt` - custom IIS path hints
- `passwords.txt` - very small custom password set
- `more_users.txt` - small user candidate list
- `one_user.txt` - single-user test
- `pirate_custom.txt` - themed custom passwords
- `pirate_users.txt` - themed custom usernames
- `subdomains.txt` - small custom subdomain list
- `users_clean.txt` - cleaned tiny username list

These are useful for fast first-pass checks but not enough for broad brute-force/fuzzing coverage.

## 2) Downloaded module-oriented lists

### usernames/
- `top-usernames-shortlist.txt`
- `names.txt`

Source: SecLists Usernames

### passwords/
- `10k-most-common.txt`
- `500-worst-passwords.txt`
- `top-20-common-SSH-passwords.txt`

Source: SecLists Passwords/Common-Credentials

### web-content/
- `common.txt`
- `raft-small-words.txt`

Source: SecLists Discovery/Web-Content

### dns/
- `subdomains-top1million-5000.txt`
- `namelist.txt`

Source: SecLists Discovery/DNS

### smb/
- `common-snmp-community-strings.txt`

Source: SecLists Discovery/SNMP

## Suggested usage mapping

- Username spraying / enumeration: `usernames/*`
- Password spraying / weak credential checks: `passwords/*`
- Web dir/file fuzzing: `web-content/*`
- Subdomain and DNS brute force: `dns/*`
- Community string checks: `smb/*`

