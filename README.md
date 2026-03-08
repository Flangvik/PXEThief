# PXEThief

PXEThief exploits the Operating System Deployment (OSD) functionality in Microsoft Endpoint Configuration Manager (MECM/SCCM) to extract credentials. It targets Network Access Accounts, Task Sequence credentials, and Collection Variables configured for the "All Unknown Computers" collection.

Based on the DEF CON 30 talk [Pulling Passwords out of Configuration Manager](https://forum.defcon.org/node/241925).

## Features

- Full PXE boot exploit chain: DHCP discover, TFTP download, media variable decryption, PFX extraction, policy retrieval, credential extraction
- Cross-platform: works on both Windows and Linux (no `win32crypt` / `pywin32` dependency)
- Built-in Python TFTP client (no external `tftp` binary needed)
- Auto-exploits blank PXE passwords end-to-end in a single run
- Outputs hashcat-compatible hashes for offline password cracking
- Supports AES-128, AES-256, and 3DES media variable encryption
- CMS envelope decryption with PKCS1v15, OAEP-SHA1, and OAEP-SHA256 key transport
- Auto-converts extracted PFX certificates to PEM format for mTLS use
- Detailed error output on every decryption path -- never silently fails

## Setup

### Requirements

- Python >= 3.9
- Npcap (Windows) or libpcap (Linux) for Scapy packet capture

### Install

```bash
# Using uv (recommended)
uv sync

# Using pip
pip install -r requirements.txt
```

On Windows, install [Npcap](https://npcap.com/#download) (or Wireshark, which bundles it).

## Usage

```
python pxethief.py 1                                    Auto-discover PXE server via DHCP and exploit
python pxethief.py 2 <ip>                               Target a specific Distribution Point by IP
python pxethief.py 3 <variables-file> [password]        Decrypt media variables and retrieve secrets
python pxethief.py 4 <variables-file> <policy> [pass]   Decrypt stand-alone media variables and policy
python pxethief.py 5 <variables-file>                   Print hashcat hash for offline cracking
python pxethief.py 6 <guid> <cert-file>                 Retrieve task sequences using DP registry values
python pxethief.py 7 <hex-value>                        Decrypt PXE password from DP registry Reserved1
python pxethief.py 8                                    Write default settings.ini
python pxethief.py 10                                   Print Scapy interface table
```

### Mode 1 -- Full Auto Exploit

The primary attack mode. Sends a DHCP PXE boot request, downloads the encrypted media variables file via TFTP, prints the hashcat hash, and attempts automatic exploitation:

- If the server responds with an encrypted key (blank password), decrypts immediately and dumps all policies
- Otherwise, tries the default MECM blank password (`{BAC6E688-DE21-4ABE-B7FB-C9F54E6DB664}`)
- If neither works, prints the hashcat hash for offline cracking with the [configmgr-cryptderivekey-hashcat-module](https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module)

### Mode 3 -- Decrypt with Known Password

After cracking the hashcat hash, use mode 3 with the recovered password:

```bash
python pxethief.py 3 <variables-file> <cracked-password>
```

Omit the password to use the default MECM blank password.

## Configuration

Run `python pxethief.py 8` to generate a default `settings.ini`:

```ini
[SCAPY SETTINGS]
automatic_interface_selection_mode = 1
manual_interface_selection_by_id =

[HTTP CONNECTION SETTINGS]
use_proxy = 0
use_tls = 0

[GENERAL SETTINGS]
sccm_base_url =
auto_exploit_blank_password = 1
```

| Setting | Description |
|---------|-------------|
| `automatic_interface_selection_mode` | `1` = use default gateway interface, `2` = first non-loopback/non-APIPA interface |
| `manual_interface_selection_by_id` | Force a specific interface by index (get IDs from `pxethief.py 10`) |
| `sccm_base_url` | Override Management Point URL (e.g. `http://mp.configmgr.com`) -- useful when DNS doesn't resolve |
| `auto_exploit_blank_password` | `1` = auto-exploit blank password PXE DPs in mode 1 |

## Related Work

- [Identifying and retrieving credentials from SCCM/MECM Task Sequences](https://www.mwrcybersec.com/research_items/identifying-and-retrieving-credentials-from-sccm-mecm-task-sequences) -- Full writeup of the policy download and decryption flow
- [DEF CON 30 Slides](https://media.defcon.org/DEF%20CON%2030/DEF%20CON%2030%20presentations/Christopher%20Panayi%20-%20Pulling%20Passwords%20out%20of%20Configuration%20Manager%20Practical%20Attacks%20against%20Microsofts%20Endpoint%20Management%20Software.pdf)
- [configmgr-cryptderivekey-hashcat-module](https://github.com/MWR-CyberSec/configmgr-cryptderivekey-hashcat-module) -- Hashcat module for cracking SCCM media variable passwords

## Author Credit

Copyright (C) 2022 Christopher Panayi, MWR CyberSec
