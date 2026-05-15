#!/bin/bash
# 06_kali_tools.sh — Install all tools needed for the ad-lab attack chain
# Run on Kali attacker VM

set -e

echo "[*] Updating system..."
apt-get update -qq

echo "[*] Installing apt packages..."
apt-get install -y \
    python3-pip python3-venv \
    bloodhound neo4j \
    evil-winrm \
    crackmapexec netexec \
    impacket-scripts \
    certipy-ad \
    hashcat \
    libfaketime \
    golang-go \
    git curl wget

echo "[*] Installing Python tools..."
pip3 install --break-system-packages \
    bloodyAD \
    pywhisker \
    ldap3 \
    impacket \
    bloodhound \
    certipy-ad \
    pyyaml \
    rich

echo "[*] Installing PKINITtools..."
git clone https://github.com/dirkjanm/PKINITtools /opt/PKINITtools
pip3 install --break-system-packages -r /opt/PKINITtools/requirements.txt

echo "[*] Installing PetitPotam..."
git clone https://github.com/topotam/PetitPotam /opt/PetitPotam

echo "[*] Installing Coercer..."
pip3 install --break-system-packages coercer

echo "[*] Installing nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
ln -sf ~/go/bin/nuclei /usr/local/bin/nuclei

echo "[*] Installing subfinder + httpx..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
ln -sf ~/go/bin/subfinder /usr/local/bin/subfinder
ln -sf ~/go/bin/httpx /usr/local/bin/httpx

echo "[*] Configuring /etc/hosts for lab..."
echo "192.168.56.10  DC01.lab.local  DC01  lab.local" >> /etc/hosts
echo "192.168.56.11  WS01.lab.local  WS01" >> /etc/hosts

echo "[*] Configuring krb5.conf for lab.local..."
cat > /etc/krb5.conf << 'KRB5'
[libdefaults]
    default_realm = LAB.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = false
    forwardable = true
    rdns = false

[realms]
    LAB.LOCAL = {
        kdc = 192.168.56.10
        admin_server = 192.168.56.10
        default_domain = lab.local
    }

[domain_realm]
    .lab.local = LAB.LOCAL
    lab.local = LAB.LOCAL
KRB5

echo ""
echo "=== Tool installation complete ==="
echo "  impacket     : GetUserSPNs.py, GetNPUsers.py, secretsdump.py, getST.py"
echo "  certipy      : certipy find / req / auth"
echo "  bloodyAD     : ACL enumeration, dMSA creation, RBCD"
echo "  pywhisker    : Shadow Credentials"
echo "  PKINITtools  : /opt/PKINITtools/"
echo "  PetitPotam   : /opt/PetitPotam/"
echo "  BloodHound   : bloodhound (start neo4j first)"
echo "  nuclei       : nuclei"
echo ""
echo "Start BloodHound:"
echo "  sudo neo4j start"
echo "  bloodhound &"
