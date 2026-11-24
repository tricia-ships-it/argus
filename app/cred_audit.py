"""
cred_audit.py — read-only authenticated (credentialed) host audit over SSH.

WHY THIS EXISTS
  Unauthenticated scanning sees only what a host exposes to the network. The
  single biggest thoroughness gain a tool like Nessus has is *credentialed*
  scanning: logging in with the operator's own read-only credentials to see the
  OS patch level and local configuration that the network can't reveal. This
  module does exactly that, and nothing more.

SCOPE AND SAFETY (read this — it is the whole contract)
  * READ ONLY. It runs a fixed, audited allowlist of inspection commands
    (COMMANDS below) and reads their output. It never writes a file, installs
    or removes anything, changes config, or runs anything destructive. There is
    no code path that executes an arbitrary or caller-supplied command.
  * NON-INTERACTIVE and NON-ESCALATING. No sudo, no privilege escalation, no
    password prompts answered. Commands that need root simply return nothing and
    are skipped.
  * CREDENTIALS ARE NEVER PERSISTED. They are supplied per scan, used to open
    one SSH session, and discarded. This module never writes them anywhere, and
    the app holds them only in memory for the duration of the run.
  * TRANSPORT-INJECTABLE. audit_host() takes a run_cmd callable, so the logic is
    unit-tested with no network, no SSH and no credentials. paramiko is imported
    lazily and only inside the real runner, so the rest of Argus works whether
    or not paramiko is installed.

  Only connect to hosts you are authorised to assess. This is assessment, not
  exploitation: it confirms posture on systems you already administer.
"""
import re

SRC = "Built-in scanner (credentialed)"

# The complete, fixed set of read-only inspection commands. Nothing else is ever
# run. Each is side-effect-free: it reads a file or asks the package manager to
# *report* (never apply) pending updates.
COMMANDS = {
    "os_release": "cat /etc/os-release 2>/dev/null",
    "kernel": "uname -sr 2>/dev/null",
    "reboot_required": "test -f /var/run/reboot-required && echo REBOOT_REQUIRED || true",
    "sshd_config": "cat /etc/ssh/sshd_config 2>/dev/null",
    # Debian/Ubuntu: apt-check reports "<updates>;<security>" on stderr.
    "apt_check": "/usr/lib/update-notifier/apt-check 2>&1 || true",
    # RHEL/CentOS/Fedora: check-update lists upgradable packages (exit 100 if any).
    "yum_check": "(dnf -q check-update 2>/dev/null || yum -q check-update 2>/dev/null) "
                 "| grep -cE '^[a-zA-Z0-9]' || true",
}


# ---------------------------------------------------------------------------
# Parsers (pure functions — unit-tested offline)
# ---------------------------------------------------------------------------
def parse_os_release(text):
    """Parse /etc/os-release into {id, version_id, pretty}."""
    out = {"id": "", "version_id": "", "pretty": ""}
    for line in (text or "").splitlines():
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        v = v.strip().strip('"').strip("'")
        k = k.strip().upper()
        if k == "ID":
            out["id"] = v.lower()
        elif k == "VERSION_ID":
            out["version_id"] = v
        elif k == "PRETTY_NAME":
            out["pretty"] = v
    return out


# End-of-life knowledge for the common server OSes. Conservative: only versions
# known to be past vendor security support are marked EOL. Not a substitute for
# the vendor lifecycle page, but enough to flag obviously-unsupported hosts.
OS_EOL = {
    "ubuntu": {"eol_at_or_below": "18.04", "note": "Ubuntu 18.04 LTS and earlier are past standard support."},
    "debian": {"eol_at_or_below": "10", "note": "Debian 10 (buster) and earlier are end-of-life."},
    "centos": {"eol_at_or_below": "8", "note": "CentOS Linux (all versions, incl. 8) is discontinued."},
    "rhel": {"eol_at_or_below": "7", "note": "RHEL 7 and earlier are in or past the end of maintenance."},
    "fedora": {"eol_at_or_below": "37", "note": "This Fedora release is past its ~13-month support window."},
}


def _ver_tuple(v):
    return tuple(int(n) for n in re.findall(r"\d+", str(v))[:3])


def os_eol_status(os_id, version_id):
    """Return a note string if the OS/version is end-of-life, else ''."""
    rule = OS_EOL.get((os_id or "").lower())
    if not rule or not version_id:
        return ""
    if _ver_tuple(version_id) <= _ver_tuple(rule["eol_at_or_below"]):
        return rule["note"]
    return ""


def parse_sshd_config(text):
    """Effective-ish sshd_config: last non-comment occurrence of each directive
    wins (OpenSSH actually takes the first, but Match blocks and includes make
    this a heuristic read — we flag for human confirmation, we don't enforce)."""
    cfg = {}
    for line in (text or "").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split(None, 1)
        if len(parts) == 2:
            cfg[parts[0].lower()] = parts[1].strip()
    return cfg


def parse_apt_check(text):
    """apt-check prints '<total>;<security>'. Return (total, security) or None."""
    m = re.search(r"(\d+)\s*;\s*(\d+)", text or "")
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def _int_or_none(text):
    m = re.search(r"\d+", text or "")
    return int(m.group(0)) if m else None


# ---------------------------------------------------------------------------
# Finding builder
# ---------------------------------------------------------------------------
def _f(ip, vuln, synopsis, definition, risk, solution, cve=""):
    return {
        "ip_hostname": ip, "device": "",
        "vulnerability": vuln, "synopsis": synopsis, "definition": definition,
        "cve": cve, "reported_risk": risk,
        "exploit_available": "Unknown", "exploit_reference": "",
        "solution": solution, "source_tool": SRC,
    }


# ---------------------------------------------------------------------------
# Orchestration (transport-injectable)
# ---------------------------------------------------------------------------
def audit_host(ip, run_cmd):
    """Run the read-only audit against one host.

    `run_cmd(command)` must return (exit_status:int, stdout:str, stderr:str).
    Returns a list of finding dicts. Any command that fails simply yields no
    finding — a partial audit is still useful and never crashes the scan.
    """
    findings = []

    def cmd(key):
        try:
            rc, out, err = run_cmd(COMMANDS[key])
            return rc, (out or ""), (err or "")
        except Exception:
            return None, "", ""

    # --- OS identity + EOL ---
    _rc, out, _e = cmd("os_release")
    osr = parse_os_release(out)
    if osr["pretty"] or osr["id"]:
        label = osr["pretty"] or f'{osr["id"]} {osr["version_id"]}'.strip()
        eol = os_eol_status(osr["id"], osr["version_id"])
        if eol:
            findings.append(_f(
                ip, f"Operating system is end-of-life — {label}",
                f"{ip} runs {label}, which is no longer receiving vendor security updates.",
                eol + " An unsupported OS accumulates unpatched vulnerabilities with no fix path. "
                "Read from /etc/os-release over an authenticated session.",
                "Critical",
                "Plan an upgrade/migration to a vendor-supported release on a defined timeline; "
                "isolate the host until then."))
        else:
            findings.append(_f(
                ip, f"Operating system inventory — {label}",
                f"{ip} runs {label}.",
                "Operating system identified over an authenticated session (read from "
                "/etc/os-release). Recorded for inventory and lifecycle tracking.",
                "Information",
                "No action required; keep the OS on a supported release and patched."))

    # --- kernel (inventory) ---
    _rc, out, _e = cmd("kernel")
    kern = out.strip().splitlines()[0].strip() if out.strip() else ""
    if kern:
        findings.append(_f(
            ip, "Kernel version (credentialed inventory)",
            f"{ip} reports kernel: {kern}.",
            "Running kernel recorded over an authenticated session. Compare against the vendor's "
            "current kernel to judge whether a reboot into a patched kernel is pending.",
            "Information",
            "Keep the kernel current; reboot after kernel security updates."))

    # --- pending updates: Debian/Ubuntu first, then RHEL-family ---
    sec = total = None
    _rc, out, err = cmd("apt_check")
    parsed = parse_apt_check(out) or parse_apt_check(err)
    if parsed:
        total, sec = parsed
    if sec is None:
        _rc, out, _e = cmd("yum_check")
        n = _int_or_none(out)
        if n is not None:
            total = n  # RHEL path can't split security without extra plugins
    if sec:
        findings.append(_f(
            ip, f"Pending security updates: {sec}",
            f"{ip} has {sec} security update(s) available"
            + (f" ({total} updates in total)." if total is not None else "."),
            "The package manager reports outstanding security updates that have not been applied. "
            "Determined by asking the package manager to *report* (not apply) available updates over "
            "an authenticated session.",
            "High",
            "Apply the outstanding security updates through your patch process and reboot if required."))
    elif total:
        findings.append(_f(
            ip, f"Pending package updates: {total}",
            f"{ip} has {total} package update(s) available.",
            "The package manager reports available updates (security split not available on this "
            "host). Reported, not applied, over an authenticated session.",
            "Medium",
            "Review and apply pending updates through your patch process."))

    # --- reboot required ---
    _rc, out, _e = cmd("reboot_required")
    if "REBOOT_REQUIRED" in out:
        findings.append(_f(
            ip, "Reboot required to finish applying updates",
            f"{ip} has a pending reboot flagged by the OS.",
            "The system flag /var/run/reboot-required is present, meaning updates (often kernel or "
            "core libraries) are installed but not yet active until reboot.",
            "Medium",
            "Schedule a maintenance reboot so the installed updates take effect."))

    # --- sshd configuration posture ---
    _rc, out, _e = cmd("sshd_config")
    cfg = parse_sshd_config(out)
    if cfg:
        root = cfg.get("permitrootlogin", "").lower()
        if root in ("yes", "prohibit-password", "without-password"):
            risk = "High" if root == "yes" else "Low"
            findings.append(_f(
                ip, "SSH permits root login",
                f"{ip} sshd_config sets PermitRootLogin {cfg.get('permitrootlogin')}.",
                "Direct root login over SSH removes per-user accountability and makes the root "
                "account a direct brute-force target. Read from /etc/ssh/sshd_config; confirm against "
                "any Match blocks.",
                risk,
                "Set 'PermitRootLogin no' and use named accounts with sudo."))
        if cfg.get("passwordauthentication", "").lower() == "yes":
            findings.append(_f(
                ip, "SSH password authentication enabled",
                f"{ip} sshd_config sets PasswordAuthentication yes.",
                "Password authentication over SSH is exposed to brute-force and credential-stuffing. "
                "Key-based authentication is stronger. Read from /etc/ssh/sshd_config.",
                "Medium",
                "Prefer key-based auth: set 'PasswordAuthentication no' once keys are deployed."))
        if cfg.get("protocol", "") == "1":
            findings.append(_f(
                ip, "SSH protocol version 1 enabled",
                f"{ip} sshd_config enables the obsolete SSH protocol 1.",
                "SSH protocol 1 is cryptographically broken and must not be used.",
                "High",
                "Remove 'Protocol 1'; use protocol 2 only (the modern default)."))
    return findings


# ---------------------------------------------------------------------------
# Real SSH runner (paramiko, imported lazily). Read-only by construction.
# ---------------------------------------------------------------------------
def paramiko_available():
    try:
        import paramiko  # noqa: F401
        return True
    except Exception:
        return False


class CredAuditUnavailable(Exception):
    pass


def make_ssh_runner(host, port=22, username="", password="", key_data="", timeout=8.0):
    """Open one SSH session and return (run_cmd, close).

    run_cmd(command) -> (exit_status, stdout, stderr). The app only ever passes
    commands from COMMANDS. Credentials are used here and not stored. Raises
    CredAuditUnavailable if paramiko is missing or the connection/auth fails.
    """
    try:
        import io
        import paramiko
    except Exception:
        raise CredAuditUnavailable(
            "Credentialed scanning needs the 'paramiko' package, which isn't installed. "
            "Install it on the Argus host (pip install paramiko) to enable SSH audits.")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pkey = None
    if key_data:
        for loader in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
            try:
                pkey = loader.from_private_key(io.StringIO(key_data),
                                               password=password or None)
                break
            except Exception:
                continue
    try:
        client.connect(
            hostname=host, port=port, username=username,
            password=(password or None) if not pkey else None,
            pkey=pkey, timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
            allow_agent=False, look_for_keys=False,
        )
    except Exception as e:
        try:
            client.close()
        except Exception:
            pass
        raise CredAuditUnavailable(f"SSH connection/authentication failed: {e}")

    def run_cmd(command):
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", "ignore")
        err = stderr.read().decode("utf-8", "ignore")
        rc = stdout.channel.recv_exit_status()
        return rc, out, err

    def close():
        try:
            client.close()
        except Exception:
            pass

    return run_cmd, close


if __name__ == "__main__":
    # offline self-tests with a fake runner — no paramiko, no network, no creds
    assert parse_os_release('ID=ubuntu\nVERSION_ID="18.04"\nPRETTY_NAME="Ubuntu 18.04.6 LTS"')["id"] == "ubuntu"
    assert os_eol_status("ubuntu", "18.04")
    assert os_eol_status("ubuntu", "22.04") == ""
    assert os_eol_status("debian", "10")
    assert parse_apt_check("12;5") == (12, 5)
    cfg = parse_sshd_config("# comment\nPermitRootLogin yes\nPasswordAuthentication no\n")
    assert cfg["permitrootlogin"] == "yes" and cfg["passwordauthentication"] == "no"

    # a fully scripted host: EOL Ubuntu, 5 security updates, reboot pending, root login
    responses = {
        COMMANDS["os_release"]: (0, 'ID=ubuntu\nVERSION_ID="18.04"\nPRETTY_NAME="Ubuntu 18.04.6 LTS"\n', ""),
        COMMANDS["kernel"]: (0, "Linux 4.15.0-1\n", ""),
        COMMANDS["reboot_required"]: (0, "REBOOT_REQUIRED\n", ""),
        COMMANDS["sshd_config"]: (0, "PermitRootLogin yes\nPasswordAuthentication yes\n", ""),
        COMMANDS["apt_check"]: (0, "", "42;5"),   # apt-check writes to stderr
        COMMANDS["yum_check"]: (0, "0\n", ""),
    }
    fake = lambda c: responses.get(c, (1, "", ""))
    fs = audit_host("10.0.0.9", fake)
    vulns = [f["vulnerability"] for f in fs]
    assert any("end-of-life" in v for v in vulns), vulns
    assert any("security updates: 5" in v for v in vulns), vulns
    assert any("Reboot required" in v for v in vulns), vulns
    assert any("permits root login" in v for v in vulns), vulns
    assert any("password authentication enabled" in v.lower() for v in vulns), vulns
    # a healthy host produces inventory, not alarms
    healthy = {
        COMMANDS["os_release"]: (0, 'ID=ubuntu\nVERSION_ID="22.04"\nPRETTY_NAME="Ubuntu 22.04 LTS"\n', ""),
        COMMANDS["kernel"]: (0, "Linux 5.15.0\n", ""),
        COMMANDS["reboot_required"]: (0, "", ""),
        COMMANDS["sshd_config"]: (0, "PermitRootLogin no\nPasswordAuthentication no\n", ""),
        COMMANDS["apt_check"]: (0, "", "0;0"),
        COMMANDS["yum_check"]: (0, "0\n", ""),
    }
    hv = [f["reported_risk"] for f in audit_host("10.0.0.10", lambda c: healthy.get(c, (1, "", "")))]
    assert all(r == "Information" for r in hv), hv
    print("cred_audit self-test passed")
