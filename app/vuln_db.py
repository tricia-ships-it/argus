"""
vuln_db.py, a LOCAL, offline vulnerability dataset for version->CVE matching.

Why local: the whole tool runs air-gapped, so it cannot query the NVD or any
online feed at scan time. This module ships a curated starter set of well-known,
high-signal infrastructure vulnerabilities plus EOL/version rules, and exposes
a simple matcher. It is deliberately conservative: it only flags things it can
state confidently from a version string, so the register isn't polluted with
guesses.

HOW TO KEEP IT CURRENT (important, and documented in the README):
  This is NOT a substitute for a maintained feed. For authoritative, always-
  current coverage, run Nessus/OpenVAS and import their results, those carry
  tens of thousands of maintained checks. This dataset covers the common,
  high-impact cases so the built-in scanner is useful on its own and offline.
  Extend it by adding entries to VERSION_RULES / EOL_RULES below, or load an
  updated JSON (see load_external()).

Matching model:
  - EOL_RULES: product reached end-of-life at/under a version -> Critical EOL finding
  - VERSION_RULES: product within an affected version range -> specific CVE finding
Version comparison uses a tolerant tuple parse (1.2.3p4 -> (1,2,3,4)).
"""
import json
import os
import re

# ---------------------------------------------------------------------------
# Version parsing / comparison
# ---------------------------------------------------------------------------
def parse_version(v):
    if not v:
        return ()
    nums = re.findall(r"\d+", str(v))
    return tuple(int(n) for n in nums[:4])


def vle(a, b):  # a <= b
    return parse_version(a) <= parse_version(b)


def vlt(a, b):  # a < b
    return parse_version(a) < parse_version(b)


def vge(a, b):
    return parse_version(a) >= parse_version(b)


def in_range(v, lo=None, hi_exclusive=None, hi_inclusive=None):
    pv = parse_version(v)
    if not pv:
        return False
    if lo is not None and pv < parse_version(lo):
        return False
    if hi_exclusive is not None and not (pv < parse_version(hi_exclusive)):
        return False
    if hi_inclusive is not None and not (pv <= parse_version(hi_inclusive)):
        return False
    return True


def _norm(name):
    return (name or "").strip().lower()


# ---------------------------------------------------------------------------
# EOL rules: product at/below version is end-of-life (no more security patches).
# Mirrors the client's own example (Debian 11 EOL = Critical).
# ---------------------------------------------------------------------------
EOL_RULES = [
    # product_match (substring, lowercase), version_at_or_below, note
    {"product": "openssh", "below": "7.4", "label": "OpenSSH (very old, pre-7.4)",
     "note": "OpenSSH versions before 7.4 are long unsupported and carry multiple fixed CVEs."},
    {"product": "apache", "below": "2.4.0", "label": "Apache httpd 2.2.x / EOL",
     "note": "Apache httpd 2.2 reached end of life in 2017 and receives no security updates."},
    {"product": "nginx", "below": "1.14.0", "label": "nginx (EOL branch)",
     "note": "This nginx branch is end-of-life and no longer receives security fixes."},
    {"product": "mysql", "below": "5.7.0", "label": "MySQL 5.5/5.6 (EOL)",
     "note": "MySQL 5.5 and 5.6 are end of life; upgrade to a supported release."},
    {"product": "php", "below": "7.4.0", "label": "PHP < 7.4 (EOL)",
     "note": "PHP versions before 7.4 are end of life and unsupported."},
    {"product": "microsoft-iis", "below": "7.5", "label": "Legacy IIS",
     "note": "This IIS version is on an unsupported Windows Server release."},
]

# ---------------------------------------------------------------------------
# Specific CVE rules keyed by product + affected version range.
# Kept to famous, high-confidence, infrastructure-relevant issues.
# ---------------------------------------------------------------------------
VERSION_RULES = [
    {
        "product": "openssh",
        "lo": "0", "hi_inclusive": "9.7",
        "lo_floor": "8.5", # introduced in 8.5p1
        "cve": "CVE-2024-6387",
        "title": "regreSSHion, unauthenticated RCE (CVE-2024-6387)",
        "synopsis": "This OpenSSH version may be affected by the regreSSHion signal-handler race (CVE-2024-6387).",
        "definition": "A race condition in OpenSSH's signal handling (sshd) on glibc-based Linux can allow "
                      "unauthenticated remote code execution. Affects sshd from 8.5p1 up to before 9.8p1.",
        "severity": "Critical",
        "cvss": 8.1, "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "exploit": "Yes",
        "reference": "https://www.openssh.com/releasenotes.html",
        "solution": "Upgrade OpenSSH to 9.8p1 or later, or apply your distribution's backported fix.",
    },
    {
        "product": "openssh",
        "lo": "0", "hi_exclusive": "7.7",
        "cve": "CVE-2018-15473",
        "title": "OpenSSH username enumeration (CVE-2018-15473)",
        "synopsis": "OpenSSH before 7.7 allows remote attackers to test whether a username exists.",
        "definition": "A difference in how sshd before 7.7 handles authentication requests for valid and "
                      "invalid users lets an unauthenticated attacker enumerate valid usernames, aiding "
                      "targeted password attacks.",
        "severity": "Medium",
        "cvss": 5.3, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "exploit": "Yes",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2018-15473",
        "solution": "Upgrade OpenSSH to 7.7 or later.",
    },
    {
        "product": "openssh",
        "lo": "5.5", "hi_exclusive": "9.3.2",
        "cve": "CVE-2023-38408",
        "title": "OpenSSH ssh-agent PKCS#11 RCE (CVE-2023-38408)",
        "synopsis": "OpenSSH before 9.3p2 can allow remote code execution via a forwarded ssh-agent.",
        "definition": "An incomplete constraint on PKCS#11 providers in ssh-agent before 9.3p2 can allow remote "
                      "code execution when an agent is forwarded to an attacker-controlled host.",
        "severity": "Critical",
        "cvss": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "exploit": "Yes",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2023-38408",
        "solution": "Upgrade OpenSSH to 9.3p2 or later and avoid forwarding agents to untrusted hosts.",
    },
    {
        "product": "openssl",
        "lo": "3.0.0", "hi_exclusive": "3.0.7",
        "cve": "CVE-2022-3602, CVE-2022-3786",
        "title": "OpenSSL X.509 punycode buffer overflow",
        "synopsis": "OpenSSL 3.0.x before 3.0.7 is affected by X.509 email name buffer overflows.",
        "definition": "Two buffer overflows in OpenSSL 3.0.x punycode decoding (CVE-2022-3602 / -3786) can "
                      "cause crashes and, in some conditions, code execution.",
        "severity": "High",
        "cvss": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "exploit": "No",
        "reference": "https://www.openssl.org/news/secadv/20221101.txt",
        "solution": "Upgrade OpenSSL to 3.0.7 or later.",
    },
    {
        "product": "apache",
        "lo": "2.4.49", "hi_inclusive": "2.4.49",
        "cve": "CVE-2021-41773",
        "title": "Apache path traversal / RCE (CVE-2021-41773)",
        "synopsis": "Apache httpd 2.4.49 is affected by a path traversal that can lead to RCE.",
        "definition": "A path normalisation flaw in Apache httpd 2.4.49 allows path traversal and, with "
                      "mod_cgi enabled, remote code execution.",
        "severity": "Critical",
        "cvss": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "exploit": "Yes",
        "reference": "https://httpd.apache.org/security/vulnerabilities_24.html",
        "solution": "Upgrade Apache httpd to 2.4.51 or later.",
    },
    {
        "product": "apache",
        "lo": "2.4.50", "hi_inclusive": "2.4.50",
        "cve": "CVE-2021-42013",
        "title": "Apache path traversal / RCE (CVE-2021-42013)",
        "synopsis": "Apache httpd 2.4.50 incompletely fixed CVE-2021-41773 and remains exploitable.",
        "definition": "The 2.4.50 fix for CVE-2021-41773 was incomplete; 2.4.50 is still vulnerable to path "
                      "traversal and potential RCE.",
        "severity": "Critical",
        "cvss": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "exploit": "Yes",
        "reference": "https://httpd.apache.org/security/vulnerabilities_24.html",
        "solution": "Upgrade Apache httpd to 2.4.51 or later.",
    },
    {
        "product": "tomcat",
        "lo": "0", "hi_exclusive": "9.0.31",
        "cve": "CVE-2020-1938",
        "title": "Ghostcat, Tomcat AJP file read / RCE (CVE-2020-1938)",
        "synopsis": "Apache Tomcat with an exposed AJP connector may disclose files or allow code execution.",
        "definition": "When the AJP connector (default port 8009) is reachable, a flaw in Tomcat before 9.0.31 "
                      "(and older 7.x/8.x) allows reading files inside the web root and, where uploads are "
                      "possible, remote code execution.",
        "severity": "Critical",
        "cvss": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "exploit": "Yes",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2020-1938",
        "solution": "Upgrade Tomcat and ensure the AJP connector is disabled or firewalled if unused.",
    },
    {
        "product": "nginx",
        "lo": "0", "hi_exclusive": "1.17.7",
        "cve": "CVE-2019-20372",
        "title": "nginx error_page request smuggling (CVE-2019-20372)",
        "synopsis": "nginx before 1.17.7 with certain error_page configs allows HTTP request smuggling.",
        "definition": "nginx before 1.17.7, in configurations using error_page to redirect, can be abused for "
                      "HTTP request smuggling, potentially bypassing access controls.",
        "severity": "Medium",
        "cvss": 5.3, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "exploit": "No",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-20372",
        "solution": "Upgrade nginx to 1.17.7 or later.",
    },
    {
        "product": "proftpd",
        "lo": "1.3.5", "hi_inclusive": "1.3.5",
        "cve": "CVE-2015-3306",
        "title": "ProFTPD mod_copy arbitrary file read/write (CVE-2015-3306)",
        "synopsis": "ProFTPD 1.3.5 with mod_copy allows unauthenticated file copy, leading to RCE.",
        "definition": "The mod_copy module in ProFTPD 1.3.5 lets unauthenticated clients use SITE CPFR/CPTO to "
                      "copy files, which can be chained to write a web shell and gain remote code execution.",
        "severity": "Critical",
        "cvss": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "exploit": "Yes",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2015-3306",
        "solution": "Upgrade ProFTPD to 1.3.5a or later, or disable mod_copy.",
    },
    {
        "product": "vsftpd",
        "lo": "2.3.4", "hi_inclusive": "2.3.4",
        "cve": "CVE-2011-2523",
        "title": "vsftpd 2.3.4 backdoor",
        "synopsis": "vsftpd 2.3.4 shipped with a known backdoor.",
        "definition": "A compromised vsftpd 2.3.4 tarball contained a backdoor opening a root shell on port 6200.",
        "severity": "Critical",
        "cvss": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "exploit": "Yes",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
        "solution": "Replace with a clean, current vsftpd build immediately.",
    },
    {
        "product": "exim",
        "lo": "4.0", "hi_exclusive": "4.92",
        "cve": "CVE-2019-10149",
        "title": "Exim 'Return of the Wizard' RCE",
        "synopsis": "Exim before 4.92 is affected by a remote command execution flaw.",
        "definition": "Improper validation of recipient addresses in Exim before 4.92 allows remote command "
                      "execution (CVE-2019-10149).",
        "severity": "Critical",
        "cvss": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "exploit": "Yes",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2019-10149",
        "solution": "Upgrade Exim to 4.92 or later.",
    },
]


def match_cves(product, version):
    """Return a list of finding fragments for a product+version."""
    p = _norm(product)
    out = []
    # EOL rules
    for rule in EOL_RULES:
        if rule["product"] in p and version and vlt(version, rule["below"]):
            out.append({
                "cve": "N/A, EOL/lifecycle",
                "title": f"End-of-Life: {rule['label']}",
                "synopsis": f"{product} {version} appears to be on an end-of-life branch.",
                "definition": rule["note"],
                "severity": "Critical",
                "cvss": None, "cvss_vector": "",
                "exploit": "No",
                "reference": "",
                "solution": "Upgrade to a vendor-supported release that still receives security updates.",
            })
    # Version CVE rules
    for rule in VERSION_RULES:
        if rule["product"] not in p:
            continue
        lo = rule.get("lo_floor", rule.get("lo"))
        if in_range(version, lo=lo,
                    hi_exclusive=rule.get("hi_exclusive"),
                    hi_inclusive=rule.get("hi_inclusive")):
            frag = {k: rule[k] for k in
                    ("cve", "title", "synopsis", "definition", "severity",
                     "exploit", "reference", "solution")}
            frag["cvss"] = rule.get("cvss")
            frag["cvss_vector"] = rule.get("cvss_vector", "")
            out.append(frag)
    return out


# ---------------------------------------------------------------------------
# Service-level advice for risky exposed services (no version needed)
# ---------------------------------------------------------------------------
_SERVICE_ADVICE = {
    23: "Telnet transmits credentials and data in cleartext and is trivially intercepted. "
        "It should never be exposed; replace with SSH.",
    21: "FTP is typically cleartext and often allows anonymous or weak auth. Prefer SFTP/FTPS "
        "and restrict access.",
    161: "SNMP (especially v1/v2c with 'public'/'private' community strings) leaks system detail and "
         "can allow configuration changes. Use SNMPv3 with authentication, or disable.",
    6379: "Redis is unauthenticated by default and, if reachable, can be abused to read/write data or "
          "achieve code execution. Bind to localhost, require auth, and firewall it.",
    11211: "Memcached exposed to the network can leak data and be abused for DDoS amplification. "
           "Bind to localhost and firewall it.",
    2049: "NFS exports can expose filesystems to the network. Restrict exports and access tightly.",
}


def service_advice(port):
    return _SERVICE_ADVICE.get(port, "This service is commonly high-risk when exposed; restrict and harden it.")


# ---------------------------------------------------------------------------
# Optional: load an extended dataset from JSON (so the client can update offline)
# ---------------------------------------------------------------------------
def load_external(path):
    """Merge additional VERSION_RULES / EOL_RULES from a local JSON file."""
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    EOL_RULES.extend(data.get("eol_rules", []))
    VERSION_RULES.extend(data.get("version_rules", []))


if __name__ == "__main__":
    # sanity checks
    assert any("regreSSHion" in h["title"] for h in match_cves("OpenSSH", "9.6"))
    assert any("punycode" in h["definition"] for h in match_cves("OpenSSL", "3.0.5"))
    assert match_cves("OpenSSL", "3.0.8") == []  # patched
    assert any(h["severity"] == "Critical" for h in match_cves("Apache", "2.4.49"))
    assert any("End-of-Life" in h["title"] for h in match_cves("Apache", "2.2.15"))
    # CVSS is carried through on version rules
    hit = [h for h in match_cves("OpenSSH", "9.6") if "regreSSHion" in h["title"]][0]
    assert hit["cvss"] == 8.1 and hit["cvss_vector"].startswith("CVSS:3.1"), hit
    # new rules match where expected and not outside their range
    assert any("Ghostcat" in h["title"] for h in match_cves("Tomcat", "9.0.30"))
    assert not any("Ghostcat" in h["title"] for h in match_cves("Tomcat", "9.0.40"))
    assert any("username enumeration" in h["title"] for h in match_cves("OpenSSH", "7.6"))
    assert any("mod_copy" in h["title"] for h in match_cves("ProFTPD", "1.3.5"))
    # EOL fragments carry explicit empty CVSS, never a bogus score
    eol = [h for h in match_cves("Apache", "2.2.15") if "End-of-Life" in h["title"]][0]
    assert eol["cvss"] is None and eol["cvss_vector"] == ""
    print("vuln_db self-test passed")
