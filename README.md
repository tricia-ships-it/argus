# Argus

**Argus** is a self-contained, **offline security posture & assurance platform**
for internal and data-centre environments. It runs entirely on your own
network, no internet required, no telemetry, nothing leaves the machine.

> *Formerly "VAPT Tracker." Argus, the hundred-eyed guardian, reflects what the
> tool now does: give you eyes across your whole estate.*

It brings a security programme's day-to-day work into one place:

- **Assess**, a built-in, assessment-only scanner probes targets locally: host
  discovery, open ports, service/version fingerprinting, TLS/cipher/certificate
  analysis, SSH/SMB/RDP posture, HTTP hardening, exposed-service detection and
  known-CVE matching. It also imports Nessus, OpenVAS/Greenbone and Nmap results.
  It **identifies and reports**, it does not exploit, brute-force or alter
  targets. Penetration testing is done manually, by design.
- **Govern scanning**, an **asset register** (import your Excel/CSV inventory)
  auto-classifies assets by type and criticality. **Operational-technology (OT)
  assets are protected from active scanning** automatically; personal/BYOD assets
  require a recorded authoriser. "Never-assessed" assets are surfaced so nothing
  hides.
- **Track & report**, every finding is classified and tracked through
  remediation with automated Actual Risk, Target Fix Date, Time to Fix and Risk
  Tolerance Objective. Attach evidence, discuss, and follow a full history
  timeline. Exports to Excel (live formulas) and PDF.
- **Compare**, quarter-over-quarter scan diff: new, resolved and recurring
  findings, matched on host + CVE.
- **Map to compliance**, relate findings to the control frameworks you enable:
  ISO/IEC 27001:2022 (ISMS), PCI DSS v4.0, NIST CSF 2.0, CIS Controls v8, SOC 2,
  NIST SP 800-53, GDPR (Art. 32) and HIPAA.
- **Threat intelligence**, match public vulnerability feeds (CISA KEV, NVD)
  against your findings and inventory to surface what's **actively exploited** in
  your estate. Matching runs **locally** (see the security model below).
- **Collaborate**, individual accounts with roles (Admin / Editor / Viewer),
  comments, and an activity feed. Hosted on the intranet, reachable by IP.

A visual **Dashboard** summarises risk posture and remediation progress, a
**command palette** (⌘K) and keyboard shortcuts speed navigation, and the whole
interface has a crafted **light / dark** theme. Charts are drawn in plain SVG with
no third-party library, so everything still runs fully offline.

## Security model, the two things that never happen

1. **Your inventory never leaves the machine.** The only network activity Argus
   can perform is *downloading public vulnerability feeds*. The feed fetcher is
   **fetch-only**: it can issue an HTTP **GET** to a URL on a hardcoded,
   user-visible allow-list and nothing else, there is no code path that sends a
   request body, and no parameter through which asset data could be transmitted.
   The allow-list is shown with checkboxes in **Settings**, and online updates are
   **off by default**. Matching runs entirely locally, keyed on product and CVE,
   never on IP.
2. **OT is never actively scanned.** Assets classified (or tagged) as OT are
   marked *do-not-actively-scan*; the scanner inventories them passively and skips
   active probing, logging the omission for audit.

For truly air-gapped sites, `app/feedsync.py` runs on a connected machine, pulls
the same public feeds, and produces a file you import, same fetch-only guarantee,
no connection from the secure box.

## Repository layout

| Path | What it is |
|---|---|
| `app/` | The Flask application (the whole platform). See `app/README.md` for setup, roles and deployment. |
| `app/feedsync.py` | Standalone, fetch-only threat-feed downloader for air-gapped import. |
| `windows/` | Windows launcher and the one-click helper that adds an Argus icon to your Desktop, Start menu and taskbar. |
| `template/` | `build_template.py` generates the standalone Excel report template (same columns and automation as the app). |
| `preview/` | `argus_preview.html`, a single-file interactive preview of the UI for walkthroughs and demos (no backend; data resets on refresh). |

## Get Argus running on your computer

You do not need to be a developer to run Argus. It runs on your own machine,
in your own browser, and nothing leaves your computer. The steps below take
about five minutes the first time.

### What you need first

1. **Python 3.10 or newer.** Get it from [python.org/downloads](https://www.python.org/downloads/).
   On the first screen of the installer, tick **"Add Python to PATH"**, then
   finish the install.
2. **Git** (used to download Argus). Get it from
   [git-scm.com/downloads](https://git-scm.com/downloads). The default options
   are fine.

### Windows, the easy way

1. Pick a folder where you want to keep Argus, for example your Documents
   folder. Open that folder, click in the address bar, type `cmd`, and press
   Enter. A black command window opens in that folder.
2. Download Argus by pasting this line and pressing Enter:

   ```
   git clone https://github.com/tricia-ships-it/vapt-tracker.git
   ```
3. Open the new `vapt-tracker` folder, then open the `windows` folder inside it.
4. Double-click **`Add Argus icon.cmd`**. This puts an **Argus** icon on your
   Desktop and in your Start menu. It also tells you how to pin Argus to your
   taskbar if you want it there.
5. Double-click the **Argus** icon on your Desktop. The first time, it sets
   itself up, which takes a minute or two, then your browser opens at
   **http://127.0.0.1:8080**. Every time after that it starts in a few seconds.

A small black window stays open while Argus is running. That window is Argus.
Keep it open while you work, and close it when you are done to stop Argus.

### Mac or Linux

Open a terminal and run these lines one at a time:

```bash
git clone https://github.com/tricia-ships-it/vapt-tracker.git
cd vapt-tracker/app
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py --host 127.0.0.1 --port 8080
```

Then open **http://127.0.0.1:8080** in your browser. To start it again later,
run the last three lines again from the `app` folder (the `source...` line and
the `python app.py...` line).

### Setting up your account

The first time you open Argus it walks you through creating your own admin
account. After that you sign in, create accounts for your teammates under
**Users** (they are asked to set their own password the first time they log
in), and import your asset list under **Asset register**. More detail on roles,
running it for a team, and putting it behind HTTPS is in
[`app/README.md`](app/README.md).

### Just the Excel template

If all you want is the standalone Excel report template:

```bash
cd template
pip install openpyxl
python build_template.py
```

## For developers

If you want to work on Argus itself:

```bash
# Download and enter the repo
git clone https://github.com/tricia-ships-it/vapt-tracker.git
cd vapt-tracker/app

# Install dependencies and run the dev server
pip install -r requirements.txt
python app.py --host 127.0.0.1 --port 8080

# Run the module self-tests
for m in phishing delivery sending scanner_checks asset_classify compliance; do
  echo "== $m =="; python3 $m.py; done
```

The project map, coding conventions and the **security invariants** that must
not regress are in [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md). The phishing and
delivery architecture and roadmap are in
[`docs/phishing-delivery.md`](docs/phishing-delivery.md).

## Security & data

- `app/vapt.db` (findings, users, comments, activity, assets, feed) and
  `app/.secret_key` (session signing) are created at runtime and are
  **git-ignored**, they never leave the host.
- Passwords are hashed with PBKDF2 (via Werkzeug). CSRF protection, strict
  security headers, login throttling and bounded file uploads are built in. Serve
  behind HTTPS on anything wider than a trusted internal segment.

See [`SECURITY.md`](SECURITY.md) for the full control list and operational
hardening.

## Responsible use

This is an **assessment** tool. **Only scan systems you own or are explicitly
authorised to assess.** Scanning networks, or personal/BYOD devices, without
authorisation may be illegal in your jurisdiction; Argus records an authoriser per
asset to help you keep that straight. The software is provided as-is, with no
warranty (see `LICENSE`).

## Licence

Released under the [MIT License](LICENSE), free to use, modify and deploy in your
own network. Attribution is welcome. If it's useful to you, a star or a note back
is appreciated.
