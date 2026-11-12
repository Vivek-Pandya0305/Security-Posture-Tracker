# Posture Tracker 3.0

Assess an authorized network or domain, inventory exposed services, record findings with severity, **confidence** and evidence,
track remediation, verify fixes by retesting, and manage it from the CLI or a local web UI.
Every engagement gets its **own folder** with its own scope, database, raw outputs, logs and reports.

Scanners: **Nmap + NSE**, **Nuclei**, **testssl.sh**, **Nikto**. Storage: SQLite. Reports: HTML, PDF, Markdown, CSV, JSON.
**Use only on assets you own or have written permission to test.** The scope guard enforces this in code.

## Setup (you control the environment)

```bash
unzip posture-tracker-v3.zip
cd posture-tracker
python3 -m venv venv
source venv/bin/activate
pip install -e .                      # installs the `posture` command (PyYAML + Flask)
sudo apt install -y nmap nikto        # scanners (system packages)
```
Optional scanners (skipped with a notice if missing):
```bash
sudo apt install -y nuclei testssl.sh      # if your repo has them; otherwise:
#  nuclei:  release binary from github.com/projectdiscovery/nuclei/releases -> on PATH; then: nuclei -ut
#  testssl: git clone https://github.com/drwetter/testssl.sh ; ln -s "$PWD/testssl.sh/testssl.sh" ~/.local/bin/testssl.sh
nmap --script-help vulners                 # the vulners NSE script needs internet from the scanner machine
```
Use `pip install -e ".[dev]"` and `pytest -q` to run the tests.

## Use

```bash
posture init "Lab Assessment" -t IP_ADDRESS      # creates engagements/lab-assessment/ and selects it
#   edit engagements/lab-assessment/scope.yaml  (authorized_by, auth_reference, targets, window)
posture doctor                                        # tools, engagement, scope, DNS
posture scan                                          # fast parallel scan
posture inventory
posture findings 
posture findings 3                                    # evidence, retests, history
posture fix 3 --owner NAME --due DATE --action "Disable anonymous FTP"
posture status 3 remediation|fixed|accepted-risk|false-positive   # --approver --expiry --reason where required
posture retest                                        # rescan; closes / reopens / marks inconclusive
posture report
posture web [--allow-scan]                            # local web UI
```
Several engagements: `posture list`, `posture use <name>`, or add `-e <name>` to any command. Running a command from inside an engagement folder selects it automatically.

## Engagement folder
```
engagements/<name>/
  scope.yaml        scope + authorization record (checked before every scan)
  posture.db        findings, evidence, retests, audit log
  authorization/    signed authorization / rules of engagement
  raw/{nmap,nuclei,testssl,nikto}/   untouched tool output (SHA-256 in the DB)
  logs/             one log per tool run: command, exit code, stderr/stdout tail
  reports/<time>/   report.html, report.pdf, report.md, findings.csv, report.json
  evidence/         your own screenshots and notes
```
Set `POSTURE_HOME=/path` to keep all engagements somewhere other than the current directory.

## Targets in scope.yaml
Any mix of: single IP `IP_ADDRESS` | several `IP1, IP2`| CIDR `RANGE` | domain `lab.example.local`.
Domains are resolved when the scan starts; the IPs are **pinned**, logged (`resolutions` table, report) and scanned by IP, so a DNS change mid-scan cannot widen scope.
Nikto gets `-vhost <domain>`. Domains that resolve to public IPs need `allow_public: true`. IPv4 only. Exclusions accept the same formats.

## Speed and accuracy
- `ports: all` (default): full 65535-port TCP discovery (`--min-rate`), then `-sV` + NSE only on ports that are open. Finds services on odd ports and detects closed ports reliably at retest. `ports: top1000` is faster but can miss services.
- Nuclei, testssl and Nikto run **in parallel** (`performance.workers`, default 3; lower it for fragile VMs). Nuclei `mode: auto` runs only templates matching detected technology (much faster than `full`).
- **Confidence**: *Corroborated* (2+ tools agree) / *Tested* (behavior-based check) / *Unverified* (banner or heuristic only: triage first).
- Retest never closes a finding on weak evidence: host down, filtered port, or the finding's tool failing/not installed gives **Inconclusive**; version-based CVEs close only when the banner changed.

## If a tool fails
`posture scan` prints the reason per tool, e.g. `nikto: failed for 2/2 target(s): ... | logs: engagements/<name>/logs`.
Open `logs/nikto-<time>-<ip>-<port>.log`: it holds the exact command and stderr. Run that command by hand to see the real error.
Nikto output is parsed from its text report (its JSON is unreliable); the raw text is kept in `raw/nikto/`.

## Reports
```bash
posture report                         # HTML (default): easiest to read, opens in any browser, prints cleanly
posture report --format pdf            # PDF to share
posture report --format html,pdf,csv   # any combination; or: --format all
```
Written to `engagements/<name>/reports/<time>/`. Every report starts with the plain-language part: an overall risk rating, a short summary, KPIs and a severity chart,
then **Fix these first** (top 5 with *why it matters* and *how to fix*), progress since the last retest, a per-host view, the remediation tracker, all findings, evidence, a glossary and scope/method.
`findings.csv` opens in Excel/LibreOffice; `report.json` is for other tools. HTML is a single self-contained file (no internet needed). In the web UI, `/report` shows it with download links.

## Web UI
`posture web` prints a one-time login URL with a random token. Dashboard, filterable findings, finding detail (evidence, retests, history, remediation and status forms), inventory, scans, report download.
The **scan-launch button is off** unless you start `posture web --allow-scan`. Safeguards: localhost-only bind and Host check, login token, CSRF on every POST, scope/window/allowlist re-checked at launch,
typed engagement-name confirmation + checkbox, one scan at a time, cooldown (default 300 s), full audit log, same code path as the CLI, escaped output and strict CSP.

## Safety design
`guard.authorize()` gates every scan; the only process launcher (`scan._exec`) refuses to run without an `Authorization` and re-checks each target IP.
NSE scripts must be on an allowlist. Nuclei excludes dos/fuzz/intrusive/bruteforce tags (default-login templates still run; add that tag to `exclude_tags` if your rules forbid it). Nikto uses tuning `123b` only.
Keep `engagements/` out of public git.

## Limitations
- TCP only (no UDP). Authenticated (credentialed) scanning is not included.
- Nikto has no severity ratings (heuristic, max 50 findings per target). Nuclei by IP cannot test name-based virtual hosts (Nikto can).
- IPv4 only. Hosts that block discovery appear down (Inconclusive). Lightweight assessment, not a full vulnerability-management platform.
