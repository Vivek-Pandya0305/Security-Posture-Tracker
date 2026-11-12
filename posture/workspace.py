"""Engagement workspace: every engagement lives in its own folder: <home>/engagements/<slug>/ ."""
from __future__ import annotations

import datetime as dt
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

from . import guard

MARKER = ".posture-engagement"
POINTER = ".posture-current"
STRUCTURE = ("authorization", "raw/nmap", "raw/nuclei", "raw/testssl", "raw/nikto", "logs", "reports", "evidence")

TEMPLATE = """# Scope and authorization record for this engagement. Every scan is checked against this file.
engagement: @@NAME@@
authorized_by: CHANGE_ME          # person who owns / authorizes testing of these assets
auth_reference: CHANGE_ME         # e.g. authorization/signed-authorization.pdf
window_start: @@START@@
window_end: @@END@@

# Targets: any mix of
#   single IP        192.168.56.101
#   several IPs      192.168.56.101, 192.168.56.102      (or one per line)
#   IP range         192.168.56.10-20
#   network (CIDR)   192.168.56.0/24
#   domain name      lab.example.local   (resolved at scan time; the IPs are pinned, logged and scanned)
targets:
@@TARGETS@@
exclusions: []                    # same formats; these are never scanned
allow_public: false               # must be true to scan public IPs (also applies to domains that resolve to public IPs)

ports: all                        # all = full 65535-port discovery, then deep scan of open ports (most accurate)
                                  # top1000 = faster; or a list such as "1-1024,8080,8180"
min_cvss: 7.0                     # ignore vulners CVEs scoring below this
nse_scripts: [vulners, ftp-anon, smb-security-mode, smb2-security-mode, http-methods, ssl-enum-ciphers, smb-vuln-ms17-010]

performance:
  workers: 3                      # tools/targets run in parallel; lower this for fragile VMs
  nmap_timing: 4                  # Nmap -T level (1-5)
nuclei:
  enabled: true
  mode: full                      # full = all templates; auto = only templates matching detected technology (faster)
  severity: [low, medium, high, critical]
  exclude_tags: [dos, fuzz, intrusive, bruteforce]
  rate_limit: 150
  concurrency: 25
testssl:
  enabled: true
nikto:
  enabled: true
  max_time: 300                   # seconds per web target
"""

AUTH_TEMPLATE = """# Authorization to Test

Engagement: ______________________   Asset owner / authorizer: ______________________
Assessor: ______________________     In-scope targets: ______________________
Excluded: ______________________     Window (start - end, timezone): ______________________
Permitted: port/service discovery (Nmap), allowlisted NSE scripts, Nuclei (no dos/fuzz/intrusive/bruteforce tags), testssl.sh, Nikto (tuning 123b)
Prohibited: exploitation, denial of service, credential brute force, data extraction, testing outside scope
Emergency contact: ______________________   Snapshots/backups taken: yes / no

I own or am authorized to approve testing of the assets above.
Signature: ______________________   Date: ____________

Save the signed copy in this folder and reference it in scope.yaml (auth_reference).
"""

README_TXT = """Engagement folder layout
  scope.yaml       scope + authorization record (every scan is checked against it)
  posture.db       findings, evidence, retests, audit log (SQLite)
  authorization/   signed authorization and rules of engagement
  raw/<tool>/      untouched tool output (nmap XML, nuclei JSONL, testssl JSON, nikto text); SHA-256 stored in the DB
  logs/            one log per tool run (command, exit code, stderr/stdout tail) - read these when a tool fails
  reports/         generated Markdown reports
  evidence/        anything you add manually (screenshots, notes)
"""


@dataclass(frozen=True)
class Engagement:
    root: Path

    @property
    def name(self):
        return self.root.name

    @property
    def scope_path(self):
        return self.root / "scope.yaml"

    @property
    def db_path(self):
        return self.root / "posture.db"

    def raw(self, tool):
        p = self.root / "raw" / tool
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def logs_dir(self):
        p = self.root / "logs"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def reports_dir(self):
        p = self.root / "reports"
        p.mkdir(parents=True, exist_ok=True)
        return p


def home():
    return Path(os.environ.get("POSTURE_HOME") or ".").resolve()


def engagements_dir():
    return home() / "engagements"


def slugify(name):
    s = re.sub(r"[^a-z0-9]+", "-", str(name).lower()).strip("-")[:60].strip("-")
    if not s:
        raise ValueError("Engagement name must contain letters or digits")
    return s


def list_engagements():
    base = engagements_dir()
    return [Engagement(p) for p in sorted(base.iterdir()) if (p / MARKER).exists()] if base.exists() else []


def set_current(eng):
    home().joinpath(POINTER).write_text(eng.name)


def create(name, targets=None):
    slug = slugify(name)
    root = engagements_dir() / slug
    if root.exists():
        raise ValueError(f"Engagement '{slug}' already exists. Select it with: posture use {slug}")
    tl = guard._split(targets or [])
    for t in tl:
        guard.parse_target(t)                                   # validate before creating anything
    for d in STRUCTURE:
        (root / d).mkdir(parents=True, exist_ok=True)
    today = dt.date.today()
    block = "\n".join(f"  - {t}" for t in tl) or "  # - 192.168.56.101      (add your targets here)"
    (root / "scope.yaml").write_text(TEMPLATE.replace("@@NAME@@", json.dumps(str(name))).replace("@@START@@", str(today))
                                     .replace("@@END@@", str(today + dt.timedelta(days=30))).replace("@@TARGETS@@", block))
    (root / "authorization" / "authorization-template.md").write_text(AUTH_TEMPLATE)
    (root / "README.txt").write_text(README_TXT)
    (root / MARKER).write_text("posture engagement\n")
    eng = Engagement(root)
    set_current(eng)
    return eng


def resolve(name=None):
    base = engagements_dir()
    name = name or os.environ.get("POSTURE_ENGAGEMENT")
    if name:
        p = base / slugify(name)
        if not (p / MARKER).exists():
            have = ", ".join(e.name for e in list_engagements()) or "none"
            raise ValueError(f"No engagement '{name}'. Existing: {have}")
        return Engagement(p)
    for parent in [Path.cwd(), *Path.cwd().parents]:
        if (parent / MARKER).exists():
            return Engagement(parent)
    ptr = home() / POINTER
    if ptr.exists():
        p = base / ptr.read_text().strip()
        if (p / MARKER).exists():
            return Engagement(p)
    existing = list_engagements()
    if len(existing) == 1:
        return existing[0]
    raise ValueError("No engagement selected. Create one: posture init <name>   or select: posture use <name>")
