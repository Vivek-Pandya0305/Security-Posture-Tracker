"""Report rendering. One data model (collect) feeds every format: HTML, PDF, Markdown, CSV, JSON."""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
from collections import Counter

from jinja2 import Environment

from . import report, track
from .db import now

FORMATS = ("html", "pdf", "md", "csv", "json")
MIME = {"html": "text/html", "pdf": "application/pdf", "md": "text/markdown", "csv": "text/csv", "json": "application/json"}
FILENAME = {"csv": "findings.csv"}
SEV = track.SEVERITIES
NEEDS_ACTION = ("Open", "In Remediation", "Reopened", "Inconclusive")
CONF_RANK = {"Corroborated": 0, "Tested": 1, "Unverified": 2}
RATINGS = (("Critical", "Critical", "Immediate action needed: at least one critical issue is open."),
           ("High", "High", "High risk: serious issues are open and should be fixed soon."),
           ("Medium", "Moderate", "Moderate risk: no critical or high issues are open, but medium ones remain."),
           ("Low", "Low", "Low risk: only minor issues remain."))
GLOSSARY = (
    ("Severity", "How serious the issue is: Critical, High, Medium, Low or Info (CVSS bands where a score exists, otherwise the assessor's rating)."),
    ("Confidence: Corroborated", "Two or more independent tools reported the same issue on the same service. Most reliable."),
    ("Confidence: Tested", "A check that tests real behavior (for example a login attempt or a configuration setting) found it."),
    ("Confidence: Unverified", "Based only on a version banner or a heuristic. It may be a false positive, so verify it on the host before spending effort."),
    ("Open / In Remediation", "The issue exists and is waiting for a fix or is being fixed."),
    ("Fixed (Pending Retest)", "Someone says it is fixed. It is not counted as closed until a retest confirms it."),
    ("Verified Closed", "A retest scanned the service again and conclusively did not find the issue."),
    ("Inconclusive", "The retest could not tell (host down, port filtered, or a scanner failed). It is never treated as fixed."),
    ("Accepted Risk / False Positive", "A named person accepted the risk until a date, or the finding was judged wrong, with a written reason."),
)
LIMITS = (
    "Assessment only: no exploitation was attempted. Some Nuclei templates (for example default-login) may try default credentials.",
    "Only TCP services were scanned. Findings from version banners can be false positives when vendors back-port fixes.",
    "Config findings carry an assessor-rated severity (no CVSS). Nikto has no severity scale, so its ratings are heuristic.",
    "A scan shows the state at one moment on the scanned ports; it is not proof that everything else is secure.",
)

KB = {
    "SVC-TELNET": ("Telnet sends usernames, passwords and commands as plain text, so anyone who can see the network traffic can read them.",
                   "Stop and disable the telnet service and use SSH instead."),
    "SVC-RLOGIN": ("rlogin sends data unencrypted and trusts the connecting machine, which is easy to abuse.", "Disable the rlogin service and use SSH."),
    "SVC-RSH": ("rsh runs remote commands without encryption and relies on weak host-based trust.", "Disable rsh and use SSH."),
    "SVC-REXEC": ("rexec sends credentials in clear text.", "Disable rexec and use SSH."),
    "NSE-FTP-ANON": ("Anyone can log in to this FTP server without a password and may be able to read, or even upload, files.",
                     "Turn off anonymous FTP in the FTP server settings, or restrict it to a harmless read-only folder."),
    "NSE-SMB-SIGNING": ("Without required SMB signing, an attacker on the network can tamper with or relay file-sharing sessions.",
                        "Require SMB signing in the server's security policy, then retest."),
    "NSE-HTTP-METHODS": ("The web server accepts HTTP methods such as TRACE, PUT or DELETE that normal sites do not need and attackers can abuse.",
                         "Disable the unneeded methods in the web server configuration."),
    "TLS-WEAK": ("The server still offers outdated protocols or weak ciphers that can be broken, exposing encrypted traffic.",
                 "Disable SSLv2/SSLv3 and weak ciphers; allow only TLS 1.2 or newer with strong ciphers."),
    "TLS-OLD": ("TLS 1.0 and 1.1 are deprecated and have known weaknesses.", "Disable TLS 1.0 and 1.1 and keep TLS 1.2 or newer."),
}


def advise(f):
    vid, src = f["vuln_id"], f["source"]
    if vid in KB:
        return KB[vid]
    if vid.startswith("CVE-"):
        sw = f["banner"] or "The detected software"
        score = f" (CVSS {f['cvss']})" if f["cvss"] else ""
        note = " This match is based on the version banner only, so it may be a false positive if the vendor back-ported the fix." if src == "nmap" else ""
        return (f"{sw} matches the public vulnerability {vid}{score}. Details of this flaw are public.{note}",
                "Update the software to a vendor-patched release (or confirm on the host that the installed package already contains the fix), then run 'posture retest'.")
    if src == "testssl":
        return (f"testssl.sh reported a TLS weakness: {f['title']}.", "Fix the TLS configuration or patch the TLS library, then retest.")
    if src == "nikto":
        return (f"Nikto reported: {f['title']}. Nikto results are heuristic and need a quick manual check.",
                "Open the URL shown in the evidence. If the file or feature is not needed, remove or restrict it; if it is a false alarm, mark it False Positive with a reason.")
    if vid.startswith("NSE-"):
        return (f["description"] or "An Nmap script flagged this service.", "Review the script output in the evidence, apply the vendor's hardening guidance, then retest.")
    return (f["description"] or f"A Nuclei check ({vid}) matched this service.", "Review the evidence, apply the vendor's remediation for this issue, then retest.")


def _narrative(s):
    out = []
    if s["active"] == 0:
        out.append("No open findings in the current data.")
    else:
        parts = [f"{s['sev_counts'][k]} {k}" for k in SEV if s["sev_counts"][k]]
        out.append(f"{s['active']} open issue(s) on {s['hosts_affected']} host(s): " + ", ".join(parts) + ".")
        out.append(f"{s['conf_counts'].get('Corroborated', 0)} confirmed by more than one tool; {s['conf_counts'].get('Unverified', 0)} rest on "
                   "banner or heuristic evidence only and should be verified by hand.")
    if s["closed"]:
        out.append(f"{s['closed']} issue(s) were fixed and verified by retest.")
    if s["pending"]:
        out.append(f"{s['pending']} issue(s) are marked fixed and waiting for a retest.")
    if s["inconclusive"]:
        out.append(f"{s['inconclusive']} issue(s) could not be confirmed in the last retest (host or tool unavailable).")
    if s["overdue"]:
        out.append(f"{s['overdue']} remediation item(s) are past their due date.")
    return out


def collect(con, scope):
    today = dt.date.today().isoformat()
    runs = {r["id"]: dict(r) for r in con.execute("SELECT * FROM scan_runs ORDER BY id")}
    names = {r["ip"]: r["name"] for r in con.execute("SELECT name, ip FROM resolutions WHERE at=(SELECT MAX(at) FROM resolutions)")}
    fs = []
    for r in track.list_findings(con):
        f = dict(r)
        f["why"], f["fix"] = advise(f)
        f["evidence"] = [e[0] for e in con.execute("SELECT excerpt FROM evidence WHERE finding_id=? ORDER BY id LIMIT 2", (f["id"],))]
        f["active"] = f["status"] in track.ACTIVE
        f["overdue"] = bool(f["active"] and f["due_date"] and f["due_date"] < today)
        f["first_seen"] = (runs.get(f["first_run"]) or {}).get("started_at", "")[:10]
        if f["status"] == "Verified Closed":
            row = con.execute("SELECT at FROM status_log WHERE finding_id=? AND new='Verified Closed' ORDER BY id DESC LIMIT 1", (f["id"],)).fetchone()
            f["closed_at"] = row[0][:10] if row else ""
        fs.append(f)
    act = [f for f in fs if f["active"]]
    sev_counts = {s: sum(1 for f in act if f["sev"] == s) for s in SEV}
    conf_counts = dict(Counter(f["confidence"] for f in act))
    status_counts = dict(Counter(f["status"] for f in fs))
    summ = {"active": len(act), "sev_counts": sev_counts, "conf_counts": conf_counts, "hosts_affected": len({f["ip"] for f in act}),
            "closed": status_counts.get("Verified Closed", 0), "pending": status_counts.get("Fixed (Pending Retest)", 0),
            "inconclusive": status_counts.get("Inconclusive", 0), "overdue": sum(1 for f in act if f["overdue"])}
    rating = {"key": "Good", "label": "Good", "text": "No open findings were recorded."}
    for key, label, text in RATINGS:
        if sev_counts[key]:
            rating = {"key": key, "label": label, "text": text}
            break
    need = sorted((f for f in fs if f["status"] in NEEDS_ACTION),
                  key=lambda f: (SEV.index(f["sev"]) if f["sev"] in SEV else 9, CONF_RANK.get(f["confidence"], 3), -(f["cvss"] or 0), f["id"]))
    rid = con.execute("SELECT MAX(id) FROM scan_runs WHERE tool IN ('nmap','nmap-discovery') AND ok=1").fetchone()[0]
    hm = {}
    if rid:
        for h in con.execute("SELECT ip, up FROM hosts WHERE run_id=?", (rid,)):
            hm[h["ip"]] = {"ip": h["ip"], "up": bool(h["up"]), "services": []}
        for s in con.execute("SELECT * FROM services WHERE run_id=? AND state='open' ORDER BY port", (rid,)):
            hm.setdefault(s["ip"], {"ip": s["ip"], "up": True, "services": []})["services"].append(dict(s))
    for f in fs:
        hm.setdefault(f["ip"], {"ip": f["ip"], "up": None, "services": []})
    for h in hm.values():
        hf = [f for f in act if f["ip"] == h["ip"]]
        h["name"], h["findings"] = names.get(h["ip"], ""), len(hf)
        h["worst"] = next((s for s in SEV if any(f["sev"] == s for f in hf)), "None")
    hosts = sorted(hm.values(), key=lambda h: tuple(int(x) for x in h["ip"].split(".")))
    rt = None
    last = con.execute("SELECT MAX(run_id) FROM retests").fetchone()[0]
    if last:
        c = dict(con.execute("SELECT result, COUNT(*) FROM retests WHERE run_id=? GROUP BY result", (last,)).fetchall())
        rt = {"at": con.execute("SELECT MAX(tested_at) FROM retests WHERE run_id=?", (last,)).fetchone()[0],
              "closed": c.get("not_detected", 0), "still": c.get("still_present", 0), "inconclusive": c.get("inconclusive", 0)}
    nu = scope.nuclei
    return {
        "title": "Security Posture Assessment Report", "engagement": scope.engagement, "generated": now(),
        "authorized_by": scope.authorized_by, "auth_reference": scope.auth_reference,
        "window": f"{scope.start:%Y-%m-%d} to {scope.end:%Y-%m-%d} (UTC)",
        "targets": ", ".join([str(t) for t in scope.targets] + list(scope.target_names)),
        "excluded": ", ".join([str(t) for t in scope.exclusions] + list(scope.exclusion_names)) or "none",
        "resolved": ", ".join(f"{n} -> {i}" for i, n in names.items()) or "n/a",
        "ports": scope.ports, "scope_sha": scope.sha256,
        "tools": f"Nmap + NSE ({', '.join(scope.scripts) or 'none'}); Nuclei {'on (' + nu['mode'] + ')' if nu['enabled'] else 'off'}; "
                 f"testssl.sh {'on' if scope.testssl['enabled'] else 'off'}; Nikto {'on' if scope.nikto['enabled'] else 'off'}",
        "summary": summ, "rating": rating, "narrative": _narrative(summ), "sev_order": list(SEV), "sev_counts": sev_counts,
        "max_sev": max(max(sev_counts.values()), 1), "status_counts": status_counts, "conf_counts": conf_counts,
        "kpis": [("Open issues", len(act)), ("Critical", sev_counts["Critical"]), ("High", sev_counts["High"]), ("Medium", sev_counts["Medium"]),
                 ("Low", sev_counts["Low"]), ("Fixed & verified", summ["closed"]), ("Overdue", summ["overdue"])],
        "top": need[:5], "hosts": hosts, "findings": fs, "retest": rt,
        "tracker": [f for f in fs if f["active"] or f["status"] == "Accepted Risk"],
        "closed": [f for f in fs if f["status"] == "Verified Closed"],
        "runs": [{k: r[k] for k in ("id", "tool", "run_type", "started_at", "ok", "raw_file", "sha256")} for r in runs.values()],
        "glossary": GLOSSARY, "limits": LIMITS,
    }


HTML_TPL = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Posture Assessment Report - {{ d.engagement }}</title><style>
*{box-sizing:border-box}body{margin:0;background:#f3f5f8;color:#1b2430;font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;-webkit-print-color-adjust:exact;print-color-adjust:exact}
.wrap{max-width:980px;margin:0 auto;padding:24px 18px 60px}
header{background:#1b2a41;color:#fff;border-radius:12px;padding:22px 26px;margin-bottom:18px}header h1{margin:0 0 4px;font-size:26px}.sub{font-size:18px;margin:0}.meta{margin:8px 0 0;font-size:13px;opacity:.85}
h2{font-size:20px;margin:30px 0 10px;border-bottom:2px solid #d5dbe3;padding-bottom:6px}
.card{background:#fff;border:1px solid #d5dbe3;border-radius:10px;padding:14px 18px;margin:10px 0}
.rating{display:flex;gap:20px;align-items:center;border-left:10px solid #888}.rating .big{font-size:32px;font-weight:700;line-height:1.1}.rating ul{margin:6px 0 0;padding-left:18px}
.r-Critical{border-left-color:#b71c1c}.r-High{border-left-color:#e65100}.r-Medium{border-left-color:#f9a825}.r-Low,.r-Good{border-left-color:#2e7d32}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(105px,1fr));gap:10px}.kpi{background:#fff;border:1px solid #d5dbe3;border-radius:10px;padding:10px;text-align:center}.kpi b{display:block;font-size:26px}.kpi span{font-size:12px;color:#5b6675}
.b{display:inline-block;padding:1px 9px;border-radius:10px;font-size:12px;font-weight:600;color:#fff}
.b-Critical{background:#b71c1c}.b-High{background:#e65100}.b-Medium{background:#f9a825;color:#222}.b-Low{background:#2e7d32}.b-Info{background:#546e7a}
.c{display:inline-block;padding:0 8px;border-radius:10px;font-size:12px;border:1px solid #5b6675;color:#334}.c-Corroborated{border-color:#2e7d32;color:#1b5e20}.c-Unverified{border-color:#e65100;color:#bf360c}
.barrow{display:flex;align-items:center;gap:10px;margin:5px 0}.barrow>span{width:70px;font-size:13px}.bar{flex:1;background:#e8ecf1;border-radius:6px;height:16px;overflow:hidden}.bar i{display:block;height:100%}
table{width:100%;border-collapse:collapse;font-size:13.5px;background:#fff}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #e3e8ee;vertical-align:top}th{background:#eef1f5}
.mut{color:#5b6675}.over{color:#b71c1c;font-weight:600}pre{background:#f3f5f8;border:1px solid #e3e8ee;border-radius:6px;padding:8px;white-space:pre-wrap;word-break:break-word;font-size:12px}
.fixcard{border-left:8px solid #888}.fc-Critical{border-left-color:#b71c1c}.fc-High{border-left-color:#e65100}.fc-Medium{border-left-color:#f9a825}.fc-Low{border-left-color:#2e7d32}
details summary{cursor:pointer}.toolbar{background:#fff;border:1px solid #d5dbe3;border-radius:8px;padding:8px 14px;margin-bottom:12px;font-size:14px}
@media print{body{background:#fff;font-size:11px}.noprint{display:none}.card,.kpi,tr{break-inside:avoid}a{color:inherit;text-decoration:none}}
</style></head><body><div class="wrap">
{% macro sev(s) %}<span class="b b-{{ s }}">{{ s }}</span>{% endmacro %}
{% macro conf(c) %}<span class="c c-{{ c }}">{{ c }}</span>{% endmacro %}
{% if web %}<div class="toolbar noprint">Download: <a href="/report/pdf">PDF</a> | <a href="/report/html">HTML</a> | <a href="/report/md">Markdown</a> | <a href="/report/csv">CSV</a> | <a href="/report/json">JSON</a></div>{% endif %}
<header><h1>{{ d.title }}</h1><p class="sub">{{ d.engagement }}</p><p class="meta">Generated {{ d.generated }} | Authorized by {{ d.authorized_by }} | Window {{ d.window }}</p></header>

<h2>The short version</h2>
<div class="card rating r-{{ d.rating.key }}"><div><div class="mut">Overall risk</div><div class="big">{{ d.rating.label }}</div></div>
<div>{{ d.rating.text }}<ul>{% for s in d.narrative %}<li>{{ s }}</li>{% endfor %}</ul></div></div>
<div class="kpis">{% for k in d.kpis %}<div class="kpi"><b>{{ k[1] }}</b><span>{{ k[0] }}</span></div>{% endfor %}</div>
<div class="card"><b>Open issues by severity</b>{% for s in d.sev_order %}<div class="barrow"><span>{{ s }}</span><div class="bar"><i class="b-{{ s }}" style="width:{{ (100 * d.sev_counts[s] / d.max_sev)|round|int }}%"></i></div><b>{{ d.sev_counts[s] }}</b></div>{% endfor %}</div>

<h2>Fix these first</h2>
{% for f in d.top %}<div class="card fixcard fc-{{ f.sev }}"><div>{{ sev(f.sev) }} {{ conf(f.confidence) }} <b>{{ loop.index }}. {{ f.title }}</b></div>
<div class="mut">{{ f.ip }}:{{ f.port }}/{{ f.proto }} | status: {{ f.status }}{% if f.owner %} | owner: {{ f.owner }}{% endif %}{% if f.due_date %} | due {{ f.due_date }}{% endif %}</div>
<p><b>Why it matters.</b> {{ f.why }}</p><p><b>How to fix.</b> {{ f.fix }}</p><p class="mut"><a href="#f{{ f.id }}">Evidence and details (finding #{{ f.id }})</a></p></div>
{% else %}<div class="card">Nothing needs action right now.</div>{% endfor %}

{% if d.retest %}<h2>Progress since the last retest</h2>
<div class="card">Last retest {{ d.retest.at }}: <b>{{ d.retest.closed }}</b> confirmed fixed, <b>{{ d.retest.still }}</b> still present, <b>{{ d.retest.inconclusive }}</b> could not be confirmed.
{% if d.closed %}<ul>{% for f in d.closed %}<li>Fixed and verified: #{{ f.id }} {{ f.title }} on {{ f.ip }}:{{ f.port }} ({{ f.closed_at }})</li>{% endfor %}</ul>{% endif %}</div>{% endif %}

<h2>By host</h2>
<table><tr><th>Host</th><th>Open services</th><th>Open issues</th><th>Worst</th></tr>
{% for h in d.hosts %}<tr><td><b>{{ h.ip }}</b>{% if h.name %}<br><span class="mut">{{ h.name }}</span>{% endif %}</td>
<td>{% for s in h.services %}{{ s.port }}/{{ s.service or '?' }}{{ ', ' if not loop.last }}{% else %}<span class="mut">none seen</span>{% endfor %}</td>
<td>{{ h.findings }}</td><td>{% if h.worst != 'None' %}{{ sev(h.worst) }}{% else %}<span class="mut">-</span>{% endif %}</td></tr>{% endfor %}</table>

<h2>Remediation tracker</h2>
<table><tr><th>#</th><th>Severity</th><th>Finding</th><th>Owner</th><th>Due</th><th>Status</th></tr>
{% for f in d.tracker %}<tr><td>{{ f.id }}</td><td>{{ sev(f.sev) }}</td><td><a href="#f{{ f.id }}">{{ f.title }}</a><br><span class="mut">{{ f.ip }}:{{ f.port }}</span></td>
<td>{{ f.owner or '-' }}</td><td>{% if f.overdue %}<span class="over">{{ f.due_date }} (overdue)</span>{% else %}{{ f.due_date or '-' }}{% endif %}</td>
<td>{{ f.status }}{% if f.status == 'Accepted Risk' %}<br><span class="mut">by {{ f.approver }} until {{ f.expiry }}</span>{% endif %}</td></tr>
{% else %}<tr><td colspan="6" class="mut">Nothing to track.</td></tr>{% endfor %}</table>

<h2>All findings</h2>
<table><tr><th>#</th><th>Severity</th><th>Confidence</th><th>Where</th><th>Finding</th><th>Status</th></tr>
{% for f in d.findings %}<tr><td>{{ f.id }}</td><td>{{ sev(f.sev) }}</td><td>{{ conf(f.confidence) }}</td><td>{{ f.ip }}:{{ f.port }}</td><td><a href="#f{{ f.id }}">{{ f.title }}</a></td><td>{{ f.status }}</td></tr>{% endfor %}</table>

<h2>Details and evidence</h2>
{% for f in d.findings %}<details class="card" id="f{{ f.id }}" {{ 'open' if f.active and f.sev in ('Critical', 'High') }}>
<summary>{{ sev(f.sev) }} {{ conf(f.confidence) }} <b>#{{ f.id }} {{ f.title }}</b> <span class="mut">{{ f.ip }}:{{ f.port }} | {{ f.status }}</span></summary>
<p><b>What it is.</b> {{ f.why }}</p><p><b>How to fix.</b> {{ f.fix }}</p>
<p class="mut">ID {{ f.vuln_id }} | seen by {{ f.seen_by }}{% if f.cvss %} | CVSS {{ f.cvss }}{% endif %} | first seen {{ f.first_seen }}{% if f.override_severity %} | severity overridden from {{ f.severity }}: {{ f.override_reason }}{% endif %}{% if f.reason and f.status == 'False Positive' %} | false positive: {{ f.reason }}{% endif %}</p>
{% for e in f.evidence %}<pre>{{ e }}</pre>{% endfor %}</details>{% endfor %}

<h2>How to read this report</h2>
<div class="card"><table>{% for t, m in d.glossary %}<tr><td><b>{{ t }}</b></td><td>{{ m }}</td></tr>{% endfor %}</table></div>

<h2>Scope and method</h2>
<div class="card"><table>
<tr><td><b>Authorization</b></td><td>{{ d.authorized_by }} ({{ d.auth_reference }})</td></tr><tr><td><b>Window</b></td><td>{{ d.window }}</td></tr>
<tr><td><b>Targets</b></td><td>{{ d.targets }}</td></tr><tr><td><b>Resolved names</b></td><td>{{ d.resolved }}</td></tr>
<tr><td><b>Excluded</b></td><td>{{ d.excluded }}</td></tr><tr><td><b>Port coverage</b></td><td>{{ d.ports }}{% if d.ports == 'all' %} (full 65535-port TCP discovery, then deep scan of open ports){% endif %}</td></tr>
<tr><td><b>Tools</b></td><td>{{ d.tools }}</td></tr><tr><td><b>Scope file SHA-256</b></td><td>{{ d.scope_sha }}</td></tr></table>
<ul>{% for l in d.limits %}<li>{{ l }}</li>{% endfor %}</ul></div>
<details class="card"><summary><b>Scan run log</b> (raw outputs are hashed for integrity)</summary><table><tr><th>Run</th><th>Tool</th><th>Type</th><th>Started</th><th>OK</th><th>SHA-256</th></tr>
{% for r in d.runs %}<tr><td>{{ r.id }}</td><td>{{ r.tool }}</td><td>{{ r.run_type }}</td><td>{{ r.started_at }}</td><td>{{ 'yes' if r.ok else 'no' }}</td><td>{{ (r.sha256 or '')[:16] }}</td></tr>{% endfor %}</table></details>
</div></body></html>"""
_ENV = Environment(autoescape=True)


def render_html(d, web=False):
    return _ENV.from_string(HTML_TPL).render(d=d, web=web)


def render_csv(d):
    cols = ("id", "severity", "confidence", "status", "ip", "port", "title", "source", "seen_by", "vuln_id", "cvss", "owner",
            "due_date", "action", "first_seen", "why_it_matters", "how_to_fix")
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for f in d["findings"]:
        vals = dict(f, severity=f["sev"], why_it_matters=f["why"], how_to_fix=f["fix"])
        w.writerow([vals.get(c, "") if vals.get(c) is not None else "" for c in cols])
    return buf.getvalue()


def render_json(d):
    return json.dumps(d, indent=2, default=str)


def render_pdf(d):
    try:
        from reportlab.graphics.shapes import Drawing, Rect, String
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError:
        raise RuntimeError("PDF output needs reportlab: pip install reportlab")
    from xml.sax.saxutils import escape
    HC = colors.HexColor
    SEVC = {"Critical": "#b71c1c", "High": "#e65100", "Medium": "#f9a825", "Low": "#2e7d32", "Info": "#546e7a", "None": "#888888"}
    RC = dict(SEVC, Good="#2e7d32")
    base = getSampleStyleSheet()["BodyText"]

    def S(name, **kw):
        return ParagraphStyle(name, parent=base, **kw)
    body, small = S("b", fontSize=9.5, leading=13), S("s", fontSize=8, leading=10.5, textColor=HC("#5b6675"))
    h2, h3 = S("h2", fontSize=14, leading=18, spaceBefore=14, spaceAfter=6, textColor=HC("#1b2a41")), S("h3", fontSize=10, leading=13)
    mono = S("m", fontName="Courier", fontSize=7.5, leading=9.5, backColor=HC("#f3f5f8"))
    cell = S("c", fontSize=8, leading=10)

    def t(x, n=None):
        s = "" if x is None else str(x)
        s = s.encode("latin-1", "replace").decode("latin-1")
        return escape(s[:n] if n else s)

    def P(x, st=body, n=None):
        return Paragraph(t(x, n), st)

    def sevtag(s):
        return f"<font color='{SEVC.get(s, '#888888')}'><b>{t(s)}</b></font>"
    W = A4[0] - 30 * mm
    grid = [("GRID", (0, 0), (-1, -1), 0.25, HC("#d5dbe3")), ("BACKGROUND", (0, 0), (-1, 0), HC("#eef1f5")), ("VALIGN", (0, 0), (-1, -1), "TOP")]

    def table(head, rows, widths):
        data = [[Paragraph(f"<b>{t(h)}</b>", cell) for h in head]] + [[c if not isinstance(c, str) else P(c, cell) for c in r] for r in rows]
        tb = Table(data, colWidths=[w * W for w in widths], repeatRows=1)
        tb.setStyle(TableStyle(grid))
        return tb
    el = []
    hdr = Table([[Paragraph("Security Posture Assessment Report", S("h1", fontSize=22, leading=26, textColor=colors.white))],
                 [Paragraph(t(d["engagement"]), S("hs", fontSize=13, leading=16, textColor=colors.white))],
                 [Paragraph(t(f"Generated {d['generated']}  |  Authorized by {d['authorized_by']}  |  Window {d['window']}"),
                            S("hm", fontSize=8.5, leading=11, textColor=HC("#c9d3e0")))]], colWidths=[W])
    hdr.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), HC("#1b2a41")), ("LEFTPADDING", (0, 0), (-1, -1), 12), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    el += [hdr, Spacer(1, 8), Paragraph("The short version", h2)]
    r = d["rating"]
    rows = [[Paragraph(f"<font size=15 color='{RC[r['key']]}'><b>Overall risk: {t(r['label']).upper()}</b></font>", body)], [P(r["text"])]] + \
           [[P("- " + s, body)] for s in d["narrative"]]
    box = Table(rows, colWidths=[W])
    box.setStyle(TableStyle([("LINEBEFORE", (0, 0), (0, -1), 6, HC(RC[r["key"]])), ("BOX", (0, 0), (-1, -1), 0.25, HC("#d5dbe3")), ("LEFTPADDING", (0, 0), (-1, -1), 10)]))
    kp = Table([[Paragraph(f"<para alignment='center'><font size=16><b>{v}</b></font><br/><font size=7>{t(k)}</font></para>", body) for k, v in d["kpis"]]],
               colWidths=[W / len(d["kpis"])] * len(d["kpis"]))
    kp.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, HC("#d5dbe3")), ("BACKGROUND", (0, 0), (-1, -1), HC("#f7f9fb"))]))
    mx = max(d["max_sev"], 1)
    dr = Drawing(W, 17 * len(SEV))
    for i, s in enumerate(SEV):
        y, n = 17 * (len(SEV) - 1 - i), d["sev_counts"][s]
        dr.add(String(0, y + 4, s, fontSize=8))
        dr.add(Rect(55, y + 2, (W - 100) * n / mx, 11, fillColor=HC(SEVC[s]), strokeColor=None))
        dr.add(String(55 + (W - 100) * n / mx + 4, y + 4, str(n), fontSize=8))
    el += [box, Spacer(1, 6), kp, Spacer(1, 6), Paragraph("<b>Open issues by severity</b>", body), dr, Paragraph("Fix these first", h2)]
    for i, f in enumerate(d["top"], 1):
        meta = f"{f['ip']}:{f['port']}/{f['proto']}  |  {f['confidence']}  |  {f['status']}" + (f"  |  owner {f['owner']}" if f["owner"] else "") + (f"  |  due {f['due_date']}" if f["due_date"] else "")
        card = Table([[Paragraph(f"<b>{i}. {t(f['title'], 110)}</b>  [{sevtag(f['sev'])}]", body)], [P(meta, small)],
                      [Paragraph(f"<b>Why it matters.</b> {t(f['why'], 600)}", body)], [Paragraph(f"<b>How to fix.</b> {t(f['fix'], 600)}", body)]], colWidths=[W])
        card.setStyle(TableStyle([("LINEBEFORE", (0, 0), (0, -1), 6, HC(SEVC.get(f["sev"], "#888888"))), ("BOX", (0, 0), (-1, -1), 0.25, HC("#d5dbe3")), ("LEFTPADDING", (0, 0), (-1, -1), 10)]))
        el += [KeepTogether([card, Spacer(1, 6)])]
    if not d["top"]:
        el.append(P("Nothing needs action right now."))
    if d["retest"]:
        rt = d["retest"]
        el += [Paragraph("Progress since the last retest", h2),
               P(f"Last retest {rt['at']}: {rt['closed']} confirmed fixed, {rt['still']} still present, {rt['inconclusive']} could not be confirmed.")]
        el += [P(f"- Fixed and verified: #{f['id']} {f['title']} on {f['ip']}:{f['port']} ({f.get('closed_at', '')})", small) for f in d["closed"]]
    el += [Paragraph("By host", h2), table(["Host", "Open services", "Open issues", "Worst"],
           [[P(h["ip"] + (f" ({h['name']})" if h["name"] else ""), cell), P(", ".join(f"{s['port']}/{s['service'] or '?'}" for s in h["services"])[:200] or "none seen", cell),
             P(str(h["findings"]), cell), Paragraph(sevtag(h["worst"]) if h["worst"] != "None" else "-", cell)] for h in d["hosts"]], [.2, .5, .15, .15])]
    el += [Paragraph("Remediation tracker", h2), table(["#", "Severity", "Finding", "Owner", "Due", "Status"],
           [[str(f["id"]), Paragraph(sevtag(f["sev"]), cell), P(f"{f['title']} ({f['ip']}:{f['port']})", cell, 140), f["owner"] or "-",
             (f["due_date"] or "-") + (" OVERDUE" if f["overdue"] else ""), f["status"]] for f in d["tracker"]], [.05, .11, .44, .1, .15, .15])]
    el += [Paragraph("All findings", h2), table(["#", "Severity", "Confidence", "Where", "Finding", "Status"],
           [[str(f["id"]), Paragraph(sevtag(f["sev"]), cell), f["confidence"], f"{f['ip']}:{f['port']}", P(f["title"], cell, 140), f["status"]] for f in d["findings"]],
           [.05, .1, .13, .17, .38, .17])]
    el.append(Paragraph("Details and evidence", h2))
    for f in d["findings"]:
        parts = [Paragraph(f"<b>#{f['id']} {t(f['title'], 120)}</b>  [{sevtag(f['sev'])}]", h3),
                 P(f"{f['ip']}:{f['port']}/{f['proto']} | {f['vuln_id']} | seen by {f['seen_by']} | {f['confidence']} | {f['status']}", small),
                 Paragraph(f"<b>What it is.</b> {t(f['why'], 500)}", body), Paragraph(f"<b>How to fix.</b> {t(f['fix'], 500)}", body)]
        if f["evidence"]:
            parts.append(Paragraph(t(f["evidence"][0], 450).replace("\n", "<br/>"), mono))
        el += [KeepTogether(parts + [Spacer(1, 7)])]
    el += [Paragraph("How to read this report", h2), table(["Term", "Meaning"], [[P(a, cell), P(b, cell)] for a, b in d["glossary"]], [.28, .72]),
           Paragraph("Scope and method", h2), table(["Item", "Value"], [["Authorization", f"{d['authorized_by']} ({d['auth_reference']})"], ["Window", d["window"]],
           ["Targets", d["targets"]], ["Resolved names", d["resolved"]], ["Excluded", d["excluded"]], ["Port coverage", d["ports"]], ["Tools", d["tools"]],
           ["Scope SHA-256", d["scope_sha"]]], [.22, .78])] + [P("- " + x, small) for x in d["limits"]]

    def deco(c, doc):
        c.saveState()
        c.setFont("Helvetica", 8)
        c.setFillColor(colors.grey)
        c.drawString(15 * mm, 9 * mm, t(f"{d['engagement']} - Security Posture Assessment"))
        c.drawRightString(A4[0] - 15 * mm, 9 * mm, f"Page {doc.page}")
        c.restoreState()
    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=14 * mm, bottomMargin=18 * mm,
                      title=f"Security Posture Assessment - {t(d['engagement'])}", author="Posture Tracker").build(el, onFirstPage=deco, onLaterPages=deco)
    return buf.getvalue()


def render_bytes(con, scope, fmt):
    """Return (bytes, mime) for one format."""
    if fmt == "md":
        body = report.build(con, scope)
    else:
        d = collect(con, scope)
        body = {"html": lambda: render_html(d), "pdf": lambda: render_pdf(d), "csv": lambda: render_csv(d), "json": lambda: render_json(d)}[fmt]()
    return (body if isinstance(body, bytes) else body.encode("utf-8")), MIME[fmt]


def generate(con, scope, eng, formats=("html",)):
    """Write the chosen formats into reports/<timestamp>/ . Returns (paths, errors)."""
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    folder, n = eng.reports_dir / stamp, 1
    while folder.exists():
        n += 1
        folder = eng.reports_dir / f"{stamp}-{n}"
    folder.mkdir()
    paths, errors = {}, {}
    for fmt in formats:
        try:
            data, _ = render_bytes(con, scope, fmt)
            p = folder / FILENAME.get(fmt, f"report.{fmt}")
            p.write_bytes(data)
            paths[fmt] = p
        except RuntimeError as e:
            errors[fmt] = str(e)
    return paths, errors
