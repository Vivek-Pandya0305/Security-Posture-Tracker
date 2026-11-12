"""Local web UI. Binds to 127.0.0.1 only. Scan launching is opt-in (--allow-scan) and heavily guarded."""
from __future__ import annotations

import datetime as dt
import hmac
import secrets
import threading
import time
from collections import Counter
from pathlib import Path  # noqa

from flask import Flask, Response, abort, flash, g, redirect, render_template, request, session
from jinja2 import DictLoader

from . import db, guard, render, scan, track

TPL = {
"base.html": """<!doctype html><html><head><meta charset="utf-8"><title>Posture Tracker</title>
<style>
:root{--bg:#fff;--fg:#1a1a1a;--mut:#666;--card:#f5f6f8;--bd:#d9dce1;--ac:#2557d6}
@media(prefers-color-scheme:dark){:root{--bg:#15171a;--fg:#e8e8e8;--mut:#9aa;--card:#1e2126;--bd:#343a40;--ac:#6b9cff}}
body{font:15px system-ui,sans-serif;background:var(--bg);color:var(--fg);margin:0}
nav{background:var(--card);border-bottom:1px solid var(--bd);padding:10px 20px;display:flex;gap:18px;flex-wrap:wrap}
nav a{color:var(--ac);text-decoration:none}main{padding:20px;max-width:1200px;margin:auto}
table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid var(--bd);padding:6px 8px;text-align:left;vertical-align:top}
.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:12px 16px;margin:10px 0}
.grid{display:flex;gap:12px;flex-wrap:wrap}.grid .card{min-width:110px;text-align:center}.n{font-size:26px;font-weight:600}
.sev-Critical{color:#c0182b;font-weight:600}.sev-High{color:#d9480f;font-weight:600}.sev-Medium{color:#b7791f}.sev-Low{color:#2b7a4b}
pre{background:var(--card);padding:8px;overflow:auto;border-radius:6px;white-space:pre-wrap}
input,select,button,textarea{font:inherit;padding:4px 6px}.flash{padding:8px 12px;border-radius:6px;margin:10px 0;background:var(--card);border:1px solid var(--bd)}
.mut{color:var(--mut)}form.inline{display:flex;gap:8px;flex-wrap:wrap;align-items:end}
</style></head><body>
<nav><b>Posture Tracker</b><span class="mut">{{ engagement }}</span><a href="/">Dashboard</a><a href="/findings">Findings</a><a href="/inventory">Inventory</a><a href="/scans">Scans</a><a href="/report">Report</a></nav>
<main>{% for m in get_flashed_messages() %}<div class="flash">{{ m }}</div>{% endfor %}{% block body %}{% endblock %}</main></body></html>""",

"index.html": """{% extends "base.html" %}{% block body %}<h2>Dashboard</h2>
<div class="grid"><div class="card"><div class="n">{{ active }}</div>active</div><div class="card"><div class="n">{{ total }}</div>total</div>
<div class="card"><div class="n">{{ overdue }}</div>overdue</div>
{% for s in sevs %}<div class="card"><div class="n sev-{{ s }}">{{ sev.get(s, 0) }}</div>{{ s }}</div>{% endfor %}</div>
<div class="card"><b>Confidence (active):</b> {% for k, v in conf.items() %}{{ k }}: {{ v }} &nbsp; {% else %}none{% endfor %}</div>
<div class="card"><b>Status:</b> {% for k, v in stt.items() %}{{ k }}: {{ v }} &nbsp; {% else %}none{% endfor %}</div>
<div class="card"><b>Last Nmap run:</b> {% if last %}#{{ last.id }} ({{ last.run_type }}) finished {{ last.finished_at }}{% else %}none yet. Run <code>posture scan</code>{% endif %}</div>
{% endblock %}""",

"findings.html": """{% extends "base.html" %}{% block body %}<h2>Findings</h2>
<form class="inline card" method="get">
<label>Severity<br><select name="severity"><option value="">any</option>{% for s in sevs %}<option {{ 'selected' if request.args.get('severity') == s }}>{{ s }}</option>{% endfor %}</select></label>
<label>Status<br><select name="status"><option value="">any</option>{% for s in statuses %}<option {{ 'selected' if request.args.get('status') == s }}>{{ s }}</option>{% endfor %}</select></label>
<label>Confidence<br><select name="confidence"><option value="">any</option>{% for s in ['Corroborated','Tested','Unverified'] %}<option {{ 'selected' if request.args.get('confidence') == s }}>{{ s }}</option>{% endfor %}</select></label>
<label>Host contains<br><input name="q" value="{{ request.args.get('q', '') }}"></label><button>Filter</button></form>
<table><tr><th>ID</th><th>Severity</th><th>Confidence</th><th>Status</th><th>Host:Port</th><th>Finding</th><th>Owner</th><th>Due</th></tr>
{% for f in rows %}<tr><td>{{ f.id }}</td><td class="sev-{{ f.sev }}">{{ f.sev }}</td><td>{{ f.confidence }}</td><td>{{ f.status }}</td>
<td>{{ f.ip }}:{{ f.port }}</td><td><a href="/findings/{{ f.id }}">{{ f.title }}</a></td><td>{{ f.owner or '-' }}</td><td>{{ f.due_date or '-' }}</td></tr>
{% else %}<tr><td colspan="8" class="mut">No findings match.</td></tr>{% endfor %}</table>{% endblock %}""",

"finding.html": """{% extends "base.html" %}{% block body %}<h2>#{{ f.id }} {{ f.title }}</h2>
<div class="card"><span class="sev-{{ f.sev }}">{{ f.sev }}</span> &middot; confidence: <b>{{ f.confidence }}</b> (seen by {{ f.seen_by }}) &middot; status: <b>{{ f.status }}</b><br>
{{ f.ip }}:{{ f.port }}/{{ f.proto }} &middot; {{ f.vuln_id }}{% if f.cvss %} &middot; CVSS {{ f.cvss }}{% endif %}<p>{{ f.description }}</p>
{% if f.override_severity %}<p class="mut">Severity overridden from {{ f.severity }}: {{ f.override_reason }}</p>{% endif %}
{% if f.status == 'Accepted Risk' %}<p>Accepted by {{ f.approver }} until {{ f.expiry }}: {{ f.reason }}</p>{% endif %}</div>
<div class="card"><b>Remediation</b>
<form class="inline" method="post" action="/findings/{{ f.id }}/fix"><input type="hidden" name="csrf" value="{{ csrf }}">
<label>Owner<br><input name="owner" value="{{ f.owner or '' }}"></label><label>Due<br><input type="date" name="due" value="{{ f.due_date or '' }}"></label>
<label>Action<br><input name="action" value="{{ f.action or '' }}" size="34"></label>
<label>Override severity<br><select name="severity"><option value="">no change</option>{% for s in sevs %}<option>{{ s }}</option>{% endfor %}</select></label>
<label>Reason<br><input name="reason"></label><button>Save</button></form></div>
<div class="card"><b>Change status</b> {% if not allowed %}<span class="mut">(no manual moves from {{ f.status }}; retest decides)</span>{% endif %}
{% if allowed %}<form class="inline" method="post" action="/findings/{{ f.id }}/status"><input type="hidden" name="csrf" value="{{ csrf }}">
<label>New status<br><select name="status">{% for a, l in allowed %}<option value="{{ a }}">{{ l }}</option>{% endfor %}</select></label>
<label>Approver<br><input name="approver"></label><label>Expiry<br><input type="date" name="expiry"></label><label>Reason<br><input name="reason"></label>
<button>Apply</button></form>{% endif %}</div>
<h3>Evidence</h3>{% for e in evidence %}<pre>[run {{ e.run_id }}] {{ e.excerpt }}</pre>{% else %}<p class="mut">none</p>{% endfor %}
<h3>Retests</h3><table>{% for r in retests %}<tr><td>{{ r.tested_at }}</td><td>run {{ r.run_id }}</td><td>{{ r.result }}</td></tr>{% else %}<tr><td class="mut">none yet</td></tr>{% endfor %}</table>
<h3>Status history</h3><table>{% for r in history %}<tr><td>{{ r.at }}</td><td>{{ r.old }} &rarr; {{ r.new }}</td><td>{{ r.note }}</td></tr>{% endfor %}</table>{% endblock %}""",

"inventory.html": """{% extends "base.html" %}{% block body %}<h2>Service inventory {% if rid %}(Nmap run #{{ rid }}){% endif %}</h2>
<table><tr><th>Host</th><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr>
{% for r in rows %}<tr><td>{{ r.ip }}</td><td>{{ r.port }}/{{ r.proto }}</td><td>{{ r.service }}</td><td>{{ r.product }}</td><td>{{ r.version }}</td></tr>
{% else %}<tr><td colspan="5" class="mut">No scan yet.</td></tr>{% endfor %}</table>{% endblock %}""",

"scans.html": """{% extends "base.html" %}{% block body %}{% if job.get('running') %}<meta http-equiv="refresh" content="5">{% endif %}
<h2>Scans</h2>
<div class="card"><b>Scope</b><br>{% if scope %}Engagement: {{ scope.engagement }}<br>Authorized by: {{ scope.authorized_by }}<br>
Window: {{ scope.start.strftime('%Y-%m-%d') }} to {{ scope.end.strftime('%Y-%m-%d') }} (UTC)<br>Targets: {{ (scope.targets|map('string')|list + scope.target_names)|join(', ') }}<br>Excluded: {{ scope.exclusions|join(', ') or 'none' }}
{% else %}<span class="mut">{{ scope_error }}</span>{% endif %}</div>
<div class="card"><b>Job</b><br>{% if job.get('running') %}Running {{ job.type }} since {{ job.started }} (page refreshes)...
{% elif job.get('finished') %}Last: {{ job.type }} finished {{ job.finished }}. {% if job.error %}<b>Error:</b> {{ job.error }}{% else %}New findings: {{ job.result.new }}; tools: {{ job.result.tools }}{% if job.result.retest %}; retest: {{ job.result.retest }}{% endif %}{% endif %}
{% else %}<span class="mut">no scan launched from this session</span>{% endif %}</div>
{% if allow_scan %}<div class="card"><b>Launch scan</b>
<p class="mut">Guards: scope window and IP check, allowlisted tools, one scan at a time, {{ cooldown }}s cooldown, audit log. Review the scope above first.</p>
<form class="inline" method="post" action="/scans/start"><input type="hidden" name="csrf" value="{{ csrf }}">
<label>Type<br><select name="type"><option value="baseline">baseline</option><option value="retest">retest</option></select></label>
<label>Type the engagement name to confirm<br><input name="confirm" autocomplete="off"></label>
<label><input type="checkbox" name="ack"> I own or am authorized to test these targets</label><button>Start scan</button></form></div>
{% else %}<div class="card mut">Scan launching is disabled. Restart with <code>posture web --allow-scan</code> to enable it.</div>{% endif %}
<h3>Recent runs</h3><table><tr><th>Run</th><th>Tool</th><th>Type</th><th>Started</th><th>OK</th></tr>
{% for r in runs %}<tr><td>{{ r.id }}</td><td>{{ r.tool }}</td><td>{{ r.run_type }}</td><td>{{ r.started_at }}</td><td>{{ 'yes' if r.ok else 'no' }}</td></tr>{% endfor %}</table>
<h3>Audit log</h3><table>{% for a in audit %}<tr><td>{{ a.at }}</td><td>{{ a.action }}</td><td>{{ a.detail }}</td></tr>{% endfor %}</table>{% endblock %}""",
}


class Jobs:
    """Single-flight background scan runner with cooldown."""

    def __init__(self, cooldown):
        self.cooldown, self.lock, self.state, self.thread, self.last_end = cooldown, threading.Lock(), {"running": False}, None, 0.0

    def start(self, cfg, rtype):
        with self.lock:
            if self.state.get("running"):
                raise ValueError("A scan is already running")
            wait = self.cooldown - (time.time() - self.last_end)
            if wait > 0:
                raise ValueError(f"Cooldown active: wait {int(wait) + 1}s before the next scan")
            self.state = {"running": True, "type": rtype, "started": db.now(), "result": None, "error": None}
            self.thread = threading.Thread(target=self._run, args=(cfg, rtype), daemon=True)
            self.thread.start()

    def _run(self, cfg, rtype):
        err = None
        try:
            con = db.connect(cfg["db"])
            r = scan.execute(con, guard.load_scope(cfg["scope"]), cfg["eng"], rtype)
            con.close()
            self.state["result"] = {"new": r["new"], "observed": r["observed"], "tools": r["tools"], "retest": dict(r["retest"] or {})}
        except Exception as e:  # any failure must reach the UI and audit log
            err = str(e)
            self.state["error"] = err
        finally:
            self.last_end = time.time()
            self.state.update(running=False, finished=db.now())
            db.audit(cfg["db"], "scan_finished", f"{rtype} error={err}" if err else f"{rtype} ok")


def create_app(eng, token=None, allow_scan=False, cooldown=300):
    app = Flask(__name__)
    app.jinja_env.loader = DictLoader(TPL)
    app.secret_key = secrets.token_hex(32)
    app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict", MAX_CONTENT_LENGTH=64 * 1024)
    app.token = token or secrets.token_urlsafe(24)
    cfg = {"db": str(eng.db_path), "scope": str(eng.scope_path), "eng": eng}
    app.jobs, app.cfg, fails = Jobs(cooldown), cfg, {"n": 0}

    def con():
        if "con" not in g:
            g.con = db.connect(cfg["db"], must_exist=False)
        return g.con

    @app.teardown_appcontext
    def _close(_):
        c = g.pop("con", None)
        if c:
            c.close()

    @app.before_request
    def _gate():
        if request.host.split(":")[0] not in ("127.0.0.1", "localhost"):
            abort(400)                                   # blocks DNS-rebinding style access
        if request.endpoint == "login":
            return None
        if not session.get("auth"):
            return Response("Authentication required. Open the URL printed by `posture web`.", 401)
        if request.method == "POST" and not hmac.compare_digest(request.form.get("csrf", "").encode(), session.get("csrf", "").encode()):
            abort(400)
        return None

    @app.after_request
    def _headers(r):
        r.headers["X-Frame-Options"] = "DENY"
        r.headers["X-Content-Type-Options"] = "nosniff"
        r.headers["Cache-Control"] = "no-store"
        r.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        return r

    @app.context_processor
    def _ctx():
        return {"csrf": session.get("csrf", ""), "allow_scan": allow_scan, "sevs": track.SEVERITIES, "cooldown": app.jobs.cooldown, "engagement": eng.name}

    @app.route("/login")
    def login():
        t = request.args.get("token", "")
        if fails["n"] >= 10:
            abort(429)
        if t and hmac.compare_digest(t.encode(), app.token.encode()):
            session.clear()
            session["auth"], session["csrf"] = True, secrets.token_hex(16)
            db.audit(cfg["db"], "login", "ok")
            return redirect("/")
        if t:
            fails["n"] += 1
            db.audit(cfg["db"], "login_failed", "bad token")
        return Response("Authentication required. Open the URL printed by `posture web`.", 403)

    @app.route("/")
    def index():
        fs = track.list_findings(con())
        act = [f for f in fs if f["status"] in track.ACTIVE]
        today = dt.date.today().isoformat()
        last = con().execute("SELECT * FROM scan_runs WHERE tool IN ('nmap','nmap-discovery') AND ok=1 ORDER BY id DESC LIMIT 1").fetchone()
        return render_template("index.html", sev=Counter(f["sev"] for f in act), stt=Counter(f["status"] for f in fs),
                               conf=Counter(f["confidence"] for f in act), total=len(fs), active=len(act), last=last,
                               overdue=sum(1 for f in act if f["due_date"] and f["due_date"] < today))

    @app.route("/findings")
    def findings():
        a = request.args
        rows = track.list_findings(con(), a.get("severity") or None, a.get("status") or None, False, a.get("confidence") or None)
        if a.get("q"):
            rows = [r for r in rows if a["q"] in r["ip"]]
        return render_template("findings.html", rows=rows, statuses=list(track.TRANSITIONS))

    @app.route("/findings/<int:fid>")
    def finding(fid):
        c = con()
        f = c.execute("SELECT *, COALESCE(override_severity, severity) AS sev FROM findings WHERE id=?", (fid,)).fetchone()
        if not f:
            abort(404)
        allowed = [(k, v) for k, v in track.ALIASES.items() if v in track.TRANSITIONS.get(f["status"], set())]
        return render_template("finding.html", f=f, allowed=allowed,
                               evidence=c.execute("SELECT * FROM evidence WHERE finding_id=? ORDER BY id DESC LIMIT 5", (fid,)).fetchall(),
                               retests=c.execute("SELECT * FROM retests WHERE finding_id=? ORDER BY id", (fid,)).fetchall(),
                               history=c.execute("SELECT * FROM status_log WHERE finding_id=? ORDER BY id", (fid,)).fetchall())

    def _form(*names):
        return [request.form.get(n, "").strip()[:300] or None for n in names]

    @app.route("/findings/<int:fid>/fix", methods=["POST"])
    def fix(fid):
        try:
            owner, due, action, sev, reason = _form("owner", "due", "action", "severity", "reason")
            track.set_fix(con(), fid, owner, due, action, sev, reason)
            db.audit(cfg["db"], "fix_update", f"#{fid}")
            flash("Saved")
        except ValueError as e:
            flash(f"Error: {e}")
        return redirect(f"/findings/{fid}")

    @app.route("/findings/<int:fid>/status", methods=["POST"])
    def status(fid):
        try:
            alias, approver, expiry, reason = _form("status", "approver", "expiry", "reason")
            new = track.ALIASES.get(alias or "")
            if not new:
                raise ValueError("Unknown status")
            track.change_status(con(), fid, new, approver, expiry, reason)
            db.audit(cfg["db"], "status_change", f"#{fid} -> {new}")
            flash(f"Status set to {new}")
        except ValueError as e:
            flash(f"Error: {e}")
        return redirect(f"/findings/{fid}")

    @app.route("/inventory")
    def inventory():
        rid = con().execute("SELECT MAX(id) FROM scan_runs WHERE tool IN ('nmap','nmap-discovery') AND ok=1").fetchone()[0]
        rows = con().execute("SELECT * FROM services WHERE run_id=? AND state='open' ORDER BY ip, port", (rid,)).fetchall() if rid else []
        return render_template("inventory.html", rows=rows, rid=rid)

    @app.route("/scans")
    def scans():
        try:
            scope, err = guard.load_scope(cfg["scope"]), ""
        except guard.ScopeError as e:
            scope, err = None, str(e)
        return render_template("scans.html", scope=scope, scope_error=err, job=app.jobs.state,
                               runs=con().execute("SELECT * FROM scan_runs ORDER BY id DESC LIMIT 15").fetchall(),
                               audit=con().execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 15").fetchall())

    @app.route("/scans/start", methods=["POST"])
    def scans_start():
        if not allow_scan:
            abort(403)
        rtype = request.form.get("type")
        if rtype not in ("baseline", "retest"):
            abort(400)
        try:
            scope = guard.load_scope(cfg["scope"])
            guard.authorize(scope)                                    # window / scope / allowlist re-checked at launch
            if request.form.get("confirm", "") != scope.engagement or not request.form.get("ack"):
                raise ValueError("Confirmation failed: type the exact engagement name and tick the checkbox")
            db.audit(cfg["db"], "scan_requested", f"{rtype} scope={scope.sha256[:12]}")
            app.jobs.start(cfg, rtype)
            flash(f"{rtype} scan started")
        except (guard.ScopeError, ValueError) as e:
            db.audit(cfg["db"], "scan_refused", str(e))
            flash(f"Refused: {e}")
        return redirect("/scans")

    @app.route("/report")
    @app.route("/report/<fmt>")
    def report_view(fmt="view"):
        scope = guard.load_scope(cfg["scope"])
        if fmt == "view":
            return Response(render.render_html(render.collect(con(), scope), web=True), mimetype="text/html")
        if fmt not in render.FORMATS:
            abort(404)
        db.audit(cfg["db"], "report_download", fmt)
        try:
            data, mime = render.render_bytes(con(), scope, fmt)
        except RuntimeError as e:
            return Response(str(e), 501)
        return Response(data, mimetype=mime, headers={"Content-Disposition": f"attachment; filename={render.FILENAME.get(fmt, 'posture-report.' + fmt)}"})

    return app


def serve(eng, port=8765, allow_scan=False, cooldown=300):
    token = secrets.token_urlsafe(24)
    app = create_app(eng, token, allow_scan, cooldown)
    print(f"Engagement: {eng.name}")
    print(f"Open: http://127.0.0.1:{port}/login?token={token}")
    print("Scan launching: " + ("ENABLED (--allow-scan)" if allow_scan else "disabled (start with --allow-scan to enable)"))
    print("Bound to 127.0.0.1 only. Press Ctrl+C to stop.")
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
