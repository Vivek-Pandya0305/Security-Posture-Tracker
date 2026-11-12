import argparse
import datetime as dt
import shutil
import subprocess
import sys

from . import db, guard, render, scan, track, workspace


def _ctx(a):
    eng = workspace.resolve(getattr(a, "engagement", None))
    return eng, db.connect(str(eng.db_path), must_exist=False)


def cmd_init(a):
    eng = workspace.create(a.name, a.target)
    rel = eng.root.relative_to(workspace.home()) if eng.root.is_relative_to(workspace.home()) else eng.root
    print(f"Created engagement '{eng.name}' at {rel}/\n"
          f"  scope.yaml        <- edit: authorized_by, auth_reference, targets, window\n"
          f"  authorization/    <- save the signed authorization here\n"
          f"  raw/ logs/ reports/ evidence/   (created automatically as you scan)\n"
          f"It is now the current engagement.\nNext: edit {rel}/scope.yaml, then run: posture doctor")


def cmd_use(a):
    eng = workspace.resolve(a.name)
    workspace.set_current(eng)
    print(f"Current engagement: {eng.name}")


def cmd_list(a):
    cur = None
    try:
        cur = workspace.resolve().name
    except ValueError:
        pass
    items = workspace.list_engagements()
    if not items:
        print("No engagements yet. Create one: posture init <name>")
    for e in items:
        print(f"{'*' if e.name == cur else ' '} {e.name}")


def cmd_doctor(a):
    def line(n, good, msg):
        print(f"[{'OK' if good else '!!'}] {n}: {msg}")
    line("python", sys.version_info >= (3, 10), sys.version.split()[0])
    nm = shutil.which("nmap")
    line("nmap", bool(nm), nm or "missing -> sudo apt install nmap")
    if nm:
        r = subprocess.run(["nmap", "--script-help", "vulners"], capture_output=True, text=True)
        line("vulners NSE script", r.returncode == 0 and "vulners" in r.stdout.lower(),
             "found" if r.returncode == 0 else "not found -> see README")
    nu = shutil.which("nuclei")
    line("nuclei", bool(nu), nu or "missing (optional) -> see README")
    ts = shutil.which("testssl.sh") or shutil.which("testssl")
    line("testssl", bool(ts), ts or "missing (optional) -> see README")
    nk = shutil.which("nikto")
    line("nikto", bool(nk), nk or "missing (optional) -> sudo apt install nikto")
    try:
        import flask  # noqa: F401
        line("flask (web UI)", True, "installed")
    except ImportError:
        line("flask (web UI)", False, "missing -> pip install flask")
    try:
        eng = workspace.resolve(a.engagement)
    except ValueError as e:
        return line("engagement", False, str(e))
    line("engagement", True, str(eng.root))
    try:
        s = guard.load_scope(eng.scope_path)
        auth = guard.authorize(s)
        line("scope", True, f"valid until {s.end:%Y-%m-%d}; {len(auth.targets)} target network(s); ports={s.ports}")
        if auth.names:
            line("dns", True, "; ".join(f"{n} -> {i}" for i, n in auth.names))
    except guard.ScopeError as e:
        line("scope", False, str(e))


def _scan(a, rtype):
    eng, con = _ctx(a)
    scope = guard.load_scope(eng.scope_path)
    r = scan.execute(con, scope, eng, rtype, targets=getattr(a, "target", None) or None, log=print)
    print(f"{rtype.capitalize()} complete. New findings: {r['new']}. Observed this run: {r['observed']}.")
    for k, v in r["tools"].items():
        print(f"  {k}: {v}")
    if r["retest"] is not None:
        c = r["retest"]
        print(f"Retest: still present={c['still_present']}, not detected (closed)={c['not_detected']}, inconclusive={c['inconclusive']}")
    print("Next: posture findings")


def cmd_inventory(a):
    eng, con = _ctx(a)
    rid = con.execute("SELECT MAX(id) FROM scan_runs WHERE tool IN ('nmap','nmap-discovery') AND ok=1").fetchone()[0]
    if not rid:
        print("No scans yet. Run: posture scan")
        return
    print(f"Engagement {eng.name}, Nmap run #{rid}")
    for r in con.execute("SELECT * FROM services WHERE run_id=? AND state='open' ORDER BY ip,port", (rid,)):
        pp = f"{r['port']}/{r['proto']}"
        print(f"{r['ip']:<16}{pp:<10}{r['service']:<14}{r['product']} {r['version']}")


def _detail(con, fid):
    f = con.execute("SELECT *, COALESCE(override_severity,severity) AS sev FROM findings WHERE id=?", (fid,)).fetchone()
    if not f:
        raise ValueError(f"No finding with id {fid}")
    for k in ("title", "sev", "confidence", "seen_by", "cvss", "ip", "port", "proto", "source", "vuln_id", "status", "owner",
              "due_date", "action", "approver", "expiry", "reason", "override_reason", "description"):
        if f[k] not in (None, ""):
            print(f"{k:>16}: {f[k]}")
    print("\nEvidence (latest 3):")
    for e in con.execute("SELECT run_id, excerpt FROM evidence WHERE finding_id=? ORDER BY id DESC LIMIT 3", (fid,)):
        print(f"  [run {e['run_id']}] " + e["excerpt"].replace("\n", "\n    "))
    print("\nRetests:")
    for r in con.execute("SELECT * FROM retests WHERE finding_id=? ORDER BY id", (fid,)):
        print(f"  {r['tested_at']}  run {r['run_id']}  {r['result']}")
    print("\nStatus history:")
    for r in con.execute("SELECT * FROM status_log WHERE finding_id=? ORDER BY id", (fid,)):
        print(f"  {r['at']}  {r['old']} -> {r['new']}  {r['note'] or ''}")


def cmd_findings(a):
    eng, con = _ctx(a)
    if a.id:
        return _detail(con, a.id)
    st = track.ALIASES.get(a.status, a.status) if a.status else None
    rows = track.list_findings(con, a.severity, st, a.open, a.confidence)
    if not rows:
        print("No findings match.")
        return
    today = dt.date.today().isoformat()
    print(f"{'ID':<4}{'SEV':<9}{'CONF':<13}{'STATUS':<24}{'HOST:PORT':<22}{'OWNER':<10}{'DUE':<11}TITLE")
    for f in rows:
        late = " (OVERDUE)" if f["due_date"] and f["due_date"] < today and f["status"] in track.ACTIVE else ""
        hp = f"{f['ip']}:{f['port']}"
        print(f"{f['id']:<4}{f['sev']:<9}{(f['confidence'] or ''):<13}{f['status']:<24}{hp:<22}{(f['owner'] or '-'):<10}"
              f"{(f['due_date'] or '-'):<11}{f['title'][:60]}{late}")


def cmd_fix(a):
    eng, con = _ctx(a)
    track.set_fix(con, a.id, a.owner, a.due, a.action, a.severity, a.reason)
    print(f"Finding {a.id} updated.")


def cmd_status(a):
    eng, con = _ctx(a)
    new = track.ALIASES.get(a.status)
    if not new:
        raise ValueError(f"Status must be one of: {', '.join(track.ALIASES)}")
    track.change_status(con, a.id, new, a.approver, a.expiry, a.reason)
    print(f"Finding {a.id} -> {new}")


def cmd_report(a):
    eng, con = _ctx(a)
    scope = guard.load_scope(eng.scope_path)
    track.expire_accepted(con)
    fmts = list(render.FORMATS) if a.format == "all" else [x.strip().lower() for x in a.format.split(",") if x.strip()]
    bad = [x for x in fmts if x not in render.FORMATS]
    if bad or not fmts:
        raise ValueError(f"--format must be a comma list of {', '.join(render.FORMATS)} or 'all' (got: {a.format})")
    paths, errors = render.generate(con, scope, eng, fmts)
    for fmt, p in paths.items():
        print(f"  {fmt:<5} {p}")
    for fmt, e in errors.items():
        print(f"  {fmt:<5} FAILED: {e}")
    if errors:
        raise RuntimeError("some report formats failed (see above)")


def cmd_web(a):
    try:
        from . import web
    except ImportError:
        raise RuntimeError("Flask is not installed. Run: pip install flask")
    web.serve(workspace.resolve(a.engagement), port=a.port, allow_scan=a.allow_scan, cooldown=a.cooldown)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="posture", description="Security posture assessment and remediation tracker")
    sp = ap.add_subparsers(dest="cmd", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-e", "--engagement", help="engagement name (default: current)")

    i = sp.add_parser("init", help="create a new engagement folder")
    i.add_argument("name")
    i.add_argument("-t", "--target", action="append", help="IP, range, CIDR or domain (repeatable, commas allowed)")
    i.set_defaults(f=cmd_init)
    u = sp.add_parser("use", help="select the current engagement")
    u.add_argument("name")
    u.set_defaults(f=cmd_use)
    sp.add_parser("list", help="list engagements").set_defaults(f=cmd_list)
    sp.add_parser("doctor", parents=[common], help="check tools, engagement and scope").set_defaults(f=cmd_doctor)
    s = sp.add_parser("scan", parents=[common], help="run authorized baseline scan")
    s.add_argument("--target", action="append", help="limit to targets inside scope (repeatable)")
    s.set_defaults(f=lambda a: _scan(a, "baseline"))
    sp.add_parser("retest", parents=[common], help="rescan and update finding statuses").set_defaults(f=lambda a: _scan(a, "retest"))
    sp.add_parser("inventory", parents=[common], help="list exposed services").set_defaults(f=cmd_inventory)
    f = sp.add_parser("findings", parents=[common], help="list findings, or show one with evidence")
    f.add_argument("id", nargs="?", type=int)
    f.add_argument("--severity")
    f.add_argument("--status")
    f.add_argument("--confidence", help="Corroborated | Tested | Unverified")
    f.add_argument("--open", action="store_true", help="only active findings")
    f.set_defaults(f=cmd_findings)
    x = sp.add_parser("fix", parents=[common], help="assign owner/due date/action, or override severity")
    x.add_argument("id", type=int)
    x.add_argument("--owner")
    x.add_argument("--due", help="YYYY-MM-DD")
    x.add_argument("--action")
    x.add_argument("--severity")
    x.add_argument("--reason")
    x.set_defaults(f=cmd_fix)
    t = sp.add_parser("status", parents=[common], help="open|remediation|fixed|accepted-risk|false-positive")
    t.add_argument("id", type=int)
    t.add_argument("status")
    t.add_argument("--approver")
    t.add_argument("--expiry", help="YYYY-MM-DD")
    t.add_argument("--reason")
    t.set_defaults(f=cmd_status)
    w = sp.add_parser("web", parents=[common], help="start the local web UI (127.0.0.1 only)")
    w.add_argument("--port", type=int, default=8765)
    w.add_argument("--allow-scan", action="store_true", help="enable the guarded scan-launch button")
    w.add_argument("--cooldown", type=int, default=300, help="seconds between web-launched scans")
    w.set_defaults(f=cmd_web)
    rp = sp.add_parser("report", parents=[common], help="generate reports (html, pdf, md, csv, json)")
    rp.add_argument("--format", default="html", help="comma list of html,pdf,md,csv,json or 'all' (default: html)")
    rp.set_defaults(f=cmd_report)
    a = ap.parse_args(argv)
    try:
        a.f(a)
        return 0
    except (guard.ScopeError, ValueError, RuntimeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
