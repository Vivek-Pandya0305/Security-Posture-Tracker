import pytest

from posture import db, parse, scan, track, web
from test_core import BASE, load, mk_engagement, mk_scope

TOKEN = "tok123"


def build(tmp_path, monkeypatch, **kw):
    eng = mk_engagement(tmp_path, monkeypatch)
    con = db.connect(str(eng.db_path), must_exist=False)
    raws = parse.nmap_findings(load(tmp_path, BASE), 7.0)
    raws.append(parse.Raw("192.168.56.101", 8080, "tcp", "nuclei", "xss-test", "<script>alert(1)</script>", "d", "Low", None, "<img src=x onerror=alert(1)>"))
    track.ingest(con, 1, raws)
    con.close()
    kw.setdefault("allow_scan", True)
    kw.setdefault("cooldown", 0)
    a = web.create_app(eng, token=TOKEN, **kw)
    a.eng = eng
    return a


@pytest.fixture
def client(tmp_path, monkeypatch):
    a = build(tmp_path, monkeypatch)
    c = a.test_client()
    assert c.get(f"/login?token={TOKEN}").status_code == 302
    with c.session_transaction() as s:
        c.csrf = s["csrf"]
    c.app, c.dbp, c.eng = a, str(a.eng.db_path), a.eng
    return c


def fid(c, vid):
    return db.connect(c.dbp, must_exist=False).execute("SELECT id FROM findings WHERE vuln_id=?", (vid,)).fetchone()[0]


def post(c, url, **data):
    return c.post(url, data={"csrf": c.csrf, **data}, follow_redirects=True)


def test_auth_required(tmp_path, monkeypatch):
    c = build(tmp_path, monkeypatch).test_client()
    assert c.get("/").status_code == 401 and c.get("/findings").status_code == 401
    assert c.get("/login?token=wrong").status_code == 403
    assert c.get(f"/login?token={TOKEN}").status_code == 302
    assert b"Dashboard" in c.get("/").data and b"lab" in c.get("/").data


def test_host_header_and_csrf_and_headers(client):
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 400
    assert client.post("/findings/1/status", data={"status": "fixed"}).status_code == 400
    h = client.get("/").headers
    assert h["X-Frame-Options"] == "DENY" and "default-src 'none'" in h["Content-Security-Policy"]


def test_views_and_output_escaping(client):
    page = client.get("/findings").data.decode()
    assert "Anonymous FTP" in page and "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page
    crit = client.get("/findings?severity=Critical").data.decode()
    assert "CVE-2011-2523" in crit and "Anonymous FTP" not in crit
    detail = client.get(f"/findings/{fid(client, 'xss-test')}").data.decode()
    assert "<img src=x" not in detail and "&lt;img" in detail
    assert client.get("/inventory").status_code == 200 and client.get("/findings/9999").status_code == 404
    rep = client.get("/report")
    assert rep.status_code == 200 and b"Security Posture Assessment Report" in rep.data


def test_fix_and_status_rules(client):
    f = fid(client, "NSE-FTP-ANON")
    assert b"Saved" in post(client, f"/findings/{f}/fix", owner="Asha", due="2030-01-01").data
    assert db.connect(client.dbp, must_exist=False).execute("SELECT owner FROM findings WHERE id=?", (f,)).fetchone()[0] == "Asha"
    assert b"Status set to Fixed" in post(client, f"/findings/{f}/status", status="fixed").data
    assert b"Illegal transition" in post(client, f"/findings/{f}/status", status="accepted-risk", approver="x", expiry="2099-01-01").data
    assert b"Unknown status" in post(client, f"/findings/{f}/status", status="verified-closed").data
    assert b"Error" in post(client, f"/findings/{f}/fix", due="not-a-date").data


def test_scan_disabled_by_default(tmp_path, monkeypatch):
    c = build(tmp_path, monkeypatch, allow_scan=False).test_client()
    c.get(f"/login?token={TOKEN}")
    with c.session_transaction() as s:
        csrf = s["csrf"]
    assert c.post("/scans/start", data={"csrf": csrf, "type": "baseline"}).status_code == 403
    assert b"disabled" in c.get("/scans").data


def test_scan_launch_safeguards(client, monkeypatch):
    calls = []
    monkeypatch.setattr(scan, "execute", lambda con, scope, eng, rt, targets=None, log=None: calls.append((rt, eng.name)) or
                        {"new": 1, "observed": 2, "tools": {"nuclei": "ok"}, "retest": None})
    ok = dict(type="baseline", confirm="t", ack="on")
    assert b"Confirmation failed" in post(client, "/scans/start", type="baseline", confirm="wrong", ack="on").data
    assert b"Confirmation failed" in post(client, "/scans/start", type="baseline", confirm="t").data
    assert calls == []
    client.app.jobs.state = {"running": True}
    assert b"already running" in post(client, "/scans/start", **ok).data
    client.app.jobs.state = {"running": False}
    assert b"baseline scan started" in post(client, "/scans/start", **ok).data
    client.app.jobs.thread.join(5)
    assert calls == [("baseline", "lab")] and client.app.jobs.state["result"]["new"] == 1
    client.app.jobs.cooldown = 999
    assert b"Cooldown active" in post(client, "/scans/start", **ok).data
    acts = {r[0] for r in db.connect(client.dbp, must_exist=False).execute("SELECT action FROM audit_log")}
    assert {"login", "scan_requested", "scan_finished", "scan_refused"} <= acts


def test_scan_refused_outside_window(client, monkeypatch):
    monkeypatch.setattr(scan, "execute", lambda *a, **k: pytest.fail("must not run"))
    mk_scope(client.eng.root, window_end="2021-01-01")
    assert b"expired" in post(client, "/scans/start", type="baseline", confirm="t", ack="on").data


def test_scan_failure_is_reported(client, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("nmap failed: x")
    monkeypatch.setattr(scan, "execute", boom)
    post(client, "/scans/start", type="retest", confirm="t", ack="on")
    client.app.jobs.thread.join(5)
    assert "nmap failed" in client.app.jobs.state["error"] and client.app.jobs.state["running"] is False


def test_report_views_and_downloads(client):
    page = client.get("/report")
    assert page.status_code == 200 and page.mimetype == "text/html" and b"Fix these first" in page.data and b"/report/pdf" in page.data
    assert b"<script" not in page.data
    pdf = client.get("/report/pdf")
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF") and "attachment" in pdf.headers["Content-Disposition"]
    assert client.get("/report/csv").mimetype == "text/csv" and client.get("/report/json").mimetype == "application/json"
    assert b"Security Posture" in client.get("/report/md").data and client.get("/report/exe").status_code == 404
    acts = [r[0] for r in db.connect(client.dbp, must_exist=False).execute("SELECT detail FROM audit_log WHERE action='report_download'")]
    assert {"pdf", "csv", "json", "md"} <= set(acts)
