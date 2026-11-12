import datetime as dt
import os
import socket

import pytest
import yaml

from posture import cli, db, guard, parse, scan, track, workspace

FTP_ANON = '<script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/>\n'
VULNERS = ('<script id="vulners" output="&#xa;  cpe:/a:vsftpd:vsftpd:2.3.4: &#xa;    &#x9;CVE-2011-2523&#x9;9.8&#x9;'
           'https://vulners.com/cve/CVE-2011-2523&#xa;    &#x9;CVE-2001-0001&#x9;2.0&#x9;https://x"/>')
TELNET = '<port protocol="tcp" portid="23"><state state="open"/><service name="telnet" product="Linux telnetd"/></port>\n'
BASE = f"""<nmaprun>
<host><status state="up"/><address addr="192.168.56.101" addrtype="ipv4"/><ports>
<extraports state="closed" count="995"/>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="2.3.4"/>
{FTP_ANON}{VULNERS}</port>
{TELNET}<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.2.8"/>
<script id="http-methods" output="Supported Methods: GET&#xa;Potentially risky methods: TRACE"/></port>
</ports></host>
<host><status state="up"/><address addr="192.168.56.102" addrtype="ipv4"/><ports><extraports state="filtered" count="1000"/></ports></host>
</nmaprun>"""
FIXED = BASE.replace(FTP_ANON, "").replace(TELNET, "").replace(VULNERS, "").replace('version="2.3.4"', 'version="2.3.5"')
NUCLEI = ('{"template-id":"exposed-panel","info":{"name":"Admin Panel Exposed","severity":"medium",'
          '"classification":{"cve-id":null,"cvss-score":0}},"host":"192.168.56.101",'
          '"matched-at":"http://192.168.56.101:80/admin","ip":"192.168.56.101","type":"http"}\n')

FAKES = {
    "nmap": '#!/usr/bin/env python3\nimport sys,os,shutil\na=sys.argv\nsrc=os.environ["FAKE_NMAP_XML"]\n'
            'if "-sV" not in a and os.environ.get("FAKE_NMAP_DISCOVERY"):\n    src=os.environ["FAKE_NMAP_DISCOVERY"]\n'
            'shutil.copy(src, a[a.index("-oX")+1])\n',
    "nuclei": '#!/usr/bin/env python3\nimport sys,os\na=sys.argv\nf=os.environ.get("FAKE_NUCLEI")\n'
              'open(a[a.index("-o")+1],"w").write(open(f).read() if f else "")\n',
    "testssl": '#!/usr/bin/env python3\nimport sys,os\na=sys.argv\nopen(a[a.index("--jsonfile")+1],"w").write(open(os.environ["FAKE_TESTSSL"]).read())\n',
    "nikto": '#!/usr/bin/env python3\nimport sys,os\nif os.environ.get("FAKE_NIKTO_FAIL"):\n    sys.stderr.write("boom: cannot connect\\n"); sys.exit(2)\n'
             'print(open(os.environ["FAKE_NIKTO"]).read())\n',
}


def mk_scope(tmp_path, **over):
    d = dict(engagement="t", authorized_by="Me", auth_reference="doc", window_start="2020-01-01",
             window_end="2099-12-31", targets=["192.168.56.0/24"], exclusions=["192.168.56.1"],
             nse_scripts=["vulners", "ftp-anon"])
    d.update(over)
    p = tmp_path / "scope.yaml"
    p.write_text(yaml.safe_dump(d))
    return guard.load_scope(p)


def load(tmp_path, xml, name="x.xml"):
    p = tmp_path / name
    p.write_text(xml)
    return parse.parse_nmap(p)


def mk_engagement(tmp_path, monkeypatch, name="lab", **over):
    monkeypatch.setenv("POSTURE_HOME", str(tmp_path))
    monkeypatch.delenv("POSTURE_ENGAGEMENT", raising=False)
    assert cli.main(["init", name]) == 0
    eng = workspace.resolve(name)
    mk_scope(eng.root, **over)                 # replace the CHANGE_ME template with an authorized test scope
    return eng


def install_fakes(tmp_path, monkeypatch, names):
    b = tmp_path / "bin"
    b.mkdir(exist_ok=True)
    for n in names:
        (b / n).write_text(FAKES[n])
        (b / n).chmod(0o755)
    monkeypatch.setenv("PATH", f"{b}{os.pathsep}{os.environ['PATH']}")


@pytest.fixture
def con(tmp_path):
    c = db.connect(":memory:", must_exist=False)
    track.ingest(c, 1, parse.nmap_findings(load(tmp_path, BASE), 7.0))
    return c


def st(con, vid):
    return con.execute("SELECT status FROM findings WHERE vuln_id=?", (vid,)).fetchone()[0]


def retest(con, tmp_path, xml, **kw):
    res = load(tmp_path, xml, "r.xml")
    _, obs = track.ingest(con, 2, parse.nmap_findings(res, 7.0))
    return track.evaluate(con, 2, res, obs, **kw)


# ---------- guard: scope, windows, formats
def test_guard_allows_and_excludes(tmp_path):
    s = mk_scope(tmp_path)
    a = guard.authorize(s)
    assert a.targets == ("192.168.56.0/24",) and "192.168.56.1/32" in a.exclusions
    assert a.permits("192.168.56.101") and not a.permits("192.168.56.1") and not a.permits("10.0.0.1")
    assert guard.authorize(s, ["192.168.56.101"]).targets == ("192.168.56.101/32",)


@pytest.mark.parametrize("t", ["10.0.0.5", "192.168.57.1", "192.168.56.1", "0.0.0.0/0"])
def test_guard_refuses(tmp_path, t):
    with pytest.raises(guard.ScopeError):
        guard.authorize(mk_scope(tmp_path), [t])


def test_guard_window(tmp_path):
    with pytest.raises(guard.ScopeError, match="not started"):
        guard.authorize(mk_scope(tmp_path, window_start="2030-01-01"))
    with pytest.raises(guard.ScopeError, match="expired"):
        guard.authorize(mk_scope(tmp_path, window_end="2021-01-01"))


def test_target_formats_ip_list_range_cidr_domain(tmp_path, monkeypatch):
    monkeypatch.setattr(guard, "_resolve", lambda n: ["192.168.56.200"])
    s = mk_scope(tmp_path, exclusions=[], targets=["192.168.56.101", "192.168.56.102, 192.168.56.103", "192.168.56.10-12", "10.0.0.0/30", "Lab.Test"])
    a = guard.authorize(s)
    for ip in ("192.168.56.101", "192.168.56.103", "192.168.56.10", "192.168.56.11", "192.168.56.12", "10.0.0.2", "192.168.56.200"):
        assert a.permits(ip), ip
    assert not a.permits("192.168.56.13") and not a.permits("10.0.0.9")
    assert a.names == (("192.168.56.200", "lab.test"),) and a.names_for("192.168.56.200") == ["lab.test"]
    assert mk_scope(tmp_path, targets="192.168.56.5, 192.168.56.6").targets[1].network_address == guard.ipaddress.ip_address("192.168.56.6")


@pytest.mark.parametrize("t", ["http://x.com", "999.1.1.1", "bad_host!", "2001:db8::1", "192.168.56.20-10", "10.0.0.0/8/9"])
def test_invalid_targets_rejected(tmp_path, t):
    with pytest.raises(guard.ScopeError):
        mk_scope(tmp_path, targets=[t])


def test_domain_rules(tmp_path, monkeypatch):
    monkeypatch.setattr(guard, "_resolve", lambda n: ["8.8.8.8"])
    with pytest.raises(guard.ScopeError, match="private"):
        guard.authorize(mk_scope(tmp_path, targets=["pub.test"], exclusions=[]))
    assert guard.authorize(mk_scope(tmp_path, targets=["pub.test"], exclusions=[], allow_public=True)).permits("8.8.8.8")
    monkeypatch.setattr(guard, "_resolve", lambda n: ["192.168.56.200"])        # excluded by name
    s = mk_scope(tmp_path, exclusions=["bad.test"])
    assert not guard.authorize(s).permits("192.168.56.200")
    with pytest.raises(guard.ScopeError, match="excluded"):
        guard.authorize(s, ["192.168.56.200"])


def test_unresolvable_domain(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise socket.gaierror("nope")
    monkeypatch.setattr(guard.socket, "getaddrinfo", boom)
    with pytest.raises(guard.ScopeError, match="Cannot resolve"):
        guard.authorize(mk_scope(tmp_path, targets=["nope.test"], exclusions=[]))


def test_guard_scripts_and_placeholder(tmp_path):
    with pytest.raises(guard.ScopeError, match="allowlist"):
        guard.authorize(mk_scope(tmp_path, nse_scripts=["ftp-vsftpd-backdoor"]))
    with pytest.raises(guard.ScopeError, match="CHANGE_ME"):
        mk_scope(tmp_path, authorized_by="CHANGE_ME")
    with pytest.raises(guard.ScopeError, match="ports"):
        mk_scope(tmp_path, ports="1-100;rm")
    with pytest.raises(guard.ScopeError, match="workers"):
        mk_scope(tmp_path, performance={"workers": 99})


def test_scanner_refuses_without_authorization(tmp_path):
    with pytest.raises(guard.ScopeError):
        scan._exec(["echo", "x"], None, 5)
    with pytest.raises(guard.ScopeError, match="not permitted"):
        scan._exec(["echo", "x"], guard.authorize(mk_scope(tmp_path)), 5, ips=["8.8.8.8"])


# ---------- parsing / dedupe
def test_parse_findings(tmp_path):
    raws = parse.nmap_findings(load(tmp_path, BASE), 7.0)
    assert {r.vuln_id for r in raws} == {"CVE-2011-2523", "NSE-FTP-ANON", "SVC-TELNET", "NSE-HTTP-METHODS"}
    cve = next(r for r in raws if r.vuln_id.startswith("CVE"))
    assert cve.cvss == 9.8 and cve.severity == "Critical" and cve.banner == "vsftpd 2.3.4"


def test_parse_nuclei(tmp_path):
    p = tmp_path / "n.jsonl"
    p.write_text(NUCLEI + "garbage line\n")
    r = parse.parse_nuclei(p)
    assert len(r) == 1 and (r[0].ip, r[0].port, r[0].severity, r[0].vuln_id) == ("192.168.56.101", 80, "Medium", "exposed-panel")


def test_same_finding_twice_is_one_row(con, tmp_path):
    track.ingest(con, 2, parse.nmap_findings(load(tmp_path, BASE), 7.0))
    assert con.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 4


# ---------- retest
def test_retest_fixed(con, tmp_path):
    track.change_status(con, con.execute("SELECT id FROM findings WHERE vuln_id='NSE-FTP-ANON'").fetchone()[0], "Fixed (Pending Retest)")
    c = retest(con, tmp_path, FIXED)
    assert st(con, "NSE-FTP-ANON") == st(con, "SVC-TELNET") == st(con, "CVE-2011-2523") == "Verified Closed"
    assert st(con, "NSE-HTTP-METHODS") == "Open" and c["not_detected"] == 3 and c["still_present"] == 1


def test_retest_host_down_is_inconclusive(con, tmp_path):
    c = retest(con, tmp_path, "<nmaprun></nmaprun>")
    assert c["inconclusive"] == 4 and st(con, "SVC-TELNET") == "Inconclusive"


def test_retest_filtered_is_inconclusive(con, tmp_path):
    xml = ('<nmaprun><host><status state="up"/><address addr="192.168.56.101" addrtype="ipv4"/>'
           '<ports><extraports state="filtered" count="1000"/></ports></host></nmaprun>')
    assert retest(con, tmp_path, xml)["inconclusive"] == 4


def test_cve_with_unchanged_banner_is_inconclusive(con, tmp_path):
    retest(con, tmp_path, BASE.replace(VULNERS, ""))
    assert st(con, "CVE-2011-2523") == "Inconclusive" and st(con, "NSE-FTP-ANON") == "Open"


def test_fixed_but_still_present_reopens(con, tmp_path):
    track.change_status(con, con.execute("SELECT id FROM findings WHERE vuln_id='NSE-FTP-ANON'").fetchone()[0], "Fixed (Pending Retest)")
    retest(con, tmp_path, BASE)
    assert st(con, "NSE-FTP-ANON") == "Reopened"


def test_closed_finding_reopens_when_seen_again(con, tmp_path):
    retest(con, tmp_path, FIXED)
    track.ingest(con, 3, parse.nmap_findings(load(tmp_path, BASE, "z.xml"), 7.0))
    assert st(con, "SVC-TELNET") == "Reopened"


def test_status_rules(con):
    fid = con.execute("SELECT id FROM findings WHERE vuln_id='SVC-TELNET'").fetchone()[0]
    with pytest.raises(ValueError, match="Illegal"):
        track.change_status(con, fid, "Verified Closed")
    with pytest.raises(ValueError, match="approver"):
        track.change_status(con, fid, "Accepted Risk")
    with pytest.raises(ValueError, match="future"):
        track.change_status(con, fid, "Accepted Risk", "Boss", "2020-01-01")
    with pytest.raises(ValueError, match="reason"):
        track.change_status(con, fid, "False Positive")
    track.change_status(con, fid, "Accepted Risk", "Boss", (dt.date.today() + dt.timedelta(days=30)).isoformat(), "lab only")
    assert st(con, "SVC-TELNET") == "Accepted Risk"


def test_severity_override_needs_reason(con):
    with pytest.raises(ValueError, match="reason"):
        track.set_fix(con, 1, severity="low")
    track.set_fix(con, 1, owner="Asha", due="2030-01-01", severity="low", reason="isolated lab")
    assert track.list_findings(con, severity="low")[0]["id"] == 1


# ---------- workspace / engagement folders
def test_engagement_folders(tmp_path, monkeypatch):
    monkeypatch.setenv("POSTURE_HOME", str(tmp_path))
    monkeypatch.delenv("POSTURE_ENGAGEMENT", raising=False)
    assert cli.main(["init", "Client A Lab", "-t", "192.168.56.5,lab.test", "-t", "10.0.0.0/30"]) == 0
    root = tmp_path / "engagements" / "client-a-lab"
    for d in ("authorization", "raw/nmap", "raw/nuclei", "raw/testssl", "raw/nikto", "logs", "reports", "evidence"):
        assert (root / d).is_dir(), d
    assert (root / "scope.yaml").exists() and (root / "README.txt").exists() and (root / "authorization" / "authorization-template.md").exists()
    assert yaml.safe_load((root / "scope.yaml").read_text())["targets"] == ["192.168.56.5", "lab.test", "10.0.0.0/30"]
    assert cli.main(["init", "client a lab"]) == 1                       # same folder already exists
    assert cli.main(["init", "B", "-t", "not a target!"]) == 1 and not (tmp_path / "engagements" / "b").exists()
    assert cli.main(["init", "B"]) == 0 and workspace.resolve().name == "b"
    assert cli.main(["use", "client-a-lab"]) == 0 and workspace.resolve().name == "client-a-lab"
    monkeypatch.chdir(tmp_path / "engagements" / "b" / "raw")
    assert workspace.resolve().name == "b"                               # cwd inside an engagement wins over the pointer
    assert workspace.resolve("client-a-lab").name == "client-a-lab"      # explicit -e wins
    with pytest.raises(ValueError, match="No engagement"):
        workspace.resolve("nope")
    assert cli.main(["list"]) == 0


def test_scan_refuses_unfilled_scope(tmp_path, monkeypatch):
    monkeypatch.setenv("POSTURE_HOME", str(tmp_path))
    assert cli.main(["init", "x"]) == 0 and cli.main(["scan"]) == 1


# ---------- end to end (fake nmap/nuclei binaries)
def test_end_to_end(tmp_path, monkeypatch):
    eng = mk_engagement(tmp_path, monkeypatch)
    install_fakes(tmp_path, monkeypatch, ["nmap", "nuclei"])
    for name, content in (("base.xml", BASE), ("fixed.xml", BASE.replace(FTP_ANON, "")), ("n.jsonl", NUCLEI)):
        (tmp_path / name).write_text(content)
    monkeypatch.setenv("FAKE_NMAP_XML", str(tmp_path / "base.xml"))
    monkeypatch.setenv("FAKE_NUCLEI", str(tmp_path / "n.jsonl"))
    assert cli.main(["scan", "--target", "10.9.9.9"]) == 1               # guard blocks out-of-scope
    assert cli.main(["scan"]) == 0
    con = db.connect(str(eng.db_path), must_exist=False)
    assert con.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 5
    ids = {r["vuln_id"]: r["id"] for r in con.execute("SELECT id, vuln_id FROM findings")}
    assert cli.main(["fix", str(ids["NSE-FTP-ANON"]), "--owner", "Asha", "--due", "2030-01-01"]) == 0
    assert cli.main(["status", str(ids["NSE-FTP-ANON"]), "fixed"]) == 0
    assert cli.main(["status", str(ids["exposed-panel"]), "fixed"]) == 0
    assert cli.main(["status", str(ids["SVC-TELNET"]), "verified"]) == 1
    monkeypatch.setenv("FAKE_NMAP_XML", str(tmp_path / "fixed.xml"))
    monkeypatch.delenv("FAKE_NUCLEI")
    assert cli.main(["retest"]) == 0
    got = {r["vuln_id"]: r["status"] for r in db.connect(str(eng.db_path), must_exist=False).execute("SELECT vuln_id, status FROM findings")}
    assert got["NSE-FTP-ANON"] == "Verified Closed" and got["exposed-panel"] == "Verified Closed" and got["SVC-TELNET"] == "Open"
    assert cli.main(["findings"]) == 0 and cli.main(["findings", str(ids["NSE-FTP-ANON"])]) == 0
    assert cli.main(["inventory"]) == 0 and cli.main(["report", "--format", "all"]) == 0
    # everything lives inside the engagement folder
    assert list((eng.root / "raw" / "nmap").glob("nmap-*.xml")) and list((eng.root / "raw" / "nuclei").glob("nuclei-*.jsonl"))
    assert list((eng.root / "logs").glob("nmap-*.log")) and list((eng.root / "logs").glob("nuclei-*.log"))
    rdir = next((eng.root / "reports").iterdir())
    rep = (rdir / "report.md").read_text()
    assert (rdir / "report.html").exists() and (rdir / "report.pdf").read_bytes().startswith(b"%PDF")
    assert (rdir / "findings.csv").exists() and (rdir / "report.json").exists()
    assert "Scope and authorization" in rep and "Verified Closed" in rep and "Anonymous FTP" in rep
    assert not list(tmp_path.glob("*.db")) and not (tmp_path / "raw").exists() and not (tmp_path / "reports").exists()
