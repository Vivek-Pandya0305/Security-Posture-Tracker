import json

import pytest

from posture import cli, db, parse, track
from test_core import BASE, FIXED, TELNET, install_fakes, mk_engagement

TESTSSL = json.dumps([
    {"id": "heartbleed", "severity": "CRITICAL", "finding": "VULNERABLE (NOT ok)", "cve": "CVE-2014-0160 CWE-119"},
    {"id": "SSLv3", "severity": "HIGH", "finding": "offered (NOT ok)"},
    {"id": "TLS1", "severity": "LOW", "finding": "offered (deprecated)"},
    {"id": "TLS1_2", "severity": "OK", "finding": "offered"},
    {"id": "ROBOT", "severity": "OK", "finding": "not vulnerable (OK)"}])
TESTSSL_FIXED = json.dumps(json.loads(TESTSSL)[:2])
NIKTO = """- Nikto v2.5.0
+ Target IP:          192.168.56.101
+ Target Hostname:    192.168.56.101
+ Target Port:        80
+ Start Time:         2026-11-03 10:00:00 (GMT0)
+ Server: Apache/2.2.8 (Ubuntu) DAV/2
+ /phpinfo.php: Output from the phpinfo() function was found.
+ /x: Possible XSS in parameter
+ ERROR: something transient
+ 7915 requests: 0 error(s) and 2 item(s) reported on remote host
+ End Time:           2026-11-03 10:01:00 (GMT0) (60 seconds)
+ 1 host(s) tested
"""
WEB_XML = ('<nmaprun><host><status state="up"/><address addr="192.168.56.101" addrtype="ipv4"/><ports>'
           '<extraports state="closed" count="998"/>'
           '<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.2.8"/></port>'
           '<port protocol="tcp" portid="443"><state state="open"/><service name="http" product="Apache httpd" version="2.2.8" tunnel="ssl"/></port>'
           '</ports></host></nmaprun>')
P = lambda n: f'<port protocol="tcp" portid="{n}"><state state="open"/></port>'
DISC = ('<nmaprun><host><status state="up"/><address addr="192.168.56.101" addrtype="ipv4"/><ports>'
        f'<extraports state="closed" count="997"/>{P(21)}{P(23)}{P(80)}</ports></host></nmaprun>')
DISC_NO_TELNET = DISC.replace(P(23), "").replace('count="997"', 'count="998"')
DISC_EMPTY = ('<nmaprun><host><status state="up"/><address addr="192.168.56.101" addrtype="ipv4"/>'
              '<ports><extraports state="closed" count="65535"/></ports></host></nmaprun>')


def put(tmp_path, monkeypatch, **files):
    for env, content in files.items():
        f = tmp_path / f"{env}.dat"
        f.write_text(content)
        monkeypatch.setenv(env, str(f))


def test_parse_testssl(tmp_path):
    p = tmp_path / "t.json"
    p.write_text(TESTSSL)
    r = parse.parse_testssl(p, "192.168.56.101", 443)
    assert {x.vuln_id for x in r} == {"CVE-2014-0160", "TLS-WEAK", "TLS-OLD"}
    assert next(x for x in r if x.vuln_id.startswith("CVE")).severity == "Critical"


def test_parse_nikto_text(tmp_path):
    p = tmp_path / "n.txt"
    p.write_text(NIKTO)
    r = parse.parse_nikto(p, "192.168.56.101", 80)
    assert len(r) == 2 and sorted(x.severity for x in r) == ["Low", "Medium"] and all(x.vuln_id.startswith("NIKTO-") for x in r)
    assert [x.vuln_id for x in r] == [x.vuln_id for x in parse.parse_nikto(p, "192.168.56.101", 80)]     # stable ids


def test_confidence_levels():
    con = db.connect(":memory:", must_exist=False)

    def mk(src, vid, port=21):
        return parse.Raw("192.168.56.101", port, "tcp", src, vid, "t", "d", "High", None, "e")
    track.ingest(con, 1, [mk("nmap", "CVE-2011-2523"), mk("nmap", "NSE-FTP-ANON"), mk("nikto", "NIKTO-1", 80)])
    conf = lambda vid: {r[0] for r in con.execute("SELECT confidence FROM findings WHERE vuln_id=?", (vid,))}
    assert conf("CVE-2011-2523") == {"Unverified"} and conf("NSE-FTP-ANON") == {"Tested"} and conf("NIKTO-1") == {"Unverified"}
    track.ingest(con, 2, [mk("nuclei", "CVE-2011-2523")])
    assert conf("CVE-2011-2523") == {"Corroborated"}


def test_testssl_nikto_parallel_and_failure_semantics(tmp_path, monkeypatch, capsys):
    eng = mk_engagement(tmp_path, monkeypatch, nuclei={"enabled": False})
    install_fakes(tmp_path, monkeypatch, ["nmap", "testssl", "nikto"])
    put(tmp_path, monkeypatch, FAKE_NMAP_XML=WEB_XML, FAKE_TESTSSL=TESTSSL, FAKE_NIKTO=NIKTO)
    assert cli.main(["scan"]) == 0
    con = db.connect(str(eng.db_path), must_exist=False)
    cnt = lambda s: con.execute("SELECT COUNT(*) FROM findings WHERE source=?", (s,)).fetchone()[0]
    assert cnt("testssl") == 3 and cnt("nikto") == 4                         # nikto ran on :80 and :443
    assert len(list((eng.root / "raw" / "nikto").glob("nikto-*.txt"))) == 2 and len(list((eng.root / "logs").glob("nikto-*.log"))) == 2
    # TLS 1.0 turned off -> that finding closes; testssl ran fine
    put(tmp_path, monkeypatch, FAKE_TESTSSL=TESTSSL_FIXED)
    assert cli.main(["retest"]) == 0
    got = {r["vuln_id"]: r["status"] for r in db.connect(str(eng.db_path), must_exist=False).execute("SELECT vuln_id,status FROM findings WHERE source='testssl'")}
    assert got == {"TLS-OLD": "Verified Closed", "TLS-WEAK": "Open", "CVE-2014-0160": "Open"}
    # nikto breaks: reported with a reason + log, and its findings become Inconclusive (never falsely closed)
    monkeypatch.setenv("FAKE_NIKTO_FAIL", "1")
    capsys.readouterr()
    assert cli.main(["retest"]) == 0
    out = capsys.readouterr().out
    assert "nikto: failed for 2/2 target(s)" in out and "boom: cannot connect" in out
    st = {r[0] for r in db.connect(str(eng.db_path), must_exist=False).execute("SELECT status FROM findings WHERE source='nikto'")}
    assert st == {"Inconclusive"}
    assert "boom: cannot connect" in sorted((eng.root / "logs").glob("nikto-*.log"))[-1].read_text()
    assert len(set((eng.root / "raw" / "nikto").glob("nikto-*.txt"))) == 6        # three scans x two targets, none overwritten
    assert cli.main(["findings", "--confidence", "Tested"]) == 0


def test_two_phase_full_port_scan(tmp_path, monkeypatch):
    eng = mk_engagement(tmp_path, monkeypatch, ports="all", nuclei={"enabled": False})
    install_fakes(tmp_path, monkeypatch, ["nmap"])
    put(tmp_path, monkeypatch, FAKE_NMAP_XML=BASE, FAKE_NMAP_DISCOVERY=DISC)
    assert cli.main(["scan"]) == 0
    con = db.connect(str(eng.db_path), must_exist=False)
    runs = {r["tool"]: r["command"] for r in con.execute("SELECT tool, command FROM scan_runs")}
    assert set(runs) == {"nmap-discovery", "nmap"} and "-p 21,23,80" in runs["nmap"] and "-p-" in runs["nmap-discovery"]
    assert "--exclude 192.168.56.1/32" in runs["nmap-discovery"]
    assert con.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 4
    # retest: telnet port gone. Deep scan no longer lists it, discovery says unlisted ports are closed -> conclusive close
    put(tmp_path, monkeypatch, FAKE_NMAP_XML=BASE.replace(TELNET, ""), FAKE_NMAP_DISCOVERY=DISC_NO_TELNET)
    assert cli.main(["retest"]) == 0
    got = {r["vuln_id"]: r["status"] for r in db.connect(str(eng.db_path), must_exist=False).execute("SELECT vuln_id,status FROM findings")}
    assert got["SVC-TELNET"] == "Verified Closed" and got["NSE-FTP-ANON"] == "Open"


def test_full_scan_with_no_open_ports(tmp_path, monkeypatch):
    eng = mk_engagement(tmp_path, monkeypatch, ports="all", nuclei={"enabled": False})
    install_fakes(tmp_path, monkeypatch, ["nmap"])
    put(tmp_path, monkeypatch, FAKE_NMAP_XML=BASE, FAKE_NMAP_DISCOVERY=DISC_EMPTY)
    assert cli.main(["scan"]) == 0
    con = db.connect(str(eng.db_path), must_exist=False)
    assert [r[0] for r in con.execute("SELECT tool FROM scan_runs")] == ["nmap-discovery"]
    assert con.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0


def test_domain_target_scan_logs_resolution_and_vhost(tmp_path, monkeypatch):
    from posture import guard
    monkeypatch.setattr(guard, "_resolve", lambda n: ["192.168.56.101"])
    eng = mk_engagement(tmp_path, monkeypatch, targets=["lab.test"], exclusions=[], nuclei={"enabled": False})
    install_fakes(tmp_path, monkeypatch, ["nmap", "nikto"])
    put(tmp_path, monkeypatch, FAKE_NMAP_XML=WEB_XML, FAKE_NIKTO=NIKTO)
    assert cli.main(["scan"]) == 0
    con = db.connect(str(eng.db_path), must_exist=False)
    assert con.execute("SELECT name, ip FROM resolutions").fetchone()[:] == ("lab.test", "192.168.56.101")
    cmd = con.execute("SELECT command FROM scan_runs WHERE tool='nikto'").fetchone()[0]
    assert "-vhost lab.test" in cmd and "192.168.56.101/32" in con.execute("SELECT command FROM scan_runs WHERE tool='nmap'").fetchone()[0]
    assert cli.main(["report", "--format", "md"]) == 0
    assert "lab.test -> 192.168.56.101" in next((eng.root / "reports").glob("*/report.md")).read_text()
