import csv
import io
import json

import pytest

from posture import cli, db, parse, render, track
from test_core import BASE, FIXED, install_fakes, load, mk_engagement, mk_scope


def seed(tmp_path):
    con = db.connect(":memory:", must_exist=False)
    raws = parse.nmap_findings(load(tmp_path, BASE), 7.0)
    raws.append(parse.Raw("192.168.56.101", 8080, "tcp", "nuclei", "xss-test", "<script>alert(1)</script>", "d", "Low", None, "<img src=x onerror=alert(1)>"))
    raws.append(parse.Raw("192.168.56.101", 80, "tcp", "nikto", "NIKTO-1", "/phpinfo.php exposed", "d", "Low", None, "GET /phpinfo.php"))
    track.ingest(con, 1, raws)
    return con, mk_scope(tmp_path)


def test_collect_summary_priority_and_advice(tmp_path):
    con, scope = seed(tmp_path)
    d = render.collect(con, scope)
    assert d["rating"]["key"] == "Critical" and d["summary"]["active"] == 6
    assert d["top"][0]["vuln_id"] == "CVE-2011-2523"                      # critical first
    assert [f["sev"] for f in d["top"]] == sorted((f["sev"] for f in d["top"]), key=lambda s: render.SEV.index(s))
    assert all(f["why"] and f["fix"] for f in d["findings"])
    assert "false positive" in next(f for f in d["findings"] if f["vuln_id"].startswith("CVE"))["why"]
    assert d["hosts"][0]["ip"] == "192.168.56.101" and d["hosts"][0]["findings"] == 6 and d["hosts"][0]["worst"] == "Critical"


def test_good_rating_when_nothing_open(tmp_path):
    con = db.connect(":memory:", must_exist=False)
    d = render.collect(con, mk_scope(tmp_path))
    assert d["rating"]["key"] == "Good" and d["top"] == [] and "No open findings" in d["narrative"][0]
    assert "Nothing needs action" in render.render_html(d)
    assert render.render_pdf(d).startswith(b"%PDF")                      # empty report must not crash


def test_html_structure_and_escaping(tmp_path):
    con, scope = seed(tmp_path)
    h = render.render_html(render.collect(con, scope))
    for s in ("Security Posture Assessment Report", "The short version", "Fix these first", "Why it matters", "How to fix", "By host",
              "Remediation tracker", "How to read this report", "Corroborated"):
        assert s in h, s
    assert "<script" not in h and "&lt;script&gt;" in h and "<img src=x" not in h
    assert "Download:" not in h and "Download:" in render.render_html(render.collect(con, scope), web=True)


def test_progress_after_retest(tmp_path):
    con, scope = seed(tmp_path)
    res = load(tmp_path, FIXED, "f.xml")
    _, obs = track.ingest(con, 2, parse.nmap_findings(res, 7.0))
    track.evaluate(con, 2, res, obs)
    d = render.collect(con, scope)
    assert d["retest"]["closed"] >= 3 and d["summary"]["closed"] >= 3 and d["closed"][0]["closed_at"]
    assert "Progress since the last retest" in render.render_html(d)


def test_pdf_csv_json(tmp_path):
    con, scope = seed(tmp_path)
    d = render.collect(con, scope)
    pdf = render.render_pdf(d)
    assert pdf.startswith(b"%PDF") and len(pdf) > 3000
    pypdf = pytest.importorskip("pypdf")
    text = "\n".join(p.extract_text() for p in pypdf.PdfReader(io.BytesIO(pdf)).pages)
    assert "Fix these first" in text and "Overall risk: CRITICAL" in text and "CVE-2011-2523" in text
    rows = list(csv.DictReader(io.StringIO(render.render_csv(d))))
    assert len(rows) == 6 and {"severity", "confidence", "how_to_fix"} <= set(rows[0])
    assert json.loads(render.render_json(d))["rating"]["key"] == "Critical"


def test_generate_and_cli_formats(tmp_path, monkeypatch, capsys):
    eng = mk_engagement(tmp_path, monkeypatch)
    install_fakes(tmp_path, monkeypatch, ["nmap"])
    (tmp_path / "b.xml").write_text(BASE)
    monkeypatch.setenv("FAKE_NMAP_XML", str(tmp_path / "b.xml"))
    assert cli.main(["scan"]) == 0
    assert cli.main(["report"]) == 0                                       # default: html only
    first = sorted((eng.root / "reports").iterdir())
    assert [p.name for p in first[0].iterdir()] == ["report.html"]
    assert cli.main(["report", "--format", "pdf,csv"]) == 0 and cli.main(["report", "--format", "all"]) == 0
    assert len(list((eng.root / "reports").iterdir())) == 3
    assert cli.main(["report", "--format", "docx"]) == 1
    out = capsys.readouterr()
    assert "--format must be" in out.err
