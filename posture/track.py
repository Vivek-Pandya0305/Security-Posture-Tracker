"""Findings database logic: ingest, status workflow, retest evaluation."""
from __future__ import annotations

import datetime as dt
import hashlib
from collections import Counter

from .db import now
from .parse import band

ACTIVE = ("Open", "In Remediation", "Fixed (Pending Retest)", "Reopened", "Inconclusive")
TRANSITIONS = {
    "Open": {"In Remediation", "Fixed (Pending Retest)", "Accepted Risk", "False Positive"},
    "In Remediation": {"Open", "Fixed (Pending Retest)", "Accepted Risk", "False Positive"},
    "Fixed (Pending Retest)": {"In Remediation"},          # closing/reopening is done only by retest
    "Reopened": {"In Remediation", "Fixed (Pending Retest)", "Accepted Risk", "False Positive"},
    "Inconclusive": {"In Remediation", "Fixed (Pending Retest)", "Accepted Risk", "False Positive"},
    "Accepted Risk": {"Open"},
    "False Positive": {"Open"},
    "Verified Closed": set(),
}
ALIASES = {"open": "Open", "remediation": "In Remediation", "fixed": "Fixed (Pending Retest)",
           "accepted-risk": "Accepted Risk", "false-positive": "False Positive"}
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")
_ORDER = "CASE sev WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END"


def fingerprint(ip, port, proto, source, vid):
    return hashlib.sha256(f"{ip}|{port}|{proto}|{source}|{vid}".encode()).hexdigest()[:16]


def _log(con, fid, old, new, note=""):
    con.execute("INSERT INTO status_log(finding_id,old,new,at,note) VALUES(?,?,?,?,?)", (fid, old, new, now(), note))


def _set(con, fid, new, note=""):
    old = con.execute("SELECT status FROM findings WHERE id=?", (fid,)).fetchone()[0]
    con.execute("UPDATE findings SET status=?, updated_at=? WHERE id=?", (new, now(), fid))
    _log(con, fid, old, new, note)


def list_findings(con, severity=None, status=None, active_only=False, confidence=None):
    q = "SELECT * FROM (SELECT f.*, COALESCE(override_severity, severity) AS sev FROM findings f) WHERE 1=1"
    a = []
    if severity:
        q += " AND lower(sev)=?"
        a.append(severity.lower())
    if status:
        q += " AND status=?"
        a.append(status)
    if confidence:
        q += " AND confidence=?"
        a.append(confidence)
    if active_only:
        q += f" AND status IN ({','.join('?' * len(ACTIVE))})"
        a += list(ACTIVE)
    return con.execute(q + f" ORDER BY {_ORDER}, id", a).fetchall()


def change_status(con, fid, new, approver=None, expiry=None, reason=None):
    row = con.execute("SELECT status FROM findings WHERE id=?", (fid,)).fetchone()
    if not row:
        raise ValueError(f"No finding with id {fid}")
    old = row["status"]
    if new not in TRANSITIONS.get(old, set()):
        raise ValueError(f"Illegal transition: {old} -> {new}")
    if new == "Accepted Risk":
        if not (approver and expiry):
            raise ValueError("Accepted Risk needs --approver and --expiry YYYY-MM-DD")
        if dt.date.fromisoformat(expiry) <= dt.date.today():
            raise ValueError("--expiry must be a future date")
        con.execute("UPDATE findings SET approver=?, expiry=?, reason=? WHERE id=?", (approver, expiry, reason, fid))
    if new == "False Positive":
        if not reason:
            raise ValueError("False Positive needs --reason")
        con.execute("UPDATE findings SET reason=? WHERE id=?", (reason, fid))
    _set(con, fid, new, reason or "")
    con.commit()


def set_fix(con, fid, owner=None, due=None, action=None, severity=None, reason=None):
    if not con.execute("SELECT 1 FROM findings WHERE id=?", (fid,)).fetchone():
        raise ValueError(f"No finding with id {fid}")
    if due:
        dt.date.fromisoformat(due)
    if severity:
        severity = severity.capitalize()
        if severity not in SEVERITIES:
            raise ValueError(f"Severity must be one of {', '.join(SEVERITIES)}")
        if not reason:
            raise ValueError("Changing severity needs --reason")
        con.execute("UPDATE findings SET override_severity=?, override_reason=? WHERE id=?", (severity, reason, fid))
    for col, val in (("owner", owner), ("due_date", due), ("action", action)):
        if val:
            con.execute(f"UPDATE findings SET {col}=? WHERE id=?", (val, fid))
    con.execute("UPDATE findings SET updated_at=? WHERE id=?", (now(), fid))
    con.commit()


def expire_accepted(con):
    today = dt.date.today().isoformat()
    for r in con.execute("SELECT id FROM findings WHERE status='Accepted Risk' AND expiry < ?", (today,)).fetchall():
        _set(con, r["id"], "Open", "risk acceptance expired")
    con.commit()


def ingest(con, run_id, raws):
    groups = {}
    for r in raws:
        groups.setdefault((r.ip, r.port, r.proto, r.source, r.vuln_id), []).append(r)
    observed, new = set(), 0
    for k, rs in groups.items():
        fp, r0 = fingerprint(*k), rs[0]
        cv = [x.cvss for x in rs if x.cvss is not None]
        cvss = max(cv) if cv else None
        sev = band(cvss) if cvss is not None else r0.severity
        row = con.execute("SELECT id,status FROM findings WHERE fingerprint=?", (fp,)).fetchone()
        if row is None:
            cur = con.execute(
                "INSERT INTO findings(fingerprint,ip,port,proto,source,vuln_id,title,description,cvss,severity,banner,"
                "status,first_run,last_run,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,'Open',?,?,?)",
                (fp, r0.ip, r0.port, r0.proto, r0.source, r0.vuln_id, r0.title, r0.description, cvss, sev,
                 r0.banner, run_id, run_id, now()))
            fid = cur.lastrowid
            new += 1
            _log(con, fid, None, "Open", "first detected")
        else:
            fid = row["id"]
            con.execute("UPDATE findings SET last_run=? WHERE id=?", (run_id, fid))
            if row["status"] == "Verified Closed":
                _set(con, fid, "Reopened", "detected again after closure")
        for x in rs:
            con.execute("INSERT INTO evidence(finding_id,run_id,excerpt) VALUES(?,?,?)", (fid, run_id, x.evidence[:1500]))
        observed.add(fp)
    update_confidence(con)
    con.commit()
    return new, observed


def port_state(h, port, proto):
    if not h or not h["up"]:
        return "unknown"
    p = h["ports"].get((port, proto))
    if p:
        return p["state"]
    return h["extra"] if h["extra"] in ("closed", "filtered") else "unknown"


def evaluate(con, run_id, res, observed, nmap_ok=True, nuclei_ok=True, tools_ok=None):
    """Retest logic. Absence of a finding only proves a fix when the evidence is conclusive."""
    out = Counter()
    tools = {"nuclei": nuclei_ok, **(tools_ok or {})}
    rows = con.execute(f"SELECT * FROM findings WHERE status IN ({','.join('?' * len(ACTIVE))})", ACTIVE).fetchall()
    for f in rows:
        h = res.get(f["ip"])
        state = port_state(h, f["port"], f["proto"])
        if f["fingerprint"] in observed:
            result = "still_present"
        elif not nmap_ok or state not in ("open", "closed"):
            result = "inconclusive"          # host down, filtered, or port not scanned
        elif state == "closed":
            result = "not_detected"          # service is gone
        else:
            cur = h["ports"].get((f["port"], f["proto"]), {})
            banner = f'{cur.get("product", "")} {cur.get("version", "")}'.strip()
            if f["source"] != "nmap":
                ok = tools.get(f["source"], False)
            elif f["vuln_id"].startswith("CVE-"):
                ok = banner != (f["banner"] or "")   # version-based: only a changed banner is conclusive
            else:
                ok = True
            result = "not_detected" if ok else "inconclusive"
        st = f["status"]
        if result == "still_present":
            if st == "Fixed (Pending Retest)":
                _set(con, f["id"], "Reopened", f"retest run {run_id}: still present")
            elif st == "Inconclusive":
                _set(con, f["id"], "Open", f"retest run {run_id}: still present")
        elif result == "not_detected":
            _set(con, f["id"], "Verified Closed", f"retest run {run_id}: not detected")
        elif st != "Inconclusive":
            _set(con, f["id"], "Inconclusive", f"retest run {run_id}: could not confirm")
        con.execute("INSERT INTO retests(finding_id,run_id,result,tested_at) VALUES(?,?,?,?)", (f["id"], run_id, result, now()))
        out[result] += 1
    con.commit()
    return out


def update_confidence(con):
    """Corroborated = same ip/port/id seen by 2+ tools. Tested = behavior-based check. Unverified = banner/heuristic only."""
    groups = {}
    for r in con.execute("SELECT id, ip, port, source, vuln_id FROM findings").fetchall():
        groups.setdefault((r["ip"], r["port"], r["vuln_id"]), []).append(r)
    for rs in groups.values():
        srcs = sorted({r["source"] for r in rs})
        for r in rs:
            if len(srcs) > 1:
                conf = "Corroborated"
            elif r["source"] == "nikto" or (r["source"] == "nmap" and r["vuln_id"].startswith("CVE-")):
                conf = "Unverified"
            else:
                conf = "Tested"
            con.execute("UPDATE findings SET confidence=?, seen_by=? WHERE id=?", (conf, ",".join(srcs), r["id"]))
