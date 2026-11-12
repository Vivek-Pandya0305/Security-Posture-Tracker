"""Markdown report generator."""
from collections import Counter

from . import track


def _c(v):
    return str(v if v is not None else "").replace("|", "\\|").replace("\n", " ")


def _table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(_c(x) for x in r) + " |" for r in rows]
    return "\n".join(out)


def build(con, scope):
    from .db import now
    fs = track.list_findings(con)
    L = ["# Security Posture Assessment Report", f"Generated: {now()}  ", f"Engagement: **{scope.engagement}**", ""]
    nu = scope.nuclei
    rs = con.execute("SELECT name, ip FROM resolutions WHERE at=(SELECT MAX(at) FROM resolutions)").fetchall()
    resolved = ", ".join(f"{x['name']} -> {x['ip']}" for x in rs) or "n/a"
    L += ["## 1. Scope and authorization", _table(["Item", "Value"], [
        ("Authorized by", scope.authorized_by), ("Authorization record", scope.auth_reference),
        ("Window (UTC)", f"{scope.start:%Y-%m-%d} to {scope.end:%Y-%m-%d}"),
        ("In-scope targets", ", ".join([str(t) for t in scope.targets] + list(scope.target_names))),
        ("Resolved names (latest scan)", resolved),
        ("Excluded", ", ".join([str(t) for t in scope.exclusions] + list(scope.exclusion_names)) or "none"),
        ("Port coverage", scope.ports + (" (full 65535-port discovery, then deep scan of open ports)" if scope.ports == "all" else "")),
        ("NSE scripts (allowlisted)", ", ".join(scope.scripts)),
        ("Nuclei", f"enabled={nu['enabled']}, severity={','.join(nu['severity'])}, excluded tags={','.join(nu['exclude_tags'])}"),
        ("testssl / nikto", f"testssl enabled={scope.testssl['enabled']}; nikto enabled={scope.nikto['enabled']} (tuning 123b, non-intrusive)"),
        ("Scope file SHA-256", scope.sha256)]), ""]
    L += ["## 2. Method and limitations", "\n".join([
        "- Discovery and service inventory: Nmap `-sV`. Config and version checks: allowlisted NSE scripts. Web/misconfiguration checks: Nuclei templates and Nikto (non-intrusive tuning). TLS: testssl.sh.",
        "- Confidence: Corroborated = reported by 2+ independent tools; Tested = a behavior-based check; Unverified = banner/heuristic match only (needs manual triage).",
        "- Assessment only: no exploitation. Selected Nuclei templates (e.g. default-login) may attempt default credentials.",
        "- TCP only: UDP services are not scanned.",
        "- CVE findings from `vulners` are version-based and can be false positives when vendors backport fixes.",
        "- Config findings carry assessor-rated severity (no CVSS). CVE and some Nuclei findings carry CVSS-based severity.",
        "- A finding is only `Verified Closed` when a retest conclusively shows it gone; otherwise it is `Inconclusive`."]), ""]
    act = [f for f in fs if f["status"] in track.ACTIVE]
    sc, st = Counter(f["sev"] for f in act), Counter(f["status"] for f in fs)
    L += ["## 3. Summary", f"Total findings: {len(fs)}. Active: {len(act)}.", "",
          _table(["Severity (active)", "Count"], [(s, sc.get(s, 0)) for s in track.SEVERITIES]), "",
          _table(["Status", "Count"], sorted(st.items())), ""]
    rid = con.execute("SELECT MAX(id) FROM scan_runs WHERE tool IN ('nmap','nmap-discovery') AND ok=1").fetchone()[0]
    rows = con.execute("SELECT ip,port,proto,service,product,version FROM services WHERE run_id=? AND state='open' ORDER BY ip,port",
                       (rid,)).fetchall() if rid else []
    L += [f"## 4. Service inventory (latest Nmap run #{rid})",
          _table(["Host", "Port", "Proto", "Service", "Product", "Version"], [tuple(r) for r in rows]), ""]
    L += ["## 5. Findings", _table(["ID", "Severity", "Confidence", "CVSS", "Host:Port", "Finding", "Seen by", "Status"],
          [(f["id"], f["sev"], f["confidence"], f["cvss"], f"{f['ip']}:{f['port']}", f["title"], f["seen_by"], f["status"]) for f in fs]), ""]

    def last_retest(i):
        r = con.execute("SELECT result||' @ '||tested_at FROM retests WHERE finding_id=? ORDER BY id DESC LIMIT 1", (i,)).fetchone()
        return r[0] if r else ""

    def note(f):
        if f["status"] == "Accepted Risk":
            return f"Accepted by {f['approver']} until {f['expiry']}: {f['reason']}"
        return f["reason"] if f["status"] == "False Positive" else f["action"]

    L += ["## 6. Remediation tracker", _table(["ID", "Severity", "Finding", "Owner", "Due", "Status", "Last retest", "Notes"],
          [(f["id"], f["sev"], f["title"], f["owner"], f["due_date"], f["status"], last_retest(f["id"]), note(f)) for f in fs]), ""]
    L += ["## 7. Finding details and evidence"]
    for f in fs:
        ev = con.execute("SELECT run_id, excerpt FROM evidence WHERE finding_id=? ORDER BY id LIMIT 1", (f["id"],)).fetchone()
        L += [f"### #{f['id']} {f['title']} ({f['sev']})",
              f"- Asset: {f['ip']}:{f['port']}/{f['proto']}  |  ID: {f['vuln_id']}  |  Seen by: {f['seen_by']}  |  Confidence: {f['confidence']}  |  Status: {f['status']}",
              f"- Description: {_c(f['description'])}"]
        if f["override_severity"]:
            L.append(f"- Severity overridden from {f['severity']}: {f['override_reason']}")
        if ev:
            L += [f"- Evidence (run #{ev['run_id']}):", "  ```", "  " + ev["excerpt"][:600].replace("\n", "\n  "), "  ```"]
        L.append("")
    L += ["## 8. Scan run log", _table(["Run", "Tool", "Type", "Started", "OK", "Raw file", "SHA-256"],
          [(r["id"], r["tool"], r["run_type"], r["started_at"], r["ok"], r["raw_file"], r["sha256"])
           for r in con.execute("SELECT * FROM scan_runs ORDER BY id")]), ""]
    return "\n".join(L)
