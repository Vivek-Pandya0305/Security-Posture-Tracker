"""Parsers: Nmap XML (+NSE output) and Nuclei JSONL -> normalized Raw findings."""
from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


def band(s):
    """CVSS v3.x qualitative bands."""
    if s is None:
        return None
    return "Critical" if s >= 9 else "High" if s >= 7 else "Medium" if s >= 4 else "Low" if s > 0 else "Info"


@dataclass
class Raw:
    ip: str
    port: int
    proto: str
    source: str
    vuln_id: str
    title: str
    description: str
    severity: str
    cvss: float | None
    evidence: str
    banner: str = ""


SVC = {
    "telnet": ("SVC-TELNET", "Cleartext Telnet service exposed", "High", "Telnet sends credentials unencrypted. Disable it or replace with SSH."),
    "login": ("SVC-RLOGIN", "rlogin service exposed", "High", "rlogin is cleartext and trust-based. Disable it."),
    "shell": ("SVC-RSH", "rsh remote shell exposed", "High", "rsh is cleartext and trust-based. Disable it."),
    "exec": ("SVC-REXEC", "rexec service exposed", "High", "rexec is cleartext. Disable it."),
}


def parse_nmap(path):
    """Return {ip: {up, extra, ports{(port,proto): {...}}}}. Hosts absent from XML are treated as unknown by retest."""
    res = {}
    for h in ET.parse(path).getroot().iter("host"):
        a = h.find("address[@addrtype='ipv4']")
        if a is None:
            continue
        st = h.find("status")
        extra, best = None, -1
        for e in h.findall("ports/extraports"):
            c = int(e.get("count", "0"))
            if c > best:
                best, extra = c, e.get("state")
        ports = {}
        for p in h.findall("ports/port"):
            s, sv = p.find("state"), p.find("service")
            g = (lambda k, sv=sv: sv.get(k, "") if sv is not None else "")
            ports[(int(p.get("portid")), p.get("protocol"))] = {
                "state": s.get("state") if s is not None else "unknown",
                "service": g("name"), "product": g("product"), "version": g("version"), "tunnel": g("tunnel"),
                "scripts": {x.get("id"): x.get("output", "") for x in p.findall("script")},
            }
        res[a.get("addr")] = {"up": st is not None and st.get("state") == "up", "extra": extra, "ports": ports}
    return res


def _script_rules(sid, out):
    r = []
    if sid == "ftp-anon" and "Anonymous FTP login allowed" in out:
        r.append(("NSE-FTP-ANON", "Anonymous FTP login allowed", "Medium",
                  "Anonymous users can log in to FTP. Disable anonymous access unless required."))
    if sid in ("smb-security-mode", "smb2-security-mode"):
        if re.search(r"message_signing:\s*(disabled|supported)", out) or "not required" in out:
            r.append(("NSE-SMB-SIGNING", "SMB message signing not required", "Medium",
                      "Without required signing, SMB sessions are open to relay/tampering. Require signing."))
    if sid == "http-methods":
        m = re.search(r"Potentially risky methods:\s*(.+)", out)
        if m:
            r.append(("NSE-HTTP-METHODS", "Risky HTTP methods enabled: " + m.group(1).strip(), "Low",
                      "Disable methods such as TRACE/PUT/DELETE unless needed."))
    if sid == "ssl-enum-ciphers":
        grades = re.findall(r"least strength:\s*([A-F])", out)
        if any(g in "DEF" for g in grades) or "SSLv3" in out:
            r.append(("TLS-WEAK", "Weak TLS ciphers/protocols offered", "Medium",
                      "Disable weak ciphers and SSLv3; prefer TLS 1.2+."))
        if "TLSv1.0:" in out or "TLSv1.1:" in out:
            r.append(("TLS-OLD", "Deprecated TLS 1.0/1.1 enabled", "Low", "Disable TLS 1.0 and 1.1."))
    if "State: VULNERABLE" in out:
        m = re.search(r"VULNERABLE:\s*\n\s*(.+)", out)
        r.append((f"NSE-{sid}", m.group(1).strip() if m else sid, "High", f"Reported VULNERABLE by NSE script {sid}."))
    return r


def nmap_findings(res, min_cvss=0.0):
    out = []
    for ip, h in res.items():
        for (port, proto), p in h["ports"].items():
            if p["state"] != "open":
                continue
            banner = f'{p["product"]} {p["version"]}'.strip()
            head = f'{ip}:{port}/{proto} {p["service"]} {banner}'.strip()

            def add(vid, title, desc, sev, cvss, ev, ip=ip, port=port, proto=proto, banner=banner, head=head):
                out.append(Raw(ip, port, proto, "nmap", vid, title, desc, sev, cvss, f"{head}\n{ev}".strip(), banner))

            if p["service"] in SVC:
                vid, t, sev, d = SVC[p["service"]]
                add(vid, t, d, sev, None, "Service detected open by Nmap -sV")
            for sid, so in p["scripts"].items():
                if sid == "vulners":
                    for line in so.splitlines():
                        m = re.search(r"\b(CVE-\d{4}-\d{4,})\b\s+(\d{1,2}(?:\.\d)?)\b", line)
                        if m and float(m.group(2)) >= min_cvss:
                            c = float(m.group(2))
                            add(m.group(1), f'{m.group(1)} affects {banner or p["service"]}',
                                "Version-based match (vulners NSE). Verify the package is really unpatched; "
                                "distro backports keep the banner unchanged.", band(c), c, line.strip())
                else:
                    for vid, t, sev, d in _script_rules(sid, so):
                        add(vid, t, d, sev, None, f"[{sid}] {so.strip()[:800]}")
    return out


def _hostport(j):
    at = j.get("matched-at") or j.get("host") or ""
    if "://" in at:
        u = urlparse(at)
        host, port = u.hostname or "", u.port or (443 if u.scheme == "https" else 80)
    else:
        host, pt = at.rsplit(":", 1) if ":" in at else (at, "")
        port = int(pt) if pt.isdigit() else 0
    return (j.get("ip") or host), port


def parse_nuclei(path):
    out = []
    for line in Path(path).read_text(errors="replace").splitlines():
        try:
            j = json.loads(line)
        except ValueError:
            continue
        info = j.get("info") or {}
        cls = info.get("classification") or {}
        cves = cls.get("cve-id") or []
        if isinstance(cves, str):
            cves = [cves]
        ip, port = _hostport(j)
        if not ip:
            continue
        cvss = cls.get("cvss-score") or None
        sev = band(cvss) or str(info.get("severity", "info")).capitalize()
        vid = (cves[0].upper() if cves else j.get("template-id", "unknown"))
        ev = f'template={j.get("template-id")} matched-at={j.get("matched-at")}'
        if j.get("matcher-name"):
            ev += f' matcher={j["matcher-name"]}'
        if j.get("extracted-results"):
            ev += f' extracted={j["extracted-results"]}'
        out.append(Raw(ip, port, "tcp", "nuclei", vid, info.get("name", vid), info.get("description", "") or "",
                       sev, cvss, ev[:1500]))
    return out


def parse_testssl(path, ip, port):
    """testssl.sh flat JSON (list of {id, severity, finding, cve}). Only LOW..CRITICAL entries become findings."""
    data = json.loads(Path(path).read_text(errors="replace") or "[]")
    if not isinstance(data, list):
        raise ValueError("unexpected testssl JSON layout")
    sev_map = {"LOW": "Low", "MEDIUM": "Medium", "HIGH": "High", "CRITICAL": "Critical"}
    out = []
    for e in data:
        if not isinstance(e, dict):
            continue
        sev = sev_map.get(str(e.get("severity", "")).upper())
        if not sev:
            continue
        i, fnd = str(e.get("id", "")), str(e.get("finding", ""))
        if i in ("SSLv2", "SSLv3", "TLS1", "TLS1_1"):
            if not fnd.startswith("offered"):
                continue
            vid = "TLS-WEAK" if i in ("SSLv2", "SSLv3") else "TLS-OLD"
        else:
            m = re.search(r"CVE-\d{4}-\d{4,}", str(e.get("cve", "")))
            vid = m.group(0) if m else f"TLS-{i}"
        out.append(Raw(ip, port, "tcp", "testssl", vid, f"{i}: {fnd}"[:140], f"testssl.sh check '{i}': {fnd}",
                       sev, None, f"[testssl {i}] {fnd}"[:600]))
    return out


_NIKTO_SKIP = re.compile(r"^\+\s*(Target|Start Time|End Time|Server:|\d+ host|\d+ requests|No CGI|Scan terminated|Using|SSL Info|Subject|Ciphers|Issuer|Platform|Multiple IPs)", re.I)


def parse_nikto(path, ip, port, cap=50):
    """Parse Nikto's text report ('+ ' lines). Text is used because Nikto's JSON output is unreliable across versions.
    Nikto has no severity ratings: Low by default, Medium for clearly risky wording. Capped to limit noise."""
    out, seen = [], set()
    for line in Path(path).read_text(errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("+") or _NIKTO_SKIP.match(line):
            continue
        msg = line.lstrip("+ ").strip()
        if not msg or msg.lower().startswith("error"):
            continue
        vid = "NIKTO-" + hashlib.sha1(msg.encode()).hexdigest()[:8]
        if vid in seen:
            continue
        seen.add(vid)
        sev = "Medium" if re.search(r"(?i)xss|traversal|inclusion|backdoor|default (cred|pass)|shell|sql", msg) else "Low"
        out.append(Raw(ip, port, "tcp", "nikto", vid, msg[:120], msg, sev, None, msg[:1000]))
        if len(out) >= cap:
            break
    return out
