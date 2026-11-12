"""Scope guard: the single gate every scan must pass. Scanners refuse to run without an Authorization."""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import re
import socket
from dataclasses import dataclass
from pathlib import Path

import yaml

# Non-intrusive NSE scripts only. Anything else (e.g. ftp-vsftpd-backdoor, brute, dos) is refused.
SAFE_SCRIPTS = frozenset({
    "vulners", "banner", "ftp-anon", "ftp-syst", "smb-security-mode", "smb2-security-mode",
    "smb-protocols", "smb-vuln-ms17-010", "http-methods", "http-title", "http-server-header",
    "ssl-enum-ciphers", "ssl-cert", "ssh2-enum-algos", "ssh-auth-methods",
})
_HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


class ScopeError(Exception):
    pass


@dataclass(frozen=True)
class Authorization:
    targets: tuple            # networks to scan (resolved, pinned)
    exclusions: tuple
    names: tuple              # ((ip, domain), ...) resolved at authorization time
    scope_sha256: str

    def permits(self, ip):
        a = ipaddress.ip_address(ip)
        return (any(a in ipaddress.ip_network(t) for t in self.targets)
                and not any(a in ipaddress.ip_network(x) for x in self.exclusions))

    def names_for(self, ip):
        return [n for i, n in self.names if i == ip]


@dataclass
class Scope:
    engagement: str
    authorized_by: str
    auth_reference: str
    start: dt.datetime
    end: dt.datetime
    targets: list
    target_names: list
    exclusions: list
    exclusion_names: list
    scripts: list
    ports: str
    min_cvss: float
    nuclei: dict
    testssl: dict
    nikto: dict
    performance: dict
    allow_public: bool
    sha256: str


def _split(v):
    items = v if isinstance(v, (list, tuple)) else [v]
    out = []
    for it in items:
        out += [x for x in re.split(r"[,\s]+", str(it).strip()) if x]
    return out


def parse_target(t):
    """Return ('net', [IPv4Network, ...]) or ('name', hostname). Raises ScopeError for anything else."""
    t = str(t).strip()
    try:
        n = ipaddress.ip_network(t, strict=False)
        if n.version != 4:
            raise ScopeError(f"'{t}': IPv6 is not supported")
        return "net", [n]
    except ValueError:
        pass
    if "://" in t or "/" in t:
        raise ScopeError(f"'{t}': use an IP, range, CIDR or bare domain name (no URLs or paths)")
    m = re.fullmatch(r"(\d+\.\d+\.\d+\.\d+)-(\d+(?:\.\d+\.\d+\.\d+)?)", t)
    if m:
        try:
            a = ipaddress.ip_address(m.group(1))
            end = m.group(2) if "." in m.group(2) else ".".join(m.group(1).split(".")[:3] + [m.group(2)])
            b = ipaddress.ip_address(end)
            if int(b) < int(a) or int(b) - int(a) >= 4096:
                raise ValueError
            return "net", list(ipaddress.summarize_address_range(a, b))
        except ValueError:
            raise ScopeError(f"'{t}' is not a valid IP range (max 4096 addresses)")
    if re.fullmatch(r"[0-9.]+", t):
        raise ScopeError(f"'{t}' is not a valid IP address")
    if _HOST.match(t):
        return "name", t.lower()
    raise ScopeError(f"'{t}' is not a valid IP, range, CIDR or domain name")


def _parse_list(vals):
    nets, names = [], []
    for t in _split(vals or []):
        kind, v = parse_target(t)
        if kind == "net":
            nets.extend(v)
        else:
            names.append(v)
    return nets, names


def _resolve(name):
    try:
        infos = socket.getaddrinfo(name, None, socket.AF_INET)
    except OSError as e:
        raise ScopeError(f"Cannot resolve '{name}': {e}")
    ips = sorted({i[4][0] for i in infos})
    if not ips:
        raise ScopeError(f"Cannot resolve '{name}'")
    if len(ips) > 16:
        raise ScopeError(f"'{name}' resolves to {len(ips)} addresses; list the specific IPs you are authorized to test")
    return ips


def _when(v, end=False):
    if isinstance(v, dt.datetime):
        d = v
    elif isinstance(v, dt.date):
        d = dt.datetime.combine(v, dt.time(23, 59, 59) if end else dt.time.min)
    else:
        s = str(v)
        d = dt.datetime.fromisoformat(s)
        if end and len(s) <= 10:
            d = d.replace(hour=23, minute=59, second=59)
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def load_scope(path="scope.yaml"):
    p = Path(path)
    if not p.exists():
        raise ScopeError(f"{path} not found")
    raw = p.read_bytes()
    d = yaml.safe_load(raw) or {}
    for k in ("engagement", "authorized_by", "auth_reference", "window_start", "window_end", "targets"):
        if not d.get(k):
            raise ScopeError(f"scope.yaml: '{k}' is required")
    if "CHANGE_ME" in (str(d["authorized_by"]), str(d["auth_reference"])):
        raise ScopeError("scope.yaml: set authorized_by and auth_reference (still CHANGE_ME). No scan without authorization.")
    nu = {"enabled": True, "mode": "full", "severity": ["low", "medium", "high", "critical"],
          "exclude_tags": ["dos", "fuzz", "intrusive", "bruteforce"], "rate_limit": 150, "concurrency": 25}
    nu.update(d.get("nuclei") or {})
    if nu["mode"] not in ("full", "auto"):
        raise ScopeError("scope.yaml: nuclei.mode must be 'full' or 'auto'")
    ts = {"enabled": True}
    ts.update(d.get("testssl") or {})
    nk = {"enabled": True, "max_time": 300}
    nk.update(d.get("nikto") or {})
    perf = {"workers": 3, "nmap_timing": 4}
    perf.update(d.get("performance") or {})
    try:
        perf = {"workers": int(perf["workers"]), "nmap_timing": int(perf["nmap_timing"])}
    except (TypeError, ValueError):
        raise ScopeError("scope.yaml: performance values must be integers")
    if not (1 <= perf["workers"] <= 16 and 1 <= perf["nmap_timing"] <= 5):
        raise ScopeError("scope.yaml: performance.workers must be 1-16 and nmap_timing 1-5")
    ports = str(d.get("ports") or "top1000").strip()
    if ports not in ("all", "top1000") and not re.fullmatch(r"[0-9,\-]+", ports):
        raise ScopeError("scope.yaml: ports must be 'all', 'top1000' or a list like 1-1024,8080")
    tn, tnames = _parse_list(d["targets"])
    en, enames = _parse_list(d.get("exclusions"))
    if not (tn or tnames):
        raise ScopeError("scope.yaml: 'targets' is required")
    return Scope(
        engagement=str(d["engagement"]), authorized_by=str(d["authorized_by"]), auth_reference=str(d["auth_reference"]),
        start=_when(d["window_start"]), end=_when(d["window_end"], end=True),
        targets=tn, target_names=tnames, exclusions=en, exclusion_names=enames,
        scripts=list(d.get("nse_scripts") or []), ports=ports, min_cvss=float(d.get("min_cvss", 7.0)),
        nuclei=nu, testssl=ts, nikto=nk, performance=perf, allow_public=bool(d.get("allow_public", False)),
        sha256=hashlib.sha256(raw).hexdigest())


def _inside(net, others):
    return any(net.version == o.version and net.subnet_of(o) for o in others)


def authorize(scope, targets=None, now=None, resolver=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    if now < scope.start:
        raise ScopeError("Authorization window has not started yet")
    if now > scope.end:
        raise ScopeError("Authorization window has expired")
    bad = [s for s in scope.scripts if s not in SAFE_SCRIPTS]
    if bad:
        raise ScopeError(f"NSE scripts not on the safe allowlist: {', '.join(bad)}")
    res = resolver or _resolve
    nets, names = list(scope.targets), []
    for n in scope.target_names:
        for ip in res(n):
            nets.append(ipaddress.ip_network(ip + "/32"))
            names.append((ip, n))
    excl = list(scope.exclusions)
    for n in scope.exclusion_names:
        excl += [ipaddress.ip_network(ip + "/32") for ip in res(n)]
    if not scope.allow_public:
        for n in nets:
            if not n.is_private:
                raise ScopeError(f"{n} is not a private address. Set allow_public: true only with explicit authorization")
    if targets:
        req = []
        for t in _split(targets):
            kind, v = parse_target(t)
            if kind == "net":
                req += v
            else:
                req += [ipaddress.ip_network(ip + "/32") for ip in res(v)]
    else:
        req = nets
    for r in req:
        if not _inside(r, nets):
            raise ScopeError(f"{r} is outside the authorized scope")
        if _inside(r, excl):
            raise ScopeError(f"{r} is explicitly excluded")
    return Authorization(tuple(str(r) for r in req), tuple(str(x) for x in excl), tuple(names), scope.sha256)
