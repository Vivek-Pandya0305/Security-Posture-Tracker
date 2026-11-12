"""Scan pipeline. _exec is the ONLY place a scanner process is started, and it requires an Authorization.
Order: Nmap (discovery, then deep scan of open ports) -> Nuclei / testssl / Nikto in parallel."""
from __future__ import annotations

import concurrent.futures as cf
import datetime as dt
import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import guard, parse, track
from .db import now


def _exec(cmd, auth, timeout, ips=()):
    if not isinstance(auth, guard.Authorization):
        raise guard.ScopeError("Scan attempted without authorization")
    for ip in ips:
        if not auth.permits(ip):
            raise guard.ScopeError(f"{ip} is not permitted by this authorization")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


@dataclass
class Job:
    tool: str
    tag: str
    label: str
    cmd: list
    out: Path
    timeout: int
    ips: list
    parse: Callable
    judge: Callable
    capture: bool = False


@dataclass
class Result:
    job: Job
    started: str
    ok: bool
    reason: str
    data: object


def run_job(job, auth, eng):
    started, data, ok, reason, p = now(), None, False, "", None
    try:
        p = _exec(job.cmd, auth, job.timeout, job.ips)
        if job.capture:
            job.out.write_text(p.stdout)
        ok, reason = job.judge(p, job.out)
        if ok:
            data = job.parse(job.out)
    except subprocess.TimeoutExpired:
        ok, reason = False, f"timed out after {job.timeout}s"
    except (ValueError, OSError) as e:
        ok, reason = False, f"{type(e).__name__}: {e}"
    (eng.logs_dir / f"{job.tool}-{job.tag}.log").write_text(
        f"$ {' '.join(job.cmd)}\nexit={p.returncode if p else 'n/a'}  ok={ok}  reason={reason}\n"
        f"--- stderr (tail) ---\n{(p.stderr if p else '')[-3000:]}\n--- stdout (tail) ---\n{(p.stdout if p else '')[-3000:]}\n")
    return Result(job, started, ok, reason, data)


def _record(con, tool, rt, cmd, scope, started, path, ok):
    sha = hashlib.sha256(Path(path).read_bytes()).hexdigest() if path and Path(path).exists() else None
    cur = con.execute("INSERT INTO scan_runs(tool,run_type,command,started_at,finished_at,raw_file,sha256,ok,scope_sha256) "
                      "VALUES(?,?,?,?,?,?,?,?,?)", (tool, rt, " ".join(cmd), started, now(), str(path) if sha else None, sha, int(ok), scope.sha256))
    con.commit()
    return cur.lastrowid


def store_inventory(con, rid, res):
    for ip, h in res.items():
        con.execute("INSERT OR REPLACE INTO hosts(run_id,ip,up) VALUES(?,?,?)", (rid, ip, int(h["up"])))
        for (port, proto), p in h["ports"].items():
            con.execute("INSERT INTO services(run_id,ip,port,proto,state,service,product,version) VALUES(?,?,?,?,?,?,?,?)",
                        (rid, ip, port, proto, p["state"], p["service"], p["product"], p["version"]))
    con.commit()


def _is_web(p):
    return p["service"].startswith("http")


def _is_tls(p):
    return p["tunnel"] == "ssl" or p["service"] == "https"


def _open_tcp(res):
    for ip, h in res.items():
        for (port, proto), p in h["ports"].items():
            if p["state"] == "open" and proto == "tcp":
                yield ip, port, p


def nuclei_targets(res):
    return [f"{'https' if _is_tls(p) else 'http'}://{ip}:{port}" if _is_web(p) else f"{ip}:{port}" for ip, port, p in _open_tcp(res)]


def tls_targets(res):
    return [(ip, port) for ip, port, p in _open_tcp(res) if _is_tls(p)]


def web_targets(res):
    return [(ip, port, f"{'https' if _is_tls(p) else 'http'}://{ip}:{port}") for ip, port, p in _open_tcp(res) if _is_web(p)]


def merge_discovery(deep, disc):
    """Deep-scan ports + discovery's host state and 'extra' (state of every unlisted port) for closed-port detection."""
    out = {}
    for ip, h in disc.items():
        out[ip] = {"up": h["up"], "extra": h["extra"], "ports": deep[ip]["ports"]} if ip in deep else h
    return out


def _run_parallel(jobs, auth, eng, workers, say):
    results = [None] * len(jobs)
    if not jobs:
        return results
    with cf.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = {ex.submit(run_job, j, auth, eng): i for i, j in enumerate(jobs)}
        for f in cf.as_completed(futs):
            r = f.result()
            results[futs[f]] = r
            say(f"  {r.job.tool} {r.job.label}: " + ("ok" if r.ok else f"FAILED - {r.reason}"))
    return results


def execute(con, scope, eng, run_type="baseline", targets=None, log=None):
    say = log or (lambda *_a: None)
    track.expire_accepted(con)
    auth = guard.authorize(scope, targets)
    if not shutil.which("nmap"):
        raise RuntimeError("nmap not found. Install: sudo apt install nmap")
    ts = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")   # microseconds: raw files are never overwritten
    for ip, name in auth.names:
        con.execute("INSERT INTO resolutions(at,name,ip) VALUES(?,?,?)", (now(), name, ip))
    con.commit()
    if auth.names:
        say("Resolved (pinned for this scan): " + ", ".join(f"{n} -> {i}" for i, n in auth.names))
    timing = f"-T{scope.performance['nmap_timing']}"
    excl = ["--exclude", ",".join(auth.exclusions)] if auth.exclusions else []
    script = ["--script", ",".join(scope.scripts)] if scope.scripts else []
    nm = eng.raw("nmap")

    def run_nmap(tool, cmd, out, ips=()):
        job = Job(tool, ts, "", cmd, out, 3600, list(ips), parse.parse_nmap,
                  lambda p, o: (p.returncode == 0 and o.exists(), f"exit {p.returncode}: {p.stderr.strip()[-300:]}"))
        r = run_job(job, auth, eng)
        rid = _record(con, tool, run_type, cmd, scope, r.started, out, r.ok)
        if not r.ok:
            raise RuntimeError(f"{tool} failed: {r.reason} (log: {eng.logs_dir / (tool + '-' + ts + '.log')})")
        return rid, r.data

    out = nm / f"nmap-{ts}.xml"
    if scope.ports == "all":
        say("Nmap 1/2: full-port discovery (all 65535 TCP ports)...")
        did, disc = run_nmap("nmap-discovery", ["nmap", "-p-", timing, "-n", "--min-rate", "1500", "--max-retries", "2",
                                                "-oX", str(nm / f"nmap-discovery-{ts}.xml")] + excl + list(auth.targets),
                             nm / f"nmap-discovery-{ts}.xml")
        hosts = {ip: sorted({pt for (pt, pr), v in h["ports"].items() if v["state"] == "open" and pr == "tcp"}) for ip, h in disc.items()}
        hosts = {ip: p for ip, p in hosts.items() if p}
        if hosts:
            ports = sorted({pt for p in hosts.values() for pt in p})
            say(f"Nmap 2/2: service + script scan of {len(ports)} open port(s) on {len(hosts)} host(s)...")
            rid, deep = run_nmap("nmap", ["nmap", "-sV", timing, "-n", "-p", ",".join(map(str, ports)), "-oX", str(out)] + script + list(hosts),
                                 out, ips=list(hosts))
            res = merge_discovery(deep, disc)
        else:
            rid, res = did, disc
    else:
        say("Nmap: service + script scan...")
        rid, res = run_nmap("nmap", ["nmap", "-sV", timing, "-n"] + ([] if scope.ports == "top1000" else ["-p", scope.ports])
                            + ["-oX", str(out)] + script + excl + list(auth.targets), out)
    store_inventory(con, rid, res)
    new, observed = track.ingest(con, rid, parse.nmap_findings(res, scope.min_cvss))

    # ---- build external-tool jobs (run in parallel)
    jobs, info = [], {}
    if scope.nuclei["enabled"]:
        tl = nuclei_targets(res)
        if not shutil.which("nuclei"):
            info["nuclei"] = (False, "skipped (not installed)")
        elif not tl:
            info["nuclei"] = (True, "nothing to test")
        else:
            n = scope.nuclei
            tfile, nout = eng.raw("nuclei") / f"nuclei-targets-{ts}.txt", eng.raw("nuclei") / f"nuclei-{ts}.jsonl"
            tfile.write_text("\n".join(tl) + "\n")
            cmd = ["nuclei", "-l", str(tfile), "-jsonl", "-o", str(nout), "-silent", "-duc", "-severity", ",".join(n["severity"]),
                   "-rl", str(n["rate_limit"]), "-c", str(n["concurrency"]), "-timeout", "7", "-retries", "1"]
            if n["mode"] == "auto":
                cmd.append("-as")
            if n["exclude_tags"]:
                cmd += ["-etags", ",".join(n["exclude_tags"])]
            jobs.append(Job("nuclei", ts, f"{len(tl)} target(s)", cmd, nout, 7200,
                            sorted({t.split("//")[-1].rsplit(":", 1)[0] for t in tl}),
                            lambda o: parse.parse_nuclei(o) if o.exists() else [],
                            lambda p, o: (p.returncode == 0, f"exit {p.returncode}: {p.stderr.strip()[-200:]}")))
    else:
        info["nuclei"] = (False, "disabled")

    if scope.testssl["enabled"]:
        exe, items = shutil.which("testssl.sh") or shutil.which("testssl"), tls_targets(res)
        if not exe:
            info["testssl"] = (False, "skipped (not installed)")
        elif not items:
            info["testssl"] = (True, "no TLS services")
        else:
            for ip, port in items:
                o = eng.raw("testssl") / f"testssl-{ts}-{ip}-{port}.json"
                jobs.append(Job("testssl", f"{ts}-{ip}-{port}", f"{ip}:{port}",
                                [exe, "--jsonfile", str(o), "--warnings", "batch", "--color", "0", "--quiet", "-p", "-U", f"{ip}:{port}"],
                                o, 900, [ip], lambda f, ip=ip, port=port: parse.parse_testssl(f, ip, port),
                                lambda p, f: (f.exists(), f"no JSON output; {p.stderr.strip()[-200:]}")))
    else:
        info["testssl"] = (False, "disabled")

    if scope.nikto["enabled"]:
        exe, items = shutil.which("nikto"), web_targets(res)
        mt = int(scope.nikto["max_time"])
        if not exe:
            info["nikto"] = (False, "skipped (not installed)")
        elif not items:
            info["nikto"] = (True, "no web services")
        else:
            for ip, port, url in items:
                o = eng.raw("nikto") / f"nikto-{ts}-{ip}-{port}.txt"
                vh = auth.names_for(ip)
                jobs.append(Job("nikto", f"{ts}-{ip}-{port}", url,
                                [exe, "-h", url, "-Tuning", "123b", "-ask", "no", "-maxtime", f"{mt}s"] + (["-vhost", vh[0]] if vh else []),
                                o, mt + 180, [ip], lambda f, ip=ip, port=port: parse.parse_nikto(f, ip, port),
                                lambda p, f: (("+ Target" in p.stdout) or ("Nikto v" in p.stdout),
                                              f"nikto printed no scan header (exit {p.returncode}): {(p.stderr or p.stdout).strip()[-200:]}"),
                                capture=True))
    else:
        info["nikto"] = (False, "disabled")

    by = {}
    for r in _run_parallel(jobs, auth, eng, scope.performance["workers"], say):
        by.setdefault(r.job.tool, []).append(r)
    for tool, rs in by.items():
        bad, found = [], 0
        for r in rs:
            rid2 = _record(con, tool, run_type, r.job.cmd, scope, r.started, r.job.out, r.ok)
            if r.ok:
                n2, o2 = track.ingest(con, rid2, r.data)
                new, observed, found = new + n2, observed | o2, found + len(r.data)
            else:
                bad.append(r)
        info[tool] = (not bad, f"ok ({found} raw finding(s))" if not bad else
                      f"failed for {len(bad)}/{len(rs)} target(s): {bad[0].reason} | logs: {eng.logs_dir}")

    summary = None
    if run_type == "retest":
        ok_map = {k: v[0] for k, v in info.items()}
        summary = track.evaluate(con, rid, res, observed, nmap_ok=True, nuclei_ok=ok_map.get("nuclei", False), tools_ok=ok_map)
    return {"new": new, "observed": len(observed), "retest": summary,
            "tools": {k: info[k][1] for k in ("nuclei", "testssl", "nikto")}, "resolved": list(auth.names)}
