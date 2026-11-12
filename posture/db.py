import datetime as dt
import sqlite3
from pathlib import Path

DB = "posture.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs(id INTEGER PRIMARY KEY, tool TEXT, run_type TEXT, command TEXT,
  started_at TEXT, finished_at TEXT, raw_file TEXT, sha256 TEXT, ok INTEGER DEFAULT 0, scope_sha256 TEXT);
CREATE TABLE IF NOT EXISTS hosts(run_id INTEGER, ip TEXT, up INTEGER, PRIMARY KEY(run_id, ip));
CREATE TABLE IF NOT EXISTS services(id INTEGER PRIMARY KEY, run_id INTEGER, ip TEXT, port INTEGER,
  proto TEXT, state TEXT, service TEXT, product TEXT, version TEXT);
CREATE TABLE IF NOT EXISTS findings(id INTEGER PRIMARY KEY, fingerprint TEXT UNIQUE, ip TEXT, port INTEGER,
  proto TEXT, source TEXT, vuln_id TEXT, title TEXT, description TEXT, cvss REAL, severity TEXT,
  override_severity TEXT, override_reason TEXT, banner TEXT DEFAULT '', status TEXT DEFAULT 'Open',
  owner TEXT, due_date TEXT, action TEXT, approver TEXT, expiry TEXT, reason TEXT,
  first_run INTEGER, last_run INTEGER, updated_at TEXT,
  confidence TEXT DEFAULT 'Unverified', seen_by TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS evidence(id INTEGER PRIMARY KEY, finding_id INTEGER, run_id INTEGER, excerpt TEXT);
CREATE TABLE IF NOT EXISTS retests(id INTEGER PRIMARY KEY, finding_id INTEGER, run_id INTEGER, result TEXT, tested_at TEXT);
CREATE TABLE IF NOT EXISTS status_log(id INTEGER PRIMARY KEY, finding_id INTEGER, old TEXT, new TEXT, at TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS resolutions(id INTEGER PRIMARY KEY, at TEXT, name TEXT, ip TEXT);
CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY, at TEXT, actor TEXT, action TEXT, detail TEXT);
"""


def now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _migrate(con):
    cols = {r[1] for r in con.execute("PRAGMA table_info(findings)")}
    for c, d in (("confidence", "TEXT DEFAULT 'Unverified'"), ("seen_by", "TEXT DEFAULT ''")):
        if c not in cols:
            con.execute(f"ALTER TABLE findings ADD COLUMN {c} {d}")


def connect(path=DB, must_exist=True):
    if must_exist and not Path(path).exists():
        raise SystemExit("No posture.db in this folder. Run: posture init")
    con = sqlite3.connect(path, timeout=30)
    con.row_factory = sqlite3.Row
    if str(path) != ":memory:":
        con.execute("PRAGMA journal_mode=WAL")
    con.executescript(SCHEMA)
    _migrate(con)
    return con


def audit(path, action, detail="", actor="web"):
    con = connect(path, must_exist=False)
    try:
        con.execute("INSERT INTO audit_log(at,actor,action,detail) VALUES(?,?,?,?)", (now(), actor, action, detail[:500]))
        con.commit()
    finally:
        con.close()
