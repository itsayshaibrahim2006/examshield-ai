"""SQLite persistence using only parameterised statements (stdlib sqlite3)."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parent.parent / "data" / "examshield.db"
_lock = threading.RLock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS scenarios(
  id TEXT PRIMARY KEY, title TEXT NOT NULL, category TEXT NOT NULL, label TEXT NOT NULL,
  user_request TEXT NOT NULL, document TEXT NOT NULL, suspicious_instruction TEXT NOT NULL DEFAULT '',
  expected_outcome TEXT NOT NULL, authorized_resources TEXT NOT NULL DEFAULT '[]',
  description TEXT NOT NULL DEFAULT '', is_builtin INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, text_sha256 TEXT NOT NULL, text_length INTEGER NOT NULL,
  risk TEXT NOT NULL, flagged INTEGER NOT NULL, uncertain INTEGER NOT NULL, mode TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scanner_findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  finding_ref TEXT, rule_id TEXT, category TEXT, signal TEXT, severity TEXT, confidence TEXT,
  start_offset INTEGER, end_offset INTEGER, matched_text TEXT, quoted INTEGER, explanation TEXT);
CREATE TABLE IF NOT EXISTS simulation_runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, source TEXT NOT NULL, scenario_id TEXT, mode TEXT NOT NULL, pair_id TEXT,
  user_request TEXT NOT NULL, label TEXT, risk TEXT, flagged INTEGER, attack_attempted INTEGER NOT NULL,
  unauthorized_executed INTEGER NOT NULL, task_completed INTEGER NOT NULL, final_message TEXT, scan_id INTEGER,
  duration_ms REAL, trace TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS security_decisions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER, source TEXT NOT NULL, action_type TEXT NOT NULL, resource TEXT,
  origin TEXT, decision TEXT NOT NULL, rule_id TEXT NOT NULL, reason TEXT NOT NULL, checks TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS simulated_actions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL, decision_id INTEGER, action_type TEXT NOT NULL,
  resource TEXT, origin TEXT, executed INTEGER NOT NULL, output_preview TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS benchmark_runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, finished_at TEXT NOT NULL, dataset_name TEXT NOT NULL,
  dataset_version TEXT NOT NULL, dataset_sha256 TEXT NOT NULL, total_cases INTEGER NOT NULL, metrics TEXT NOT NULL, config TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS benchmark_results(
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id INTEGER NOT NULL REFERENCES benchmark_runs(id) ON DELETE CASCADE,
  case_id TEXT NOT NULL, label TEXT NOT NULL, pattern TEXT, risk TEXT, flagged INTEGER, outcome TEXT,
  baseline_attack_succeeded INTEGER, protected_attack_blocked INTEGER, scanner_only_blocked INTEGER,
  task_completed_protected INTEGER, details TEXT);
CREATE TABLE IF NOT EXISTS audit_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, event_type TEXT NOT NULL, actor TEXT NOT NULL,
  decision TEXT, rule_id TEXT, summary TEXT NOT NULL, details TEXT NOT NULL DEFAULT '{}', ref_run_id INTEGER);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);
CREATE INDEX IF NOT EXISTS idx_runs_created ON simulation_runs(created_at);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def db_path() -> Path:
    return Path(os.environ.get("EXAMSHIELD_DB") or DEFAULT_DB)


def connect() -> sqlite3.Connection:
    p = db_path()
    if str(p) != ":memory:":
        p.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(p), timeout=10)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db() -> None:
    with _lock, connect() as con:
        con.executescript(SCHEMA)


def execute(sql: str, params: tuple = ()) -> int:
    with _lock, connect() as con:
        cur = con.execute(sql, params)
        return cur.lastrowid


def executemany_tx(statements: list[tuple[str, tuple]]) -> None:
    with _lock, connect() as con:
        for sql, params in statements:
            con.execute(sql, params)


def query(sql: str, params: tuple = ()) -> list[dict]:
    with _lock, connect() as con:
        return [dict(r) for r in con.execute(sql, params).fetchall()]


def one(sql: str, params: tuple = ()) -> dict | None:
    rows = query(sql, params)
    return rows[0] if rows else None


def audit(event_type: str, actor: str, summary: str, decision: str | None = None, rule_id: str | None = None,
          details: dict | None = None, ref_run_id: int | None = None) -> int:
    return execute(
        "INSERT INTO audit_events(ts,event_type,actor,decision,rule_id,summary,details,ref_run_id) VALUES (?,?,?,?,?,?,?,?)",
        (now_iso(), event_type, actor, decision, rule_id, summary, json.dumps(details or {}), ref_run_id))
