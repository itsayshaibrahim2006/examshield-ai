"""Application service layer: validation, persistence and audit logging around the core modules."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import uuid

from . import db, llm, policy
from . import benchmark as B
from . import benchmark_data as D
from .pipeline import run_pipeline
from .resources import RESOURCES, catalog
from .scanner import scan_text, LIMITATIONS, SEVERITIES
from .scenarios import SCENARIOS

MAX_TEXT = 100_000
MAX_REQUEST = 2_000
MAX_UPLOAD_BYTES = 256 * 1024
ALLOWED_EXT = {".txt", ".md", ".csv", ".json", ".log", ".eml", ".html", ".htm"}


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def _bad(msg, code="invalid_input", status=422):
    raise ApiError(status, code, msg)


def _text(value, name, max_len, required=True, allow_empty=False):
    if value is None or value == "":
        if required and not allow_empty:
            _bad(f"'{name}' is required.")
        return ""
    if not isinstance(value, str):
        _bad(f"'{name}' must be text.")
    if len(value) > max_len:
        _bad(f"'{name}' is too long (max {max_len} characters).", "too_large", 413)
    if "\x00" in value:
        _bad(f"'{name}' contains a null byte.")
    return value


def _auth_list(value):
    if value in (None, ""):
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value) or len(value) > 20:
        _bad("'authorized_resources' must be a list of resource paths.")
    unknown = [x for x in value if x not in RESOURCES]
    if unknown:
        _bad(f"Unknown resource(s) in authorized_resources: {', '.join(unknown[:3])}.")
    return value


def _hash(t: str) -> str:
    return hashlib.sha256(t.encode("utf-8", "replace")).hexdigest()


# ---------- scenarios
def seed_scenarios():
    for s in SCENARIOS:
        db.execute(
            "INSERT OR REPLACE INTO scenarios(id,title,category,label,user_request,document,suspicious_instruction,expected_outcome,authorized_resources,description,is_builtin,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,1,?)",
            (s["id"], s["title"], s["category"], s["label"], s["user_request"], s["document"], s.get("suspicious_instruction", ""),
             s["expected_outcome"], json.dumps(s.get("authorized_resources", [])), s.get("description", ""), "2026-01-01T00:00:00.000Z"))


def _scn(row):
    row = dict(row)
    row["authorized_resources"] = json.loads(row["authorized_resources"])
    row["is_builtin"] = bool(row["is_builtin"])
    return row


def list_scenarios():
    return [_scn(r) for r in db.query("SELECT * FROM scenarios ORDER BY is_builtin DESC, id")]


def get_scenario(sid):
    r = db.one("SELECT * FROM scenarios WHERE id=?", (sid,))
    if not r:
        raise ApiError(404, "not_found", f"Scenario '{sid}' does not exist.")
    return _scn(r)


def create_scenario(p):
    if not isinstance(p, dict):
        _bad("Request body must be a JSON object.", "bad_request", 400)
    title = _text(p.get("title"), "title", 120)
    req = _text(p.get("user_request"), "user_request", MAX_REQUEST)
    doc = _text(p.get("document"), "document", MAX_TEXT)
    label = p.get("label", "ambiguous")
    if label not in ("malicious", "benign", "ambiguous"):
        _bad("'label' must be malicious, benign or ambiguous.")
    expected = p.get("expected_outcome", "block" if label == "malicious" else "allow")
    if expected not in ("block", "allow"):
        _bad("'expected_outcome' must be block or allow.")
    susp = _text(p.get("suspicious_instruction"), "suspicious_instruction", 1000, required=False)
    desc = _text(p.get("description"), "description", 500, required=False)
    auth = _auth_list(p.get("authorized_resources"))
    sid = "CU-" + uuid.uuid4().hex[:6].upper()
    db.execute("INSERT INTO scenarios(id,title,category,label,user_request,document,suspicious_instruction,expected_outcome,authorized_resources,description,is_builtin,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,0,?)",
               (sid, title, "custom", label, req, doc, susp, expected, json.dumps(auth), desc, db.now_iso()))
    db.audit("scenario_created", "user", f"Custom scenario {sid} created: {title[:60]}", details={"id": sid})
    return get_scenario(sid)


def delete_scenario(sid):
    s = get_scenario(sid)
    if s["is_builtin"]:
        raise ApiError(403, "forbidden", "Built-in scenarios cannot be deleted.")
    db.execute("DELETE FROM scenarios WHERE id=?", (sid,))
    db.audit("scenario_deleted", "user", f"Custom scenario {sid} deleted", details={"id": sid})
    return {"deleted": sid}


# ---------- scanning
def _store_scan(result, text, source):
    scan_id = db.execute("INSERT INTO scans(source,text_sha256,text_length,risk,flagged,uncertain,mode,created_at) VALUES (?,?,?,?,?,?,?,?)",
                         (source, _hash(text), len(text), result.risk, int(result.flagged), int(result.uncertain), result.mode, db.now_iso()))
    for f in result.findings:
        db.execute("INSERT INTO scanner_findings(scan_id,finding_ref,rule_id,category,signal,severity,confidence,start_offset,end_offset,matched_text,quoted,explanation) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                   (scan_id, f.id, f.rule_id, f.category, f.signal, f.severity, f.confidence, f.start, f.end, f.text[:300], int(f.quoted), f.explanation))
    return scan_id


def scan(payload, source="scanner", scanner=None):
    if not isinstance(payload, dict):
        _bad("Request body must be a JSON object.", "bad_request", 400)
    text = _text(payload.get("text"), "text", MAX_TEXT)
    res = (scanner or scan_text)(text)
    scan_id = _store_scan(res, text, source)
    out = res.to_dict()
    out["scan_id"] = scan_id
    out["llm_analysis"] = llm.analyze(text) if payload.get("use_llm") else {"used": False, "reason": "Not requested."}
    out["text_length"] = len(text)
    db.audit("scan", "scanner", f"Scan ({source}) rated {res.risk.upper()} with {len(res.findings)} finding(s)",
             decision="flagged" if res.flagged else "clear", details={"scan_id": scan_id, "risk": res.risk, "categories": res.categories})
    return out


def scan_upload(payload):
    if not isinstance(payload, dict):
        _bad("Request body must be a JSON object.", "bad_request", 400)
    name = payload.get("filename")
    b64 = payload.get("content_base64")
    if not isinstance(name, str) or not name.strip():
        _bad("'filename' is required.")
    if not isinstance(b64, str):
        _bad("'content_base64' is required.")
    safe = re.sub(r"[^\w.\- ]", "_", os.path.basename(name.replace("\\", "/")))[:100]
    ext = os.path.splitext(safe)[1].lower()
    if ext not in ALLOWED_EXT:
        raise ApiError(415, "unsupported_type", f"File type '{ext or 'none'}' is not accepted. Allowed: {', '.join(sorted(ALLOWED_EXT))}.")
    if len(b64) > MAX_UPLOAD_BYTES * 4 // 3 + 8:
        raise ApiError(413, "too_large", f"File is larger than {MAX_UPLOAD_BYTES // 1024} KB.")
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        _bad("File content is not valid base64.")
    if len(raw) > MAX_UPLOAD_BYTES:
        raise ApiError(413, "too_large", f"File is larger than {MAX_UPLOAD_BYTES // 1024} KB.")
    if b"\x00" in raw:
        raise ApiError(415, "binary_content", "File appears to be binary, not text.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ApiError(422, "bad_encoding", "File is not valid UTF-8 text.")
    if not text.strip():
        _bad("File is empty.")
    out = scan({"text": text, "use_llm": payload.get("use_llm")}, source="upload")
    out["file"] = {"name": safe, "bytes": len(raw), "handling": "Decoded as plain text only. Never executed, rendered or stored."}
    out["text"] = text
    return out


# ---------- policy evaluation
def evaluate_action(payload):
    if not isinstance(payload, dict):
        _bad("Request body must be a JSON object.", "bad_request", 400)
    req = _text(payload.get("task_request"), "task_request", MAX_REQUEST, required=False)
    action = payload.get("action")
    if not isinstance(action, dict):
        _bad("'action' must be an object with at least a 'type'.")
    auth = _auth_list(payload.get("authorized_resources"))
    grant = policy.derive_grant(req)
    dec = policy.evaluate(action, grant, auth)
    atype = str(action.get("type"))[:60]
    did = db.execute("INSERT INTO security_decisions(run_id,source,action_type,resource,origin,decision,rule_id,reason,checks,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                     (None, "api", atype, str(action.get("resource") or "")[:200] or None, str(action.get("origin") or "unknown")[:40],
                      dec.decision, dec.rule_id, dec.reason, json.dumps(dec.checks), db.now_iso()))
    db.audit("policy_decision", "protection_engine", f"{dec.decision.upper()} {atype}: {dec.reason}", decision=dec.decision, rule_id=dec.rule_id,
             details={"decision_id": did, "resource": action.get("resource")})
    return {"decision_id": did, "grant": grant.to_dict(), **dec.to_dict()}


# ---------- simulation
def _resolve_case(p):
    if p.get("scenario_id"):
        s = get_scenario(str(p["scenario_id"]))
        return s["user_request"], s["document"], s["authorized_resources"], s["id"], s["label"]
    req = _text(p.get("user_request"), "user_request", MAX_REQUEST)
    doc = _text(p.get("document"), "document", MAX_TEXT)
    return req, doc, _auth_list(p.get("authorized_resources")), None, None


def _store_run(trace, req, scenario_id, label, source, pair_id):
    scan_id = None
    flagged = risk = None
    if trace["scan"]:
        sc = trace["scan"]
        class _R:  # lightweight adapter for _store_scan
            pass
        from .scanner import Finding, ScanResult
        findings = [Finding(**f) for f in sc["findings"]]
        res = ScanResult(sc["risk"], sc["flagged"], sc["uncertain"], sc["score"], findings, sc["mode"], sc["llm_used"], sc["summary"], sc["limitations"], sc["categories"])
        scan_id = _store_scan(res, trace.get("_document", ""), "simulation")
        flagged, risk = int(sc["flagged"]), sc["risk"]
    o = trace["outcome"]
    t = {k: v for k, v in trace.items() if k != "_document"}
    run_id = db.execute("INSERT INTO simulation_runs(source,scenario_id,mode,pair_id,user_request,label,risk,flagged,attack_attempted,unauthorized_executed,task_completed,final_message,scan_id,duration_ms,trace,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (source, scenario_id, trace["mode"], pair_id, req[:500], label, risk, flagged, int(o["attack_attempted"]), int(o["unauthorized_executed"]),
                        int(o["task_completed"]), o["final_message"], scan_id, trace["duration_ms"], json.dumps(t), db.now_iso()))
    for rec in trace["actions"]:
        a, d = rec["action"], rec["decision"]
        did = db.execute("INSERT INTO security_decisions(run_id,source,action_type,resource,origin,decision,rule_id,reason,checks,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                         (run_id, source, a["type"], a.get("resource"), a.get("origin"), d["decision"], d["rule_id"], d["reason"], json.dumps(d["checks"]), db.now_iso()))
        db.execute("INSERT INTO simulated_actions(run_id,decision_id,action_type,resource,origin,executed,output_preview,created_at) VALUES (?,?,?,?,?,?,?,?)",
                   (run_id, did, a["type"], a.get("resource"), a.get("origin"), int(rec["executed"]), (rec["output"] or "")[:200], db.now_iso()))
        if trace["mode"] == "protected":
            db.audit("policy_decision", "protection_engine", f"{d['decision'].upper()} {a['type']}" + (f" on {a['resource']}" if a.get("resource") else "") + f" (origin: {a['origin']})",
                     decision=d["decision"], rule_id=d["rule_id"], details={"decision_id": did}, ref_run_id=run_id)
    db.audit("simulation_run", "simulator", f"{trace['mode']} run: {o['final_message']}", decision="failure" if o["unauthorized_executed"] else "safe",
             details={"scenario_id": scenario_id, "pair_id": pair_id}, ref_run_id=run_id)
    return run_id


def simulate(payload, source="lab", scanner=None):
    if not isinstance(payload, dict):
        _bad("Request body must be a JSON object.", "bad_request", 400)
    mode = payload.get("mode", "both")
    if mode not in ("both", "protected", "unprotected"):
        _bad("'mode' must be both, protected or unprotected.")
    req, doc, auth, sid, label = _resolve_case(payload)
    pair_id = uuid.uuid4().hex[:8].upper()
    out = {"pair_id": pair_id, "scenario_id": sid, "user_request": req, "document": doc, "authorized_resources": auth,
           "simulation_notice": "Simulated assistant and simulated resources only. Not evidence that a real model or system was compromised."}
    if mode in ("unprotected", "both"):
        tr = run_pipeline(req, doc, auth, protected=False)
        tr["_document"] = doc
        tr["run_id"] = _store_run(tr, req, sid, label, source, pair_id)
        tr.pop("_document", None)
        out["unprotected"] = tr
    if mode in ("protected", "both"):
        tr = run_pipeline(req, doc, auth, protected=True, scanner=scanner)
        tr["_document"] = doc
        tr["run_id"] = _store_run(tr, req, sid, label, source, pair_id)
        tr.pop("_document", None)
        out["protected"] = tr
    return out


def get_run(run_id):
    r = db.one("SELECT * FROM simulation_runs WHERE id=?", (run_id,))
    if not r:
        raise ApiError(404, "not_found", f"Run {run_id} does not exist.")
    r["trace"] = json.loads(r["trace"] or "{}")
    return r


def list_runs(limit=50, offset=0):
    rows = db.query("SELECT id,source,scenario_id,mode,pair_id,user_request,label,risk,flagged,attack_attempted,unauthorized_executed,task_completed,final_message,created_at FROM simulation_runs ORDER BY id DESC LIMIT ? OFFSET ?", (limit, offset))
    return {"runs": rows, "total": db.one("SELECT COUNT(*) AS n FROM simulation_runs")["n"]}


# ---------- benchmark
def run_benchmark(scanner=None):
    started = db.now_iso()
    cases = D.build_cases()
    results, metrics = B.run_all(scanner, cases)
    finished = db.now_iso()
    config = {"scanner_mode": "local-deterministic", "flag_threshold": "medium", "protection": "policy engine enforced independently"}
    rid = db.execute("INSERT INTO benchmark_runs(started_at,finished_at,dataset_name,dataset_version,dataset_sha256,total_cases,metrics,config) VALUES (?,?,?,?,?,?,?,?)",
                     (started, finished, D.DATASET_NAME, D.DATASET_VERSION, D.dataset_sha256(cases), len(cases), json.dumps(metrics), json.dumps(config)))
    for r in results:
        db.execute("INSERT INTO benchmark_results(run_id,case_id,label,pattern,risk,flagged,outcome,baseline_attack_succeeded,protected_attack_blocked,scanner_only_blocked,task_completed_protected,details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                   (rid, r["case_id"], r["label"], r["pattern"], r["risk"], int(r["flagged"]), r["outcome"],
                    int(r["baseline_attack_succeeded"]), None if r["protected_attack_blocked"] is None else int(r["protected_attack_blocked"]),
                    None if r["scanner_only_blocked"] is None else int(r["scanner_only_blocked"]), int(r["task_completed_protected"]), json.dumps(r["details"])))
    c = metrics["confusion"]
    db.audit("benchmark_run", "benchmark", f"Benchmark run {rid}: {len(cases)} cases, TP={c['tp']} FP={c['fp']} TN={c['tn']} FN={c['fn']}",
             details={"run_id": rid, "dataset_sha256": D.dataset_sha256(cases)})
    return get_benchmark(rid)


def _bm(row):
    row = dict(row)
    row["metrics"] = json.loads(row["metrics"])
    row["config"] = json.loads(row["config"])
    return row


def list_benchmarks():
    return [_bm(r) for r in db.query("SELECT * FROM benchmark_runs ORDER BY id DESC LIMIT 50")]


def get_benchmark(rid, with_results=True):
    r = db.one("SELECT * FROM benchmark_runs WHERE id=?", (rid,))
    if not r:
        raise ApiError(404, "not_found", f"Benchmark run {rid} does not exist.")
    r = _bm(r)
    if with_results:
        rows = db.query("SELECT * FROM benchmark_results WHERE run_id=? ORDER BY id", (rid,))
        for x in rows:
            x["details"] = json.loads(x["details"] or "{}")
        r["results"] = rows
    return r


def latest_benchmark_id():
    r = db.one("SELECT id FROM benchmark_runs ORDER BY id DESC LIMIT 1")
    return r["id"] if r else None


# ---------- audit / stats
def list_audit(limit=100, offset=0, event_type=None, decision=None):
    where, params = [], []
    if event_type:
        where.append("event_type=?"); params.append(event_type)
    if decision:
        where.append("decision=?"); params.append(decision)
    w = (" WHERE " + " AND ".join(where)) if where else ""
    rows = db.query(f"SELECT * FROM audit_events{w} ORDER BY id DESC LIMIT ? OFFSET ?", tuple(params) + (limit, offset))
    for r in rows:
        r["details"] = json.loads(r["details"] or "{}")
    total = db.one(f"SELECT COUNT(*) AS n FROM audit_events{w}", tuple(params))["n"]
    return {"events": rows, "total": total}


def get_audit(eid):
    r = db.one("SELECT * FROM audit_events WHERE id=?", (eid,))
    if not r:
        raise ApiError(404, "not_found", f"Audit event {eid} does not exist.")
    r["details"] = json.loads(r["details"] or "{}")
    related = None
    if r["ref_run_id"]:
        related = db.one("SELECT id,mode,scenario_id,final_message,created_at FROM simulation_runs WHERE id=?", (r["ref_run_id"],))
    return {"event": r, "run": related}


def stats():
    n = lambda sql, p=(): db.one(sql, p)["n"]
    runs = n("SELECT COUNT(*) AS n FROM simulation_runs")
    bench_cases = n("SELECT COUNT(*) AS n FROM benchmark_results")
    lb = latest_benchmark_id()
    latest = get_benchmark(lb, with_results=False) if lb else None
    return {
        "total_tests": runs + bench_cases, "simulation_runs": runs, "benchmark_cases_executed": bench_cases,
        "scans": n("SELECT COUNT(*) AS n FROM scans"),
        "threats_detected": n("SELECT COUNT(*) AS n FROM scans WHERE flagged=1"),
        "unauthorized_blocked": n("SELECT COUNT(*) AS n FROM security_decisions WHERE decision='deny' AND source<>'api' AND origin='untrusted_content'"),
        "denials_total": n("SELECT COUNT(*) AS n FROM security_decisions WHERE decision='deny'"),
        "simulated_failures_unprotected": n("SELECT COUNT(*) AS n FROM simulation_runs WHERE mode='unprotected' AND unauthorized_executed=1"),
        "false_positives_lab": n("SELECT COUNT(*) AS n FROM simulation_runs WHERE mode='protected' AND label='benign' AND flagged=1"),
        "false_positives_benchmark_latest": latest["metrics"]["confusion"]["fp"] if latest else None,
        "latest_benchmark": latest,
        "recent_events": list_audit(limit=8)["events"],
        "latest_runs": list_runs(limit=8)["runs"],
        "data_note": "Every number is counted from stored records. Empty until you run scenarios or the benchmark.",
    }


def system_info():
    import platform, sys
    return {
        "version": "1.0.0", "python": sys.version.split()[0], "platform": platform.system(),
        "detection_mode": "local-deterministic", "llm": llm.status(),
        "database": "SQLite (stdlib sqlite3, parameterised queries)",
        "limits": {"max_text_chars": MAX_TEXT, "max_upload_kb": MAX_UPLOAD_BYTES // 1024, "allowed_extensions": sorted(ALLOWED_EXT)},
        "dataset": {"name": D.DATASET_NAME, "version": D.DATASET_VERSION, "cases": len(D.build_cases()), "synthetic": True},
        "limitations": LIMITATIONS,
        "stack_note": "Built with the Python standard library and a no-build JavaScript front end because package installation was unavailable. See docs/VERIFICATION.md.",
        "resources": catalog(),
    }


def clear_history(confirm):
    if confirm is not True:
        _bad("Send {\"confirm\": true} to clear stored history.")
    for t in ("benchmark_results", "benchmark_runs", "simulated_actions", "security_decisions", "simulation_runs", "scanner_findings", "scans", "audit_events"):
        db.execute(f"DELETE FROM {t}")
    db.audit("history_cleared", "user", "Run history, benchmark records and audit events were cleared by the user.")
    return {"cleared": True}


def init():
    db.init_db()
    seed_scenarios()
