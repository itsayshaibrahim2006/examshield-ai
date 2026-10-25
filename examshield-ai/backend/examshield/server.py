"""HTTP API + static file server (Python standard library only).

Run:  python run.py   (binds to 127.0.0.1:8000 by default)
"""
from __future__ import annotations

import json
import mimetypes
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from . import service as S
from . import policy
from .resources import catalog, RESOURCES
from .service import ApiError

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
MAX_BODY = 600 * 1024


def _int(qs, key, default, lo, hi):
    raw = qs.get(key, [None])[0]
    if raw is None:
        return default
    try:
        v = int(raw)
    except ValueError:
        raise ApiError(422, "invalid_input", f"'{key}' must be an integer.")
    if not lo <= v <= hi:
        raise ApiError(422, "invalid_input", f"'{key}' must be between {lo} and {hi}.")
    return v


def route(method: str, path: str, qs: dict, body):
    m = None
    def match(p):
        nonlocal m
        m = re.fullmatch(p, path)
        return m
    if path == "/api/health" and method == "GET":
        return {"status": "ok", "service": "examshield-ai", "version": "1.0.0"}
    if path == "/api/system" and method == "GET":
        return S.system_info()
    if path == "/api/stats" and method == "GET":
        return S.stats()
    if path == "/api/resources" and method == "GET":
        return {"resources": [dict(r, content=RESOURCES[r["path"]]["content"]) for r in catalog()],
                "note": "All resources are synthetic and held in memory. No real file is ever read."}
    if path == "/api/policy" and method == "GET":
        return policy.policy_description()
    if path == "/api/scenarios":
        if method == "GET":
            return {"scenarios": S.list_scenarios()}
        if method == "POST":
            return S.create_scenario(body)
    if match(r"/api/scenarios/([\w\-]+)"):
        if method == "GET":
            return S.get_scenario(m.group(1))
        if method == "DELETE":
            return S.delete_scenario(m.group(1))
    if path == "/api/scan" and method == "POST":
        return S.scan(body)
    if path == "/api/scan/upload" and method == "POST":
        return S.scan_upload(body)
    if path == "/api/policy/evaluate" and method == "POST":
        return S.evaluate_action(body)
    if path == "/api/simulate" and method == "POST":
        return S.simulate(body)
    if path == "/api/runs" and method == "GET":
        return S.list_runs(_int(qs, "limit", 50, 1, 200), _int(qs, "offset", 0, 0, 10**7))
    if match(r"/api/runs/(\d+)") and method == "GET":
        return S.get_run(int(m.group(1)))
    if path == "/api/benchmark/run" and method == "POST":
        return S.run_benchmark()
    if path == "/api/benchmark/runs" and method == "GET":
        return {"runs": S.list_benchmarks()}
    if path == "/api/benchmark/latest" and method == "GET":
        rid = S.latest_benchmark_id()
        if rid is None:
            raise ApiError(404, "not_found", "No benchmark has been run yet.")
        return S.get_benchmark(rid)
    if match(r"/api/benchmark/runs/(\d+)") and method == "GET":
        return S.get_benchmark(int(m.group(1)))
    if path == "/api/audit" and method == "GET":
        et = qs.get("event_type", [None])[0]
        dc = qs.get("decision", [None])[0]
        return S.list_audit(_int(qs, "limit", 100, 1, 500), _int(qs, "offset", 0, 0, 10**7), et, dc)
    if match(r"/api/audit/(\d+)") and method == "GET":
        return S.get_audit(int(m.group(1)))
    if path == "/api/admin/clear-history" and method == "POST":
        return S.clear_history((body or {}).get("confirm") if isinstance(body, dict) else None)
    known = [r"/api/health", r"/api/system", r"/api/stats", r"/api/resources", r"/api/policy", r"/api/scenarios", r"/api/scan",
             r"/api/scan/upload", r"/api/policy/evaluate", r"/api/simulate", r"/api/runs", r"/api/benchmark/\w+", r"/api/audit"]
    if path.startswith("/api/"):
        for k in known:
            if re.fullmatch(k, path):
                raise ApiError(405, "method_not_allowed", f"{method} is not supported on {path}.")
        raise ApiError(404, "not_found", f"No such endpoint: {path}")
    return None


class Handler(BaseHTTPRequestHandler):
    server_version = "ExamShield/1.0"

    def log_message(self, fmt, *args):
        if os.environ.get("EXAMSHIELD_QUIET") != "1":
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, status, payload, ctype="application/json; charset=utf-8", extra=None):
        data = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _error(self, e: ApiError):
        self._send(e.status, {"error": {"code": e.code, "message": e.message}})

    def _read_body(self):
        length = self.headers.get("Content-Length") or "0"
        try:
            n = int(length)
        except ValueError:
            raise ApiError(400, "bad_request", "Invalid Content-Length.")
        if n < 0 or n > MAX_BODY:
            raise ApiError(413, "too_large", f"Request body exceeds {MAX_BODY // 1024} KB.")
        raw = self.rfile.read(n) if n else b""
        if not raw:
            return {}
        if "json" not in (self.headers.get("Content-Type") or ""):
            raise ApiError(415, "unsupported_media_type", "Content-Type must be application/json.")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ApiError(400, "malformed_json", "Request body is not valid JSON.")

    def _handle(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        try:
            if u.path.startswith("/api/"):
                body = self._read_body() if self.command in ("POST", "PUT", "PATCH", "DELETE") else None
                result = route(self.command, u.path, qs, body)
                status = 201 if (self.command == "POST" and u.path == "/api/scenarios") else 200
                return self._send(status, result)
            if self.command not in ("GET", "HEAD"):
                raise ApiError(405, "method_not_allowed", "Only GET is supported for pages.")
            return self._static(u.path)
        except ApiError as e:
            return self._error(e)
        except Exception as e:  # never leak internals
            sys.stderr.write(f"internal error: {type(e).__name__}: {e}\n")
            return self._send(500, {"error": {"code": "internal_error", "message": "Something went wrong on the server. The action was not performed."}})

    def _static(self, path):
        rel = path.lstrip("/") or "index.html"
        target = (FRONTEND / rel).resolve()
        if FRONTEND.resolve() not in target.parents and target != FRONTEND.resolve():
            raise ApiError(403, "forbidden", "Path not allowed.")
        if not target.is_file():
            target = FRONTEND / "index.html"
        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        self._send(200, target.read_bytes(), ctype)

    do_GET = do_POST = do_DELETE = do_PUT = do_PATCH = do_HEAD = _handle


def make_server(host="127.0.0.1", port=8000):
    S.init()
    return ThreadingHTTPServer((host, port), Handler)


def main():
    host = os.environ.get("EXAMSHIELD_HOST", "127.0.0.1")
    port = int(os.environ.get("EXAMSHIELD_PORT", "8000"))
    srv = make_server(host, port)
    print(f"ExamShield AI running at http://{host}:{port}  (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
