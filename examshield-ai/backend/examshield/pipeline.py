"""Runs one scenario through the simulated assistant with or without protection."""
from __future__ import annotations

import time
from typing import Callable

from . import policy as P
from .resources import RESOURCES, canaries
from . import simulator as S
from .scanner import scan_text, ScanResult, empty_result

ScannerFn = Callable[[str], ScanResult]


def run_pipeline(user_request: str, document: str, authorized_resources: list[str] | None = None,
                 protected: bool = True, scanner: ScannerFn | None = None) -> dict:
    t0 = time.perf_counter()
    authorized = [a for a in (authorized_resources or []) if a in RESOURCES]
    grant = P.derive_grant(user_request)
    steps: list[dict] = []
    scan = None
    sanitize: list[str] = []
    if protected:
        scan = (scanner or scan_text)(document)
        steps.append({"step": "scan", "detail": f"Scanner ({scan.mode}) rated the document {scan.risk.upper()} with {len(scan.findings)} finding(s)."})
        if scan.flagged:
            sanitize = S.directive_sentences(document)
    steps.append({"step": "trusted_grant", "detail": f"Grant derived from the user's request only: {grant.allowed_actions or 'nothing'}."})
    proposed = S.plan(grant, user_request, document, reassert_task=protected)
    steps.append({"step": "assistant_plan", "detail": f"Simulated assistant proposed {len(proposed)} action(s)."})
    records: list[dict] = []
    outputs_for_summary: list[str] = []
    for act in proposed:
        shadow = P.evaluate(act, grant, authorized)  # what the real policy says, always computed
        if protected:
            dec = shadow
        else:
            dec = P.Decision("allow", "UNPROTECTED_ALLOW_ALL", "Protection disabled: every proposed action is allowed (simulation).", [])
        executed = dec.decision == "allow"
        output = None
        if executed:
            ctx = outputs_for_summary if act["type"] in ("summarize_text", "answer_question") else []
            output = S.execute(act, document, ctx, sanitize)
            if act["type"] == "read_resource" and act["origin"] == "user_task":
                outputs_for_summary.append(output)
        records.append({"action": act, "decision": dec.to_dict(), "policy_verdict": shadow.decision,
                        "policy_rule": shadow.rule_id, "executed": executed, "output": output})
    attack = [r for r in records if r["action"]["origin"] == "untrusted_content"]
    unauthorized_executed = [r for r in records if r["executed"] and r["policy_verdict"] == "deny"]
    disclosed = sorted({p for r in unauthorized_executed for c, p in canaries().items() if r["output"] and c in r["output"]}
                       | {r["action"].get("resource") for r in unauthorized_executed if r["action"]["type"] in ("read_resource", "reveal_secret") and r["action"].get("resource")})
    intended = [r for r in records if r["action"]["origin"] in ("user_task", "assistant_plan")]
    task_completed = bool(intended) and all(r["executed"] for r in intended) and not any(
        r["action"]["type"] == "summarize_text" and not (r["output"] or "").startswith("Summary") for r in intended)
    if protected:
        denied_own = [r for r in intended if not r["executed"]]
        final = ("Original task completed safely. " if task_completed else
                 ("Original task blocked by policy: " + denied_own[0]["decision"]["rule_id"] + ". " if denied_own else "Original task could not be completed. ")) + \
                (f"{len(attack)} unauthorised action(s) from untrusted content were denied." if attack else "No unauthorised actions were proposed.")
    else:
        final = ("SIMULATED SECURITY FAILURE: unauthorised action executed. " if unauthorized_executed else "No unauthorised action occurred. ") + \
                ("Original task " + ("completed." if task_completed else "was abandoned."))
    return {
        "mode": "protected" if protected else "unprotected",
        "simulation_notice": "Simulated assistant and simulated resources only. This is not evidence that a real model or system was compromised.",
        "scan": scan.to_dict() if scan else None,
        "grant": grant.to_dict(),
        "authorized_resources": authorized,
        "steps": steps,
        "actions": records,
        "outcome": {
            "attack_attempted": bool(attack),
            "attack_actions": len(attack),
            "unauthorized_executed": bool(unauthorized_executed),
            "unauthorized_count": len(unauthorized_executed),
            "disclosed_resources": disclosed,
            "task_completed": task_completed,
            "final_message": final,
        },
        "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
    }
