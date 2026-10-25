"""Protection Engine: independent authorisation policy.

This module imports NOTHING from the scanner and takes no scanner input. Even if the
scanner finds nothing, every proposed action is still checked here. It fails closed:
any malformed input, unknown action, unknown resource or internal error is a DENY.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict

from .resources import RESOURCES, canaries

GLOBAL_ALLOWLIST = ["summarize_text", "answer_question", "read_resource", "list_resources"]
KNOWN_DANGEROUS = ["send_message", "reveal_secret", "write_file", "execute_command", "delete_resource"]
ORIGINS = ["user_task", "assistant_plan", "untrusted_content", "unknown"]

RULE_CATALOG = [
    ("P1", "DENY_MALFORMED", "Action must be well-formed (known type string, valid origin, resource is text)."),
    ("P2", "DENY_ACTION_NOT_ALLOWLISTED", "Action type must be on the global allowlist."),
    ("P3", "DENY_UNTRUSTED_ORIGIN", "Actions proposed by untrusted content are never authorised."),
    ("P4", "DENY_NO_TASK_GRANT / DENY_NOT_IN_TASK_GRANT", "Action must be covered by a grant derived from the user's own request."),
    ("P5", "DENY_UNKNOWN_RESOURCE / DENY_RESOURCE_OUT_OF_SCOPE", "Resource must exist and be inside the grant's scope."),
    ("P6", "DENY_PROTECTED_RESOURCE", "Protected and secret resources need explicit trusted authorisation."),
    ("P7", "DENY_DISCLOSURE / DENY_EXTERNAL_DESTINATION", "Outgoing content must not contain protected data or target external destinations."),
    ("P8", "DENY_INTERNAL_ERROR", "Any unexpected error fails closed."),
]

TEXT_TASK = re.compile(r"\b(summari[sz]e|summary|tl;?dr|key\s+points|main\s+points|overview|digest|extract|proofread|rewrite|"
                       r"translate|explain|answer|classify|tone|what|why|how|who|when|list\s+the|action\s+items|outline|review)\b", re.I)
READ_TASK = re.compile(r"\b(read|open|show|report|count|summari[sz]e|print|display|tell\s+me|what)\b", re.I)
LIST_TASK = re.compile(r"\blist\s+(?:the\s+)?(?:available\s+)?(?:public\s+)?(?:files|resources)\b", re.I)
PATH = re.compile(r"demo/(?:public|protected|secrets)/[\w\-]+(?:\.[\w\-]+)*")


@dataclass
class TaskGrant:
    kind: str
    allowed_actions: list[str]
    resource_scope: list[str]
    source: str = "trusted user request"

    def to_dict(self):
        return asdict(self)


@dataclass
class Decision:
    decision: str            # allow | deny
    rule_id: str             # reason code
    reason: str
    checks: list[dict] = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def derive_grant(task_request: str) -> TaskGrant:
    """Build the permitted-action grant from the TRUSTED user request only."""
    if not isinstance(task_request, str) or not task_request.strip():
        return TaskGrant("none", [], [])
    actions: list[str] = []
    scope: list[str] = []
    kinds = []
    if TEXT_TASK.search(task_request):
        actions += ["summarize_text", "answer_question"]
        kinds.append("text_task")
    paths = PATH.findall(task_request)
    if paths and READ_TASK.search(task_request):
        actions.append("read_resource")
        scope += paths
        kinds.append("read_file")
    if LIST_TASK.search(task_request):
        actions.append("list_resources")
        kinds.append("list_files")
    if not actions:
        return TaskGrant("unrecognised", [], [])
    return TaskGrant("+".join(kinds), sorted(set(actions)), sorted(set(scope)))


def _c(name, passed, detail):
    return {"check": name, "passed": passed, "detail": detail}


def evaluate(action: dict, grant: TaskGrant | None, authorized_resources: list[str] | None) -> Decision:
    checks: list[dict] = []
    try:
        return _evaluate(action, grant, authorized_resources, checks)
    except Exception as exc:  # fail closed
        checks.append(_c("internal", False, f"unexpected error: {type(exc).__name__}"))
        return Decision("deny", "DENY_INTERNAL_ERROR", "Policy could not establish authorisation, so the action is denied (fail closed).", checks)


def _deny(code, reason, checks):
    return Decision("deny", code, reason, checks)


def _evaluate(action, grant, authorized, checks) -> Decision:
    authorized = authorized if isinstance(authorized, list) else []
    # P1 well-formed
    if (not isinstance(action, dict) or not isinstance(action.get("type"), str) or not action.get("type")
            or action.get("origin", "unknown") not in ORIGINS
            or not isinstance(action.get("resource", None) or "", str)
            or not isinstance(action.get("content", None) or "", str)
            or not isinstance(action.get("destination", None) or "", str)):
        checks.append(_c("well_formed", False, "action is missing a valid type/origin or has non-text fields"))
        return _deny("DENY_MALFORMED", "The proposed action is malformed.", checks)
    atype = action["type"]
    origin = action.get("origin", "unknown")
    resource = action.get("resource") or None
    content = action.get("content") or ""
    dest = action.get("destination") or ""
    checks.append(_c("well_formed", True, f"type={atype}, origin={origin}"))
    # P2 allowlist
    if atype not in GLOBAL_ALLOWLIST:
        why = "is a known high-risk action that is never allowlisted" if atype in KNOWN_DANGEROUS else "is not a recognised action"
        checks.append(_c("allowlist", False, f"'{atype}' {why}"))
        return _deny("DENY_ACTION_NOT_ALLOWLISTED", f"Action '{atype}' is not on the allowlist.", checks)
    checks.append(_c("allowlist", True, f"'{atype}' is allowlisted"))
    # P3 provenance
    if origin == "untrusted_content":
        checks.append(_c("provenance", False, "action was proposed by instructions inside untrusted content"))
        return _deny("DENY_UNTRUSTED_ORIGIN", "Instructions found inside untrusted content cannot authorise actions.", checks)
    checks.append(_c("provenance", True, f"origin '{origin}' is not untrusted content"))
    # P4 grant
    if grant is None or not grant.allowed_actions:
        checks.append(_c("task_grant", False, "no grant could be derived from the user's request"))
        return _deny("DENY_NO_TASK_GRANT", "No authorisation could be derived from the user's request (fail closed).", checks)
    if atype not in grant.allowed_actions:
        checks.append(_c("task_grant", False, f"user's request grants {grant.allowed_actions}, not '{atype}'"))
        return _deny("DENY_NOT_IN_TASK_GRANT", f"The user's request does not cover '{atype}'.", checks)
    checks.append(_c("task_grant", True, f"'{atype}' is covered by the user's request"))
    # P5/P6 resource checks
    if atype == "read_resource":
        if resource not in RESOURCES:
            checks.append(_c("resource_known", False, f"'{resource}' is not a known resource"))
            return _deny("DENY_UNKNOWN_RESOURCE", "Unknown resource.", checks)
        checks.append(_c("resource_known", True, resource))
        if resource not in grant.resource_scope:
            checks.append(_c("resource_scope", False, f"'{resource}' is outside the grant scope {grant.resource_scope}"))
            return _deny("DENY_RESOURCE_OUT_OF_SCOPE", "Resource is outside what the user's request covers.", checks)
        checks.append(_c("resource_scope", True, "inside grant scope"))
        cls = RESOURCES[resource]["classification"]
        if cls != "public" and resource not in authorized:
            checks.append(_c("classification", False, f"'{resource}' is {cls} and not explicitly authorised"))
            return _deny("DENY_PROTECTED_RESOURCE", f"Access to {cls} resource is not explicitly authorised.", checks)
        checks.append(_c("classification", True, f"{cls}" + (" (explicitly authorised)" if cls != "public" else "")))
    # P7 disclosure
    if dest:
        checks.append(_c("destination", False, f"external destination '{dest[:60]}' is not permitted"))
        return _deny("DENY_EXTERNAL_DESTINATION", "Sending data to an external destination is not permitted.", checks)
    leaked = [p for c, p in canaries().items() if c in content and p not in authorized]
    if leaked:
        checks.append(_c("disclosure", False, f"content contains data from unauthorised resource {leaked[0]}"))
        return _deny("DENY_DISCLOSURE", "Output would disclose protected data that is not authorised.", checks)
    checks.append(_c("disclosure", True, "no unauthorised protected data in content"))
    return Decision("allow", "ALLOW_AUTHORIZED", "All policy checks passed.", checks)


def policy_description() -> dict:
    return {
        "global_allowlist": GLOBAL_ALLOWLIST,
        "never_allowlisted": KNOWN_DANGEROUS,
        "rules": [{"id": a, "codes": b, "description": c} for a, b, c in RULE_CATALOG],
        "principles": [
            "Trusted instructions (the user's request) and untrusted content are kept separate.",
            "Authorisation comes only from the user's request plus explicit trusted authorisation, never from document text.",
            "The policy never reads scanner output, so a scanner miss cannot cause an unauthorised action.",
            "Fail closed: anything unclear is denied.",
        ],
    }
