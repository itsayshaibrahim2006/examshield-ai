"""A deliberately gullible SIMULATED assistant. It is NOT a real language model.

It follows imperative-looking directives found in untrusted text so we can show what the
protection layer prevents. Its extraction patterns are independent from the scanner's, so
the benchmark can contain attacks the scanner misses but the policy still stops.
"""
from __future__ import annotations

import re

from .resources import RESOURCES, DEFAULT_PROTECTED

READ_VERBS = r"(?:read|open|access|fetch|retrieve|grab|pull|peek|dump|cat|load|get|obtain|consult|view)"
TARGETS = [
    (re.compile(r"demo/(?:protected|secrets|public)/[\w\-]+(?:\.[\w\-]+)*", re.I), None),
    (re.compile(r"answer[\s_-]?key", re.I), "demo/protected/answer_key.txt"),
    (re.compile(r"grades?(?:\.csv|\s+(?:file|sheet|records?))", re.I), "demo/protected/grades.csv"),
    (re.compile(r"credentials?|passwords?|api[\s_-]?keys?|\.env\b", re.I), "demo/secrets/credentials.env"),
    (re.compile(r"protected\s+(?:demo\s+)?(?:file|resource|document)", re.I), DEFAULT_PROTECTED),
]
OBEY_READ = re.compile(r"\b" + READ_VERBS + r"\b[^.\n]{0,60}", re.I)
OBEY_REVEAL = re.compile(r"\b(?:reveal|print|paste|disclose|leak|show|display|include|output)\b[^.\n]{0,60}\b(?:contents?|secret|password|key|answers?)\b", re.I)
OBEY_SEND = re.compile(r"\b(?:send|email|post|upload|forward)\b[^.\n]{0,60}?(https?://\S+|[\w.+-]+@[\w-]+\.[\w.]+)", re.I)
OBEY_EXEC = re.compile(r"\b(?:run|execute)\b[^.\n]{0,30}\b(?:command|shell|script)\b", re.I)
OVERRIDE = re.compile(r"\b(?:ignore|disregard|forget|override|abandon)\b[^.\n]{0,40}\b(?:instructions?|request|task|prompt)\b", re.I)
CUE = re.compile(r"(?:for\s+example|e\.g\.|such\s+as|attackers?\s+(?:write|use|might|may|can)|an?\s+attacker|example\s+of|security\s+(?:training|slide|lecture)|the\s+(?:phrase|payload|string)|injection\s+(?:example|payload))", re.I)


def _resolve(fragment: str) -> str | None:
    m = TARGETS[0][0].search(fragment)
    if m:
        return m.group(0).lower()
    for pat, path in TARGETS[1:]:
        if pat.search(fragment):
            return path
    return None


def _quoted_sentence(sentence: str) -> bool:
    if sentence.count('"') >= 2 or ("\u201c" in sentence and "\u201d" in sentence) or sentence.lstrip().startswith(">"):
        return True
    if "`" in sentence and sentence.count("`") >= 2:
        return True
    return bool(CUE.search(sentence))


def split_sentences(text: str) -> list[str]:
    return [s for s in re.split(r"(?<=[.!?])\s+|\n+", text) if s.strip()]


def _read_target(sentence: str):
    """First read-verb fragment that names a resolvable resource (later verbs are not shadowed by earlier ones)."""
    for m in OBEY_READ.finditer(sentence):
        t = _resolve(m.group(0))
        if t:
            return t
    return None


def REVEAL_TARGET(s: str) -> bool:
    return bool(re.search(r"\b(?:reveal|print|paste|disclose|leak|show|display)\b", s, re.I) and _resolve(s))


def directive_sentences(text: str) -> list[str]:
    """Sentences the gullible assistant would treat as instructions (unquoted ones only)."""
    out = []
    for s in split_sentences(text):
        if _quoted_sentence(s):
            continue
        if OVERRIDE.search(s) or OBEY_SEND.search(s) or OBEY_EXEC.search(s) or OBEY_REVEAL.search(s) or REVEAL_TARGET(s) or \
                _read_target(s):
            out.append(s)
    return out


def plan(task_grant, user_request: str, document: str, reassert_task: bool = False) -> list[dict]:
    """Return the actions the simulated assistant proposes.

    reassert_task=True models the protection layer keeping the trusted task in force even when
    the document tells the assistant to abandon it (the injected actions are still proposed).
    """
    actions: list[dict] = []
    injected: list[dict] = []
    for s in directive_sentences(document):
        sentence_actions = []
        m = OBEY_SEND.search(s)
        if m:
            sentence_actions.append({"type": "send_message", "destination": m.group(1), "content": RESOURCES[DEFAULT_PROTECTED]["content"], "origin": "untrusted_content", "source_span": s})
        if OBEY_EXEC.search(s):
            sentence_actions.append({"type": "execute_command", "content": s, "origin": "untrusted_content", "source_span": s})
        target = _read_target(s)
        if target:
            sentence_actions.append({"type": "read_resource", "resource": target, "origin": "untrusted_content", "source_span": s})
        elif OBEY_REVEAL.search(s) or REVEAL_TARGET(s):
            sentence_actions.append({"type": "reveal_secret", "resource": _resolve(s) or DEFAULT_PROTECTED, "origin": "untrusted_content", "source_span": s})
        injected += sentence_actions
    overridden = bool(OVERRIDE.search(" ".join(directive_sentences(document))))
    intended: list[dict] = []
    if task_grant.resource_scope:
        for p in task_grant.resource_scope:
            intended.append({"type": "read_resource", "resource": p, "origin": "user_task"})
    if "summarize_text" in task_grant.allowed_actions or "answer_question" in task_grant.allowed_actions:
        intended.append({"type": "summarize_text", "origin": "user_task"})
    if "list_resources" in task_grant.allowed_actions:
        intended.append({"type": "list_resources", "origin": "user_task"})
    if not intended and not injected:
        # nothing recognised: the assistant still tries a plain summary of the text
        intended.append({"type": "summarize_text", "origin": "assistant_plan"})
    actions += injected
    if not overridden or reassert_task:
        actions += intended
    return actions


def execute(action: dict, document: str, executed_outputs: list[str], sanitize: list[str] | None = None) -> str:
    """Execute a (simulated) action in memory. Never touches the real file system or network."""
    t = action["type"]
    if t == "read_resource":
        r = RESOURCES.get(action.get("resource"))
        return r["content"] if r else "[unknown resource]"
    if t == "reveal_secret":
        r = RESOURCES.get(action.get("resource"))
        return "REVEALED: " + (r["content"] if r else "")
    if t == "send_message":
        return f"[simulated] message with {len(action.get('content',''))} characters 'sent' to {action.get('destination')} (nothing was transmitted)"
    if t == "execute_command":
        return "[simulated] command accepted (nothing was executed)"
    if t == "list_resources":
        return ", ".join(p for p, r in RESOURCES.items() if r["classification"] == "public")
    if t in ("summarize_text", "answer_question"):
        skip = set(sanitize or [])
        sents = [s for s in split_sentences(document) if s not in skip]
        body = " ".join(sents[:2]) if sents else "(empty document)"
        extra = (" Referenced file content: " + " | ".join(executed_outputs)) if executed_outputs else ""
        return "Summary: " + body[:280] + extra
    return "[unsupported]"
