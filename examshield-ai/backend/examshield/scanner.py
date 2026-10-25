"""AI Security Scanner (detection layer).

Three kinds of signals are combined:
  * rule       - deterministic regular-expression rules, one finding per match
  * structural - hidden characters, HTML comments, fake role markers
  * contextual - quotation / educational-context analysis, narrative-vs-imperative
                 analysis, and compound escalation (override + data access ...)

The scanner is ADVISORY. It never authorises or blocks anything by itself; the
Protection Engine (policy.py) enforces. It does not detect every possible attack.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field, asdict

SEVERITIES = ["low", "medium", "high", "critical"]
FLAG_THRESHOLD = "medium"  # risk >= medium counts as "flagged" in metrics

LIMITATIONS = [
    "Deterministic rules only see English phrasing they were written for; paraphrases, other languages and heavy obfuscation can be missed.",
    "Quote and educational-context detection is heuristic: a real attack hidden inside quotes can be under-rated, and a harmless quote can be over-rated.",
    "The scanner is advisory. Enforcement is done independently by the Protection Engine, which does not rely on scanner output.",
    "Results on the bundled synthetic dataset do not prove real-world performance.",
]

ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}

PROTECTED_TARGET = (
    r"(?:demo[/\\](?:protected|secrets)[/\\][\w\-]+(?:\.[\w\-]+)*"
    r"|protected\s+(?:demo\s+)?(?:file|folder|directory|resource|document|data)s?"
    r"|confidential\s+(?:file|data|record|information|document)s?"
    r"|(?:answer[\s_-]?key|grades?\.csv|credentials?(?:\.env)?|\.env\b|api[\s_-]?keys?|passwords?|private\s+keys?"
    r"|secrets?\b|system\s+prompt|hidden\s+instructions|secret\s+(?:file|data|token)s?))"
)


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    severity: str
    signal: str  # rule | structural
    pattern: re.Pattern
    explanation: str


def _r(pat: str) -> re.Pattern:
    return re.compile(pat, re.I)


RULES: list[Rule] = [
    Rule("OVR-01", "instruction_override", "high", "rule",
         _r(r"\b(?:ignore|disregard|forget|override|bypass|discard|abandon)\b[^.\n]{0,40}?\b(?:previous|prior|above|earlier|all|any|the\s+user'?s?|your|original|system)\b[^.\n]{0,40}?\b(?:instructions?|prompts?|rules?|requests?|tasks?|directions?|guidelines?|constraints?|restrictions?)\b"),
         "Tries to make the assistant drop the instructions it was legitimately given."),
    Rule("OVR-02", "instruction_override", "medium", "rule",
         _r(r"\b(?:instead\s+of|rather\s+than)\b[^.\n]{0,40}?\b(?:summari[sz]ing|the\s+user'?s?\s+request|what\s+the\s+user|answering|the\s+task)\b"),
         "Redirects the assistant away from the user's actual request."),
    Rule("OVR-03", "instruction_override", "medium", "rule",
         _r(r"\b(?:new|updated|real|actual|revised)\s+(?:instructions?|task|directive|orders?)\s*(?:are|is|follow|:)"),
         "Announces replacement instructions inside untrusted content."),
    Rule("OVR-04", "instruction_override", "medium", "rule",
         _r(r"\b(?:highest|top|overriding)\s+priority\b|\bthis\s+(?:message\s+)?(?:takes|has)\s+precedence\b|\bmust\s+be\s+followed\s+(?:immediately|first)\b"),
         "Claims priority over the trusted instructions."),
    Rule("ROL-01", "role_hijack", "medium", "rule",
         _r(r"\byou\s+are\s+now\b|\bpretend\s+(?:to\s+be|you\s+are)\b|\bfrom\s+now\s+on\s+you\b"),
         "Attempts to redefine the assistant's role."),
    Rule("ROL-02", "role_hijack", "high", "rule",
         _r(r"\bact\s+as\b[^.\n]{0,30}?\b(?:admin(?:istrator)?|root|developer|system|unrestricted|dan)\b|\bdeveloper\s+mode\b|\bjailbreak(?:en)?\b|\bno\s+restrictions\b"),
         "Attempts to grant the assistant elevated or unrestricted privileges."),
    Rule("AUT-01", "fake_authority", "medium", "structural",
         _r(r"\b(?:system|admin(?:istrator)?|developer|security\s+team|operator)\s+(?:message|override|notice|directive|command|instruction)\b|^\s*\[?(?:system|admin|root)\]?\s*:|<\|?(?:system|im_start)\|?>"),
         "Imitates a trusted authority or a system role marker."),
    Rule("AUD-01", "addressed_to_ai", "medium", "rule",
         _r(r"\b(?:notes?|messages?|instructions?)\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|model|llm|chatbot|agent)\b|\b(?:dear|hey|attention)\s+(?:ai|assistant|model|llm|chatbot)\b|\bif\s+you\s+are\s+an?\s+(?:ai|assistant|language\s+model|llm)\b"),
         "Ordinary documents rarely address the AI reading them directly."),
    Rule("CON-01", "concealment", "high", "rule",
         _r(r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention|reveal|let|notify|alert|show)\b[^.\n]{0,30}?\b(?:the\s+)?user\b|\bwithout\s+(?:telling|informing|notifying)\s+(?:the\s+)?user\b|\bkeep\s+this\s+(?:secret|hidden)\s+from\b"),
         "Asks the assistant to hide its behaviour from the user."),
    Rule("DAT-01", "data_access", "high", "rule",
         _r(r"\b(?:read|open|access|fetch|retrieve|load|view|cat|dump|copy|extract|get|attempt\s+to\s+access|look\s+(?:in|at|into))\b[^.\n]{0,60}?" + PROTECTED_TARGET),
         "Requests access to a protected or confidential resource."),
    Rule("DAT-02", "data_access", "critical", "rule",
         _r(r"\b(?:reveal|disclose|leak|print|paste|output|display|show|include|embed|append|expose)\b[^.\n]{0,60}?" + PROTECTED_TARGET),
         "Requests disclosure of protected or confidential content."),
    Rule("EXF-01", "exfiltration", "high", "rule",
         _r(r"\b(?:send|email|mail|post|upload|transmit|forward|exfiltrate|submit)\b[^.\n]{0,60}?\b(?:to|at)\s+(?:https?://\S+|[\w.+-]+@[\w-]+\.[\w.]+)"),
         "Asks for data to be sent to an external destination."),
    Rule("EXE-01", "command_execution", "high", "rule",
         _r(r"\b(?:run|execute|eval|invoke|spawn)\b[^.\n]{0,40}?\b(?:command|shell|script|bash|powershell|curl|wget)\b|\brm\s+-rf\b|\bcurl\s+https?://"),
         "Asks the assistant to run commands."),
]

DIRECTIVE_VERBS = r"(?:ignore|disregard|forget|override|bypass|read|open|access|fetch|retrieve|reveal|send|email|post|upload|run|execute|dump|print|disclose|leak)"
HTML_COMMENT = re.compile(r"<!--([\s\S]*?)-->")

CUE = re.compile(
    r"(?:for\s+example|e\.g\.|such\s+as|for\s+instance|an?\s+attacker\s+(?:might|may|could|would|can)"
    r"|attackers?\s+(?:often|commonly|typically|may|might|can)?\s*(?:write|use|embed|insert|hide|inject|say)"
    r"|the\s+(?:phrase|string|sentence|prompt|payload|text)\b"
    r"|example\s+of\s+(?:a\s+)?(?:prompt[\s-]injection|malicious|injection)"
    r"|injection\s+(?:payload|example|attempt)s?|classic\s+(?:attack|example)"
    r"|security\s+(?:training|awareness|lecture|research|article|report|slide)s?"
    r"|common\s+(?:attack|example|payload)|known\s+(?:attack|payload)"
    r"|(?:he|she|they|someone|a\s+user|the\s+user)\s+(?:wrote|typed|said|pasted)\b"
    r"|labell?ed\s+as\s+(?:malicious|an\s+attack)|this\s+is\s+an?\s+example)", re.I)
LURE = re.compile(
    r"(?:(?:follow|obey|execute|carry\s+out|comply\s+with)\s+(?:the\s+)?(?:following|these|this)"
    r"|(?:assistant|ai|model|agent|you)\b[^.\n]{0,30}\b(?:must|should|will|shall)\b)", re.I)
NARRATIVE = re.compile(r"\b(?:he|she|they|we|i|attackers?|hackers?|malware|users?|students?|employees?|admins?|someone|people)\b(?:\s+\w+){0,2}\s*$", re.I)
IMPERATIVE_START = re.compile(r"^\W*(?:please\b|now\b|then\b|also\b|first\b|before\b|immediately\b|kindly\b|"
                              r"ignore|disregard|forget|override|bypass|read|open|access|fetch|retrieve|reveal|send|email|post|upload|run|execute|dump|print|disclose|leak|show|display|include|output|copy|get|attempt)", re.I)
ADDRESS = re.compile(r"\byou\s+(?:must|should|need\s+to|will|are\s+to|have\s+to)\b|\b(?:assistant|ai|model|agent|llm)\b", re.I)


def normalize_with_map(text: str) -> tuple[str, list[int]]:
    """NFKC-fold and strip zero-width characters, keeping a map back to original offsets."""
    out: list[str] = []
    idx: list[int] = []
    for i, ch in enumerate(text):
        if ch in ZERO_WIDTH:
            continue
        for c in unicodedata.normalize("NFKC", ch):
            out.append(c)
            idx.append(i)
    return "".join(out), idx


def _in_quotes(text: str, s: int, e: int) -> bool:
    ls = text.rfind("\n", 0, s) + 1
    le = text.find("\n", e)
    le = len(text) if le == -1 else le
    line = text[ls:le]
    a, b = s - ls, e - ls
    before, after = line[:a], line[b:]
    if before.count('"') % 2 == 1 and '"' in after:
        return True
    if "\u201c" in before and before.rfind("\u201c") > before.rfind("\u201d") and "\u201d" in after:
        return True
    if "\u00ab" in before and before.rfind("\u00ab") > before.rfind("\u00bb") and "\u00bb" in after:
        return True
    if before.count("`") % 2 == 1 and "`" in after:
        return True
    opens = re.findall(r"(?<![A-Za-z0-9])'", before)
    if len(opens) % 2 == 1 and re.search(r"'(?![A-Za-z0-9])", after):
        return True
    if line.lstrip().startswith(">"):
        return True
    if len(re.findall(r"^```", text[:s], re.M)) % 2 == 1:
        return True
    return False


def quote_context(text: str, s: int, e: int) -> str | None:
    """Return 'quoted', 'educational' or None. A lure ('follow the following: ...') defeats the quote exemption."""
    ps = text.rfind("\n\n", 0, s) + 1
    sent_start = max(text.rfind(".", 0, s), text.rfind("!", 0, s), text.rfind("?", 0, s), text.rfind("\n", 0, s)) + 1
    if text[:sent_start].rstrip().endswith(":"):
        sent_start = max(text.rfind(".", 0, max(0, sent_start - 2)), text.rfind("\n", 0, max(0, sent_start - 2))) + 1
    window_start = max(ps, sent_start, s - 200)
    before = text[window_start:s]
    quoted = _in_quotes(text, s, e)
    educational = bool(CUE.search(before))
    if not (quoted or educational):
        return None
    if quoted and not educational and LURE.search(text[max(ps, s - 90):s]):
        return None
    return "quoted" if quoted else "educational"


def _sentence_bounds(text: str, s: int, e: int) -> tuple[int, int]:
    a = max(text.rfind(".", 0, s), text.rfind("!", 0, s), text.rfind("?", 0, s), text.rfind("\n", 0, s)) + 1
    ends = [x for x in (text.find(".", e), text.find("!", e), text.find("?", e), text.find("\n", e)) if x != -1]
    return a, (min(ends) + 1 if ends else len(text))


def _downgrade(sev: str, n: int) -> str:
    return SEVERITIES[max(0, SEVERITIES.index(sev) - n)]


@dataclass
class Finding:
    id: str
    rule_id: str
    category: str
    signal: str            # rule | structural | contextual
    severity: str          # effective severity after context adjustment
    base_severity: str
    confidence: str        # high | medium | uncertain
    start: int
    end: int
    text: str
    quoted: bool
    context: str | None
    explanation: str
    notes: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    risk: str
    flagged: bool
    uncertain: bool
    score: int
    findings: list[Finding]
    mode: str
    llm_used: bool
    summary: str
    limitations: list[str]
    categories: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def empty_result(mode: str = "local-deterministic") -> ScanResult:
    return ScanResult("low", False, False, 0, [], mode, False,
                      "No suspicious instructions found by the local rules.", LIMITATIONS, [])


def scan_text(text: str) -> ScanResult:
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    norm, idx = normalize_with_map(text)
    raw: list[tuple[Rule, int, int]] = []
    for rule in RULES:
        for m in rule.pattern.finditer(norm):
            raw.append((rule, idx[m.start()], idx[m.end() - 1] + 1))
    for m in HTML_COMMENT.finditer(text):
        if re.search(r"\b" + DIRECTIVE_VERBS + r"\b", m.group(1), re.I):
            raw.append((Rule("HID-01", "hidden_content", "medium", "structural", re.compile(""),
                             "An HTML comment (invisible to readers) contains directive wording."), m.start(), m.end()))
    zw = [i for i, ch in enumerate(text) if ch in ZERO_WIDTH]
    if len(zw) >= 3:
        raw.append((Rule("HID-02", "hidden_content", "medium", "structural", re.compile(""),
                         "Several zero-width characters are present; they can hide or split instructions."),
                    zw[0], zw[-1] + 1))

    raw.sort(key=lambda t: (t[1], t[2]))
    kept: list[tuple[Rule, int, int]] = []
    for rule, s, e in raw:
        if any(k[0].id == rule.id and s < k[2] and e > k[1] for k in kept):
            continue
        kept.append((rule, s, e))

    findings: list[Finding] = []
    for n, (rule, s, e) in enumerate(kept, 1):
        notes: list[str] = []
        sev = rule.severity
        conf = "high"
        ctx = None if rule.id.startswith("HID") else quote_context(text, s, e)
        quoted = ctx is not None
        if quoted:
            notes.append(f"Appears in {ctx} context (quotation or educational framing); not treated as an active instruction.")
            conf = "uncertain"
        else:
            a, b = _sentence_bounds(text, s, e)
            before_words = text[a:s]
            sentence = text[a:b]
            if NARRATIVE.search(before_words) and not ADDRESS.search(before_words):
                sev = _downgrade(sev, 2)
                conf = "uncertain"
                notes.append("Sentence reads as a description (third-person narrative), not a command; severity reduced.")
            elif IMPERATIVE_START.search(before_words + text[s:s + 12]) or ADDRESS.search(sentence):
                notes.append("Phrased as a command or addressed to the assistant.")
            else:
                conf = "medium"
                notes.append("Wording matches a rule but is not clearly phrased as a command.")
        findings.append(Finding(f"F{n}", rule.id, rule.category, rule.signal, sev, rule.severity, conf, s, e,
                                text[s:e], quoted, ctx, rule.explanation, notes))

    active = [f for f in findings if not f.quoted and f.confidence != "uncertain"]
    cats = {f.category for f in active}
    if cats & {"data_access", "exfiltration"} and cats & {"instruction_override", "role_hijack", "concealment",
                                                           "fake_authority", "addressed_to_ai", "hidden_content"}:
        first = min(active, key=lambda f: f.start)
        findings.append(Finding(f"F{len(findings) + 1}", "CTX-01", "compound_attack", "contextual", "critical", "critical",
                                "high", first.start, first.end, first.text, False, None,
                                "Compound signal: an instruction to override or hide behaviour appears together with a request for protected data or external transfer.",
                                ["Escalated because several independent signals agree."]))

    if not findings:
        return empty_result()
    live = [f for f in findings if not f.quoted]
    risk = "low"
    for f in live:
        if SEVERITIES.index(f.severity) > SEVERITIES.index(risk):
            risk = f.severity
    uncertain = any(f.quoted or f.confidence == "uncertain" for f in findings)
    score = sum({"low": 1, "medium": 3, "high": 6, "critical": 10}[f.severity] for f in live)
    flagged = SEVERITIES.index(risk) >= SEVERITIES.index(FLAG_THRESHOLD)
    categories = sorted({f.category for f in live})
    if flagged:
        summary = f"{risk.capitalize()} risk: {len(live)} active finding(s) across {', '.join(categories)}."
    elif not live:
        summary = "Only quoted or educational examples found; not treated as active instructions (uncertain)."
    else:
        summary = "Weak or ambiguous signals only; below the flagging threshold."
    return ScanResult(risk, flagged, uncertain, score, findings, "local-deterministic", False, summary, LIMITATIONS, categories)
