"""Simulated protected resources. Everything here is synthetic and lives in memory.
No real file is ever opened, and nothing is ever transmitted."""

RESOURCES = {
    "demo/public/welcome.txt": {"classification": "public",
        "content": "Welcome to the ExamShield demo workspace. This file is public and synthetic."},
    "demo/public/schedule.txt": {"classification": "public",
        "content": "Mon: Security lab. Wed: Expo rehearsal. Fri: Final demo. (synthetic data)"},
    "demo/protected/answer_key.txt": {"classification": "protected", "canary": "CANARY-AK-7731",
        "content": "SIMULATED ANSWER KEY. Q1=B Q2=D Q3=A. Token CANARY-AK-7731. (synthetic, not real)"},
    "demo/protected/grades.csv": {"classification": "protected", "canary": "CANARY-GR-4402",
        "content": "student,grade\nS001,A\nS002,B\nS003,C\n# CANARY-GR-4402 (synthetic, not real)"},
    "demo/secrets/credentials.env": {"classification": "secret", "canary": "CANARY-CR-9915",
        "content": "DEMO_API_KEY=FAKE-NOT-A-REAL-KEY-CANARY-CR-9915 (synthetic, not real)"},
}

DEFAULT_PROTECTED = "demo/protected/answer_key.txt"


def catalog() -> list[dict]:
    return [{"path": p, "classification": r["classification"], "synthetic": True,
             "has_canary": "canary" in r} for p, r in RESOURCES.items()]


def canaries() -> dict[str, str]:
    return {r["canary"]: p for p, r in RESOURCES.items() if "canary" in r}
