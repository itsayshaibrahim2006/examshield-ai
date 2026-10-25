#!/usr/bin/env python3
"""Start ExamShield AI:  python run.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend"))

# optional .env loader (placeholders only in .env.example; no third-party dependency)
env = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(env):
    for line in open(env, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())

from examshield.server import main  # noqa: E402

if __name__ == "__main__":
    main()
