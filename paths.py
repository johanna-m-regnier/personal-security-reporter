from __future__ import annotations

import os
from pathlib import Path

_environment_override = os.getenv("PSR_HOME")

if _environment_override:
    BASE_DIR = Path(_environment_override).expanduser().resolve()
else:
    BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "output"

BASELINE_PATH = DATA_DIR / "baseline.json"
LEDGER_PATH = DATA_DIR / "ledger.db"
STATUS_PATH = OUTPUT_DIR / "LAST_RUN_STATUS.txt"