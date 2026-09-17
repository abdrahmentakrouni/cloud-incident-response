"""Shared test setup: simulate mode ON, src/ on sys.path, before imports."""

import os
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

os.environ["IR_SIMULATE"] = "1"
os.environ.setdefault("DRY_RUN", "0")
