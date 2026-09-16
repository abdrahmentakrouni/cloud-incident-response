#!/usr/bin/env python3
"""Offline incident simulator - the whole pipeline, no AWS account needed.

Feeds recorded EventBridge payloads through the REAL triage code (same
handlers that run in Lambda) with IR_SIMULATE=1: incidents are "stored",
reports are printed exactly as the security channel would receive them,
and remediation decisions are shown instead of executed.

Usage:
    python3 simulator/simulate.py --all
    python3 simulator/simulate.py --event simulator/events/sg-port-22-open.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / "src"
sys.path.insert(0, str(SRC))

# Must be set BEFORE importing the pipeline - every module reads it once.
os.environ["IR_SIMULATE"] = "1"

from handler import triage_handler  # noqa: E402


def load_event(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def run_one(path: Path) -> dict:
    print("\n" + "#" * 62)
    print(f"# EVENT FILE: {path.name}")
    print("#" * 62)
    event = load_event(path)
    summary = triage_handler(event)
    print("TRIAGE SUMMARY:")
    print(json.dumps(
        {k: v for k, v in summary.items() if k != "deliveries"},
        indent=2, sort_keys=True))
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="offline IR pipeline demo")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true",
                       help="replay every recorded event")
    group.add_argument("--event", type=Path, help="replay a single event file")
    args = parser.parse_args()

    events_dir = HERE / "events"
    if args.all:
        files = sorted(events_dir.glob("*.json"))
    else:
        files = [args.event]

    summaries = [run_one(f) for f in files]

    print("\n" + "=" * 62)
    print("RECAP")
    print("=" * 62)
    print(f"{'event file':<32} {'sev':<4} {'result'}")
    for f, s in zip(files, summaries, strict=True):
        if s.get("status") == "ignored":
            print(f"{f.name:<32} -    ignored (not a tracked event)")
            continue
        print(f"{f.name:<32} {s['severity']:<4} {s['action_taken']}")
    print("=" * 62)
    print(f"{len(summaries)} event(s) processed in simulation mode "
          "(no AWS calls, no notifications sent).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
