"""End-to-end triage tests against the recorded simulator events.

These run the exact code path Lambda runs (triage.handle) with
IR_SIMULATE=1, asserting on the decision tree: severity, remediation
hand-off, alert fan-out, and the ignore path.
"""

import json
from pathlib import Path

import pytest

from responders import triage

EVENTS = Path(__file__).resolve().parents[1] / "simulator" / "events"


def load(name):
    return json.loads((EVENTS / name).read_text())


def test_public_ssh_end_to_end_auto_remediates():
    summary = triage.handle(load("sg-port-22-open.json"))
    assert summary["status"] == "triaged"
    assert summary["severity"] == "P1"
    assert "close_public_ports" in summary["action_taken"] or \
           "executed in simulation" in summary["action_taken"]
    assert summary["deliveries"]["slack"] == "simulated"


def test_root_failed_login_alerts_without_remediation():
    summary = triage.handle(load("root-failed-login.json"))
    assert summary["severity"] == "P0"
    assert summary["action_taken"].startswith("no safe automated action")
    assert summary["deliveries"]["email"] == "simulated"


def test_guardduty_key_exfil_triggers_quarantine():
    summary = triage.handle(load("guardduty-key-exfil.json"))
    assert summary["severity"] == "P0"
    assert "executed in simulation" in summary["action_taken"]


def test_low_severity_guardduty_is_record_only(capsys):
    event = load("guardduty-crypto.json")
    event["detail"]["severity"] = 1.2
    summary = triage.handle(event)
    assert summary["severity"] == "P3"
    assert summary["deliveries"] == {"channels": "skipped (P3 record-only)"}
    assert summary["action_taken"] == "none (alert and record only)"


def test_auto_remediation_disabled_leaves_runbook_action(monkeypatch):
    monkeypatch.setenv("AUTO_REMEDIATION", "0")
    summary = triage.handle(load("sg-port-22-open.json"))
    assert "AUTO_REMEDIATION=0" in summary["action_taken"]


def test_untracked_event_is_ignored():
    assert triage.handle({"detail-type": "Scheduled Event"}) == \
        {"status": "ignored"}


def test_every_recorded_event_replays_clean():
    """Guard against sample files drifting out of the supported shapes."""
    for path in sorted(EVENTS.glob("*.json")):
        summary = triage.handle(json.loads(path.read_text()))
        assert summary["status"] in ("triaged", "ignored"), path.name


@pytest.mark.parametrize("name,sev", [
    ("sg-port-22-open.json", "P1"),
    ("root-failed-login.json", "P0"),
    ("iam-new-access-key.json", "P2"),
    ("guardduty-crypto.json", "P0"),
    ("guardduty-key-exfil.json", "P0"),
])
def test_severity_of_recorded_catalog(name, sev):
    assert triage.handle(load(name))["severity"] == sev
