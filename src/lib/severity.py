"""Severity model shared by every responder.

Four levels, mapped from P0 (act now) to P3 (record only). The matrix is
deliberately small: during an incident nobody reads a 7-level scale, and
every automation branch in this repo hangs off one of these four values.
"""

from __future__ import annotations

from dataclasses import dataclass

P0 = "P0"
P1 = "P1"
P2 = "P2"
P3 = "P3"

LEVELS = (P0, P1, P2, P3)

# Short operator-facing label per level, reused in reports and alerts.
LABELS = {
    P0: "CRITICAL - act now",
    P1: "HIGH - automated response engaged",
    P2: "MEDIUM - review today",
    P3: "LOW - recorded for the audit trail",
}


@dataclass(frozen=True)
class Severity:
    """A severity level plus a human reason, so alerts are self-explaining."""

    level: str
    reason: str

    def __str__(self) -> str:  # pragma: no cover - cosmetics
        return f"{self.level} ({LABELS[self.level]})"


def guardduty_level(raw_severity: float) -> str:
    """Map a GuardDuty finding severity to our P-scale.

    GuardDuty uses a 0-8.3 scale in its API/console, but the EventBridge
    payload has been seen carrying the 0-100 variant in older accounts,
    so normalize first. Thresholds follow the AWS console bands:
    Low < 4, Medium 4-7, High >= 7 (we pull High down to P0 because
    automated response, not a human, is on the other side of this call).
    """
    sev = float(raw_severity)
    if sev > 10:  # normalize the 0-100 variant onto the 0-8.3 scale
        sev = sev / 12.5
    if sev >= 7:
        return P0
    if sev >= 4:
        return P1
    if sev >= 2:
        return P2
    return P3
