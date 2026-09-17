"""Severity mapping tests - both GuardDuty scales and the P-bands."""

from lib.severity import P0, P1, P2, P3, guardduty_level


def test_guardduty_console_scale():
    assert guardduty_level(8.0) == P0
    assert guardduty_level(7.0) == P0
    assert guardduty_level(5.0) == P1
    assert guardduty_level(4.0) == P1
    assert guardduty_level(2.5) == P2
    assert guardduty_level(0.9) == P3


def test_guardduty_legacy_100_scale_is_normalized():
    # some accounts emit 0-100; 72 -> 5.76 -> P1
    assert guardduty_level(72) == P1
    # 88 -> 7.04 -> P0
    assert guardduty_level(88) == P0


def test_band_edges_do_not_flip():
    assert guardduty_level(6.99) == P1
    assert guardduty_level(3.99) == P2
