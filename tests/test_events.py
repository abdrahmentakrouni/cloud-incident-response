"""Event normalization tests: every tracked family + the ignore path."""

import json
from pathlib import Path

from lib.events import DANGEROUS_PORTS, normalize, parse_sg_change

EVENTS = Path(__file__).resolve().parents[1] / "simulator" / "events"


def load(name):
    return json.loads((EVENTS / name).read_text())


# ------------------------------------------------------------ root login --

def test_failed_root_login_is_p0():
    inc = normalize(load("root-failed-login.json"))
    assert inc is not None
    assert inc.severity.level == "P0"
    assert inc.source == "root-login"
    assert inc.payload_ref["failed"] is True
    assert inc.remediable is False  # root cannot be disabled by a robot
    assert "45.155.205.233" in inc.payload_ref["source_ip"]


def test_non_root_signin_is_ignored():
    event = load("root-failed-login.json")
    event["detail"]["userIdentity"]["type"] = "IAMUser"
    assert normalize(event) is None


# ------------------------------------------------------------- sg ingress --

def test_public_ssh_is_remediable():
    inc = normalize(load("sg-port-22-open.json"))
    assert inc is not None
    assert inc.severity.level == "P1"
    assert inc.remediable is True
    assert inc.remediation == "close_public_ports"
    assert inc.payload_ref["dangerous"][0]["service"] == DANGEROUS_PORTS[22]
    assert inc.payload_ref["dangerous"][0]["cidrs"] == ["0.0.0.0/0"]


def test_world_open_but_benign_port_is_p2_not_remediated():
    event = load("sg-port-22-open.json")
    items = event["detail"]["requestParameters"]["ipPermissions"]["items"]
    items[0]["fromPort"] = items[0]["toPort"] = 8443
    inc = parse_sg_change(event)
    assert inc is not None
    assert inc.severity.level == "P2"
    assert inc.remediable is False


def test_private_cidr_change_is_ignored():
    event = load("sg-port-22-open.json")
    items = event["detail"]["requestParameters"]["ipPermissions"]["items"]
    items[0]["ranges"]["items"][0]["cidrIp"] = "10.0.0.0/8"
    assert parse_sg_change(event) is None


def test_ipv6_world_open_is_caught():
    event = load("sg-port-22-open.json")
    items = event["detail"]["requestParameters"]["ipPermissions"]["items"]
    items[0]["ranges"]["items"][0]["cidrIp"] = "::/0"
    inc = parse_sg_change(event)
    assert inc is not None
    assert inc.remediation == "close_public_ports"


def test_ipv6_world_open_benign_port_is_p2():
    event = load("sg-port-22-open.json")
    items = event["detail"]["requestParameters"]["ipPermissions"]["items"]
    items[0]["fromPort"] = items[0]["toPort"] = 8443
    items[0]["ranges"]["items"][0]["cidrIp"] = "::/0"
    inc = parse_sg_change(event)
    assert inc.severity.level == "P2"
    assert inc.remediable is False


# ----------------------------------------------------------------- iam ----

def test_new_access_key_is_p2_alert_only():
    inc = normalize(load("iam-new-access-key.json"))
    assert inc is not None
    assert inc.severity.level == "P2"
    assert inc.payload_ref["target_user"] == "reporting-service"
    assert inc.remediable is False


# -------------------------------------------------------------- guardduty --

def test_guardduty_user_finding_is_quarantinable():
    inc = normalize(load("guardduty-key-exfil.json"))
    assert inc is not None
    assert inc.severity.level == "P0"
    assert inc.remediation == "quarantine_iam"
    assert inc.payload_ref["finding_user"] == "ci-bot"


def test_guardduty_instance_finding_is_alert_only():
    inc = normalize(load("guardduty-crypto.json"))
    assert inc is not None
    assert inc.severity.level == "P0"
    assert inc.remediation is None
    assert inc.remediable is False


# ----------------------------------------------------------------- misc ----

def test_unknown_and_malformed_events_are_ignored():
    assert normalize({"detail-type": "Something Else"}) is None
    assert normalize({}) is None
    assert normalize("not-a-dict") is None
