"""Remediator planning and execution tests (simulate mode)."""

import pytest

from responders import quarantine_iam, remediate_sg

DANGEROUS_SSH = {
    "group_id": "sg-0a1b2c3d4e5f60011",
    "protocol": "tcp",
    "from_port": 22,
    "to_port": 22,
    "cidrs": ["0.0.0.0/0"],
    "service": "SSH",
}


def test_plan_groups_and_splits_v4_v6():
    v6 = dict(DANGEROUS_SSH, cidrs=["::/0"])
    plan = remediate_sg.plan_revokes([DANGEROUS_SSH, v6])
    assert len(plan) == 1  # same protocol/port tuple -> one permission
    perm = plan[0]["IpPermissions"][0]
    assert perm["IpRanges"] == [{"CidrIp": "0.0.0.0/0"}]
    assert perm["Ipv6Ranges"] == [{"CidrIpv6": "::/0"}]
    assert plan[0]["GroupId"] == "sg-0a1b2c3d4e5f60011"
    assert (perm["FromPort"], perm["ToPort"]) == (22, 22)


def test_plan_distinct_ports_stay_distinct():
    redis = dict(DANGEROUS_SSH, from_port=6379, to_port=6379, service="Redis")
    plan = remediate_sg.plan_revokes([DANGEROUS_SSH, redis])
    assert len(plan) == 2


def test_plan_skips_tuples_without_ranges():
    empty = dict(DANGEROUS_SSH, cidrs=[])
    assert remediate_sg.plan_revokes([empty]) == []


def test_describe_plan_is_human_readable():
    plan = remediate_sg.plan_revokes([DANGEROUS_SSH])
    text = remediate_sg.describe_plan(plan)
    assert "sg-0a1b2c3d4e5f60011" in text
    assert "tcp/22-22" in text
    assert "0.0.0.0/0" in text


def test_execute_simulate_mode_never_calls_aws(capsys):
    plan = remediate_sg.plan_revokes([DANGEROUS_SSH])
    result = remediate_sg.execute(plan)
    assert result["status"] == "simulated"
    out = capsys.readouterr().out
    assert "REMEDIATOR [SIMULATED]" in out


def test_sg_respond_returns_action_name():
    class FakeIncident:
        payload_ref = {"dangerous": [DANGEROUS_SSH]}

    result = remediate_sg.respond(FakeIncident())
    assert result["action"] == "close_public_ports"
    assert result["status"] == "simulated"


def test_quarantine_plan_is_reversible_by_design():
    plan = quarantine_iam.plan_quarantine("ci-bot")
    assert plan["action"] == "disable_all_access_keys"
    assert plan["reversible"] is True


def test_quarantine_skips_without_a_user(capsys):
    result = quarantine_iam.execute("unknown")
    assert result["status"] == "skipped"


def test_quarantine_simulate_mode(capsys):
    result = quarantine_iam.execute("ci-bot")
    assert result["status"] == "simulated"
    assert "ci-bot" in capsys.readouterr().out


@pytest.mark.parametrize("cidr", ["0.0.0.0/0", "::/0"])
def test_plan_handles_each_family_alone(cidr):
    item = dict(DANGEROUS_SSH, cidrs=[cidr])
    plan = remediate_sg.plan_revokes([item])
    perm = plan[0]["IpPermissions"][0]
    if cidr == "0.0.0.0/0":
        assert perm["IpRanges"] == [{"CidrIp": cidr}]
    else:
        assert perm["Ipv6Ranges"] == [{"CidrIpv6": cidr}]
