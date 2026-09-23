import json
import socket

import pytest

from test_snat_preservation import (
    fake as _fake_fixture,
    invoke,
    OTHER_RULE,
    TARGET,
    TARGET_RULE,
    UNRELATED,
)


@pytest.fixture(name="fake")
def fake_rules(tmp_path):
    return _fake_fixture.__wrapped__(tmp_path)


def test_node_reconcile_checks_identity_and_target_readback(fake):
    fake[2]["R42_ALLOW_EXACT"] = "1"
    fake[0].write_text(json.dumps([UNRELATED, OTHER_RULE, TARGET_RULE, TARGET_RULE]))
    result = invoke(
        fake,
        "reconcile-node",
        {"node": socket.gethostname(), "targets": [{"source": TARGET, "want": 0}]},
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(fake[0].read_text()) == [UNRELATED, OTHER_RULE]
    assert json.loads(result.stdout)["results"][0]["after"] == 0


@pytest.mark.parametrize(
    "node,want",
    [("wrong-node", 0), (socket.gethostname(), True), (socket.gethostname(), 2)],
)
def test_invalid_node_or_policy_cannot_mutate_any_rule(fake, node, want):
    fake[0].write_text(json.dumps([TARGET_RULE]))
    assert (
        invoke(
            fake,
            "reconcile-node",
            {"node": node, "targets": [{"source": TARGET, "want": want}]},
        ).returncode
        != 0
    )
    assert json.loads(fake[1].read_text()) == []


def test_missing_enabled_rule_is_not_a_successful_node_reconciliation(fake):
    result = invoke(
        fake,
        "reconcile-node",
        {"node": socket.gethostname(), "targets": [{"source": TARGET, "want": 1}]},
    )
    assert result.returncode != 0
    assert json.loads(fake[1].read_text()) == []
