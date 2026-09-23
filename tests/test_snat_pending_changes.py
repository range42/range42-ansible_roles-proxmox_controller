"""A pending apply may change only explicitly reviewed existing NAT sources."""

import json
from pathlib import Path

import pytest

from test_snat_preservation import (
    LEGACY, OTHER, OTHER_RULE, OTHER_SHAPE, TARGET, TARGET_RULE, UNRELATED,
    fake as _fake_fixture, invoke, restore, snapshot,
)


@pytest.fixture(name="fake")
def fake_rules(tmp_path):
    return _fake_fixture.__wrapped__(tmp_path)


def reviewed_snapshot(fake, baseline, changed):
    fake[0].write_text(json.dumps(baseline))
    policy = {"excluded_sources": changed, "allow_new_rules": True}
    result = invoke(fake, "snapshot-reviewed", policy)
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["reviewed_policy"] == policy
    return document


@pytest.mark.parametrize("after_target", [[], [OTHER_SHAPE, OTHER_RULE], [OTHER_SHAPE]])
def test_reviewed_source_can_be_removed_reordered_or_replaced(fake, after_target):
    baseline = [UNRELATED, OTHER_RULE, OTHER_SHAPE, LEGACY]
    before = reviewed_snapshot(fake, baseline, [OTHER])
    # Changed rules may move around protected rows; only the relative order of
    # untouched rows is fixed. Their original multiplicities are not reset to 1.
    after = [*after_target, UNRELATED, LEGACY, LEGACY]
    fake[0].write_text(json.dumps(after))
    result = restore(fake, before, [OTHER], allow_new=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(fake[0].read_text()) == [*after_target, UNRELATED, LEGACY]
    assert json.loads(result.stdout)["deleted"] == 1


def test_unlisted_existing_source_cannot_gain_a_new_rule_shape(fake):
    before = snapshot(fake, [UNRELATED, OTHER_RULE, LEGACY])
    after = [UNRELATED, OTHER_RULE, LEGACY, LEGACY, OTHER_SHAPE]
    fake[0].write_text(json.dumps(after))
    result = restore(fake, before, allow_new=True)
    assert result.returncode != 0
    assert json.loads(fake[1].read_text()) == []
    assert json.loads(fake[0].read_text()) == after


def test_new_source_can_be_added_without_authorizing_changes_to_existing_sources(fake):
    before = reviewed_snapshot(fake, [UNRELATED, OTHER_RULE, LEGACY], [])
    fake[0].write_text(json.dumps([UNRELATED, OTHER_RULE, LEGACY, TARGET_RULE, LEGACY]))
    result = restore(fake, before, allow_new=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(fake[0].read_text()) == [UNRELATED, OTHER_RULE, LEGACY, TARGET_RULE]


@pytest.mark.parametrize("change", ["remove_non_nat", "reorder_other", "remove_other"])
def test_review_does_not_authorize_non_nat_or_other_sources(fake, change):
    before = reviewed_snapshot(fake, [UNRELATED, OTHER_RULE, LEGACY, TARGET_RULE], [OTHER])
    after = {
        "remove_non_nat": [OTHER_RULE, LEGACY, TARGET_RULE],
        "reorder_other": [UNRELATED, TARGET_RULE, LEGACY, OTHER_RULE],
        "remove_other": [UNRELATED, OTHER_RULE, TARGET_RULE],
    }[change]
    fake[0].write_text(json.dumps(after))
    assert restore(fake, before, [OTHER], allow_new=True).returncode != 0
    assert json.loads(fake[1].read_text()) == []
    assert json.loads(fake[0].read_text()) == after


@pytest.mark.parametrize("changed", [None, "10.0.0.0/24", [7], [OTHER, OTHER],
                                     ["10.0.0.3/24"], ["::/0"], ["10.0.0.0/255.255.255.0"],
                                     [f"10.{i}.0.0/24" for i in range(65)]])
def test_invalid_review_scope_is_rejected_before_snapshot(fake, changed):
    result = invoke(fake, "snapshot-reviewed", {"excluded_sources": changed, "allow_new_rules": True})
    assert result.returncode != 0
    assert fake[0].read_text() == "[]"
    assert fake[1].read_text() == "[]"
    assert int(Path(fake[2]["R42_READS"]).read_text()) == 0


@pytest.mark.parametrize("changed,allow_new", [([OTHER, TARGET], True), ([], True), ([OTHER], False)])
def test_scope_cannot_change_after_the_reviewed_snapshot(fake, changed, allow_new):
    before = reviewed_snapshot(fake, [UNRELATED, OTHER_RULE, LEGACY], [OTHER])
    fake[0].write_text(json.dumps([UNRELATED, OTHER_RULE, LEGACY, LEGACY]))
    result = restore(fake, before, changed, allow_new=allow_new)
    assert result.returncode != 0
    assert json.loads(fake[1].read_text()) == []
