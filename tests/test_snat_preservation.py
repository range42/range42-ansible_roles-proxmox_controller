"""Execute the controller helper against private rule fixtures, never host NAT."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

HELPER = (
    Path(__file__).resolve().parents[1]
    / "roles/range42-ansible_roles-proxmox_controller/files/snat_rules.py"
)
TARGET = "10.42.70.0/24"
OTHER = "10.42.80.0/24"


def rule(*args):
    return ["-A", "POSTROUTING", *args]


TARGET_RULE = rule(
    "-s", TARGET, "-o", "vmbr0", "-j", "SNAT", "--to-source", "192.0.2.1"
)
OTHER_RULE = rule("-s", OTHER, "-o", "vmbr0", "-j", "SNAT", "--to-source", "192.0.2.2")
OTHER_SHAPE = rule(
    "-s",
    OTHER,
    "-o",
    "vmbr0",
    "-m",
    "comment",
    "--comment",
    'preserve quoted "rule"',
    "-j",
    "SNAT",
    "--to-source",
    "192.0.2.3",
)
UNRELATED = rule("-s", OTHER, "-j", "ACCEPT")
LEGACY = rule("-s", "192.168.140.0/24", "-o", "vmbr0", "-j", "MASQUERADE")


@pytest.fixture
def fake(tmp_path):
    state = tmp_path / "rules.json"
    state.write_text("[]")
    counter = tmp_path / "reads"
    counter.write_text("0")
    writes = tmp_path / "writes.json"
    writes.write_text("[]")
    binary = tmp_path / "iptables"
    binary.write_text(
        f"#!{sys.executable}\n"
        + """import json, os, pathlib, shlex, sys
state=pathlib.Path(os.environ['R42_RULES']); counter=pathlib.Path(os.environ['R42_READS']); writes=pathlib.Path(os.environ['R42_WRITES'])
args=sys.argv[1:]; assert args[:4]==['-w','5','-t','nat']; args=args[4:]
rules=json.loads(state.read_text())
if args==['-S','POSTROUTING']:
 count=int(counter.read_text())+1; counter.write_text(str(count))
 if str(count)==os.environ.get('R42_CHANGE_AT_READ'):
  rules.append(['-A','POSTROUTING','-j','ACCEPT']);state.write_text(json.dumps(rules))
 print('\\n'.join(shlex.join(row) for row in rules))
elif args[:2]==['-D','POSTROUTING']:
 assert len(args)==3 and args[2].isdigit(), 'Preservation must delete the appended position, not the first matching rule'
 index=int(args[2])-1; del rules[index];state.write_text(json.dumps(rules))
 history=json.loads(writes.read_text()); history.append(int(args[2]));writes.write_text(json.dumps(history))
else: raise AssertionError(args)
"""
    )
    binary.chmod(0o755)
    env = {
        **os.environ,
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "R42_RULES": str(state),
        "R42_READS": str(counter),
        "R42_WRITES": str(writes),
    }
    return state, writes, env


def invoke(fake, operation, payload=None):
    return subprocess.run(
        [sys.executable, str(HELPER), operation],
        env=fake[2],
        input=json.dumps(payload) if payload is not None else None,
        capture_output=True,
        text=True,
        timeout=15,
    )


def snapshot(fake, baseline):
    fake[0].write_text(json.dumps(baseline))
    result = invoke(fake, "snapshot")
    assert result.returncode == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["version"] == 1 and document["rules"] == baseline
    return document


def restore(fake, baseline, excluded=None, allow_new=False):
    return invoke(
        fake,
        "restore",
        {
            "snapshot": baseline,
            "excluded_sources": excluded or [],
            "allow_new_rules": allow_new,
        },
    )


def test_snapshot_retains_complete_rule_arguments_without_grouping(fake):
    baseline = [UNRELATED, OTHER_RULE, OTHER_SHAPE, *([LEGACY] * 3)]
    snapshot(fake, baseline)
    assert json.loads(fake[0].read_text()) == baseline
    assert json.loads(fake[1].read_text()) == []


def test_restore_removes_only_appended_duplicates_preserving_old_counts_shapes_and_order(
    fake,
):
    baseline = [UNRELATED, OTHER_RULE, OTHER_SHAPE, *([LEGACY] * 3), TARGET_RULE]
    before = snapshot(fake, baseline)
    after = [*baseline, OTHER_RULE, OTHER_SHAPE, LEGACY, TARGET_RULE]
    fake[0].write_text(json.dumps(after))
    result = restore(fake, before, [TARGET])
    assert result.returncode == 0, result.stderr
    assert json.loads(fake[0].read_text()) == [*baseline, TARGET_RULE]
    assert json.loads(fake[1].read_text()) == [10, 9, 8]
    assert json.loads(result.stdout)["deleted"] == 3


def test_restore_noop_does_not_delete_anything(fake):
    baseline = [UNRELATED, OTHER_RULE, OTHER_SHAPE, LEGACY]
    before = snapshot(fake, baseline)
    result = restore(fake, before)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["deleted"] == 0
    assert json.loads(fake[0].read_text()) == baseline


@pytest.mark.parametrize("mutation", ["removed", "reordered", "inserted", "new_shape"])
def test_unexplained_non_target_drift_refuses_before_any_deletion(fake, mutation):
    baseline = [UNRELATED, OTHER_RULE, LEGACY]
    before = snapshot(fake, baseline)
    after = {
        "removed": [OTHER_RULE, LEGACY],
        "reordered": [LEGACY, UNRELATED, OTHER_RULE],
        "inserted": [UNRELATED, OTHER_RULE, OTHER_RULE, LEGACY],
        "new_shape": [*baseline, OTHER_SHAPE],
    }[mutation]
    fake[0].write_text(json.dumps(after))
    result = restore(fake, before)
    assert result.returncode != 0
    assert json.loads(fake[1].read_text()) == []
    assert json.loads(fake[0].read_text()) == after


def test_fresh_table_guard_refuses_a_concurrent_change_before_numbered_delete(fake):
    baseline = [UNRELATED, OTHER_RULE, LEGACY]
    before = snapshot(fake, baseline)
    fake[0].write_text(json.dumps([*baseline, OTHER_RULE]))
    fake[2]["R42_CHANGE_AT_READ"] = "3"
    result = restore(fake, before)
    assert result.returncode != 0
    assert json.loads(fake[1].read_text()) == []


def test_standalone_apply_can_retain_legitimate_new_rules_while_removing_known_duplicates(
    fake,
):
    baseline = [UNRELATED, OTHER_RULE, LEGACY]
    before = snapshot(fake, baseline)
    fake[0].write_text(json.dumps([*baseline, OTHER_RULE, TARGET_RULE, OTHER_SHAPE]))
    result = restore(fake, before, allow_new=True)
    assert result.returncode == 0, result.stderr
    assert json.loads(fake[0].read_text()) == [*baseline, TARGET_RULE, OTHER_SHAPE]
    assert json.loads(result.stdout)["retained_new_rules"] == 2


def test_restore_rejects_snapshot_from_another_node(fake):
    baseline = [UNRELATED, OTHER_RULE]
    before = snapshot(fake, baseline)
    before["node"] = "another-node"
    fake[0].write_text(json.dumps([*baseline, OTHER_RULE]))
    result = restore(fake, before)
    assert result.returncode != 0
    assert json.loads(fake[1].read_text()) == []


def test_empty_successful_table_is_a_valid_snapshot(fake):
    document = snapshot(fake, [])
    assert document["nat_counts"] == {}


def test_snapshot_exposes_exact_source_counts_for_noop_decisions(fake):
    document = snapshot(fake, [UNRELATED, OTHER_RULE, OTHER_SHAPE, TARGET_RULE])
    assert document["nat_counts"] == {OTHER: 2, TARGET: 1}


def test_invalid_exclusion_input_cannot_authorize_a_source(fake):
    document = snapshot(fake, [OTHER_RULE])
    fake[0].write_text(json.dumps([OTHER_RULE, OTHER_RULE]))
    result = restore(fake, document, [1234])
    assert result.returncode != 0
    assert json.loads(fake[1].read_text()) == []
