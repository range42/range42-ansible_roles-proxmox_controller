"""Exercise separate cooperating writers with real flock, never host iptables."""

import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from test_snat_preservation import (
    HELPER, LEGACY, OTHER_RULE, UNRELATED, fake as _fake_fixture, invoke, restore, snapshot,
)


@pytest.fixture(name="fake")
def fake_rules(tmp_path):
    return _fake_fixture.__wrapped__(tmp_path)


def test_independent_writer_cannot_move_a_rule_between_check_and_numbered_delete(fake):
    baseline = [UNRELATED, OTHER_RULE, LEGACY]
    before = snapshot(fake, baseline)
    fake[0].write_text(json.dumps([*baseline, OTHER_RULE]))
    directory = fake[0].parent
    fake[2].update(R42_PAUSE_AT_READ="3", R42_READY=str(directory / "ready"),
                   R42_ATTEMPT=str(directory / "attempt"))
    # The writer waits for the helper's last read, then takes the conventional
    # lock and inserts a rule. Without an outer transaction the numeric delete
    # now addresses LEGACY instead of the appended OTHER_RULE.
    writer = subprocess.Popen([sys.executable, "-c", """
import fcntl,json,os,pathlib,time
ready=pathlib.Path(os.environ['R42_READY']);deadline=time.monotonic()+8
while not ready.exists():
 assert time.monotonic()<deadline;time.sleep(.01)
pathlib.Path(os.environ['R42_ATTEMPT']).touch()
with open(os.environ['XTABLES_LOCKFILE'],'a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 state=pathlib.Path(os.environ['R42_RULES']);rules=json.loads(state.read_text())
 rules.insert(0,['-A','POSTROUTING','-j','ACCEPT'])
 state.write_text(json.dumps(rules))
"""], env=fake[2], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        result = restore(fake, before)
        _, errors = writer.communicate(timeout=10)
        assert writer.returncode == 0, errors
        assert result.returncode == 0, result.stderr
        assert json.loads(fake[0].read_text()) == [["-A", "POSTROUTING", "-j", "ACCEPT"], *baseline]
    finally:
        if writer.poll() is None:
            writer.kill()
            writer.wait()


def test_held_conventional_lock_prevents_any_snapshot_command(fake):
    lock_path = Path(fake[2]["XTABLES_LOCKFILE"])
    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        process = subprocess.Popen([sys.executable, str(HELPER), "snapshot"], env=fake[2],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            time.sleep(.25)
            assert process.poll() is None
            assert Path(fake[2]["R42_READS"]).read_text() == "0"
            fcntl.flock(lock, fcntl.LOCK_UN)
            stdout, stderr = process.communicate(timeout=5)
            assert process.returncode == 0, stderr
            assert json.loads(stdout)["rules"] == []
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


@pytest.mark.parametrize("version", ["iptables v1.8.9 (nf_tables)", "iptables unknown"])
def test_unsupported_backend_refuses_snapshot_before_any_table_access(fake, version):
    fake[2]["R42_IPTABLES_VERSION"] = version
    result = invoke(fake, "snapshot")
    assert result.returncode != 0
    assert Path(fake[2]["R42_READS"]).read_text() == "0"
    assert json.loads(fake[1].read_text()) == []


def test_lock_symlink_is_rejected_without_touching_its_target(fake):
    target = fake[0].parent / "unrelated"
    target.write_text("keep")
    Path(fake[2]["XTABLES_LOCKFILE"]).symlink_to(target)
    result = invoke(fake, "snapshot")
    assert result.returncode != 0
    assert target.read_text() == "keep"
    assert Path(fake[2]["R42_READS"]).read_text() == "0"


def test_restore_failure_releases_outer_lock(fake):
    before = snapshot(fake, [OTHER_RULE, LEGACY])
    fake[0].write_text(json.dumps([LEGACY, OTHER_RULE]))
    assert restore(fake, before).returncode != 0
    with open(fake[2]["XTABLES_LOCKFILE"], "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    assert os.path.isfile(fake[2]["XTABLES_LOCKFILE"])
