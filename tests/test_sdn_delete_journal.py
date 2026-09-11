"""The private journal must block retries until deletion has finished."""

import importlib.util
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "roles/range42-ansible_roles-proxmox_controller/files/sdn_delete_journal.py"
)


def invoke(active_root, operation, **fields):
    return subprocess.run(
        [sys.executable, str(SCRIPT), operation],
        input=json.dumps({"root": str(active_root), "zone": "lab", **fields}),
        text=True,
        capture_output=True,
        check=False,
    )


def success(root, operation, **fields):
    result = invoke(root, operation, **fields)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def module():
    assert SCRIPT.is_file(), "The private deletion journal helper is missing"
    spec = importlib.util.spec_from_file_location("sdn_delete_journal", SCRIPT)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def evidence():
    return {"original": {"nodes": ["pve1"], "rules": ["private-original-rule"]}}


def test_begin_retains_original_evidence_and_blocks_incomplete_retry(tmp_path):
    tmp_path.chmod(0o755)
    assert success(tmp_path, "check")["state"] == "absent"
    receipt = success(tmp_path, "begin", payload=evidence())
    record_path = tmp_path / ".sdn-delete/lab.json"
    assert receipt["path"] == str(record_path)
    assert len(receipt["token"]) == 64
    assert "private-original-rule" not in json.dumps(receipt)
    record = json.loads(record_path.read_text())
    assert record["payload"] == evidence()
    assert record["state"] == "incomplete"
    assert stat.S_IMODE(record_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(record_path.parent.stat().st_mode) == 0o700
    assert invoke(tmp_path, "check").returncode != 0
    assert invoke(tmp_path, "begin", payload={"replacement": True}).returncode != 0
    assert json.loads(record_path.read_text()) == record


def test_successful_repeat_archives_original_completed_evidence(tmp_path):
    first = success(tmp_path, "begin", payload=evidence())
    success(
        tmp_path,
        "phase",
        token=first["token"],
        phase="declarations_deleted",
        evidence={"count": 3},
    )
    success(tmp_path, "complete", token=first["token"], evidence={"verified": True})
    assert success(tmp_path, "check")["state"] == "completed"
    path = Path(first["path"])
    completed = path.read_bytes()
    assert json.loads(completed)["payload"] == evidence()
    second = success(tmp_path, "begin", payload={"replacement": True})
    assert second["token"] != first["token"]
    archives = list(path.parent.glob("lab.*.json"))
    assert len(archives) == 1
    assert archives[0].read_bytes() == completed
    assert invoke(tmp_path, "check").returncode != 0


@pytest.mark.parametrize("operation", ["phase", "complete", "unknown"])
def test_wrong_receipt_cannot_update_journal(tmp_path, operation):
    receipt = success(tmp_path, "begin", payload=evidence())
    original = Path(receipt["path"]).read_bytes()
    result = invoke(tmp_path, operation, token="0" * 64, phase="deleted")
    assert result.returncode != 0
    assert result.stdout == ""
    assert "private-original-rule" not in result.stderr
    assert Path(receipt["path"]).read_bytes() == original


@pytest.mark.parametrize(
    "fault",
    [
        "root_symlink",
        "ancestor_symlink",
        "root_write",
        "dir_symlink",
        "dir_mode",
        "file_symlink",
        "file_mode",
        "hardlink",
    ],
)
def test_unsafe_paths_fail_without_touching_original(tmp_path, fault):
    root = tmp_path / "active"
    root.mkdir(mode=0o755)
    target = tmp_path / "untouched"
    target.write_text("do not touch")
    directory = root / ".sdn-delete"
    if fault == "root_symlink":
        (tmp_path / "alias").symlink_to(root, target_is_directory=True)
        root = tmp_path / "alias"
    elif fault == "ancestor_symlink":
        (tmp_path / "alias").symlink_to(tmp_path, target_is_directory=True)
        root = tmp_path / "alias/active"
    elif fault == "root_write":
        root.chmod(0o777)
    elif fault == "dir_symlink":
        directory.symlink_to(tmp_path, target_is_directory=True)
    elif fault == "dir_mode":
        directory.mkdir(mode=0o755)
    else:
        receipt = success(root, "begin", payload=evidence())
        record = Path(receipt["path"])
        if fault == "file_symlink":
            record.unlink()
            record.symlink_to(target)
        elif fault == "file_mode":
            record.chmod(0o644)
        else:
            os.link(record, tmp_path / "hardlink")
    result = invoke(root, "check")
    assert result.returncode != 0
    assert result.stdout == ""
    assert target.read_text() == "do not touch"


@pytest.mark.parametrize("operation", ["phase", "complete"])
def test_file_fsync_failure_preserves_existing_incomplete_record(
    tmp_path, monkeypatch, operation
):
    helper = module()
    receipt = success(tmp_path, "begin", payload=evidence())
    path = Path(receipt["path"])
    original = path.read_bytes()
    real_fsync = os.fsync

    def fail_file(fd):
        if stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("injected file fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(helper.os, "fsync", fail_file)
    with pytest.raises(OSError):
        helper.execute(
            operation,
            {
                "root": str(tmp_path),
                "zone": "lab",
                "token": receipt["token"],
                "phase": "deleted",
            },
        )
    assert path.read_bytes() == original
    assert not list(path.parent.glob("*.tmp"))
    assert invoke(tmp_path, "check").returncode != 0


def test_begin_fsync_failure_leaves_no_partial_evidence(tmp_path, monkeypatch):
    helper = module()
    success(tmp_path, "check")

    def fail_fsync(_fd):
        raise OSError("injected fsync failure")

    monkeypatch.setattr(helper.os, "fsync", fail_fsync)
    with pytest.raises(OSError):
        helper.execute(
            "begin", {"root": str(tmp_path), "zone": "lab", "payload": evidence()}
        )
    assert not (tmp_path / ".sdn-delete/lab.json").exists()
    assert not list((tmp_path / ".sdn-delete").glob("*.tmp"))


@pytest.mark.parametrize(
    "fields",
    [{"root": "relative"}, {"zone": "../escape"}, {"zone": ""}, {"payload": []}],
)
def test_invalid_begin_input_is_rejected(tmp_path, fields):
    result = invoke(tmp_path, "begin", **{"payload": evidence(), **fields})
    assert result.returncode != 0
    assert result.stdout == ""


@pytest.mark.parametrize(
    "fault", ["state_phase", "last_event", "time", "empty_payload"]
)
def test_malformed_completed_record_does_not_authorize_retry(tmp_path, fault):
    receipt = success(tmp_path, "begin", payload=evidence())
    success(tmp_path, "complete", token=receipt["token"])
    path = Path(receipt["path"])
    record = json.loads(path.read_text())
    if fault == "state_phase":
        record["phase"] = "prepared"
    elif fault == "last_event":
        record["events"][-1]["phase"] = "prepared"
    elif fault == "time":
        record["events"][-1]["at_ns"] = 0
    else:
        record["payload"] = {}
    path.write_text(json.dumps(record))
    assert invoke(tmp_path, "check").returncode != 0


def test_only_one_concurrent_begin_can_issue_receipt(tmp_path):
    success(tmp_path, "check")
    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(
            workers.map(
                lambda _: invoke(tmp_path, "begin", payload=evidence()), range(4)
            )
        )
    assert sum(result.returncode == 0 for result in results) == 1
    assert invoke(tmp_path, "check").returncode != 0


@pytest.mark.parametrize("operation", ["phase", "complete"])
def test_directory_fsync_failure_restores_previous_incomplete_record(
    tmp_path, monkeypatch, operation
):
    helper = module()
    receipt = success(tmp_path, "begin", payload=evidence())
    path = Path(receipt["path"])
    original = path.read_bytes()
    real_fsync = os.fsync

    def fail_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("injected directory fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(helper.os, "fsync", fail_directory)
    with pytest.raises(OSError):
        helper.execute(
            operation,
            {
                "root": str(tmp_path),
                "zone": "lab",
                "token": receipt["token"],
                "phase": "deleted",
            },
        )
    assert path.read_bytes() == original
    assert path.stat().st_nlink == 1
    assert not list(path.parent.glob("*.tmp"))
    assert invoke(tmp_path, "check").returncode != 0


def test_begin_directory_fsync_failure_retains_incomplete_evidence(
    tmp_path, monkeypatch
):
    helper = module()
    success(tmp_path, "check")
    real_fsync = os.fsync

    def fail_directory(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("injected directory fsync failure")
        real_fsync(fd)

    monkeypatch.setattr(helper.os, "fsync", fail_directory)
    with pytest.raises(OSError):
        helper.execute(
            "begin", {"root": str(tmp_path), "zone": "lab", "payload": evidence()}
        )
    record = json.loads((tmp_path / ".sdn-delete/lab.json").read_text())
    assert record["state"] == "incomplete"
    assert record["payload"] == evidence()
    assert invoke(tmp_path, "check").returncode != 0


def test_different_owner_is_rejected(tmp_path, monkeypatch):
    helper = module()
    success(tmp_path, "begin", payload=evidence())
    wrong_uid = os.geteuid() + 1
    monkeypatch.setattr(helper.os, "geteuid", lambda: wrong_uid)
    with pytest.raises(ValueError):
        helper.execute("check", {"root": str(tmp_path), "zone": "lab"})


@pytest.mark.parametrize("raw", ['{"zone":"lab","zone":"other"}', '{"number":NaN}'])
def test_ambiguous_json_is_rejected(raw):
    helper = module()
    with pytest.raises(ValueError):
        helper.decode(raw.encode())


def test_oversized_evidence_is_rejected_before_record_creation(tmp_path, monkeypatch):
    helper = module()
    monkeypatch.setattr(helper, "MAX_BYTES", 512)
    with pytest.raises(ValueError):
        helper.execute(
            "begin",
            {"root": str(tmp_path), "zone": "lab", "payload": {"large": "x" * 512}},
        )
    assert not (tmp_path / ".sdn-delete/lab.json").exists()


def test_phase_limit_keeps_room_for_completion(tmp_path, monkeypatch):
    helper = module()
    monkeypatch.setattr(helper, "MAX_EVENTS", 3)
    base = {"root": str(tmp_path), "zone": "lab"}
    receipt = helper.execute("begin", {**base, "payload": evidence()})
    operation = {**base, "token": receipt["token"], "phase": "deleted"}
    helper.execute("phase", operation)
    with pytest.raises(ValueError):
        helper.execute("phase", operation)
    assert helper.execute("complete", operation)["state"] == "completed"
