"""Private deletion evidence; no Proxmox calls or automatic recovery.

Usage: sdn_delete_journal.py {check,begin,phase,complete}, JSON on stdin.
The caller supplies an absolute, stable operator-owned state ``root`` and
``zone``. The same root must be used for every attempt against that cluster;
per-attempt workspaces cannot provide retry protection. Every mutation also
requires ``cluster_identity``: ``pve-root-ca-sha256:`` plus the lowercase SHA-256
fingerprint of the cluster's pve-root-ca.pem certificate. Check may omit that
identity only for the preliminary incomplete-attempt gate before discovery.
One root-wide lock and journal scan prevent overlapping deletions across zones.
Legacy evidence without a cluster identity requires operator review. Begin
retains ``payload`` and returns a random receipt ``token`` and journal ``path``.
Phase/complete require that token; optional ``evidence`` is retained privately.
An incomplete or unreadable journal requires operator review before a retry.
"""

from contextlib import contextmanager
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import PurePosixPath
import re
import secrets
import stat
import sys
import time


MAX_BYTES = 16 * 1024 * 1024
MAX_EVENTS = 512
ZONE_PATTERN = r"[A-Za-z][A-Za-z0-9]{1,7}"
CLUSTER_PATTERN = r"pve-root-ca-sha256:[0-9a-f]{64}"
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def require(condition):
    if not condition:
        raise ValueError("Deletion journal refused")


def json_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError("Invalid JSON constant")


def decode(data):
    require(len(data) <= MAX_BYTES)
    return json.loads(
        data, object_pairs_hook=json_object, parse_constant=reject_constant
    )


def encode(document):
    data = json.dumps(
        document, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    require(len(data) <= MAX_BYTES)
    return data


def private_file(fd):
    info = os.fstat(fd)
    require(
        stat.S_ISREG(info.st_mode)
        and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o600
        and info.st_nlink == 1
    )


def root_directory(root):
    require(isinstance(root, str) and root.startswith("/") and len(root) <= 4096)
    path = PurePosixPath(root)
    require(str(path) == root and ".." not in path.parts)
    fd = os.open("/", DIRECTORY_FLAGS)
    try:
        for part in path.parts[1:]:
            child = os.open(part, DIRECTORY_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            require(info.st_uid in {0, os.geteuid()})
            require(
                not info.st_mode & 0o022
                or (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
            )
        info = os.fstat(fd)
        require(info.st_uid == os.geteuid() and not info.st_mode & 0o022)
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextmanager
def journal_directory(root):
    root_fd = root_directory(root)
    directory_fd = lock_fd = None
    try:
        try:
            os.mkdir(".sdn-delete", 0o700, dir_fd=root_fd)
            os.fsync(root_fd)
        except FileExistsError:
            pass
        directory_fd = os.open(".sdn-delete", DIRECTORY_FLAGS, dir_fd=root_fd)
        info = os.fstat(directory_fd)
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
        lock_fd = os.open(
            "cluster.lock",
            os.O_RDWR | os.O_CREAT | FILE_FLAGS,
            0o600,
            dir_fd=directory_fd,
        )
        private_file(lock_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield directory_fd
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        if directory_fd is not None:
            os.close(directory_fd)
        os.close(root_fd)


def read_file(directory_fd, name):
    try:
        fd = os.open(name, os.O_RDONLY | FILE_FLAGS, dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        private_file(stream.fileno())
        data = stream.read(MAX_BYTES + 1)
        require(len(data) <= MAX_BYTES)
        return data


def stage_file(directory_fd, data):
    name = f".{secrets.token_hex(16)}.tmp"
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | FILE_FLAGS,
        0o600,
        dir_fd=directory_fd,
    )
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        return name
    except BaseException:
        os.unlink(name, dir_fd=directory_fd)
        raise


def publish(directory_fd, name, data, *, replace=False):
    """Publish durable bytes, retaining the previous inode until directory sync.

    If an update cannot sync, restore its previous record. A crash while the
    old inode has a backup link makes the next read fail closed on link count.
    A failed initial publication may leave an incomplete record for review.
    """
    temporary = stage_file(directory_fd, data)
    backup = None
    try:
        if replace:
            backup = f".{secrets.token_hex(16)}.tmp"
            os.link(name, backup, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            os.replace(
                temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd
            )
        else:
            os.link(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            os.unlink(temporary, dir_fd=directory_fd)
        temporary = None
        os.fsync(directory_fd)
        if backup is not None:
            os.unlink(backup, dir_fd=directory_fd)
            backup = None
    except BaseException:
        if backup is not None:
            os.replace(backup, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            backup = None
            try:
                os.fsync(directory_fd)
            except OSError:
                pass  # The old incomplete record remains; never report success.
        raise
    finally:
        if temporary is not None:
            os.unlink(temporary, dir_fd=directory_fd)


def read_record(directory_fd, zone, name):
    raw = read_file(directory_fd, name)
    if raw is None:
        return None, None
    record = decode(raw)
    require(isinstance(record, dict))
    require(
        type(record.get("version")) is int
        and record["version"] == 2
        and record.get("zone") == zone
        and isinstance(record.get("cluster_identity"), str)
        and re.fullmatch(CLUSTER_PATTERN, record["cluster_identity"])
        and record.get("state") in {"incomplete", "completed"}
        and isinstance(record.get("payload"), dict)
        and record["payload"]
        and isinstance(record.get("token_hash"), str)
        and re.fullmatch(r"[0-9a-f]{64}", record["token_hash"])
        and isinstance(record.get("phase"), str)
        and isinstance(record.get("events"), list)
        and 1 <= len(record["events"]) <= MAX_EVENTS
        and all(isinstance(event, dict) for event in record["events"])
    )
    require(
        (record["state"] == "completed") == (record["phase"] == "completed")
        and record["events"][-1].get("phase") == record["phase"]
        and record["events"][0].get("phase") == "prepared"
        and all(event.get("phase") != "completed" for event in record["events"][:-1])
    )
    for event in record["events"]:
        require(
            isinstance(event.get("phase"), str)
            and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", event["phase"])
            and type(event.get("at_ns")) is int
            and event["at_ns"] > 0
            and isinstance(event.get("evidence", {}), dict)
        )
    return raw, record


def inspect_records(directory_fd, zone, cluster_identity, operation):
    """Validate all active records and completed history while holding one lock."""
    selected = (None, None)
    observed_identity = cluster_identity
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            if not entry.name.endswith(".json"):
                continue
            match = re.fullmatch(
                rf"({ZONE_PATTERN})(?:\.([0-9a-f]{{64}}))?\.json", entry.name
            )
            require(match is not None)
            record_zone, archive_hash = match.groups()
            raw, record = read_record(directory_fd, record_zone, entry.name)
            require(record is not None)
            if observed_identity is None:
                observed_identity = record["cluster_identity"]
            require(record["cluster_identity"] == observed_identity)
            if archive_hash is not None:
                require(
                    record["state"] == "completed"
                    and hashlib.sha256(raw).hexdigest() == archive_hash
                )
            else:
                require(
                    record["state"] == "completed"
                    or (record_zone == zone and operation in {"phase", "complete"})
                )
                if record_zone == zone:
                    selected = (raw, record)
    return selected


def execute(operation, document):
    require(operation in {"check", "begin", "phase", "complete"})
    require(isinstance(document, dict))
    zone = document.get("zone")
    require(isinstance(zone, str) and re.fullmatch(ZONE_PATTERN, zone))
    cluster_identity = document.get("cluster_identity")
    if operation != "check" or "cluster_identity" in document:
        require(
            isinstance(cluster_identity, str)
            and re.fullmatch(CLUSTER_PATTERN, cluster_identity)
        )
    root = document.get("root")
    with journal_directory(root) as directory_fd:
        raw, record = inspect_records(directory_fd, zone, cluster_identity, operation)
        path = f"{root}/.sdn-delete/{zone}.json"
        if operation == "check":
            require(record is None or record["state"] == "completed")
            return {"state": "absent" if record is None else "completed", "path": path}
        if operation == "begin":
            require(isinstance(document.get("payload"), dict) and document["payload"])
            require(record is None or record["state"] == "completed")
            token = secrets.token_hex(32)
            created = {
                "version": 2,
                "zone": zone,
                "cluster_identity": cluster_identity,
                "state": "incomplete",
                "phase": "prepared",
                "token_hash": hashlib.sha256(token.encode()).hexdigest(),
                "payload": document["payload"],
                "events": [{"phase": "prepared", "at_ns": time.time_ns()}],
            }
            data = encode(created)
            if raw is not None:
                archive = f"{zone}.{hashlib.sha256(raw).hexdigest()}.json"
                archived = read_file(directory_fd, archive)
                require(archived is None or archived == raw)
                if archived is None:
                    publish(directory_fd, archive, raw)
            publish(directory_fd, f"{zone}.json", data, replace=record is not None)
            return {"state": "incomplete", "token": token, "path": path}
        token = document.get("token")
        require(
            record is not None
            and isinstance(token, str)
            and re.fullmatch(r"[0-9a-f]{64}", token)
        )
        require(
            hmac.compare_digest(
                record["token_hash"], hashlib.sha256(token.encode()).hexdigest()
            )
        )
        event_limit = MAX_EVENTS if operation == "complete" else MAX_EVENTS - 1
        require(record["state"] == "incomplete" and len(record["events"]) < event_limit)
        phase = "completed" if operation == "complete" else document.get("phase")
        require(
            isinstance(phase, str) and re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", phase)
        )
        require(operation == "complete" or phase not in {"completed", "prepared"})
        evidence = document.get("evidence", {})
        require(isinstance(evidence, dict))
        record["events"].append(
            {"phase": phase, "at_ns": time.time_ns(), "evidence": evidence}
        )
        record["phase"] = phase
        if operation == "complete":
            record["state"] = "completed"
        publish(directory_fd, f"{zone}.json", encode(record), replace=True)
        return {"state": record["state"], "phase": phase, "path": path}


def main():
    try:
        require(len(sys.argv) == 2)
        document = decode(sys.stdin.buffer.read(MAX_BYTES + 1))
        result = execute(sys.argv[1], document)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        print(
            "Deletion journal refused; review private journal and filesystem permissions.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
