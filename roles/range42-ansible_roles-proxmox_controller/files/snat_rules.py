"""Read or reconcile concrete source SNAT/MASQUERADE rules on one host.

iptables -S uses shell quoting. Parse it with shlex, preserve original argument
boundaries for deletion, and never evaluate rule text as a shell command.
"""
from collections import Counter
from contextlib import contextmanager
import fcntl
import ipaddress
import json
import os
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import time


@contextmanager
def legacy_transaction():
    """Serialize a complete table operation with cooperating legacy writers.

    Child iptables commands use a separate private lock to avoid deadlocking on
    the lock held by this process. nft ignores --wait and cannot safely use the
    positional restore algorithm, so reject it before snapshotting/applying.
    """
    version = subprocess.run(["iptables", "--version"], check=True,
                             capture_output=True, text=True, timeout=5).stdout.strip()
    if not version.startswith("iptables v") or not version.endswith(" (legacy)"):
        raise ValueError("Exact preservation requires iptables-legacy")
    original = os.environ.get("XTABLES_LOCKFILE")
    path = original or "/run/xtables.lock"
    descriptor = os.open(path, os.O_CREAT | os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ValueError("The xtables lock must be a regular file")
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ValueError("The xtables lock is busy") from None
                time.sleep(0.05)
        current = os.stat(path, follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError("The xtables lock path changed")
        with tempfile.TemporaryDirectory(prefix="range42-xtables-") as directory:
            os.environ["XTABLES_LOCKFILE"] = os.path.join(directory, "child.lock")
            try:
                yield
            finally:
                if original is None:
                    os.environ.pop("XTABLES_LOCKFILE", None)
                else:
                    os.environ["XTABLES_LOCKFILE"] = original
    finally:
        os.close(descriptor)


def iptables(*arguments):
    return subprocess.run(
        ["iptables", "-w", "5", "-t", "nat", *arguments],
        check=True, capture_output=True, text=True, timeout=15,
    ).stdout


def read_table():
    table = iptables("-S", "POSTROUTING")
    if len(table) > 8 * 1024 * 1024:
        raise ValueError("NAT table exceeds audit bound")
    result = []
    for line in table.splitlines():
        if not line.strip():
            continue
        arguments = shlex.split(line)
        if arguments[:2] not in (["-A", "POSTROUTING"], ["-P", "POSTROUTING"]):
            raise ValueError("Unexpected POSTROUTING table entry")
        result.append(arguments)
    return result


def parse_rules(table):
    result = []
    for arguments in table:
        if arguments[:2] != ["-A", "POSTROUTING"]:
            continue
        fields = {}
        negated_source = False
        index = 2
        while index < len(arguments):
            option = arguments[index]
            # These string-valued options can contain text that resembles
            # other options. Treat their entire quoted argument as opaque.
            if option in {"--comment", "--log-prefix", "--nflog-prefix", "--string", "--hex-string"}:
                index += 2
                continue
            key = {"-s": "source", "--source": "source", "-j": "target", "--jump": "target",
                   "-o": "out", "--out-interface": "out"}.get(option)
            if key:
                if index + 1 >= len(arguments) or key in fields:
                    raise ValueError("Ambiguous NAT rule options")
                fields[key] = arguments[index + 1]
                if key == "source" and arguments[index - 1] == "!":
                    negated_source = True
                index += 2
                continue
            index += 1
        if negated_source or not fields.get("source") or fields.get("target") not in {"SNAT", "MASQUERADE"}:
            continue
        source = str(ipaddress.IPv4Network(fields["source"], strict=False))
        result.append({"source": source, "target": fields["target"], "out": fields.get("out", "any"), "argv": arguments})
    return result


def read_rules():
    return parse_rules(read_table())


def preservation_policy(document):
    if not isinstance(document, dict) or set(document) - {"excluded_sources", "allow_new_rules"}:
        raise ValueError("Invalid preservation policy")
    excluded = document.get("excluded_sources", [])
    if not isinstance(excluded, list) or len(excluded) > 64 or not all(isinstance(source, str) for source in excluded):
        raise ValueError("Invalid excluded source list")
    canonical = [str(ipaddress.IPv4Network(source, strict=True)) for source in excluded]
    if canonical != excluded or len(set(canonical)) != len(canonical):
        raise ValueError("Changed sources must be unique canonical IPv4 CIDRs")
    allow_new = document.get("allow_new_rules", False)
    if type(allow_new) is not bool:
        raise ValueError("New rule policy must be explicit")
    return {"excluded_sources": canonical, "allow_new_rules": allow_new}


def read_document():
    document = sys.stdin.read(16 * 1024 * 1024 + 1)
    if len(document) > 16 * 1024 * 1024:
        raise ValueError("Snapshot exceeds audit bound")
    document = json.loads(document)
    if not isinstance(document, dict):
        raise ValueError("Invalid snapshot document")
    return document


def restore_snapshot(document):
    """Delete only appended duplicate NAT identities; preserve old rule positions.

    Scoped changes refuse unknown non-target drift. Explicit standalone apply
    may retain NAT rules for new sources introduced by pending configuration.
    A reviewed snapshot binds the existing sources authorized to change.
    The caller holds the conventional xtables lock through all checks/deletions.
    """
    snapshot = document.get("snapshot")
    if not isinstance(snapshot, dict) or snapshot.get("version") != 1 or snapshot.get("node") != socket.gethostname():
        raise ValueError("Snapshot is invalid or belongs to a different node")
    before = snapshot.get("rules")
    if not isinstance(before, list) or len(before) > 100000 or any(
        not isinstance(row, list) or not all(isinstance(value, str) for value in row)
        or row[:2] not in (["-A", "POSTROUTING"], ["-P", "POSTROUTING"])
        for row in before
    ):
        raise ValueError("Invalid snapshot rule arguments")
    policy = preservation_policy({
        "excluded_sources": document.get("excluded_sources", []),
        "allow_new_rules": document.get("allow_new_rules", False),
    })
    if "reviewed_policy" in snapshot and preservation_policy(snapshot["reviewed_policy"]) != policy:
        raise ValueError("Preservation scope changed after the snapshot")
    excluded = set(policy["excluded_sources"])
    allow_new = policy["allow_new_rules"]

    def protected(table):
        nat = {tuple(rule["argv"]): rule["source"] for rule in parse_rules(table)}
        return [(index, row) for index, row in enumerate(table) if nat.get(tuple(row)) not in excluded]

    original = [row for _, row in protected(before)]
    current = read_table()
    observed = protected(current)
    if [row for _, row in observed[:len(original)]] != original:
        raise ValueError("Non-target rules were removed, reordered or inserted")
    known_nat = {tuple(rule["argv"]) for rule in parse_rules(original)}
    prior_sources = {rule["source"] for rule in parse_rules(before)}
    delete = []
    retained = 0
    for index, row in observed[len(original):]:
        if tuple(row) in known_nat:
            delete.append(index)
        elif allow_new and (rules := parse_rules([row])) and rules[0]["source"] not in prior_sources:
            retained += 1
        else:
            raise ValueError("Unexpected new non-target rule; preserve for operator review")
    if len(delete) > 1000:
        raise ValueError("Deletion limit exceeded")
    for index in reversed(delete):
        if read_table() != current:
            raise ValueError("NAT table changed concurrently; no further cleanup")
        number = sum(row[:2] == ["-A", "POSTROUTING"] for row in current[:index + 1])
        iptables("-D", "POSTROUTING", str(number))
        del current[index]
    if read_table() != current:
        raise ValueError("NAT cleanup readback differs; inspect live state")
    return {"deleted": len(delete), "retained_new_rules": retained,
            "original_non_target_rules": len(original), "preserved": True}


def main(arguments):
    if arguments in (["snapshot"], ["snapshot-reviewed"]):
        policy = preservation_policy(read_document()) if arguments == ["snapshot-reviewed"] else None
        with legacy_transaction():
            table = read_table()
        counts = dict(Counter(rule["source"] for rule in parse_rules(table)))
        snapshot = {"version": 1, "node": socket.gethostname(), "rules": table, "nat_counts": counts}
        if policy is not None:
            snapshot["reviewed_policy"] = policy
        print(json.dumps(snapshot))
        return
    if arguments == ["restore"]:
        document = read_document()
        with legacy_transaction():
            result = restore_snapshot(document)
        print(json.dumps(result))
        return
    if arguments == ["list"]:
        counts = Counter((rule["source"], rule["out"], rule["target"]) for rule in read_rules())
        for (source, out, target), count in sorted(counts.items()):
            print(json.dumps({"snat_source": source, "snat_out_iface": out, "snat_target": target, "snat_count": count}))
        return
    if len(arguments) != 3 or arguments[0] != "reconcile" or arguments[2] not in {"0", "1"}:
        raise ValueError("Expected list or reconcile CIDR 0|1")
    source = str(ipaddress.IPv4Network(arguments[1], strict=True))
    want = int(arguments[2])
    matches = [rule for rule in read_rules() if rule["source"] == source]
    before = len(matches)
    deleted = 0
    while len(matches) > want:
        if deleted >= 1000:
            raise ValueError("Deletion limit exceeded")
        iptables("-D", *matches[0]["argv"][1:])
        updated = [rule for rule in read_rules() if rule["source"] == source]
        if len(updated) >= len(matches):
            raise ValueError("SNAT rule count did not decrease; coordinate concurrent writers")
        deleted += 1
        matches = updated
    # Never create a missing rule. The caller must compare after with want;
    # an enabled subnet with zero live rules remains observably mismatched.
    print(json.dumps({"before": before, "after": len(matches), "want": want, "deleted": deleted}))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"SNAT operation failed ({type(error).__name__}); check inputs and iptables access. Changes may be partial.", file=sys.stderr)
        sys.exit(1)
