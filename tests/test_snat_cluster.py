"""Pure planning rejects incomplete coverage before any remote command."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

HELPER = (
    Path(__file__).resolve().parents[1]
    / "roles/range42-ansible_roles-proxmox_controller/files/snat_cluster.py"
)


def request():
    return {
        "status": [
            {"type": "node", "name": "pve1", "online": 1},
            {"type": "node", "name": "pve2", "online": 1},
            {"type": "cluster", "name": "fixture", "nodes": 2, "quorate": 1},
        ],
        "primary_node": "pve1",
        "node_hosts": {"pve1": "ssh1", "pve2": "ssh2"},
        "cli_hosts": ["ssh1", "ssh2"],
        "zones": [{"zone": "lab", "type": "simple", "nodes": "pve1"}],
        "desired_sources": [
            {"source": "10.1.0.0/24", "vnet": "net1", "zone": "lab", "want": 1}
        ],
        "known_subnets": [],
        "new_zones": {},
        "policy": {"excluded_sources": [], "allow_new_rules": False},
    }


def invoke(document, operation="plan"):
    return subprocess.run(
        [sys.executable, str(HELPER), operation],
        input=json.dumps(document),
        capture_output=True,
        text=True,
        timeout=5,
    )


def planned(document):
    result = invoke(document)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_every_cluster_node_is_covered_but_only_zone_members_reconcile():
    plan = planned(request())
    assert [(node["node"], node["host"]) for node in plan["nodes"]] == [
        ("pve1", "ssh1"),
        ("pve2", "ssh2"),
    ]
    assert plan["nodes"][0]["targets"] == [{"source": "10.1.0.0/24", "want": 1}]
    assert plan["nodes"][0]["policy"]["excluded_sources"] == ["10.1.0.0/24"]
    assert plan["nodes"][1]["targets"] == []
    assert plan["nodes"][1]["policy"]["excluded_sources"] == []


def test_single_node_uses_the_existing_single_cli_host_by_default():
    document = request()
    document.update(status=document["status"][:1], cli_hosts=["ssh1"], node_hosts=None)
    assert planned(document)["nodes"][0]["host"] == "ssh1"


@pytest.mark.parametrize(
    "mutation",
    [
        "missing",
        "extra",
        "duplicate_host",
        "unknown_host",
        "offline",
        "duplicate_node",
        "wrong_primary",
        "empty",
        "invalid_status",
        "no_quorum",
    ],
)
def test_incomplete_or_ambiguous_cluster_coverage_is_rejected(mutation):
    document = request()
    if mutation == "missing":
        del document["node_hosts"]["pve2"]
    if mutation == "extra":
        document["node_hosts"]["pve3"] = "ssh3"
    if mutation == "duplicate_host":
        document["node_hosts"]["pve2"] = "ssh1"
    if mutation == "unknown_host":
        document["node_hosts"]["pve2"] = "unlisted"
    if mutation == "offline":
        document["status"][1]["online"] = 0
    if mutation == "duplicate_node":
        document["status"].append(document["status"][0])
    if mutation == "wrong_primary":
        document["primary_node"] = "other"
    if mutation == "empty":
        document["status"] = []
    if mutation == "invalid_status":
        document["status"] = {"error": "permission denied"}
    if mutation == "no_quorum":
        document["status"][-1]["quorate"] = 0
    assert invoke(document).returncode != 0


def test_zone_without_node_restriction_targets_every_node():
    document = request()
    del document["zones"][0]["nodes"]
    plan = planned(document)
    assert all(
        node["targets"] == [{"source": "10.1.0.0/24", "want": 1}]
        for node in plan["nodes"]
    )


def test_new_zone_defaults_to_all_nodes_but_honors_explicit_creation_members():
    document = request()
    document.update(zones=[], new_zones={"lab": None})
    assert all(node["targets"] for node in planned(document)["nodes"])
    document["new_zones"]["lab"] = "pve2"
    plan = planned(document)
    assert not plan["nodes"][0]["targets"] and plan["nodes"][1]["targets"]


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown_zone",
        "unknown_member",
        "unsupported_type",
        "duplicate_cidr",
        "ambiguous_vnet",
        "invalid_want",
    ],
)
def test_scope_cannot_guess_zone_membership_or_ambiguous_nat_sources(mutation):
    document = request()
    if mutation == "unknown_zone":
        document["zones"] = []
    if mutation == "unknown_member":
        document["zones"][0]["nodes"] = "pve3"
    if mutation == "unsupported_type":
        document["zones"][0]["type"] = "evpn"
    if mutation == "duplicate_cidr":
        document["desired_sources"].append(document["desired_sources"][0])
    if mutation == "ambiguous_vnet":
        document["known_subnets"] = [
            {"subnet_cidr": "10.1.0.0/24", "subnet_vnet": "othernet"}
        ]
    if mutation == "invalid_want":
        document["desired_sources"][0]["want"] = 2
    assert invoke(document).returncode != 0


def test_explicit_apply_review_policy_applies_to_each_covered_node():
    document = request()
    document["desired_sources"] = []
    document["policy"] = {"excluded_sources": ["10.8.0.0/24"], "allow_new_rules": True}
    assert all(
        node["policy"] == document["policy"] for node in planned(document)["nodes"]
    )


def test_changed_cluster_membership_invalidates_an_existing_plan():
    before = planned(request())
    after = deepcopy(before)
    after["nodes"].pop()
    assert invoke({"before": before, "after": after}, "verify").returncode != 0


def test_collect_requires_every_snapshot_to_match_its_mapped_node_and_review_policy():
    plan = planned(request())
    results = [
        {
            "node": node["node"],
            "rc": 0,
            "stdout": json.dumps(
                {
                    "version": 1,
                    "node": node["node"],
                    "reviewed_policy": node["policy"],
                    "rules": [],
                    "nat_counts": {},
                    "captured_at": 1234567890,
                }
            ),
        }
        for node in plan["nodes"]
    ]
    result = invoke({"plan": plan, "results": results}, "collect")
    assert result.returncode == 0, result.stderr
    assert set(json.loads(result.stdout)) == {"pve1", "pve2"}
    results[1]["stdout"] = results[0]["stdout"]
    assert invoke({"plan": plan, "results": results}, "collect").returncode != 0


def task(node="pve1", pid="123", *, finished=True, status="OK"):
    result = {
        "upid": f"UPID:{node}:{pid}:1:499602D2:srvreload:networking:root@pam:",
        "type": "srvreload",
        "id": "networking",
        "node": node,
        "starttime": 1234567890,
    }
    if finished:
        result.update(endtime=1234567891, status=status)
    return result


def test_reload_baseline_refuses_active_network_workers():
    result = invoke({"node": "pve1", "rows": [task()]}, "reload-baseline")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["upids"] == [task()["upid"]]
    assert (
        invoke(
            {"node": "pve1", "rows": [task(finished=False)]}, "reload-baseline"
        ).returncode
        != 0
    )


def test_completion_waits_for_one_new_node_worker_instead_of_accepting_old_success():
    old = task()
    document = {"node": "pve1", "known": [old["upid"]], "rows": [old]}
    result = invoke(document, "reload-completion")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["ready"] is False
    document["rows"].append(task(pid="456", finished=False))
    result = invoke(document, "reload-completion")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["ready"] is False
    document["rows"][-1] = task(pid="456")
    assert json.loads(invoke(document, "reload-completion").stdout)["ready"] is True


@pytest.mark.parametrize(
    "rows",
    [
        [task(status="ERROR")],
        [task(node="other")],
        [task(), task(pid="456")],
        [{"id": "networking"}],
    ],
)
def test_failed_wrong_node_ambiguous_or_malformed_worker_does_not_prove_completion(
    rows,
):
    assert (
        invoke(
            {"node": "pve1", "known": [], "rows": rows}, "reload-completion"
        ).returncode
        != 0
    )


INVALID_CLUSTER_ROWS = [
    [],
    [{"type": "cluster", "nodes": 2}],
    [{"type": "cluster", "nodes": 2, "quorate": 1}] * 2,
    [{"type": "cluster", "nodes": 2, "quorate": 0}],
    [{"type": "cluster", "nodes": 2, "quorate": 1.0}],
    [{"type": "cluster", "nodes": 2.0, "quorate": 1}],
    [{"type": "cluster", "nodes": 3, "quorate": 1}],
]


@pytest.mark.parametrize(
    "cluster_rows",
    INVALID_CLUSTER_ROWS,
    ids=[
        "missing",
        "incomplete",
        "duplicate",
        "nonquorate",
        "float-quorum",
        "float-nodes",
        "wrong-count",
    ],
)
def test_multiple_nodes_require_one_usable_quorum_record(cluster_rows):
    document = request()
    document["status"] = document["status"][:2] + cluster_rows
    assert invoke(document).returncode != 0
