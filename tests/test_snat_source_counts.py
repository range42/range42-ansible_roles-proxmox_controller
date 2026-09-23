"""Source inspection is a pure read of complete, current snapshot receipts."""

from copy import deepcopy
import json

import pytest

from test_snat_cluster import invoke, planned, request

SOURCE = "10.1.0.0/24"


def document():
    plan = planned(request())
    return {
        "source": SOURCE,
        "plan": plan,
        "snapshot_verified": True,
        "apply_attempted": False,
        "apply_verified": False,
        "snapshots": {
            node["node"]: {
                "version": 1,
                "node": node["node"],
                "captured_at": 1234567890,
                "nat_counts": {SOURCE: 105 if node["node"] == "pve1" else 3},
            }
            for node in plan["nodes"]
        },
    }


def test_inspection_reports_every_node_without_modifying_snapshots():
    payload = document()
    original = deepcopy(payload)
    result = invoke(payload, "count-source")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "source": SOURCE,
        "primary_node": "pve1",
        "read_only": True,
        "nodes": [
            {"node": "pve1", "count": 105, "captured_at": 1234567890},
            {"node": "pve2", "count": 3, "captured_at": 1234567890},
        ],
    }
    assert payload == original


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "extra",
        "wrong_host",
        "bad_count",
        "negative_count",
        "bool_count",
        "bad_source",
        "stale",
        "attempted",
        "verified_apply",
        "bad_time",
    ],
)
def test_incomplete_or_unverified_source_counts_are_rejected(fault):
    payload = document()
    if fault == "missing":
        payload["snapshots"].pop("pve2")
    elif fault == "extra":
        payload["snapshots"]["pve3"] = payload["snapshots"]["pve1"]
    elif fault == "wrong_host":
        payload["snapshots"]["pve2"]["node"] = "other"
    elif fault in ["bad_count", "negative_count", "bool_count"]:
        payload["snapshots"]["pve1"]["nat_counts"][SOURCE] = {
            "bad_count": "3",
            "negative_count": -1,
            "bool_count": True,
        }[fault]
    elif fault == "bad_source":
        payload["source"] = "10.1.0.1/24"
    elif fault == "stale":
        payload["snapshot_verified"] = False
    elif fault == "attempted":
        payload["apply_attempted"] = True
    elif fault == "verified_apply":
        payload["apply_verified"] = True
    elif fault == "bad_time":
        payload["snapshots"]["pve2"]["captured_at"] = 0
    assert invoke(payload, "count-source").returncode != 0
