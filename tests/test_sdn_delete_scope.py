"""Deletion planning must prove complete scope before any declaration write."""

from copy import deepcopy
import json

import pytest

from test_snat_cluster import invoke


def document():
    return {
        "zone": "lab",
        "status": [
            {"type": "node", "name": "pve1", "online": 1},
            {"type": "node", "name": "pve2", "online": 1},
            {"type": "cluster", "name": "test", "nodes": 2, "quorate": 1},
        ],
        "features": ["zones", "vnets", "controllers", "ipams", "dns"],
        "families": {
            "zones": [
                {
                    "zone": "lab",
                    "type": "simple",
                    "nodes": "pve1",
                    "state": "unchanged",
                },
                {"zone": "external", "type": "simple", "state": "unchanged"},
            ],
            "vnets": [
                {"vnet": "target", "zone": "lab", "state": "unchanged"},
                {"vnet": "outside", "zone": "external", "state": "unchanged"},
            ],
            "controllers": [],
            "ipams": [],
            "dns": [],
        },
        "subnets": {
            "target": [
                {
                    "subnet": "lab-10.42.70.0-24",
                    "cidr": "10.42.70.0/24",
                    "state": "unchanged",
                }
            ],
            "outside": [
                {
                    "subnet": "external-10.42.80.0-24",
                    "cidr": "10.42.80.0/24",
                    "state": "unchanged",
                }
            ],
        },
        "guests": [{"vmid": 100, "type": "qemu", "node": "pve2"}],
        "guest_configs": {
            "qemu/100": {
                "current": {"net0": "virtio=AA:BB:CC:DD:EE:FF,bridge=outside"},
                "pending": [
                    {"key": "net0", "value": "virtio=AA:BB:CC:DD:EE:FF,bridge=outside"}
                ],
            }
        },
    }


def test_delete_retains_exact_source_membership_and_all_zone_objects():
    request = document()
    original = deepcopy(request)
    result = invoke(request, "delete-scope")
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan["zone"] == "lab"
    assert plan["zone_nodes"] == ["pve1"]
    assert plan["vnets"] == ["target"]
    assert plan["subnets"] == [
        {
            "subnet": "lab-10.42.70.0-24",
            "subnet_vnet": "target",
            "subnet_cidr": "10.42.70.0/24",
        }
    ]
    assert plan["desired_sources"] == [
        {"source": "10.42.70.0/24", "vnet": "target", "zone": "lab", "want": 0}
    ]
    assert plan["zone_present"] is True
    assert len(plan["inventory_sha256"]) == 64
    assert "guest_configs" not in plan
    assert request == original


@pytest.mark.parametrize(
    "fault",
    [
        "missing_cidr",
        "noncanonical",
        "missing_zone",
        "missing_vnet",
        "ambiguous_source",
        "duplicate_vnet",
        "unknown_member",
        "incomplete_subnets",
        "pending_external",
        "pending_selected",
        "unknown_feature",
        "incomplete_family",
        "missing_guest",
        "pending_guest",
        "attached_qemu",
        "attached_lxc",
        "bad_nic",
        "missing_quorum",
        "missing_pending",
        "unknown_guest_node",
        "outside_missing_cidr",
        "outside_noncanonical",
        "custom_qemu",
        "raw_lxc",
        "duplicate_bridge",
    ],
)
def test_unproven_scope_or_attachments_refuse_before_deletion(fault):
    request = document()
    if fault == "missing_cidr":
        request["subnets"]["target"][0].pop("cidr")
    elif fault == "noncanonical":
        request["subnets"]["target"][0]["cidr"] = "10.42.70.1/24"
    elif fault == "missing_zone":
        request["families"]["vnets"][0].pop("zone")
    elif fault == "missing_vnet":
        request["families"]["vnets"].pop(0)
    elif fault == "ambiguous_source":
        request["subnets"]["outside"][0]["cidr"] = "10.42.70.0/24"
    elif fault == "duplicate_vnet":
        request["families"]["vnets"].append(request["families"]["vnets"][0])
    elif fault == "unknown_member":
        request["families"]["zones"][0]["nodes"] = "other"
    elif fault == "incomplete_subnets":
        request["subnets"].pop("outside")
    elif fault == "pending_external":
        request["families"]["controllers"] = [
            {"controller": "ext", "pending": {"asn": 12}}
        ]
    elif fault == "pending_selected":
        request["subnets"]["target"][0]["state"] = "deleted"
    elif fault == "unknown_feature":
        request["features"].append("new-family")
    elif fault == "incomplete_family":
        request["families"].pop("controllers")
    elif fault == "missing_guest":
        request["guest_configs"].clear()
    elif fault == "pending_guest":
        request["guest_configs"]["qemu/100"]["pending"][0]["pending"] = (
            "virtio=AA:BB:CC:DD:EE:FF,bridge=target"
        )
    elif fault == "attached_qemu":
        request["guest_configs"]["qemu/100"]["current"]["net0"] = (
            "virtio=AA:BB:CC:DD:EE:FF,bridge=target"
        )
    elif fault == "attached_lxc":
        request["guests"][0]["type"] = "lxc"
        request["guest_configs"] = {
            "lxc/100": {
                "current": {"net0": "name=eth0,bridge=target,ip=dhcp"},
                "pending": [],
            }
        }
    elif fault == "bad_nic":
        request["guest_configs"]["qemu/100"]["current"]["net0"] = {"bridge": "target"}
    elif fault == "missing_quorum":
        request["status"].pop()
    elif fault == "missing_pending":
        request["guest_configs"]["qemu/100"].pop("pending")
    elif fault == "outside_missing_cidr":
        request["subnets"]["outside"][0].pop("cidr")
    elif fault == "outside_noncanonical":
        request["subnets"]["outside"][0]["cidr"] = "10.42.70.1/24"
    elif fault == "unknown_guest_node":
        request["guests"][0]["node"] = "hidden"
    elif fault == "custom_qemu":
        request["guest_configs"]["qemu/100"]["current"]["args"] = (
            "-netdev bridge,br=target,id=n1"
        )
    elif fault == "raw_lxc":
        request["guest_configs"]["qemu/100"]["current"]["lxc.net.0.link"] = "target"
    elif fault == "duplicate_bridge":
        request["guest_configs"]["qemu/100"]["current"]["net0"] = (
            "bridge=outside,bridge=target"
        )
    assert invoke(request, "delete-scope").returncode != 0


def test_absent_zone_is_observed_without_inventing_orphan_scope():
    request = document()
    request["zone"] = "absent"
    result = invoke(request, "delete-scope")
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan["zone_present"] is False
    assert plan["desired_sources"] == plan["vnets"] == plan["subnets"] == []


def test_retained_expected_inventory_hash_verifies_only_selected_deletions():
    before = document()
    result = invoke(before, "delete-scope")
    assert result.returncode == 0
    scope = json.loads(result.stdout)
    after = deepcopy(before)
    after["families"]["zones"].pop(0)
    after["families"]["vnets"].pop(0)
    after["subnets"].pop("target")
    after["families"]["zones"][0]["digest"] = "fresh-global-digest"
    observed = json.loads(invoke(after, "delete-scope").stdout)
    assert observed["inventory_sha256"] == scope["remaining_sha256"]
    after["families"]["zones"][0]["mtu"] = 1234
    changed = json.loads(invoke(after, "delete-scope").stdout)
    assert changed["inventory_sha256"] != scope["remaining_sha256"]


@pytest.mark.parametrize("zone", ["x", "bad-zone", "bad_zone", "123", "toolongid"])
def test_zone_names_follow_proxmox_contract(zone):
    request = document()
    request["zone"] = zone
    assert invoke(request, "delete-scope").returncode != 0


def test_reordered_api_rows_preserve_identical_deletion_scope():
    before = document()
    before["subnets"]["target"].append(
        {"subnet": "lab-10.42.71.0-24", "cidr": "10.42.71.0/24", "state": "unchanged"}
    )
    before["families"]["vnets"].append(
        {"vnet": "another", "zone": "lab", "state": "unchanged"}
    )
    before["subnets"]["another"] = [
        {"subnet": "lab-10.42.72.0-24", "cidr": "10.42.72.0/24", "state": "unchanged"}
    ]
    shuffled = deepcopy(before)
    shuffled["families"]["vnets"].reverse()
    shuffled["families"]["zones"].reverse()
    shuffled["subnets"]["target"].reverse()
    assert json.loads(invoke(before, "delete-scope").stdout) == json.loads(
        invoke(shuffled, "delete-scope").stdout
    )


@pytest.mark.parametrize(
    "fault",
    [
        "duplicate_key",
        "bad_key",
        "unknown_property",
        "bad_delete",
        "bool_delete",
        "empty_qemu",
        "key_only",
    ],
)
def test_malformed_complete_pending_configuration_is_rejected(fault):
    request = document()
    pending = request["guest_configs"]["qemu/100"]["pending"]
    if fault == "duplicate_key":
        pending.append(dict(pending[0]))
    elif fault == "bad_key":
        pending[0]["key"] = "net0,bridge=target"
    elif fault == "unknown_property":
        pending[0]["new_unreadable"] = "target"
    elif fault == "bad_delete":
        pending[0]["delete"] = "1"
    elif fault == "bool_delete":
        pending[0]["delete"] = True
    elif fault == "empty_qemu":
        pending.clear()
    elif fault == "key_only":
        pending[0] = {"key": "net0"}
    assert invoke(request, "delete-scope").returncode != 0


def test_delete_only_pending_row_is_valid():
    request = document()
    request["guest_configs"]["qemu/100"]["pending"].append(
        {"key": "net1", "delete": 1}
    )
    result = invoke(request, "delete-scope")
    assert result.returncode == 0, result.stderr
