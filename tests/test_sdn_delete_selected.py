"""Selected VNet deletion must retain its shared zone and unrelated users."""

from copy import deepcopy
import json

import pytest

from test_sdn_delete_scope import document
from test_snat_cluster import invoke


def selected_document():
    request = document()
    request["vnets"] = ["target"]
    request["families"]["vnets"].append(
        {"vnet": "shared", "zone": "lab", "state": "unchanged"}
    )
    request["subnets"]["shared"] = [
        {"subnet": "opaque-shared-id", "cidr": "10.42.90.0/24", "state": "unchanged"}
    ]
    request["guest_configs"]["qemu/100"]["current"]["net0"] = "bridge=shared"
    request["guest_configs"]["qemu/100"]["pending"][0]["value"] = "bridge=shared"
    return request


def test_selected_scope_preserves_shared_zone_other_vnet_and_its_guest():
    request = selected_document()
    outcome = invoke(request, "delete-scope")
    assert outcome.returncode == 0, outcome.stderr
    scope = json.loads(outcome.stdout)
    assert scope["selection"] == "vnets"
    assert scope["requested_vnets"] == ["target"]
    assert scope["vnets"] == ["target"]
    assert scope["objects_present"] is True
    assert scope["desired_sources"] == [
        {"source": "10.42.70.0/24", "vnet": "target", "zone": "lab", "want": 0}
    ]
    after = deepcopy(request)
    after["families"]["vnets"] = [
        row for row in after["families"]["vnets"] if row["vnet"] != "target"
    ]
    del after["subnets"]["target"]
    repeated = invoke(after, "delete-scope")
    assert repeated.returncode == 0, repeated.stderr
    remaining = json.loads(repeated.stdout)
    assert remaining["zone_present"] is True
    assert remaining["objects_present"] is False
    assert remaining["desired_sources"] == []
    assert remaining["inventory_sha256"] == scope["remaining_sha256"]


@pytest.mark.parametrize(
    "selection",
    [
        [],
        "target",
        True,
        ["target", "target"],
        ["outside"],
        ["bad/name"],
        ["net" + str(i) for i in range(65)],
    ],
)
def test_selected_scope_rejects_malformed_or_foreign_zone_selection(selection):
    request = document()
    request["vnets"] = selection
    assert invoke(request, "delete-scope").returncode != 0


def test_absent_selected_vnet_does_not_authorize_existing_zone_or_guessed_sources():
    request = document()
    request["vnets"] = ["absent"]
    result = invoke(request, "delete-scope")
    assert result.returncode == 0, result.stderr
    scope = json.loads(result.stdout)
    assert scope["vnets"] == []
    assert scope["absent_vnets"] == ["absent"]
    assert scope["desired_sources"] == []
    assert scope["remaining_sha256"] == scope["inventory_sha256"]


def test_selected_sources_come_from_cidr_not_subnet_identifier():
    request = document()
    request["vnets"] = ["target"]
    request["subnets"]["target"][0]["subnet"] = "opaque-subnet-name"
    result = invoke(request, "delete-scope")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["desired_sources"][0]["source"] == "10.42.70.0/24"
    del request["subnets"]["target"][0]["cidr"]
    assert invoke(request, "delete-scope").returncode != 0
