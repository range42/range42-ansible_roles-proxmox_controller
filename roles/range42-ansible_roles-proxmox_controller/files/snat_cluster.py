"""Bounded, read-only planning for cluster-wide NAT preservation."""

import ipaddress
import json
import re
import sys


def cidrs(values):
    if (
        not isinstance(values, list)
        or len(values) > 64
        or not all(isinstance(value, str) for value in values)
    ):
        raise ValueError("Expected at most 64 canonical source CIDRs")
    if len(set(values)) != len(values) or any(
        str(ipaddress.IPv4Network(value, strict=True)) != value for value in values
    ):
        raise ValueError("Source CIDRs must be unique and canonical")
    return values


def members(value, nodes):
    if value is None or value == "" or value == []:
        return set(nodes)
    selected = value.split(",") if isinstance(value, str) else value
    if (
        not isinstance(selected, list)
        or not selected
        or any(not isinstance(node, str) for node in selected)
    ):
        raise ValueError("Invalid zone node list")
    if len(set(selected)) != len(selected) or not set(selected) <= set(nodes):
        raise ValueError("Zone membership is not covered by this cluster")
    return set(selected)


def cluster_nodes(status):
    if (
        not isinstance(status, list)
        or not 1 <= len(status) <= 65
        or any(not isinstance(row, dict) for row in status)
    ):
        raise ValueError("Cannot establish complete cluster membership")
    if any(row.get("type") not in {"node", "cluster"} for row in status):
        raise ValueError("Unknown cluster status record")
    rows = [row for row in status if row["type"] == "node"]
    nodes = [row.get("name") for row in rows]
    if (
        not nodes
        or len(nodes) > 64
        or any(
            not isinstance(node, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", node)
            for node in nodes
        )
    ):
        raise ValueError("Invalid cluster node identities")
    if len(nodes) != len(set(nodes)) or any(
        type(row.get("online")) not in (int, bool) or row["online"] != 1 for row in rows
    ):
        raise ValueError("Every cluster node must be online exactly once")
    clusters = [row for row in status if row["type"] == "cluster"]
    if len(clusters) > 1 or any(
        row.get("quorate") != 1 or row.get("nodes") != len(nodes) for row in clusters
    ):
        raise ValueError("Cluster membership or quorum is incomplete")
    return nodes, clusters


def plan(document):
    nodes, clusters = cluster_nodes(document.get("status"))
    primary = document.get("primary_node")
    if primary not in nodes:
        raise ValueError("The requested node is not a member of this cluster")
    hosts = document.get("cli_hosts")
    if not isinstance(hosts, list) or any(not isinstance(host, str) for host in hosts):
        raise ValueError("Explicit proxmox_cli inventory hosts are required")
    mapping = document.get("node_hosts")
    if mapping is None or mapping == {}:
        mapping = {primary: hosts[0]} if len(nodes) == len(hosts) == 1 else {}
    if not isinstance(mapping, dict) or set(mapping) != set(nodes):
        raise ValueError("Map every cluster node to an explicit SSH inventory host")
    if any(
        not isinstance(host, str) or not host or host not in hosts
        for host in mapping.values()
    ) or len(set(mapping.values())) != len(nodes):
        raise ValueError("Each cluster node needs its own listed SSH inventory host")

    zones = document.get("zones", [])
    new_zones = document.get("new_zones", {})
    desired = document.get("desired_sources", [])
    known = document.get("known_subnets", [])
    if (
        not isinstance(zones, list)
        or any(not isinstance(zone, dict) for zone in zones)
        or not isinstance(new_zones, dict)
    ):
        raise ValueError("Invalid zone inventory")
    if (
        not isinstance(desired, list)
        or len(desired) > 64
        or any(not isinstance(target, dict) for target in desired)
    ):
        raise ValueError("Invalid desired source list")
    if not isinstance(known, list) or any(not isinstance(row, dict) for row in known):
        raise ValueError("Invalid existing subnet inventory")
    cidrs([target.get("source") for target in desired])
    policy = document.get("policy", {})
    if (
        not isinstance(policy, dict)
        or type(policy.get("allow_new_rules", False)) is not bool
    ):
        raise ValueError("Invalid preservation policy")
    excluded = cidrs(policy.get("excluded_sources", []))
    result = {
        node: {
            "node": node,
            "host": mapping[node],
            "targets": [],
            "policy": {
                "excluded_sources": list(excluded),
                "allow_new_rules": policy.get("allow_new_rules", False),
            },
        }
        for node in sorted(nodes)
    }
    for target in desired:
        source, zone = target["source"], target.get("zone")
        if (
            type(target.get("want")) is not int
            or target["want"] not in (0, 1)
            or not isinstance(target.get("vnet"), str)
        ):
            raise ValueError(
                "Each target needs a concrete VNet and strict desired state 0 or 1"
            )
        matches = [row for row in zones if row.get("zone") == zone]
        if len(matches) == 1:
            if matches[0].get("type") != "simple":
                raise ValueError(
                    "Scoped source reconciliation currently supports simple zones only"
                )
            selected = members(matches[0].get("nodes"), nodes)
        elif not matches and isinstance(zone, str) and zone in new_zones:
            selected = members(new_zones[zone], nodes)
        else:
            raise ValueError("Cannot establish the source zone's node membership")
        if any(
            row.get("subnet_cidr") == source
            and row.get("subnet_vnet") != target["vnet"]
            for row in known
        ):
            raise ValueError(
                "The source CIDR is shared with another VNet; its NAT rules are ambiguous"
            )
        for node in selected:
            result[node]["targets"].append({"source": source, "want": target["want"]})
            result[node]["policy"]["excluded_sources"] = sorted(
                set(result[node]["policy"]["excluded_sources"] + [source])
            )
    return {
        "version": 1,
        "primary_node": primary,
        "nodes": list(result.values()),
        "cluster": [
            {key: row.get(key) for key in ("name", "version", "nodes")}
            for row in clusters
        ],
    }


def zone_nodes(document):
    """Validate the requested membership and encode Proxmox's pve-node-list."""
    nodes, _ = cluster_nodes(document.get("status"))
    selected = members(document.get("requested"), nodes)
    saved, intent = document.get("plan"), document.get("intent")
    verified = document.get("snapshot_verified")
    if saved is not None or intent is not None or verified is not None:
        if (
            verified is not True
            or not isinstance(saved, dict)
            or not isinstance(intent, dict)
            or not isinstance(saved.get("nodes"), list)
            or any(not isinstance(node, dict) for node in saved["nodes"])
            or sorted(node.get("node", "") for node in saved["nodes"]) != sorted(nodes)
            or not isinstance(intent.get("new_zones"), dict)
            or document.get("zone") not in intent["new_zones"]
        ):
            raise ValueError(
                "Zone creation requires its current verified snapshot membership"
            )
        if selected != members(intent["new_zones"][document["zone"]], nodes):
            raise ValueError("Zone membership changed after snapshot")
    return {"nodes": None if selected == set(nodes) else ",".join(sorted(selected))}


def collect(document):
    expected = {node["node"]: node for node in document["plan"]["nodes"]}
    results = document.get("results")
    if not isinstance(results, list) or len(results) != len(expected):
        raise ValueError("Every mapped node requires a successful snapshot")
    snapshots = {}
    for result in results:
        node = result.get("node")
        if node not in expected or node in snapshots or result.get("rc") != 0:
            raise ValueError("A mapped node did not return a successful snapshot")
        snapshot = json.loads(result["stdout"])
        if (
            not isinstance(snapshot, dict)
            or snapshot.get("version") != 1
            or not isinstance(snapshot.get("node"), str)
        ):
            raise ValueError("Invalid node snapshot")
        if snapshot["node"] != node and snapshot["node"].split(".")[0] != node:
            raise ValueError("The SSH host does not match its mapped Proxmox node")
        if (
            snapshot.get("reviewed_policy") != expected[node]["policy"]
            or not isinstance(snapshot.get("rules"), list)
            or not isinstance(snapshot.get("nat_counts"), dict)
        ):
            raise ValueError(
                "The node did not validate the required preservation policy"
            )
        if type(snapshot.get("captured_at")) is not int or snapshot["captured_at"] <= 0:
            raise ValueError(
                "The snapshot does not provide a node-local observation time"
            )
        snapshots[node] = snapshot
    return snapshots


def reloads(document, *, baseline):
    rows, node = document.get("rows"), document.get("node")
    if (
        not isinstance(rows, list)
        or len(rows) > 128
        or any(not isinstance(row, dict) for row in rows)
    ):
        raise ValueError("Cannot establish bounded node reload history")
    tasks = []
    for row in rows:
        if row.get("id") != "networking":
            continue
        fields = row.get("upid", "").split(":")
        if (
            len(fields) != 9
            or fields[:2] != ["UPID", node]
            or fields[5:7] != ["srvreload", "networking"]
            or row.get("type") != "srvreload"
            or row.get("node") != node
        ):
            raise ValueError("Network reload task identity does not match the node")
        if any(not re.fullmatch(r"[0-9A-Fa-f]+", value) for value in fields[2:5]):
            raise ValueError("Invalid network reload task identity")
        finished = type(row.get("endtime")) is int and row["endtime"] > 0
        if baseline and not finished:
            raise ValueError(
                "A network reload is already active; no SDN write is authorized"
            )
        tasks.append((row, finished))
    if len({row["upid"] for row, _ in tasks}) != len(tasks):
        raise ValueError("Duplicate network reload task identities")
    if baseline:
        return {"upids": [row["upid"] for row, _ in tasks]}
    known = document.get("known")
    if not isinstance(known, list) or any(
        not isinstance(value, str) for value in known
    ):
        raise ValueError("A reload baseline is required")
    fresh = [(row, finished) for row, finished in tasks if row["upid"] not in known]
    if len(fresh) > 1:
        raise ValueError("Concurrent network reloads are ambiguous; inspect the node")
    if not fresh or not fresh[0][1]:
        return {"ready": False}
    if fresh[0][0].get("status") != "OK":
        raise ValueError("The node network reload failed; preservation must not run")
    return {"ready": True, "upid": fresh[0][0]["upid"]}


def main():
    raw = sys.stdin.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError("Cluster planning input exceeds the bound")
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise ValueError("Invalid cluster planning input")
    if sys.argv[1:] == ["plan"]:
        result = plan(document)
    elif sys.argv[1:] == ["zone-nodes"]:
        result = zone_nodes(document)
    elif sys.argv[1:] == ["collect"]:
        result = collect(document)
    elif sys.argv[1:] in (["reload-baseline"], ["reload-completion"]):
        result = reloads(document, baseline=sys.argv[1] == "reload-baseline")
    elif sys.argv[1:] == ["verify"]:
        before, after = document.get("before"), document.get("after")
        if not isinstance(before, dict) or before != after:
            raise ValueError("Cluster membership, SSH mapping or target scope changed")
        result = {"verified": True}
    else:
        raise ValueError("Unknown cluster planning operation")
    print(json.dumps(result))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError) as error:
        print(f"SNAT coverage failed: {error}", file=sys.stderr)
        sys.exit(1)
