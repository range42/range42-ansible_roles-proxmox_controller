"""Bounded, read-only planning for cluster-wide NAT preservation."""

from contextlib import ExitStack
import hashlib
import ipaddress
import json
import os
import re
import resource
import signal
import subprocess
import tempfile
import time
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
    if (
        len(clusters) > 1
        or (len(nodes) > 1 and len(clusters) != 1)
        or any(
            type(row.get("quorate")) not in (int, bool)
            or row["quorate"] != 1
            or type(row.get("nodes")) is not int
            or row["nodes"] != len(nodes)
            for row in clusters
        )
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


def certificate_identity(certificates):
    if not isinstance(certificates, list) or any(
        not isinstance(row, dict) for row in certificates
    ):
        raise ValueError("Cluster CA certificate inventory is unreadable")
    matches = [row for row in certificates if row.get("filename") == "pve-root-ca.pem"]
    fingerprint = matches[0].get("fingerprint") if len(matches) == 1 else None
    if not isinstance(fingerprint, str) or not re.fullmatch(
        r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){31}", fingerprint
    ):
        raise ValueError("Exactly one SHA256 cluster CA fingerprint is required")
    return "pve-root-ca-sha256:" + fingerprint.replace(":", "").lower()


def read_delete(document):
    """Use a verified privileged node to avoid ACL-filtered inventory omissions."""
    deadline = time.monotonic() + 120
    total_output = 0

    def commands(arguments):
        """Run one or two reads from this thread, retaining child identity until cleanup."""
        nonlocal total_output
        if not 1 <= len(arguments) <= 2:
            raise ValueError("Deletion inventory batches contain at most two reads")

        def limit_output():
            resource.setrlimit(
                resource.RLIMIT_FSIZE, (4 * 1024 * 1024, 4 * 1024 * 1024)
            )

        with ExitStack() as files:
            running = []
            try:
                for argv in arguments:
                    started = time.monotonic()
                    if started >= deadline:
                        raise ValueError(
                            "Deletion inventory exceeded its overall read deadline"
                        )
                    output = files.enter_context(tempfile.TemporaryFile())
                    process = subprocess.Popen(
                        argv,
                        stdout=output,
                        stderr=subprocess.DEVNULL,
                        preexec_fn=limit_output,
                        start_new_session=True,
                    )
                    running.append(
                        {
                            "process": process,
                            "output": output,
                            "deadline": min(deadline, started + 10),
                            "finished": False,
                        }
                    )
                while not all(entry["finished"] for entry in running):
                    for entry in running:
                        if entry["finished"]:
                            continue
                        if time.monotonic() >= entry["deadline"]:
                            raise ValueError("Deletion inventory command timed out")
                        # WNOWAIT keeps even an exited leader unreaped. Its PID
                        # cannot be reused before we stop its entire process group.
                        status = os.waitid(
                            os.P_PID,
                            entry["process"].pid,
                            os.WEXITED | os.WNOHANG | os.WNOWAIT,
                        )
                        if status is not None:
                            if status.si_code != os.CLD_EXITED or status.si_status != 0:
                                raise ValueError("Deletion inventory read failed")
                            entry["finished"] = True
                    if not all(entry["finished"] for entry in running):
                        time.sleep(0.01)
                result = []
                for entry in running:
                    entry["output"].seek(0)
                    raw = entry["output"].read(4 * 1024 * 1024 + 1)
                    if len(raw) > 4 * 1024 * 1024:
                        raise ValueError("Deletion inventory output is too large")
                    total_output += len(raw)
                    if total_output > 16 * 1024 * 1024:
                        raise ValueError(
                            "Deletion inventory exceeded its aggregate output limit"
                        )
                    result.append(raw.decode("utf-8"))
                return result
            except OSError as exc:
                raise ValueError("Deletion inventory command is unavailable") from exc
            finally:
                # Failure of either read stops both siblings and descendants;
                # successful commands must not leave background read children.
                for entry in running:
                    try:
                        os.killpg(entry["process"].pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                for entry in running:
                    entry["process"].wait()

    def command(argv):
        return commands([argv])[0]

    def decode(raw):
        def unique_object(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("Duplicate JSON keys in deletion inventory")
                value[key] = item
            return value

        def invalid_constant(_value):
            raise ValueError("Invalid JSON constant in deletion inventory")

        return json.loads(
            raw, object_pairs_hook=unique_object, parse_constant=invalid_constant
        )

    node = document.get("node")
    if not isinstance(node, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", node
    ):
        raise ValueError("A mapped cluster node is required for deletion inventory")
    if (
        command(["id", "-u"]).strip() != "0"
        or command(["hostname", "-s"]).strip() != node
    ):
        raise ValueError("Deletion inventory requires root on the exact mapped node")

    def get(path, *options):
        return decode(
            command(["pvesh", "get", path, *options, "--output-format", "json"])
        )

    def settled(value):
        if (
            not isinstance(value, list)
            or len(value) > 4096
            or any(not isinstance(row, dict) for row in value)
        ):
            raise ValueError("Incomplete deletion inventory response")
        if any(
            row.get("state") not in (None, "unchanged")
            or row.get("pending") not in (None, {})
            for row in value
        ):
            raise ValueError("Pending SDN changes require review before deletion")
        return value

    status = get("/cluster/status")
    nodes, _ = cluster_nodes(status)
    if node not in nodes:
        raise ValueError("The SSH node is not in the authoritative cluster")
    cluster_identity = certificate_identity(get(f"/nodes/{node}/certificates/info"))
    directory = get("/cluster/sdn")
    if not isinstance(directory, list) or any(
        not isinstance(row, dict) for row in directory
    ):
        raise ValueError("SDN feature directory is unreadable")
    features = [row.get("id") for row in directory]
    base = {"zones", "vnets", "controllers", "ipams", "dns"}
    if (
        any(not isinstance(name, str) for name in features)
        or len(set(features)) != len(features)
        or not base <= set(features) <= base | {"fabrics", "prefix-lists", "route-maps"}
    ):
        raise ValueError("Unsupported or incomplete SDN feature directory")
    families = {}
    for name in features:
        path = "/cluster/sdn/" + {
            "fabrics": "fabrics/all",
            "route-maps": "route-maps/entries",
        }.get(name, name)
        options = [] if name in {"ipams", "dns"} else ["--pending", "1"]
        if name == "prefix-lists":
            options += ["--verbose", "1"]
        value = get(path, *options)
        if name == "fabrics":
            if not isinstance(value, dict) or set(value) != {"fabrics", "nodes"}:
                raise ValueError("Incomplete fabric inventory")
            settled(value["fabrics"])
            settled(value["nodes"])
        else:
            settled(value)
        families[name] = value
    subnets = {}
    for row in families["vnets"]:
        name = row.get("vnet")
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{1,7}", name)
            or name in subnets
        ):
            raise ValueError("VNet identity is invalid or duplicated")
        subnets[name] = settled(
            get(f"/cluster/sdn/vnets/{name}/subnets", "--pending", "1")
        )
    guests = get("/cluster/resources", "--type", "vm")
    if not isinstance(guests, list) or len(guests) > 4096:
        raise ValueError("Guest inventory is incomplete or excessive")
    configs = {}
    reads = []
    for guest in guests:
        if (
            not isinstance(guest, dict)
            or guest.get("type") not in {"qemu", "lxc"}
            or type(guest.get("vmid")) is not int
            or guest["vmid"] <= 0
            or guest.get("node") not in nodes
        ):
            raise ValueError("Guest identity cannot be safely addressed")
        key = f"{guest['type']}/{guest['vmid']}"
        if key in configs:
            raise ValueError("Duplicate guest identity")
        path = f"/nodes/{guest['node']}/{key}"
        configs[key] = {"current": {}}
        # /pending includes every scalar current value, candidate and deletion.
        # Raw LXC arrays are omitted by GuestHelpers, so LXC keeps /config too.
        if guest["type"] == "lxc":
            reads.append(
                (
                    key,
                    "current",
                    [
                        "pvesh",
                        "get",
                        path + "/config",
                        "--current",
                        "1",
                        "--output-format",
                        "json",
                    ],
                )
            )
        reads.append(
            (
                key,
                "pending",
                ["pvesh", "get", path + "/pending", "--output-format", "json"],
            )
        )
    for offset in range(0, len(reads), 2):
        batch = reads[offset : offset + 2]
        values = commands([entry[2] for entry in batch])
        for (key, field, _), raw in zip(batch, values):
            configs[key][field] = decode(raw)
    # Discovery must remain stable while all configuration reads are completed.
    after = get("/cluster/resources", "--type", "vm")

    def identity(rows):
        return sorted(
            (row.get("type"), row.get("vmid"), row.get("node")) for row in rows
        )

    if (
        not isinstance(after, list)
        or any(not isinstance(row, dict) for row in after)
        or identity(after) != identity(guests)
    ):
        raise ValueError("Guest inventory changed during attachment inspection")
    scope = delete_scope(
        {
            "zone": document.get("zone"),
            "status": status,
            "features": features,
            "families": families,
            "subnets": subnets,
            "guests": guests,
            "guest_configs": configs,
        }
    )
    scope["cluster_identity"] = cluster_identity
    return {"scope": scope, "node": node, "privileged": True}


def delete_scope(document):
    """Resolve one complete zone deletion from privileged read-only inventory."""
    nodes, _ = cluster_nodes(document.get("status"))
    zone = document.get("zone")
    if not isinstance(zone, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{1,7}", zone):
        raise ValueError("Deletion requires one explicit zone name")
    features = document.get("features")
    required = {"zones", "vnets", "controllers", "ipams", "dns"}
    supported = required | {"fabrics", "prefix-lists", "route-maps"}
    if not isinstance(features, list) or any(not isinstance(x, str) for x in features):
        raise ValueError("SDN feature inventory is unreadable")
    if (
        len(features) != len(set(features))
        or not required <= set(features) <= supported
    ):
        raise ValueError("Unsupported or incomplete SDN feature coverage")
    families, subnets = document.get("families"), document.get("subnets")
    if (
        not isinstance(families, dict)
        or set(families) != set(features)
        or not isinstance(subnets, dict)
    ):
        raise ValueError("Every advertised SDN family must be read")

    def rows(value):
        if (
            not isinstance(value, list)
            or len(value) > 4096
            or any(not isinstance(x, dict) for x in value)
        ):
            raise ValueError("Malformed or excessive inventory rows")
        return value

    def settled(value):
        for row in rows(value):
            if row.get("state") not in (None, "unchanged") or row.get(
                "pending"
            ) not in (None, {}):
                raise ValueError(
                    "Pending SDN changes require separate review before deletion"
                )
        return value

    for name, value in families.items():
        if name == "fabrics":
            if not isinstance(value, dict) or set(value) != {"fabrics", "nodes"}:
                raise ValueError("Incomplete fabric coverage")
            settled(value["fabrics"])
            settled(value["nodes"])
        else:
            settled(value)
    zones = families["zones"]
    zone_names = [row.get("zone") for row in zones]
    if any(not isinstance(name, str) for name in zone_names) or len(
        set(zone_names)
    ) != len(zone_names):
        raise ValueError("Zone bindings are incomplete or duplicated")
    selected_zone = [row for row in zones if row["zone"] == zone]
    if selected_zone and selected_zone[0].get("type") != "simple":
        raise ValueError("Deletion preservation currently supports simple zones")
    selected_nodes = (
        sorted(members(selected_zone[0].get("nodes"), nodes)) if selected_zone else []
    )
    vnets = families["vnets"]
    names = [row.get("vnet") for row in vnets]
    if (
        any(
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{1,7}", name)
            for name in names
        )
        or len(set(names)) != len(names)
        or set(subnets) != set(names)
        or any(row.get("zone") not in zone_names for row in vnets)
    ):
        raise ValueError(
            "Every VNet needs one authoritative zone and complete subnet coverage"
        )
    selected_vnets = sorted(row["vnet"] for row in vnets if row["zone"] == zone)
    if len(selected_vnets) > 64:
        raise ValueError("One bounded deletion supports at most 64 selected VNets")
    all_subnets = []
    for vnet in sorted(subnets):
        for row in settled(subnets[vnet]):
            identifier = row.get("subnet")
            if not isinstance(identifier, str) or not re.fullmatch(
                r"[A-Za-z0-9_.:-]{1,128}", identifier
            ):
                raise ValueError("Subnet identity is missing or unsafe")
            source = row.get("cidr")
            if (
                not isinstance(source, str)
                or str(ipaddress.ip_network(source, strict=True)) != source
            ):
                raise ValueError(
                    "Every subnet requires an authoritative canonical CIDR"
                )
            all_subnets.append(
                {
                    "subnet": identifier,
                    "subnet_vnet": vnet,
                    "subnet_cidr": row.get("cidr"),
                }
            )
    all_subnets.sort(key=lambda row: (row["subnet_vnet"], row["subnet"]))
    selected = [row for row in all_subnets if row["subnet_vnet"] in selected_vnets]
    sources = cidrs([row["subnet_cidr"] for row in selected])
    if any(
        sum(row["subnet_cidr"] == source for row in all_subnets) != 1
        for source in sources
    ):
        raise ValueError(
            "Selected source CIDRs must have unique cluster-wide ownership"
        )
    if len({(row["subnet_vnet"], row["subnet"]) for row in all_subnets}) != len(
        all_subnets
    ):
        raise ValueError("Duplicate subnet identities")

    guests, configs = rows(document.get("guests")), document.get("guest_configs")
    if not isinstance(configs, dict):
        raise ValueError("Guest configuration coverage is unreadable")
    keys = []
    for guest in guests:
        if (
            guest.get("type") not in ("qemu", "lxc")
            or type(guest.get("vmid")) is not int
            or guest["vmid"] <= 0
            or guest.get("node") not in nodes
        ):
            raise ValueError("Guest inventory identity is incomplete")
        key = f"{guest['type']}/{guest['vmid']}"
        keys.append(key)
        config = configs.get(key)
        if not isinstance(config, dict) or not isinstance(config.get("current"), dict):
            raise ValueError("Every guest needs current and pending configuration")
        definitions = list(config["current"].items())
        pending_rows = rows(config.get("pending"))
        if guest["type"] == "qemu" and not pending_rows:
            raise ValueError(
                "A QEMU pending response must include its current configuration"
            )
        seen_keys = set()
        for pending in pending_rows:
            option = pending.get("key")
            if (
                not isinstance(option, str)
                or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", option)
                or option in seen_keys
                or not set(pending) <= {"key", "value", "pending", "delete"}
                or (
                    "delete" in pending
                    and (
                        type(pending["delete"]) is not int
                        or pending["delete"] not in (0, 1, 2)
                    )
                )
            ):
                raise ValueError("Malformed or duplicate pending guest configuration")
            seen_keys.add(option)
            definitions.extend(
                (pending["key"], pending[name])
                for name in ("value", "pending")
                if name in pending
            )
        for name, value in definitions:
            if name == "args" or name == "lxc" or name.startswith("lxc."):
                if value:
                    raise ValueError(
                        "Custom guest networking cannot prove safe detachment"
                    )
            if not re.fullmatch(r"net[0-9]+", name):
                continue
            if not isinstance(value, str) or len(value) > 8192:
                raise ValueError("Guest NIC configuration is unreadable")
            bridges = [
                part.split("=", 1)[1]
                for part in value.split(",")
                if part.startswith("bridge=")
            ]
            if len(bridges) > 1:
                raise ValueError("Ambiguous guest bridge configuration")
            if any(bridge in selected_vnets for bridge in bridges):
                raise ValueError(
                    "A current or pending guest NIC is attached to the selected zone"
                )
    if len(keys) != len(set(keys)) or set(keys) != set(configs):
        raise ValueError("Guest configuration coverage is incomplete")

    def inventory_hash(selected_families, selected_subnets):
        def normalized(value):
            if isinstance(value, dict):
                return {key: normalized(rows) for key, rows in value.items()}
            cleaned = [
                {
                    key: item
                    for key, item in row.items()
                    if key not in {"digest", "state", "pending"}
                }
                for row in value
            ]
            return sorted(cleaned, key=lambda row: json.dumps(row, sort_keys=True))

        canonical = json.dumps(
            {
                "families": normalized(selected_families),
                "subnets": normalized(selected_subnets),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    remaining = {
        **families,
        "zones": [row for row in zones if row["zone"] != zone],
        "vnets": [row for row in vnets if row["vnet"] not in selected_vnets],
    }
    return {
        "version": 1,
        "zone": zone,
        "zone_present": bool(selected_zone),
        "zone_nodes": selected_nodes,
        "cluster_nodes": sorted(nodes),
        "vnets": selected_vnets,
        "subnets": selected,
        "desired_sources": [
            {
                "source": row["subnet_cidr"],
                "vnet": row["subnet_vnet"],
                "zone": zone,
                "want": 0,
            }
            for row in selected
        ],
        "known_subnets": all_subnets,
        "inventory_sha256": inventory_hash(families, subnets),
        "remaining_sha256": inventory_hash(
            remaining,
            {key: rows for key, rows in subnets.items() if key not in selected_vnets},
        ),
    }


def source_counts(document):
    """Expose only counts from every verified snapshot; never invoke iptables."""
    source = cidrs([document.get("source")])[0]
    plan, snapshots = document.get("plan"), document.get("snapshots")
    if (
        document.get("snapshot_verified") is not True
        or document.get("apply_attempted") is not False
        or document.get("apply_verified") is not False
        or not isinstance(plan, dict)
        or plan.get("version") != 1
        or not isinstance(plan.get("nodes"), list)
        or not 1 <= len(plan["nodes"]) <= 64
        or any(not isinstance(node, dict) for node in plan["nodes"])
        or not isinstance(snapshots, dict)
    ):
        raise ValueError(
            "Counts require a complete fresh snapshot with no apply attempt"
        )
    names = [node.get("node") for node in plan["nodes"]]
    if (
        any(not isinstance(name, str) for name in names)
        or len(set(names)) != len(names)
        or set(snapshots) != set(names)
        or plan.get("primary_node") not in names
    ):
        raise ValueError("Counts require exact mapped node coverage")
    result = []
    for name in names:
        snapshot = snapshots[name]
        if (
            not isinstance(snapshot, dict)
            or snapshot.get("version") != 1
            or not isinstance(snapshot.get("node"), str)
            or snapshot["node"] != name
            and snapshot["node"].split(".")[0] != name
            or type(snapshot.get("captured_at")) is not int
            or snapshot["captured_at"] <= 0
            or not isinstance(snapshot.get("nat_counts"), dict)
        ):
            raise ValueError("A mapped node snapshot cannot prove its count")
        count = snapshot["nat_counts"].get(source, 0)
        if type(count) is not int or count < 0:
            raise ValueError("A source count must be a nonnegative integer")
        result.append(
            {"node": name, "count": count, "captured_at": snapshot["captured_at"]}
        )
    return {
        "source": source,
        "primary_node": plan["primary_node"],
        "read_only": True,
        "nodes": result,
    }


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
    elif sys.argv[1:] == ["cluster-identity"]:
        result = {
            "cluster_identity": certificate_identity(document.get("certificates"))
        }
    elif sys.argv[1:] == ["read-delete"]:
        result = read_delete(document)
    elif sys.argv[1:] == ["delete-scope"]:
        result = delete_scope(document)
    elif sys.argv[1:] == ["count-source"]:
        result = source_counts(document)
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
