"""Validate the concrete scenario's optional VM bootstrap configuration."""
from collections.abc import Mapping
from ipaddress import IPv4Interface
import re

from ansible.errors import AnsibleFilterError


def bootstrap_config(value):
    if not isinstance(value, Mapping):
        raise AnsibleFilterError("VM extra config must be a mapping")
    result = dict(value)
    networks = set()
    addresses = set()
    for key, item in result.items():
        if key in ("cores", "memory"):
            lower, upper = (1, 128) if key == "cores" else (128, 1048576)
            if isinstance(item, bool) or not isinstance(item, int) or not lower <= item <= upper:
                raise AnsibleFilterError(f"VM {key} must be an integer between {lower} and {upper}")
            continue
        match = re.fullmatch(r"(net|ipconfig)([1-9]|[12][0-9]|3[01])", str(key))
        if not match:
            raise AnsibleFilterError("VM extra config permits only cores, memory and secondary NIC pairs")
        kind, index = match.groups()
        if kind == "net":
            if not isinstance(item, str) or not re.fullmatch(r"virtio,bridge=[A-Za-z][A-Za-z0-9_.-]{0,14}", item):
                raise AnsibleFilterError("Secondary NIC must specify only a virtio bridge")
            networks.add(int(index))
        else:
            if not isinstance(item, str) or not re.fullmatch(r"ip=[0-9.]+/[0-9]{1,2}", item):
                raise AnsibleFilterError("Secondary NIC must specify a static IPv4 address without a gateway")
            try:
                IPv4Interface(item[3:])
            except ValueError as error:
                raise AnsibleFilterError("Secondary NIC has an invalid IPv4 address") from error
            addresses.add(int(index))
    if networks != addresses or networks != set(range(1, len(networks) + 1)):
        raise AnsibleFilterError("Secondary NICs require contiguous net/ipconfig pairs starting at 1")
    return result


def bootstrap_template_config(value, extra):
    if not isinstance(value, Mapping):
        raise AnsibleFilterError("Cannot verify template network configuration")
    planned = {"net0"} | {key for key in bootstrap_config(extra) if key.startswith("net")}
    inherited = {key for key in value if re.fullmatch(r"net[0-9]+", str(key))}
    if inherited - planned:
        raise AnsibleFilterError("Template has network interfaces outside the authored topology")
    return True


class FilterModule:
    def filters(self):
        return {
            "range42_bootstrap_config": bootstrap_config,
            "range42_bootstrap_template_config": bootstrap_template_config,
        }
