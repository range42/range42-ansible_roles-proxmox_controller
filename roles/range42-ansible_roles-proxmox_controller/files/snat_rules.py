"""Read or reconcile concrete source SNAT/MASQUERADE rules on one host.

iptables -S uses shell quoting. Parse it with shlex, preserve original argument
boundaries for deletion, and never evaluate rule text as a shell command.
"""
from collections import Counter
import ipaddress
import json
import shlex
import subprocess
import sys


def iptables(*arguments):
    return subprocess.run(
        ["iptables", "-w", "5", "-t", "nat", *arguments],
        check=True, capture_output=True, text=True, timeout=15,
    ).stdout


def read_rules():
    table = iptables("-S", "POSTROUTING")
    if len(table) > 8 * 1024 * 1024:
        raise ValueError("NAT table exceeds audit bound")
    result = []
    for line in table.splitlines():
        arguments = shlex.split(line)
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


def main(arguments):
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
