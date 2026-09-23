"""Exercise the actual controller task commands against a private fake iptables."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

import jinja2
import pytest
import yaml

ROLE = Path(__file__).resolve().parents[1] / "roles/range42-ansible_roles-proxmox_controller"
CIDR = "10.42.70.0/24"


def rule(*arguments):
    return shlex.join(["-A", "POSTROUTING", *arguments])


UNRELATED = [
    rule("-s", CIDR, "-j", "ACCEPT"),
    rule("-s", CIDR, "-j", "LOG", "--log-prefix", "SNAT audit -s 10.42.70.0/24 -j SNAT"),
    rule("-s", "10.42.0.0/16", "-j", "SNAT", "--to-source", "192.0.2.10"),
    rule("-s", "10.42.70.128/25", "-j", "MASQUERADE"),
    rule("!", "-s", CIDR, "-j", "SNAT", "--to-source", "192.0.2.10"),
    rule("-s", "10.42.80.0/24", "-m", "comment", "--comment", "pretend -s 10.42.70.0/24 -j SNAT", "-j", "ACCEPT"),
    rule("-s", CIDR, "-m", "comment", "--comment", "pretend -j SNAT", "-j", "LOG"),
    rule("-j", "SNAT", "--to-source", "192.0.2.10"),
]
TARGETS = [
    rule("-s", CIDR, "-o", "vmbr0", "-m", "comment", "--comment", "space and \"quote\"; $(touch should-not-run)", "-j", "SNAT", "--to-source", "192.0.2.10"),
    rule("-s", CIDR, "-o", "vmbr0", "-j", "MASQUERADE"),
]


@pytest.fixture
def fake(tmp_path):
    binary = tmp_path / "iptables"
    binary.write_text(f"#!{sys.executable}\n" + '''import json, os, pathlib, shlex, sys
path = pathlib.Path(os.environ["R42_FAKE_RULES"])
args = sys.argv[1:]
if args[:2] == ["-w", "5"]:
    args = args[2:]
assert args[:2] == ["-t", "nat"], args
rules = json.loads(path.read_text())
if args[2:] == ["-S", "POSTROUTING"]:
    if os.environ.get("R42_FAKE_READ_FAIL"):
        sys.exit(3)
    print("\\n".join(rules))
elif args[2:4] == ["-D", "POSTROUTING"]:
    if os.environ.get("R42_FAKE_DELETE_FAIL"):
        sys.exit(4)
    wanted = ["-A", *args[3:]]
    for index, line in enumerate(rules):
        if shlex.split(line) == wanted:
            del rules[index]
            path.write_text(json.dumps(rules))
            break
    else:
        print("wrong deletion argv", repr(wanted), file=sys.stderr)
        sys.exit(5)
else:
    raise AssertionError(args)
''')
    binary.chmod(0o755)
    state = tmp_path / "rules.json"
    state.write_text("[]")
    return state, {"PATH": f"{tmp_path}:{os.environ['PATH']}", "R42_FAKE_RULES": str(state)}


def run_task(fake, mode, want=1, cidr=CIDR):
    _, env = fake
    filename = "delete_network_extra_snat_rules.yaml" if mode == "reconcile" else "list_network_snat_rules.yaml"
    block = yaml.safe_load((ROLE / "tasks/include/network" / filename).read_text())[0]["block"]
    task = next(task for task in block if task.get("register") == "proxmox_call")
    template = jinja2.Environment(undefined=jinja2.StrictUndefined)
    variables = {"sdn_subnet_cidr": cidr, "sdn_snat_want": want, "role_path": str(ROLE),
                 "lookup": lambda kind, path: Path(path).read_text() if kind == "file" else None}
    if "ansible.builtin.shell" in task:
        argv = ["/bin/bash", "-c", template.from_string(task["ansible.builtin.shell"]).render(**variables)]
    else:
        argv = [template.from_string(argument).render(**variables) for argument in task["ansible.builtin.command"]["argv"]]
    return subprocess.run(argv, env=env, capture_output=True, text=True, timeout=10)


@pytest.mark.parametrize("want", [0, 1])
def test_only_exact_source_snat_targets_are_reconciled_and_comments_survive(fake, want):
    state, _ = fake
    state.write_text(json.dumps([*UNRELATED, *TARGETS]))
    result = run_task(fake, "reconcile", want)
    assert result.returncode == 0, result.stdout + result.stderr
    counts = json.loads(result.stdout)
    assert counts == {"before": 2, "after": want, "want": want, "deleted": 2 - want}
    remaining = json.loads(state.read_text())
    assert all(line in remaining for line in UNRELATED)
    assert len(remaining) == len(UNRELATED) + want


def test_unrelated_accept_cannot_fake_enabled_nat(fake):
    state, _ = fake
    state.write_text(json.dumps([UNRELATED[0]]))
    result = run_task(fake, "reconcile", 1)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"before": 0, "after": 0, "want": 1, "deleted": 0}
    assert json.loads(state.read_text()) == [UNRELATED[0]]


def test_readback_lists_only_concrete_snat_and_masquerade_rules(fake):
    state, _ = fake
    initial = [*UNRELATED, *TARGETS]
    state.write_text(json.dumps(initial))
    result = run_task(fake, "list")
    assert result.returncode == 0, result.stderr
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert sorted((row["snat_source"], row["snat_target"], row["snat_count"]) for row in rows) == [
        ("10.42.0.0/16", "SNAT", 1), ("10.42.70.0/24", "MASQUERADE", 1),
        ("10.42.70.0/24", "SNAT", 1), ("10.42.70.128/25", "MASQUERADE", 1),
    ]
    assert json.loads(state.read_text()) == initial


@pytest.mark.parametrize("mode", ["list", "reconcile"])
def test_unreadable_table_is_an_error_not_zero_rules(fake, mode):
    _, env = fake
    env["R42_FAKE_READ_FAIL"] = "1"
    result = run_task(fake, mode)
    assert result.returncode != 0
    assert not result.stdout.strip()


def test_refused_delete_cannot_claim_success(fake):
    state, env = fake
    state.write_text(json.dumps(TARGETS))
    env["R42_FAKE_DELETE_FAIL"] = "1"
    result = run_task(fake, "reconcile", 0)
    assert result.returncode != 0
    assert json.loads(state.read_text()) == TARGETS


@pytest.mark.parametrize("want,cidr", [(2, CIDR), (-1, CIDR), (1, "999.42.70.0/24")])
def test_invalid_reconciliation_input_does_not_touch_rules(fake, want, cidr):
    state, _ = fake
    state.write_text(json.dumps(TARGETS))
    result = run_task(fake, "reconcile", want, cidr)
    assert result.returncode != 0
    assert json.loads(state.read_text()) == TARGETS


@pytest.mark.parametrize("mode,want", [("reconcile", 0), ("reconcile", 1), ("list", 1)])
def test_actual_ansible_action_uses_shared_parser_and_preserves_result_contract(fake, tmp_path, mode, want):
    from copy import deepcopy
    state, env = fake
    initial = [*UNRELATED, *TARGETS]
    state.write_text(json.dumps(initial))
    filename = "delete_network_extra_snat_rules.yaml" if mode == "reconcile" else "list_network_snat_rules.yaml"
    action = "network_delete_extra_snat_rules" if mode == "reconcile" else "network_list_snat_rules"
    tasks = deepcopy(yaml.safe_load((ROLE / "tasks/include/network" / filename).read_text()))
    command = next(task for task in tasks[0]["block"] if task.get("register") == "proxmox_call")
    command["environment"] = env
    output = tmp_path / "result.json"
    tasks.append({"ansible.builtin.copy": {"content": "{{ " + action + " | to_json }}", "dest": str(output), "mode": "0600"}})
    playbook = tmp_path / "check.yml"
    playbook.write_text(yaml.safe_dump([{"hosts": "proxmox", "gather_facts": False, "vars": {
        "role_path": str(ROLE), "proxmox_vm_action": action, "proxmox_node": "pve-test",
        "sdn_subnet_cidr": CIDR, "sdn_snat_want": want,
    }, "tasks": tasks}], sort_keys=False))
    inventory = tmp_path / "inventory.yml"
    inventory.write_text(yaml.safe_dump({"all": {"vars": {"ansible_connection": "local", "ansible_python_interpreter": sys.executable},
        "children": {"proxmox": {"hosts": {"api": {}}}, "proxmox_cli": {"hosts": {"cli": {}}}}}}))
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\nretry_files_enabled=False\n")
    binary = Path(sys.executable).parent / "ansible-playbook"
    completed = subprocess.run([str(binary), "-i", str(inventory), str(playbook)],
        env={**env, "ANSIBLE_CONFIG": str(config)}, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    result = json.loads(output.read_text())
    if mode == "reconcile":
        assert result["snat_before"] == 2
        assert result["snat_after"] == want
        assert result["snat_host"] == "cli"
        assert result["snat_rule_matching"] == "exact_source_nat_target_v1"
        assert all(line in json.loads(state.read_text()) for line in UNRELATED)
    else:
        assert {item["snat_target"] for item in result} == {"SNAT", "MASQUERADE"}
        assert json.loads(state.read_text()) == initial
