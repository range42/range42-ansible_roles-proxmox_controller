"""Execute snapshot/restore Ansible tasks against a disposable fake NAT table."""

from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

import yaml
import pytest

from test_snat_preservation import (
    fake as _fake_fixture,
    LEGACY,
    OTHER_RULE,
    OTHER_SHAPE,
    TARGET,
    TARGET_RULE,
    UNRELATED,
)


@pytest.fixture(name="fake")
def fake_rules(tmp_path):
    return _fake_fixture.__wrapped__(tmp_path)


ROLE = (
    Path(__file__).resolve().parents[1]
    / "roles/range42-ansible_roles-proxmox_controller"
)


@pytest.mark.parametrize("concurrent_change", [False, True])
def test_actual_ansible_snapshot_and_restore_preserve_scope_without_logging_rule_contents(
    fake, tmp_path, concurrent_change
):
    state, _, env = fake
    if concurrent_change:
        env["R42_CHANGE_AT_READ"] = "3"
    before = [UNRELATED, OTHER_RULE, OTHER_SHAPE, *([LEGACY] * 3), TARGET_RULE]
    state.write_text(json.dumps(before))
    after = [*before, OTHER_RULE, OTHER_SHAPE, LEGACY, TARGET_RULE]
    original = yaml.safe_load(
        (ROLE / "tasks/include/network/preserve_network_snat_rules.yaml").read_text()
    )
    tasks = deepcopy(original)
    for task in tasks[0]["block"]:
        if "ansible.builtin.command" in task:
            task["environment"] = env
    output = tmp_path / "observed.json"
    play = {
        "hosts": "proxmox",
        "gather_facts": False,
        "vars": {
            "role_path": str(ROLE),
            "proxmox_node": socket.gethostname().split(".")[0],
            "sdn_snat_excluded_sources": [TARGET],
            "sdn_snat_allow_new_rules": False,
        },
        "tasks": [
            {
                "ansible.builtin.set_fact": {
                    "proxmox_vm_action": "network_snapshot_snat_rules"
                }
            },
            *tasks,
            {
                "ansible.builtin.copy": {
                    "dest": str(state),
                    "content": json.dumps(after),
                    "mode": "0600",
                }
            },
            {
                "ansible.builtin.set_fact": {
                    "proxmox_vm_action": "network_restore_snat_snapshot"
                }
            },
            *deepcopy(tasks),
            {
                "ansible.builtin.copy": {
                    "dest": str(output),
                    "content": "{{ network_restore_snat_snapshot | to_json }}",
                    "mode": "0600",
                }
            },
        ],
    }
    playbook = tmp_path / "playbook.yml"
    playbook.write_text(yaml.safe_dump([play], sort_keys=False))
    inventory = tmp_path / "hosts.yml"
    inventory.write_text(
        yaml.safe_dump(
            {
                "all": {
                    "vars": {
                        "ansible_connection": "local",
                        "ansible_python_interpreter": sys.executable,
                    },
                    "children": {
                        "proxmox": {"hosts": {"api": {}}},
                        "proxmox_cli": {"hosts": {"cli": {}}},
                    },
                }
            }
        )
    )
    result = subprocess.run(
        [
            str(Path(sys.executable).with_name("ansible-playbook")),
            "-i",
            str(inventory),
            str(playbook),
        ],
        env={**os.environ, "ANSIBLE_NOCOLOR": "1"},
        capture_output=True,
        text=True,
        timeout=30,
    )
    if concurrent_change:
        assert result.returncode != 0
        assert "SNAT preservation did not finish" in result.stdout
        assert "preserve quoted" not in result.stdout
        return
    assert result.returncode == 0, result.stdout[-5000:] + result.stderr
    assert json.loads(state.read_text()) == [*before, TARGET_RULE]
    assert json.loads(output.read_text())["deleted"] == 3
    assert "preserve quoted" not in result.stdout
