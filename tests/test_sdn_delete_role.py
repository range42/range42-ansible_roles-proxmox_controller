"""Actual role rejects an API/SSH cluster mismatch before authorizing deletion."""

import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from test_sdn_delete_collector import run_collector
from test_snat_cluster import HELPER


@pytest.mark.parametrize("same_cluster", [True, False])
def test_role_checks_api_and_privileged_ssh_cluster_identity(tmp_path, same_cluster):
    result, _ = run_collector(tmp_path)
    assert result.returncode == 0
    role = tmp_path / "roles/range42-ansible_roles-proxmox_controller"
    (role / "tasks").mkdir(parents=True)
    (role / "files").mkdir()
    (role / "files/snat_cluster.py").write_bytes(HELPER.read_bytes())
    tasks = yaml.safe_load(
        (
            HELPER.parent.parent / "tasks/include/network/plan_sdn_delete.yaml"
        ).read_text()
    )
    for task in tasks:
        if "ansible.builtin.uri" in task:
            value = task.pop("ansible.builtin.uri")
            task["fixture_certificate_api"] = {
                "url": value["url"],
                "method": value["method"],
                "fingerprint": ":".join(["AB" if same_cluster else "CD"] * 32),
            }
        if (
            "ansible.builtin.command" in task
            and task["ansible.builtin.command"]["argv"][-1] == "read-delete"
        ):
            task["environment"] = {
                "PATH": str(tmp_path / "bin") + os.pathsep + os.environ["PATH"],
                "DELETE_FIXTURE": str(tmp_path / "fixture.json"),
            }
    (role / "tasks/main.yml").write_text(yaml.safe_dump(tasks, sort_keys=False))
    library = tmp_path / "library"
    library.mkdir()
    (
        library / "fixture_certificate_api.py"
    ).write_text("""from ansible.module_utils.basic import AnsibleModule
m=AnsibleModule(argument_spec={'url':{'type':'str'},'method':{'type':'str'},'fingerprint':{'type':'str'}})
if m.params['method']!='GET' or not m.params['url'].endswith('/nodes/pve1/certificates/info'): m.fail_json(msg='Unexpected API request')
m.exit_json(changed=False,status=200,json={'data':[{'filename':'pve-root-ca.pem','fingerprint':m.params['fingerprint']}]})
""")
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
                        "proxmox_cli": {"hosts": {"ssh1": {}}},
                    },
                }
            }
        )
    )
    play = tmp_path / "play.yml"
    play.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": "proxmox",
                    "gather_facts": False,
                    "vars": {
                        "proxmox_node": "pve1",
                        "proxmox_api_host": "fixture.invalid",
                        "proxmox_api_user": "fixture",
                        "proxmox_api_token_id": "fixture",
                        "proxmox_api_token_secret": "fixture",
                        "sdn_zone": "lab",
                    },
                    "tasks": [{"ansible.builtin.include_role": {"name": role.name}}],
                }
            ]
        )
    )
    result = subprocess.run(
        [
            str(Path(sys.executable).with_name("ansible-playbook")),
            "-i",
            str(inventory),
            str(play),
        ],
        env={
            **os.environ,
            "ANSIBLE_ROLES_PATH": str(tmp_path / "roles"),
            "ANSIBLE_LIBRARY": str(library),
            "ANSIBLE_NOCOLOR": "1",
        },
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert (result.returncode == 0) is same_cluster, (
        result.stdout[-5000:] + result.stderr
    )
    if not same_cluster:
        assert "same cluster CA identity" in result.stdout
