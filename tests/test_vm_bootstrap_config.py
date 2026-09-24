"""Run the cloud-init task file against a local recording URI module."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "roles/range42-ansible_roles-proxmox_controller"


class BootstrapConfigTests(unittest.TestCase):
    def run_config(self, extra):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = root / "library"
            library.mkdir()
            (library / "uri.py").write_text('''from ansible.module_utils.basic import AnsibleModule
import json, os
m = AnsibleModule(argument_spec={k: {"type": "raw"} for k in
    ["url", "method", "headers", "validate_certs", "body_format", "body"]})
with open(os.environ["BOOTSTRAP_REQUEST_LOG"], "a") as f:
    f.write(json.dumps(m.params) + "\\n")
m.exit_json(changed=m.params["method"] != "GET", json={"data": {"status": "stopped"}})
''')
            variables = {
                "proxmox_vm_action": "cloudinit_set_variables", "vm_id": 60020,
                "proxmox_api_host": "never-contact.example", "proxmox_node": "node",
                "proxmox_api_user": "test", "proxmox_api_token_id": "test",
                "proxmox_api_token_secret": "test", "vm_ci_ssh_key": "ssh-ed25519 test",
                "vm_ci_ip": "10.42.10.10", "vm_ci_netmask": 24,
                "vm_ci_ip_gw": "10.42.10.1", "vm_net_virtio_bridge": "blue1",
                "vm_extra_config": extra,
            }
            play = [{"hosts": "localhost", "connection": "local", "gather_facts": False,
                "vars": variables, "tasks": [{"include_role": {
                    "name": ROLE.name, "tasks_from": "include/templates/cloudinit_set_variables.yaml"}}]}]
            (root / "play.yml").write_text(yaml.safe_dump(play))
            log = root / "requests.jsonl"
            executable = shutil.which("ansible-playbook")
            self.assertIsNotNone(executable, "ansible-playbook must be on PATH")
            result = subprocess.run([executable, "-i", "localhost,", str(root / "play.yml")],
                text=True, capture_output=True, env={**os.environ,
                    "ANSIBLE_ROLES_PATH": str(ROOT / "roles"), "ANSIBLE_LIBRARY": str(library),
                    "BOOTSTRAP_REQUEST_LOG": str(log), "ANSIBLE_NOCOLOR": "1"})
            requests = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            return result, requests

    def test_secondary_interface_and_resources_are_applied_before_regeneration(self):
        extra = {"net1": "virtio,bridge=red1", "ipconfig1": "ip=10.42.11.10/24", "cores": 4, "memory": 4096}
        result, requests = self.run_config(extra)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = next(row["body"] for row in requests if row["url"].endswith("/config"))
        self.assertEqual({key: config.get(key) for key in extra}, extra)
        self.assertEqual(config["net0"], "virtio,bridge=blue1")
        self.assertEqual(config["ipconfig0"], "ip=10.42.10.10/24,gw=10.42.10.1")
        self.assertTrue(requests[-1]["url"].endswith("/cloudinit"))

    def test_invalid_or_unpaired_extra_config_is_rejected_before_api_calls(self):
        for extra in [{"net0": "virtio,bridge=evil"}, {"delete": "scsi0"},
                      {"net1": "virtio,bridge=red1"}, {"ipconfig1": "ip=10.42.11.10/24"},
                      {"cores": True}, {"memory": 0}, {"cores": 129},
                      {"net1": "virtio,bridge=red1,tag=4", "ipconfig1": "ip=10.42.11.10/24"},
                      {"net1": "virtio,bridge=red1", "ipconfig1": "ip=10.42.11.10/24,gw=10.42.11.1"}]:
            with self.subTest(extra=extra):
                result, requests = self.run_config(extra)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(requests, [])

    def test_empty_extra_config_retains_primary_interface_behavior(self):
        result, requests = self.run_config({})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = next(row["body"] for row in requests if row["url"].endswith("/config"))
        self.assertEqual(config["net0"], "virtio,bridge=blue1")
        self.assertNotIn("cores", config)
        self.assertNotIn("memory", config)

    def test_secondary_interface_accepts_existing_vlan_bridge_name(self):
        extra = {"net1": "virtio,bridge=vmbr0.20", "ipconfig1": "ip=10.42.11.10/24"}
        result, requests = self.run_config(extra)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = next(row["body"] for row in requests if row["url"].endswith("/config"))
        self.assertEqual(config["net1"], extra["net1"])


if __name__ == "__main__":
    unittest.main()
