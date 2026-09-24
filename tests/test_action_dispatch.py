"""Exercise the real role dispatcher with harmless task-file boundaries."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "roles/range42-ansible_roles-proxmox_controller"
ACTIONS = json.loads((ROOT / "tests/controller_actions.json").read_text())


class ActionDispatchTests(unittest.TestCase):
    def run_actions(self, actions, extra=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            role = root / "roles" / ROLE.name
            shutil.copytree(ROLE, role)
            for action, relative in ACTIONS.items():
                (role / "tasks" / relative).write_text(yaml.safe_dump([
                    {"name": "Record selected primitive", "ansible.builtin.assert": {
                        "that": ["proxmox_vm_action == " + repr(action)],
                        "fail_msg": "The dispatcher selected another primitive"}},
                ]))
            playbook = root / "play.yml"
            playbook.write_text(yaml.safe_dump([{
                "hosts": "localhost", "connection": "local", "gather_facts": False,
                "tasks": [{"ansible.builtin.include_role": {"name": ROLE.name},
                           "vars": {"proxmox_vm_action": "{{ selected_action }}"},
                           "loop": actions, "loop_control": {"loop_var": "selected_action"}}],
            }]))
            start = time.monotonic()
            variables = root / "extra.json"
            variables.write_text(json.dumps(extra or {}))
            result = subprocess.run([shutil.which("ansible-playbook"), "-i", "localhost,", str(playbook), "-e", "@" + str(variables)],
                text=True, capture_output=True, timeout=180,
                env={**os.environ, "ANSIBLE_ROLES_PATH": str(root / "roles"), "ANSIBLE_NOCOLOR": "1"})
            return result, time.monotonic() - start

    def test_network_actions_do_not_walk_unrelated_dispatch(self):
        result, elapsed = self.run_actions(["network_delete_sdn_subnet", "network_delete_extra_snat_rules"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        skipped = int(re.search(r"skipped=(\d+)", result.stdout).group(1))
        print(f"Two network dispatches: {elapsed:.3f}s, {skipped} skipped tasks")
        self.assertEqual(skipped, 0, "Network actions traversed unrelated controller actions")

    def test_every_existing_selector_keeps_its_exact_primitive(self):
        result, _ = self.run_actions(list(ACTIONS))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.count("TASK [range42-ansible_roles-proxmox_controller : Record selected primitive]"), len(ACTIONS))

    def test_unknown_and_path_selectors_are_rejected(self):
        for action in ("unknown", "../include/vm/vm_delete.yaml"):
            with self.subTest(action=action):
                result, _ = self.run_actions([action])
                self.assertNotEqual(result.returncode, 0, "Unsupported selector silently succeeded")
                self.assertNotIn("TASK [range42-ansible_roles-proxmox_controller : Record selected primitive]", result.stdout)

    def test_variables_cannot_redirect_an_allowed_selector(self):
        result, _ = self.run_actions(["network_delete_extra_snat_rules"], {
            "_r42_proxmox_action_tasks": {"network_delete_extra_snat_rules": "./include/vm/vm_delete.yaml"},
        })
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
