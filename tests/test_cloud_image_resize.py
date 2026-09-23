"""Template import must grow VM storage without altering the downloaded image."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / "roles/range42-ansible_roles-proxmox_controller/tasks/include/templates/cloudinit_import_disk_workaround.yaml"


def test_template_import_grows_attached_vm_disk_and_reuses_source_image(tmp_path):
    source = tmp_path / "cloud.qcow2"
    source.write_bytes(b"unchanged source image")
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"attached": False, "size": "8G", "commands": []}))
    binaries = tmp_path / "bin"
    binaries.mkdir()
    qm = binaries / "qm"
    qm.write_text(f'''#!{sys.executable}
import json, os, sys
from pathlib import Path
p=Path(os.environ['QM_TEST_STATE'])
s=json.loads(p.read_text())
a=sys.argv[1:]
s['commands'].append(a)
if a[0]=='config':
    if s['attached']: print('scsi0: local-lvm:vm-9000-disk-0,size='+s['size'])
elif a[0]=='set' and '--scsi0' in a: s['attached']=True
elif a[0]=='resize':
    assert s['attached'], 'VM disk must be attached before resize'
    s['size']=a[3]
p.write_text(json.dumps(s))
''')
    qm.chmod(0o700)
    image_tool = binaries / "qemu-img"
    image_tool.write_text(f'''#!{sys.executable}
import sys
from pathlib import Path
Path(sys.argv[-2]).write_bytes(b'source image was resized')
''')
    image_tool.chmod(0o700)
    inventory = tmp_path / "hosts.ini"
    inventory.write_text(f"localhost ansible_connection=local ansible_python_interpreter={sys.executable}\n")
    playbook = tmp_path / "import.yml"
    playbook.write_text(f'''- hosts: localhost
  gather_facts: false
  vars:
    proxmox_vm_action: template_cloudinit_import_disk
    vm_id: 9000
    cloudinit_image_full_path: {source}
    proxmox_dest_vm_storage_name: local-lvm
    vm_disk_size: 40G
  tasks:
    - ansible.builtin.include_tasks: {TASKS}
''')
    environment = {**os.environ, "PATH": f"{binaries}:{os.environ['PATH']}", "QM_TEST_STATE": str(state), "ANSIBLE_NOCOLOR": "1"}
    command = [str(Path(sys.executable).with_name("ansible-playbook")), "-i", str(inventory), str(playbook)]
    first = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=60)
    assert first.returncode == 0, first.stdout[-5000:] + first.stderr
    assert source.read_bytes() == b"unchanged source image"
    current = json.loads(state.read_text())
    assert current["size"] == "40G"
    assert sum(row[0] == "resize" for row in current["commands"]) == 1
    second = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=60)
    assert second.returncode == 0, second.stdout[-5000:] + second.stderr
    current = json.loads(state.read_text())
    assert sum(row[0] == "resize" for row in current["commands"]) == 1
    assert sum(row[:2] == ["disk", "import"] for row in current["commands"]) == 1
