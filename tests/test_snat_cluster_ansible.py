"""Real Ansible + real helper processes; all API/rule data is disposable."""

from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml

from test_snat_preservation import (
    fake as fake_rules,
    OTHER_RULE,
    TARGET,
    TARGET_RULE,
    UNRELATED,
)

ROLE = (
    Path(__file__).resolve().parents[1]
    / "roles/range42-ansible_roles-proxmox_controller"
)


def run_cluster(
    tmp_path,
    *,
    mapping=None,
    offline=False,
    wrong_host=False,
    delayed=False,
    failed=False,
    missing=False,
    ambiguous=False,
    actions=None,
    denied_audit=False,
    intervening_reload=False,
    intervening_before_put=False,
    single_node=False,
    target_want=0,
    duplicate_target=False,
    before_reconcile=None,
    recover_failed_apply=False,
    caller_tasks=None,
    fixture_role_tasks=None,
    target_counts=None,
):
    role = tmp_path / "roles/range42-ansible_roles-proxmox_controller"
    (role / "tasks/include/network").mkdir(parents=True)
    shutil.copytree(ROLE / "files", role / "files")
    fixtures = {}
    hosts = {}
    indices = (1,) if single_node else (1, 2)
    for index in indices:
        node = f"pve{index}"
        directory = tmp_path / node
        directory.mkdir()
        state, writes, environment = fake_rules.__wrapped__(directory)
        state.write_text(
            json.dumps(
                [UNRELATED, OTHER_RULE]
                + [TARGET_RULE]
                * ((target_counts or {}).get(node, 2 if duplicate_target else 1))
            )
        )
        environment["R42_TEST_NODE"] = "wrong" if wrong_host and index == 2 else node
        environment["R42_ALLOW_EXACT"] = "1"
        environment["R42_READY_NODES"] = json.dumps(
            [str(tmp_path / f"worker-pve{i}") for i in indices]
        )
        environment["R42_APPLY_MARKER"] = str(tmp_path / "applied")
        binary = directory / "iptables"
        binary.write_text(
            binary.read_text().replace(
                "elif args[:2]==['-D','POSTROUTING']:",
                "elif args[:2]==['-D','POSTROUTING']:\n assert not pathlib.Path(os.environ['R42_APPLY_MARKER']).exists() or all(pathlib.Path(path).exists() for path in json.loads(os.environ['R42_READY_NODES'])), 'cleanup preceded complete node reloads'",
            )
        )
        shim = directory / "python3"
        shim.write_text(
            f"#!{sys.executable}\nimport os,socket,sys\nsocket.gethostname=lambda:os.environ['R42_TEST_NODE']\ncode=sys.argv[2]\nsys.argv=['-c',*sys.argv[3:]]\nexec(code)\n"
        )
        shim.chmod(0o755)
        fixtures[node] = {"state": str(state), "writes": str(writes)}
        hosts[f"ssh{index}"] = {"fixture_environment": environment}
    document = {
        "status": [
            {
                "type": "node",
                "name": f"pve{i}",
                "online": 0 if offline and i == 2 else 1,
            }
            for i in indices
        ],
        "zones": [{"zone": "lab", "type": "simple", "nodes": "pve1"}],
        "nodes": fixtures,
        "apply_marker": str(tmp_path / "applied"),
        "delayed": delayed,
        "failed": failed,
        "missing": missing,
        "ambiguous": ambiguous,
        "denied_audit": denied_audit,
        "intervening_reload": intervening_reload,
        "intervening_before_put": intervening_before_put,
        "polls": str(tmp_path / "polls"),
        "worker_marker": str(tmp_path / "worker-"),
    }
    if not single_node:
        document["status"].append(
            {"type": "cluster", "name": "fixture", "nodes": len(indices), "quorate": 1}
        )
    api_fixture = tmp_path / "api.json"
    api_fixture.write_text(json.dumps(document))

    # Replace only the URI transport, keeping each task's delegation, loops,
    # until/retry behavior, result shape and actual Python helpers intact.
    def adapt(value):
        if isinstance(value, list):
            return [adapt(item) for item in value]
        if not isinstance(value, dict):
            return value
        value = deepcopy(value)
        for key in ("uri", "ansible.builtin.uri"):
            if key in value:
                params = value.pop(key)
                value["range42_fixture_api"] = {
                    "url": params["url"],
                    "method": params.get("method", "GET"),
                    "fixture_file": str(api_fixture),
                }
        if "ansible.builtin.command" in value and "snat_rules.py" in str(
            value["ansible.builtin.command"]
        ):
            value["environment"] = (
                "{{ hostvars[_sdn_snat_node.host].fixture_environment }}"
            )
        return {key: adapt(item) for key, item in value.items()}

    for source in (ROLE / "tasks/include/network").glob("*.yaml"):
        (role / "tasks/include/network" / source.name).write_text(
            yaml.safe_dump(adapt(yaml.safe_load(source.read_text())), sort_keys=False)
        )
    (role / "tasks/main.yml").write_text(
        (
            yaml.safe_dump(fixture_role_tasks, sort_keys=False)
            if fixture_role_tasks
            else ""
        )
        + """- ansible.builtin.include_tasks: include/network/count_network_snat_source.yaml
  when: proxmox_vm_action == 'network_count_snat_source'
- ansible.builtin.include_tasks: include/network/apply_network_sdn.yaml
  when: proxmox_vm_action == 'network_apply_sdn'
- ansible.builtin.include_tasks: include/network/preserve_network_snat_rules.yaml
  when: proxmox_vm_action in ['network_snapshot_snat_rules', 'network_restore_snat_snapshot', 'network_reconcile_snat_sources']
"""
    )
    library = tmp_path / "library"
    library.mkdir()
    (
        library / "range42_fixture_api.py"
    ).write_text("""from ansible.module_utils.basic import AnsibleModule
import json,pathlib,urllib.parse
m=AnsibleModule(argument_spec={'url':{'type':'str'},'method':{'type':'str'},'fixture_file':{'type':'str'}})
fixture=json.loads(pathlib.Path(m.params['fixture_file']).read_text());url=urllib.parse.urlsplit(m.params['url']);path=url.path;query=urllib.parse.parse_qs(url.query)
marker=pathlib.Path(fixture['apply_marker'])
if path.endswith('/cluster/status'): data=fixture['status']
elif path.endswith('/cluster/sdn/zones'): data=fixture['zones']
elif path.endswith('/access/permissions'):
 aclpath=query['path'][0];data={aclpath:{} if fixture['denied_audit'] and aclpath=='/nodes/pve2' else {'Sys.Audit':0}}
elif path.endswith('/cluster/sdn') and m.params['method']=='PUT':
 marker.touch()
 for entry in fixture['nodes'].values():
  file=pathlib.Path(entry['state']);rules=json.loads(file.read_text());rules.extend([rules[1],rules[2]]);file.write_text(json.dumps(rules))
 data='UPID:pve1:111:1:499602D2:reloadnetworkall::root@pam:'
elif '/tasks/' in path and path.endswith('/status'): data={'status':'stopped','exitstatus':'OK'}
elif path.endswith('/tasks'):
 node=path.split('/')[4];data=[]
 recent=pathlib.Path(fixture['polls']+'-recent-'+node)
 if not marker.exists() and query.get('source')!=['active']: recent.write_text(str(int(recent.read_text())+1 if recent.exists() else 1))
 drift=fixture['intervening_reload'] or (fixture['intervening_before_put'] and recent.exists() and int(recent.read_text())>=2)
 if drift and node=='pve2' and query.get('source')!=['active']:
  data=[{'upid':f'UPID:{node}:222:1:499602D3:srvreload:networking:root@pam:','node':node,'type':'srvreload','id':'networking','starttime':1234567891,'endtime':1234567892,'status':'OK'}]
 if marker.exists() and query.get('source')!=['active'] and not(fixture['missing'] and node=='pve2'):
  poll=pathlib.Path(fixture['polls']+'-'+node);count=int(poll.read_text())+1 if poll.exists() else 1;poll.write_text(str(count))
  row={'upid':f'UPID:{node}:222:1:499602D3:srvreload:networking:root@pam:','node':node,'type':'srvreload','id':'networking','starttime':1234567891}
  if not(fixture['delayed'] and node=='pve2' and count==1): row.update(endtime=1234567892,status='ERROR' if fixture['failed'] and node=='pve2' else 'OK')
  data=[row]
  if fixture['ambiguous'] and node=='pve2': data.append({**row,'upid':row['upid'].replace(':222:',':333:')})
  if row.get('status')=='OK': pathlib.Path(fixture['worker_marker']+node).touch()
else: m.fail_json(msg='Unexpected fixture API path')
m.exit_json(changed=False,status=200,json={'data':data})
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
                        "proxmox_cli": {"hosts": hosts},
                    },
                }
            }
        )
    )
    tasks = []
    for action in actions or (
        "network_snapshot_snat_rules",
        "network_apply_sdn",
        "network_reconcile_snat_sources",
        "network_restore_snat_snapshot",
    ):
        if action == "network_reconcile_snat_sources" and before_reconcile:
            tasks.extend(before_reconcile(document))
        task = {
            "ansible.builtin.include_role": {"name": role.name},
            "vars": {"proxmox_vm_action": action},
        }
        if action == "network_apply_sdn" and recover_failed_apply:
            task = {
                "block": [task],
                "rescue": [{"ansible.builtin.debug": {"msg": "apply refused"}}],
            }
        tasks.append(task)
    if caller_tasks is not None:
        tasks = deepcopy(caller_tasks)
    observed = tmp_path / "observed.json"
    tasks.append(
        {
            "ansible.builtin.copy": {
                "dest": str(observed),
                "content": "{{ {'snapshot_verified': network_snat_snapshot_verified | default(none), 'apply_attempted': network_snat_apply_attempted | default(none), 'apply_verified': network_snat_apply_verified | default(none)} | to_json }}",
                "mode": "0600",
            }
        }
    )
    play = [
        {
            "hosts": "proxmox",
            "gather_facts": False,
            "vars": {
                "proxmox_node": "pve1",
                "proxmox_api_host": "fixture.invalid",
                "proxmox_api_user": "fixture",
                "proxmox_api_token_id": "fixture",
                "proxmox_api_token_secret": "not-a-secret",
                "sdn_snat_node_hosts": None
                if single_node
                else mapping
                if mapping is not None
                else {"pve1": "ssh1", "pve2": "ssh2"},
                "sdn_snat_desired_sources": [
                    {
                        "source": TARGET,
                        "vnet": "net1",
                        "zone": "lab",
                        "want": target_want,
                    }
                ],
                "sdn_apply_poll_retries": 2,
                "sdn_apply_poll_delay": 0,
            },
            "tasks": tasks,
        }
    ]
    if single_node:
        del play[0]["vars"]["sdn_snat_node_hosts"]
    playbook = tmp_path / "playbook.yml"
    playbook.write_text(yaml.safe_dump(play, sort_keys=False))
    result = subprocess.run(
        [
            str(Path(sys.executable).with_name("ansible-playbook")),
            "-i",
            str(inventory),
            str(playbook),
        ],
        env={
            **os.environ,
            "ANSIBLE_ROLES_PATH": str(tmp_path / "roles"),
            "ANSIBLE_LIBRARY": str(library),
            "ANSIBLE_NOCOLOR": "1",
        },
        capture_output=True,
        text=True,
        timeout=90,
    )
    return result, document


def test_real_ansible_preserves_every_node_and_reconciles_only_zone_members(tmp_path):
    result, fixture = run_cluster(tmp_path, delayed=True)
    assert result.returncode == 0, result.stdout[-6000:] + result.stderr
    assert json.loads(Path(fixture["nodes"]["pve1"]["state"]).read_text()) == [
        UNRELATED,
        OTHER_RULE,
    ]
    assert json.loads(Path(fixture["nodes"]["pve2"]["state"]).read_text()) == [
        UNRELATED,
        OTHER_RULE,
        TARGET_RULE,
    ]
    assert int(Path(fixture["polls"] + "-pve2").read_text()) >= 2


@pytest.mark.parametrize(
    "arguments",
    [{"mapping": {"pve1": "ssh1"}}, {"offline": True}, {"wrong_host": True}],
)
def test_missing_offline_or_wrong_ssh_node_refuses_before_any_global_write(
    tmp_path, arguments
):
    result, fixture = run_cluster(tmp_path, **arguments)
    assert result.returncode != 0
    assert not Path(fixture["apply_marker"]).exists()
    assert all(
        json.loads(Path(node["writes"]).read_text()) == []
        for node in fixture["nodes"].values()
    )


@pytest.mark.parametrize("fault", ["failed", "missing", "ambiguous"])
def test_unverified_second_node_reload_prevents_cleanup_on_every_node(tmp_path, fault):
    result, fixture = run_cluster(tmp_path, **{fault: True})
    assert result.returncode != 0
    assert Path(fixture["apply_marker"]).exists(), result.stdout[-5000:]
    assert "SDN node reload could not be verified on pve2" in result.stdout
    assert all(
        json.loads(Path(node["writes"]).read_text()) == []
        for node in fixture["nodes"].values()
    )


def test_apply_requires_a_complete_saved_snapshot_before_put(tmp_path):
    result, fixture = run_cluster(tmp_path, actions=["network_apply_sdn"])
    assert result.returncode != 0
    assert not Path(fixture["apply_marker"]).exists()


def test_restore_cannot_bypass_reload_completion(tmp_path):
    result, fixture = run_cluster(
        tmp_path,
        actions=["network_snapshot_snat_rules", "network_restore_snat_snapshot"],
    )
    assert result.returncode != 0
    assert (
        "Every covered node must finish its verified SDN reload before cleanup"
        in result.stdout
    )
    assert all(
        json.loads(Path(node["writes"]).read_text()) == []
        for node in fixture["nodes"].values()
    )


@pytest.mark.parametrize(
    "fault", ["denied_audit", "intervening_reload", "intervening_before_put"]
)
def test_incomplete_task_visibility_or_snapshot_drift_prevents_apply(tmp_path, fault):
    result, fixture = run_cluster(tmp_path, **{fault: True})
    assert result.returncode != 0
    assert not Path(fixture["apply_marker"]).exists(), result.stdout[-5000:]
    assert all(
        json.loads(Path(node["writes"]).read_text()) == []
        for node in fixture["nodes"].values()
    )


def test_single_node_default_mapping_still_waits_before_cleanup(tmp_path):
    result, fixture = run_cluster(tmp_path, single_node=True)
    assert result.returncode == 0, result.stdout[-5000:] + result.stderr
    assert json.loads(Path(fixture["nodes"]["pve1"]["state"]).read_text()) == [
        UNRELATED,
        OTHER_RULE,
    ]
    assert Path(fixture["worker_marker"] + "pve1").exists()


@pytest.mark.parametrize("want", [0, 1])
def test_stable_snapshot_reconciles_without_claiming_apply_completion(tmp_path, want):
    result, fixture = run_cluster(
        tmp_path,
        actions=["network_snapshot_snat_rules", "network_reconcile_snat_sources"],
        target_want=want,
        duplicate_target=True,
    )
    assert result.returncode == 0, result.stdout[-6000:] + result.stderr
    assert not Path(fixture["apply_marker"]).exists()
    assert json.loads(Path(fixture["nodes"]["pve1"]["state"]).read_text()) == [
        UNRELATED,
        OTHER_RULE,
        *([TARGET_RULE] if want else []),
    ]
    assert json.loads(Path(fixture["nodes"]["pve2"]["state"]).read_text()) == [
        UNRELATED,
        OTHER_RULE,
        TARGET_RULE,
        TARGET_RULE,
    ]
    assert json.loads((tmp_path / "observed.json").read_text()) == {
        "snapshot_verified": True,
        "apply_attempted": False,
        "apply_verified": False,
    }


@pytest.mark.parametrize("fault", ["failed", "missing", "ambiguous"])
def test_rescued_unverified_apply_cannot_use_stable_reconcile(tmp_path, fault):
    result, fixture = run_cluster(
        tmp_path,
        actions=[
            "network_snapshot_snat_rules",
            "network_apply_sdn",
            "network_reconcile_snat_sources",
        ],
        recover_failed_apply=True,
        **{fault: True},
    )
    assert result.returncode != 0
    assert Path(fixture["apply_marker"]).exists(), result.stdout[-5000:]
    assert "apply refused" in result.stdout
    assert "An unknown or incomplete apply cannot authorize cleanup" in result.stdout
    assert all(
        json.loads(Path(node["writes"]).read_text()) == []
        for node in fixture["nodes"].values()
    )


@pytest.mark.parametrize("fault", ["membership", "zone", "audit", "reload"])
def test_stable_reconcile_revalidates_snapshot_before_any_node_write(tmp_path, fault):
    def drift(document):
        changed = deepcopy(document)
        if fault == "membership":
            changed["status"][1]["online"] = 0
        elif fault == "zone":
            changed["zones"][0]["nodes"] = "pve1,pve2"
        elif fault == "audit":
            changed["denied_audit"] = True
        else:
            changed["intervening_reload"] = True
        return [
            {
                "ansible.builtin.copy": {
                    "dest": str(tmp_path / "api.json"),
                    "content": json.dumps(changed),
                    "mode": "0600",
                }
            }
        ]

    result, fixture = run_cluster(
        tmp_path,
        actions=["network_snapshot_snat_rules", "network_reconcile_snat_sources"],
        before_reconcile=drift,
    )
    assert result.returncode != 0
    assert not Path(fixture["apply_marker"]).exists()
    assert all(
        json.loads(Path(node["writes"]).read_text()) == []
        for node in fixture["nodes"].values()
    )


@pytest.mark.parametrize(
    "facts",
    [
        {"network_snat_snapshot_verified": None},
        {"network_snat_apply_attempted": None},
        {"network_snat_snapshots": {}},
        {"network_snat_reload_baseline": {}},
    ],
)
def test_stable_reconcile_refuses_unknown_or_incomplete_snapshot_facts(tmp_path, facts):
    result, fixture = run_cluster(
        tmp_path,
        actions=["network_snapshot_snat_rules", "network_reconcile_snat_sources"],
        before_reconcile=lambda _: [{"ansible.builtin.set_fact": facts}],
    )
    assert result.returncode != 0
    assert (
        "Cleanup requires a fresh verified snapshot" in result.stdout
        or "An unknown or incomplete apply cannot authorize cleanup" in result.stdout
    )
    assert all(
        json.loads(Path(node["writes"]).read_text()) == []
        for node in fixture["nodes"].values()
    )


def test_failed_new_snapshot_invalidates_previous_stable_reconcile_authorization(
    tmp_path,
):
    def failed_snapshot(document):
        changed = deepcopy(document)
        changed["status"][1]["online"] = 0

        def replace_api(contents):
            return {
                "ansible.builtin.copy": {
                    "dest": str(tmp_path / "api.json"),
                    "content": json.dumps(contents),
                    "mode": "0600",
                }
            }

        return [
            replace_api(changed),
            {
                "block": [
                    {
                        "ansible.builtin.include_role": {"name": ROLE.name},
                        "vars": {"proxmox_vm_action": "network_snapshot_snat_rules"},
                    }
                ],
                "rescue": [{"ansible.builtin.debug": {"msg": "new snapshot refused"}}],
            },
            replace_api(document),
        ]

    result, fixture = run_cluster(
        tmp_path,
        actions=["network_snapshot_snat_rules", "network_reconcile_snat_sources"],
        before_reconcile=failed_snapshot,
    )
    assert result.returncode != 0
    assert "new snapshot refused" in result.stdout
    assert "Cleanup requires a fresh verified snapshot" in result.stdout
    assert all(
        json.loads(Path(node["writes"]).read_text()) == []
        for node in fixture["nodes"].values()
    )
