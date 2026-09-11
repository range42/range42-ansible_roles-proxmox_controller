"""Actual bounded CLI collector with a private pvesh/host OS boundary."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from test_sdn_delete_scope import document
from test_snat_cluster import HELPER


def run_collector(tmp_path, *, uid="0", hostname="pve1", fault=None):
    request = document()
    request.update(
        uid=uid, hostname=hostname, fault=fault, calls=str(tmp_path / "calls.json")
    )
    if fault == "aggregate":
        for vmid in (101, 102):
            request["guests"].append({"vmid": vmid, "type": "qemu", "node": "pve2"})
            request["guest_configs"][f"qemu/{vmid}"] = request["guest_configs"][
                "qemu/100"
            ]
    source = tmp_path / "fixture.json"
    source.write_text(json.dumps(request))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "fixture"
    script.write_text(
        f"#!{sys.executable}\n"
        + """import json,os,pathlib,sys,subprocess,time
fixture=json.loads(pathlib.Path(os.environ['DELETE_FIXTURE']).read_text())
name=pathlib.Path(sys.argv[0]).name
if name=='id': print(fixture['uid']);raise SystemExit
if name=='hostname': print(fixture['hostname']);raise SystemExit
calls=pathlib.Path(fixture['calls']);history=json.loads(calls.read_text()) if calls.exists() else [];history.append(sys.argv[1:]);calls.write_text(json.dumps(history))
assert sys.argv[1]=='get' and sys.argv[-2:]==['--output-format','json']
path=sys.argv[2];fault=fixture['fault']
if fault=='oversize': print('x'*5000000);raise SystemExit
if fault=='failure': raise SystemExit(1)
if fault=='timeout':
 child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])
 pathlib.Path(fixture['calls']+'.child').write_text(str(child.pid));time.sleep(60)
if path=='/cluster/status': value=fixture['status']
elif path.endswith('/certificates/info'):
 value=[{'filename':'pve-root-ca.pem','fingerprint':':'.join(['AB']*32)}]
 if fault=='missing_ca': value=[]
 if fault=='duplicate_ca': value=value*2
 if fault=='bad_ca': value[0]['fingerprint']='not-a-sha256'
elif path=='/cluster/sdn': value=[{'id':x} for x in fixture['features']]
elif path=='/cluster/resources':
 value=fixture['guests']
 if fault=='guest_drift' and sum(row[1]=='/cluster/resources' for row in history)>1: value=[]
elif path.endswith('/config') or path.endswith('/pending'):
 parts=path.split('/');entry=fixture['guest_configs'][parts[3]+'/'+parts[4]]
 value=entry['current' if parts[-1]=='config' else 'pending']
 if fault=='missing_config': value=None
 if fault=='aggregate': value={'memo':'x'*3000000} if parts[-1]=='config' else [{'key':'memo','value':'x'*3000000}]
elif path.endswith('/subnets'):
 value=fixture['subnets'][path.split('/')[-2]]
else: value=fixture['families'][path.split('/')[-1]]
print(json.dumps(value))
"""
    )
    script.chmod(0o700)
    for name in ("id", "hostname", "pvesh"):
        (bin_dir / name).symlink_to(script)
    result = subprocess.run(
        [sys.executable, str(HELPER), "read-delete"],
        input=json.dumps({"zone": "lab", "node": "pve1"}),
        text=True,
        capture_output=True,
        env={**os.environ, "PATH": str(bin_dir), "DELETE_FIXTURE": str(source)},
        timeout=15,
    )
    calls = (
        json.loads((tmp_path / "calls.json").read_text())
        if (tmp_path / "calls.json").exists()
        else []
    )
    return result, calls


def test_collector_uses_only_get_and_reads_both_guest_configurations(tmp_path):
    result, calls = run_collector(tmp_path)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["scope"]["vnets"] == ["target"]
    assert (
        json.loads(result.stdout)["scope"]["cluster_identity"]
        == "pve-root-ca-sha256:" + "ab" * 32
    )
    assert all(row[0] == "get" for row in calls)
    assert [
        "get",
        "/nodes/pve2/qemu/100/config",
        "--current",
        "1",
        "--output-format",
        "json",
    ] in calls
    assert ["get", "/nodes/pve2/qemu/100/pending", "--output-format", "json"] in calls
    assert sum(row[1] == "/cluster/resources" for row in calls) == 2
    assert "guest_configs" not in result.stdout


@pytest.mark.parametrize(
    "options",
    [
        {"uid": "1000"},
        {"hostname": "other"},
        {"fault": "failure"},
        {"fault": "oversize"},
        {"fault": "guest_drift"},
        {"fault": "missing_config"},
        {"fault": "missing_ca"},
        {"fault": "duplicate_ca"},
        {"fault": "bad_ca"},
        {"fault": "aggregate"},
    ],
)
def test_collector_rejects_unproven_visibility_and_bounded_failures(tmp_path, options):
    result, calls = run_collector(tmp_path, **options)
    assert result.returncode != 0
    assert result.stdout == ""
    assert all(row[0] == "get" for row in calls)
    if "uid" in options or "hostname" in options:
        assert not calls


def test_timed_out_inventory_reaps_the_read_command_process_group(tmp_path):
    import signal
    import time

    result, _ = run_collector(tmp_path, fault="timeout")
    assert result.returncode != 0
    pid = int((tmp_path / "calls.json.child").read_text())
    time.sleep(0.1)
    state = Path(f"/proc/{pid}/stat")
    alive = state.exists() and state.read_text().split(") ", 1)[1][0] != "Z"
    if alive:
        os.kill(pid, signal.SIGKILL)
    assert not alive, "Timed-out pvesh descendants must not survive the read"
