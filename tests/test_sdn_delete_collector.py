"""Actual bounded CLI collector with a private pvesh/host OS boundary."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from test_sdn_delete_scope import document
from test_snat_cluster import HELPER


def run_collector(
    tmp_path, *, uid="0", hostname="pve1", fault=None, guest_type="qemu", guest_count=1
):
    request = document()
    request.update(
        uid=uid, hostname=hostname, fault=fault, calls=str(tmp_path / "calls.json")
    )
    original = request["guest_configs"].pop("qemu/100")
    if fault == "current_removal":
        original["pending"][0].update(value="bridge=target", delete=1)
    elif fault == "candidate_attachment":
        original["pending"][0]["pending"] = "bridge=target"
    elif fault == "custom_args":
        original["pending"].append(
            {"key": "args", "value": "-netdev bridge,br=target,id=n0"}
        )
    elif fault == "raw_lxc":
        original["current"]["lxc"] = [["lxc.net.0.link", "target"]]
    request["guests"] = []
    for vmid in range(100, 100 + (6 if fault == "aggregate" else guest_count)):
        request["guests"].append({"vmid": vmid, "type": guest_type, "node": "pve2"})
        request["guest_configs"][f"{guest_type}/{vmid}"] = original
    source = tmp_path / "fixture.json"
    source.write_text(json.dumps(request))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    script = bin_dir / "fixture"
    script.write_text(
        f"#!{sys.executable}\n"
        + """import json,os,pathlib,sys,subprocess,time,fcntl,atexit
fixture=json.loads(pathlib.Path(os.environ['DELETE_FIXTURE']).read_text())
name=pathlib.Path(sys.argv[0]).name
if name=='id': print(fixture['uid']);raise SystemExit
if name=='hostname': print(fixture['hostname']);raise SystemExit
calls=pathlib.Path(fixture['calls'])
with open(str(calls)+'.lock','a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 history=json.loads(calls.read_text()) if calls.exists() else [];history.append(sys.argv[1:]);calls.write_text(json.dumps(history))
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
 if fault in ('parallel','batch_error','batch_timeout'):
  stats=pathlib.Path(str(calls)+'.stats')
  with open(str(calls)+'.lock','a') as lock:
   fcntl.flock(lock,fcntl.LOCK_EX)
   counts=json.loads(stats.read_text()) if stats.exists() else {'active':0,'peak':0}
   counts['active']+=1;counts['peak']=max(counts['peak'],counts['active']);stats.write_text(json.dumps(counts))
  def finish():
   with open(str(calls)+'.lock','a') as lock:
    fcntl.flock(lock,fcntl.LOCK_EX);counts=json.loads(stats.read_text());counts['active']-=1;stats.write_text(json.dumps(counts))
  atexit.register(finish)
  if fault=='parallel': time.sleep(0.2)
  else:
   child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])
   pathlib.Path(str(calls)+'.processes-'+parts[4]).write_text(json.dumps([os.getpid(),child.pid]))
   if fault=='batch_error' and parts[4]=='101': time.sleep(0.1);raise SystemExit(1)
   time.sleep(60)
 value=entry['current' if parts[-1]=='config' else 'pending']
 if fault=='missing_config': value=None
 if fault=='duplicate_json' and parts[-1]=='pending': print('[{"key":"net0","key":"memory","value":"bridge=target"}]');raise SystemExit
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


def test_collector_uses_one_complete_qemu_pending_read_and_get_only(tmp_path):
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
    ] not in calls
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
        {"fault": "duplicate_json"},
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


def test_lxc_keeps_current_read_for_raw_array_configuration(tmp_path):
    result, calls = run_collector(tmp_path, guest_type="lxc")
    assert result.returncode == 0, result.stderr
    assert [
        "get",
        "/nodes/pve2/lxc/100/config",
        "--current",
        "1",
        "--output-format",
        "json",
    ] in calls
    assert ["get", "/nodes/pve2/lxc/100/pending", "--output-format", "json"] in calls


def test_guest_reads_overlap_with_at_most_two_owned_children(tmp_path):
    result, calls = run_collector(tmp_path, fault="parallel", guest_count=4)
    assert result.returncode == 0, result.stderr
    counts = json.loads((tmp_path / "calls.json.stats").read_text())
    assert counts == {"active": 0, "peak": 2}
    assert len([row for row in calls if row[1].endswith("/pending")]) == 4
    assert not any(row[1].endswith("/config") for row in calls)


@pytest.mark.parametrize("fault", ["batch_error", "batch_timeout"])
def test_failed_batch_reaps_every_sibling_and_descendant(tmp_path, fault):
    import signal
    import time

    result, _ = run_collector(tmp_path, fault=fault, guest_count=2)
    assert result.returncode != 0
    records = list(tmp_path.glob("calls.json.processes-*"))
    time.sleep(0.1)
    alive = []
    for record in records:
        for pid in json.loads(record.read_text()):
            state = Path(f"/proc/{pid}/stat")
            if state.exists() and state.read_text().split(") ", 1)[1][0] != "Z":
                alive.append(pid)
                os.kill(pid, signal.SIGKILL)
    assert not alive, f"Batch failure left owned processes alive: {alive}"
    assert len(records) == 2, "Both independent sibling reads must start"


@pytest.mark.parametrize(
    "fault,guest_type",
    [
        ("current_removal", "qemu"),
        ("candidate_attachment", "qemu"),
        ("custom_args", "qemu"),
        ("raw_lxc", "lxc"),
    ],
)
def test_optimized_reads_retain_all_supported_attachment_evidence(
    tmp_path, fault, guest_type
):
    result, calls = run_collector(tmp_path, fault=fault, guest_type=guest_type)
    assert result.returncode != 0
    assert result.stdout == ""
    assert any(row[1].endswith("/pending") for row in calls)
    if guest_type == "lxc":
        assert any(row[1].endswith("/config") for row in calls)
