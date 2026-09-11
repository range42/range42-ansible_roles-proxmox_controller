"""Inspect the actual zone POST over private TLS; never contact a Proxmox host."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest
import yaml

from test_snat_cluster import INVALID_CLUSTER_ROWS

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "roles/range42-ansible_roles-proxmox_controller"
NODES = ["pve1", "pve2"]


@contextmanager
def zone_api(tmp_path, *, status=None):
    if status is None:
        status = [{"type": "node", "name": node, "online": 1} for node in NODES] + [
            {"type": "cluster", "name": "fixture", "nodes": len(NODES), "quorate": 1}
        ]
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    ca, private = tmp_path / "ca.pem", tmp_path / "key.pem"
    ca.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private.chmod(0o600)
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def respond(self, data, status=200):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"data": data}).encode())

        def do_GET(self):
            if self.path != "/api2/json/cluster/status":
                self.respond({}, 404)
                return
            self.respond(status)

        def do_POST(self):
            assert self.path == "/api2/json/cluster/sdn/zones"
            calls.append(
                json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            )
            self.respond(None)

    api = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ca, private)
    api.socket = context.wrap_socket(api.socket, server_side=True)
    thread = threading.Thread(target=api.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"127.0.0.1:{api.server_port}", ca, calls
    finally:
        api.shutdown()
        thread.join()
        api.server_close()


def run_zone(tmp_path, host, ca, membership, *, saved=None):
    variables = {
        "proxmox_api_host": host,
        "proxmox_api_user": "fixture",
        "proxmox_api_token_id": "fixture",
        "proxmox_api_token_secret": "fixture",
        "proxmox_api_validate_certs": True,
        "proxmox_node": "pve1",
        "sdn_zone": "lab",
        "sdn_zone_nodes": membership,
        "role_path": str(ROLE),
        "proxmox_vm_action": "network_add_sdn_zone",
    }
    if saved is not None:
        variables.update(
            network_snat_snapshot_verified=True,
            network_snat_plan={"nodes": [{"node": node} for node in NODES]},
            network_snat_plan_input={"new_zones": {"lab": saved}},
        )
    inventory = tmp_path / "hosts.ini"
    inventory.write_text(
        f"api ansible_connection=local ansible_python_interpreter={sys.executable}\n"
    )
    play = tmp_path / "zone.yml"
    play.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": "api",
                    "gather_facts": False,
                    "vars": variables,
                    "tasks": [
                        {
                            "ansible.builtin.include_tasks": str(
                                ROLE / "tasks/include/network/add_network_sdn_zone.yaml"
                            )
                        }
                    ],
                }
            ]
        )
    )
    return subprocess.run(
        [
            str(Path(sys.executable).with_name("ansible-playbook")),
            "-i",
            str(inventory),
            str(play),
        ],
        env={**os.environ, "SSL_CERT_FILE": str(ca), "ANSIBLE_NOCOLOR": "1"},
        text=True,
        capture_output=True,
        timeout=25,
    )


@pytest.mark.parametrize(
    "membership,expected",
    [
        (["pve2"], "pve2"),
        ("pve2", "pve2"),
        ([], None),
        (None, None),
        (["pve2", "pve1"], None),
        ("pve2,pve1", None),
    ],
)
def test_zone_post_normalizes_membership_to_api_string_or_omits_all_nodes(
    tmp_path, membership, expected
):
    with zone_api(tmp_path) as (host, ca, calls):
        result = run_zone(tmp_path, host, ca, membership)
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr
    assert calls == [
        {"zone": "lab", "type": "simple", **({"nodes": expected} if expected else {})}
    ]


@pytest.mark.parametrize(
    "membership", [["pve3"], ["pve1", "pve1"], [1], {"pve1": True}]
)
def test_invalid_membership_is_rejected_before_zone_post(tmp_path, membership):
    with zone_api(tmp_path) as (host, ca, calls):
        result = run_zone(tmp_path, host, ca, membership)
    assert result.returncode != 0
    assert calls == []


def test_zone_post_rejects_membership_changed_since_verified_snapshot(tmp_path):
    with zone_api(tmp_path) as (host, ca, calls):
        result = run_zone(tmp_path, host, ca, ["pve2"], saved=["pve1"])
    assert result.returncode != 0
    assert calls == []


@pytest.mark.parametrize(
    "cluster_rows",
    INVALID_CLUSTER_ROWS,
    ids=[
        "missing",
        "incomplete",
        "duplicate",
        "nonquorate",
        "float-quorum",
        "float-nodes",
        "wrong-count",
    ],
)
def test_zone_post_requires_complete_multinode_quorum_evidence(tmp_path, cluster_rows):
    status = [
        {"type": "node", "name": node, "online": 1} for node in NODES
    ] + cluster_rows
    with zone_api(tmp_path, status=status) as (host, ca, calls):
        result = run_zone(tmp_path, host, ca, ["pve2"])
    assert result.returncode != 0
    assert calls == []


def test_standalone_zone_creation_needs_no_cluster_record(tmp_path):
    with zone_api(tmp_path, status=[{"type": "node", "name": "pve1", "online": 1}]) as (
        host,
        ca,
        calls,
    ):
        result = run_zone(tmp_path, host, ca, None)
    assert result.returncode == 0, result.stdout[-4000:] + result.stderr
    assert calls == [{"zone": "lab", "type": "simple"}]
