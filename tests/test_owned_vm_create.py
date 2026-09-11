"""Strict template creation must neither adopt a foreign VM nor lose ownership."""

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
from urllib.parse import parse_qs

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
TASKS = (
    ROOT
    / "roles/range42-ansible_roles-proxmox_controller/tasks/include/vm/vm_create.yaml"
)


@contextmanager
def api(tmp_path, get_status, post_status=200, state_path=None):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
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
            False,
        )
        .sign(key, hashes.SHA256())
    )
    ca, private = tmp_path / "ca.pem", tmp_path / "key.pem"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
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

        def reply(self, status, data=None):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"data": data}).encode())

        def do_GET(self):
            if state_path:
                state = json.loads(state_path.read_text())
                if self.path.endswith("/config"):
                    self.reply(200, state["config"])
                elif self.path.endswith("/certificates/info"):
                    self.reply(
                        200,
                        [
                            {
                                "filename": "pve-root-ca.pem",
                                "fingerprint": state.get(
                                    "api_fingerprint", ":".join(["AA"] * 32)
                                ),
                            }
                        ],
                    )
                elif "/tasks/" in self.path:
                    self.reply(200, {"status": "stopped", "exitstatus": "OK"})
                else:
                    self.reply(
                        200 if state["exists"] else 500,
                        {"status": state.get("status", "stopped")},
                    )
            else:
                self.reply(get_status)

        def do_POST(self):
            data = {
                key: values[0]
                for key, values in parse_qs(
                    self.rfile.read(int(self.headers["Content-Length"])).decode()
                ).items()
            }
            calls.append(data)
            if state_path:
                state = json.loads(state_path.read_text())
                if self.path.endswith("/qemu"):
                    state.update(exists=True, config={**data, "template": 0})
                elif self.path.endswith("/config"):
                    state["config"].update(data)
                elif self.path.endswith("/status/stop"):
                    state["status"] = "stopped"
                state["commands"].append(["API", self.command, self.path])
                state_path.write_text(json.dumps(state))
            self.reply(post_status)

        do_PUT = do_POST

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ca, private)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, ca, calls
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def create(tmp_path, port, ca, **overrides):
    variables = {
        "proxmox_vm_action": "vm_create",
        "proxmox_api_host": f"127.0.0.1:{port}",
        "proxmox_api_user": "test@pve",
        "proxmox_api_token_id": "test",
        "proxmox_api_token_secret": "test",
        "proxmox_api_validate_certs": True,
        "proxmox_node": "pve",
        "vm_id": 62000,
        "vm_name": "owned-template",
        "vm_cpu": "host",
        "vm_cores": 1,
        "vm_sockets": 1,
        "vm_memory": 1024,
        "vm_create_require_absent": True,
        "vm_description": "range42-template-build:1234567890abcdef1234567890abcdef",
        **overrides,
    }
    playbook = tmp_path / "create.yml"
    playbook.write_text(
        yaml.safe_dump(
            [
                {
                    "hosts": "localhost",
                    "gather_facts": False,
                    "vars": variables,
                    "tasks": [{"ansible.builtin.include_tasks": str(TASKS)}],
                }
            ]
        )
    )
    return subprocess.run(
        [
            str(Path(sys.executable).with_name("ansible-playbook")),
            "-i",
            "localhost,",
            "-c",
            "local",
            str(playbook),
        ],
        env={**os.environ, "SSL_CERT_FILE": str(ca), "ANSIBLE_NOCOLOR": "1"},
        capture_output=True,
        text=True,
        timeout=45,
    )


def test_strict_create_carries_marker_in_atomic_post(tmp_path):
    with api(tmp_path, 500) as (port, ca, calls):
        result = create(tmp_path, port, ca)
    assert result.returncode == 0, result.stdout[-2000:]
    assert (
        calls[0].get("description")
        == "range42-template-build:1234567890abcdef1234567890abcdef"
    )


def test_strict_create_accepts_and_preserves_the_bound_plan_digest(tmp_path):
    marker = (
        "range42-template-build:" + "a" * 32 + "\nrange42-template-plan:" + "b" * 64
    )
    with api(tmp_path, 500) as (port, ca, calls):
        result = create(tmp_path, port, ca, vm_description=marker)
    assert result.returncode == 0, result.stdout[-2000:]
    assert calls[0]["description"] == marker


@pytest.mark.parametrize("status", [200, 401, 403, 503])
def test_strict_create_refuses_existing_or_unreadable_target(tmp_path, status):
    with api(tmp_path, status) as (port, ca, calls):
        result = create(tmp_path, port, ca)
    assert result.returncode != 0
    assert calls == []


def test_strict_create_does_not_hide_atomic_conflict(tmp_path):
    with api(tmp_path, 500, 409) as (port, ca, calls):
        result = create(tmp_path, port, ca)
    assert result.returncode != 0
    assert len(calls) == 1


def test_default_create_retains_existing_vm_noop(tmp_path):
    with api(tmp_path, 200) as (port, ca, calls):
        result = create(tmp_path, port, ca, vm_create_require_absent=False)
    assert result.returncode == 0, result.stdout[-2000:]
    assert calls == []
