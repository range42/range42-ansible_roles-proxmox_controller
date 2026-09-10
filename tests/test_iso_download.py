"""Exercise ISO caching on a custom storage path against a local TLS API."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
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

ROOT = Path(__file__).resolve().parents[1]
TASKS = ROOT / "roles/range42-ansible_roles-proxmox_controller/tasks/include/storage/iso_download.yaml"
IMAGE = b"verified cloud image fixture"


@contextmanager
def server(tmp_path, image_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
                   .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
                   .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    ca, private = tmp_path / "ca.pem", tmp_path / "key.pem"
    ca.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    private.chmod(0o600)
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain" if self.path.endswith("SUMS") else "application/json")
            self.end_headers()
            if self.path.endswith("SHA256SUMS"):
                self.wfile.write(f"{hashlib.sha256(IMAGE).hexdigest()}  cloud.qcow2\n".encode())
            else:
                self.wfile.write(json.dumps({"data": {"status": "stopped", "exitstatus": "OK"}}).encode())
        def do_POST(self):
            body = {key: value[0] for key, value in parse_qs(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()).items()}
            calls.append(body)
            image_path.parent.mkdir(parents=True, exist_ok=True)
            image_path.write_bytes(IMAGE)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"data":"UPID:local:download"}')
    api = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ca, private)
    api.socket = context.wrap_socket(api.socket, server_side=True)
    thread = threading.Thread(target=api.serve_forever, daemon=True)
    thread.start()
    try:
        yield api.server_port, ca, calls
    finally:
        api.shutdown()
        thread.join()
        api.server_close()


def download(tmp_path, port, ca, image_path):
    binaries = tmp_path / "bin"
    binaries.mkdir(exist_ok=True)
    pvesm = binaries / "pvesm"
    pvesm.write_text(f'#!{sys.executable}\nimport os\nprint(os.environ["ISO_TEST_PATH"])\n')
    pvesm.chmod(0o700)
    inventory = tmp_path / "hosts.ini"
    inventory.write_text(f"pve ansible_connection=local ansible_python_interpreter={sys.executable}\npve-cli ansible_connection=local ansible_python_interpreter={sys.executable}\n")
    playbook = tmp_path / "download.yml"
    playbook.write_text(f'''- hosts: pve
  gather_facts: false
  vars:
    proxmox_vm_action: storage_download_iso
    proxmox_api_host: 127.0.0.1:{port}
    proxmox_api_user: test@pve
    proxmox_api_token_id: test
    proxmox_api_token_secret: test
    proxmox_api_validate_certs: true
    proxmox_node: pve
    proxmox_storage: custom-iso
    iso_file_content_type: iso
    iso_file_name: cloud.qcow2
    iso_url: https://127.0.0.1:{port}/images/cloud.qcow2
  tasks:
    - ansible.builtin.include_tasks: {TASKS}
''')
    env = {**os.environ, "PATH": f"{binaries}:{os.environ['PATH']}", "ISO_TEST_PATH": str(image_path),
           "SSL_CERT_FILE": str(ca), "RANGE42_PROXMOX_CA_FILE": str(ca), "ANSIBLE_NOCOLOR": "1"}
    return subprocess.run([str(Path(sys.executable).with_name("ansible-playbook")), "-i", str(inventory), str(playbook)],
                          env=env, text=True, capture_output=True, timeout=60)


@pytest.mark.parametrize("initial", [IMAGE, b"stale image", None])
def test_download_reuses_verified_cache_and_repairs_stale_custom_storage(tmp_path, initial):
    image_path = tmp_path / "custom-storage/iso/cloud.qcow2"
    if initial is not None:
        image_path.parent.mkdir(parents=True)
        image_path.write_bytes(initial)
    with server(tmp_path, image_path) as (port, ca, calls):
        first = download(tmp_path, port, ca, image_path)
        assert first.returncode == 0, first.stdout[-5000:] + first.stderr
        assert len(calls) == (0 if initial == IMAGE else 1)
        assert image_path.read_bytes() == IMAGE
        if calls:
            assert calls[0]["checksum"] == hashlib.sha256(IMAGE).hexdigest()
            assert calls[0]["checksum-algorithm"] == "sha256"
        second = download(tmp_path, port, ca, image_path)
        assert second.returncode == 0, second.stdout[-5000:] + second.stderr
        assert len(calls) == (0 if initial == IMAGE else 1)
