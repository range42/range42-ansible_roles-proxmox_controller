from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import json
import os
import ssl
import subprocess
import threading

import pytest
import yaml

ROOT=Path(__file__).resolve().parents[1]
TASK=ROOT/'roles/range42-ansible_roles-proxmox_controller/tasks/include/storage/iso_download.yaml'

@pytest.mark.parametrize('outcome',['OK','download failed','missing-task','cached'])
def test_native_image_download_is_verified_before_the_caller_imports_the_file(tmp_path,outcome):
    certificate=tmp_path/'server.crt';key=tmp_path/'server.key'
    subprocess.run(['openssl','req','-x509','-nodes','-newkey','rsa:2048','-keyout',str(key),'-out',str(certificate),
        '-days','1','-subj','/CN=127.0.0.1','-addext','subjectAltName=IP:127.0.0.1'],check=True,capture_output=True)
    polls=[];downloads=[]
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def reply(self,value):
            body=json.dumps({'data':value}).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(body)
        def do_POST(self):
            downloads.append(self.path);self.rfile.read(int(self.headers.get('Content-Length',0)))
            self.reply(None if outcome=='missing-task' else 'UPID:fixture:00000001:00000001:00000001:download:image:fixture@pam!api:')
        def do_GET(self):
            if self.path.endswith('/content'):
                self.reply([{'volid':'local:iso/image.img','size':12345}] if outcome=='cached' else []);return
            polls.append(self.path);self.reply({'status':'running'} if len(polls)==1 else {'status':'stopped','exitstatus':outcome})
    server=HTTPServer(('127.0.0.1',0),Handler);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(certificate,key);server.socket=context.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    sentinel=tmp_path/'caller-continued'
    play=tmp_path/'play.yml';play.write_text(yaml.safe_dump([{'hosts':'localhost','gather_facts':False,'vars':{
        'ansible_connection':'local','ansible_python_interpreter':os.sys.executable,
        'proxmox_vm_action':'storage_download_iso','proxmox_api_host':f'127.0.0.1:{server.server_port}',
        'proxmox_node':'fixture','proxmox_storage':'local','proxmox_api_user':'fixture@pam',
        'proxmox_api_token_id':'api','proxmox_api_token_secret':'PUBLIC-FIXTURE-ONLY',
        'proxmox_api_validate_certs':True,'iso_file_content_type':'iso','iso_file_name':'image.img','iso_url':'https://example.invalid/image.img',
        'image_download_poll_retries':3,'image_download_poll_delay':0},'tasks':[
            {'ansible.builtin.include_tasks':str(TASK)},
            {'ansible.builtin.copy':{'dest':str(sentinel),'content':'import can begin'}}]}]))
    env={k:v for k,v in os.environ.items() if not k.startswith('ANSIBLE_')};env['SSL_CERT_FILE']=str(certificate)
    try:r=subprocess.run(['ansible-playbook','-i','localhost,',str(play)],capture_output=True,text=True,env=env,timeout=30)
    finally:server.shutdown();server.server_close();thread.join()
    if outcome=='cached':
        assert r.returncode==0,r.stdout+r.stderr
        assert sentinel.exists() and downloads==[] and polls==[]
    elif outcome=='OK':
        assert r.returncode==0,r.stdout+r.stderr
        assert len(polls)>=2,'Native controller returned before the asynchronous download finished'
        assert sentinel.exists()
    else:
        assert r.returncode!=0,'The caller continued after an unverified or failed image download'
        assert not sentinel.exists()
