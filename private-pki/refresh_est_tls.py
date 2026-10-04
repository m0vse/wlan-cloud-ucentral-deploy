"""Refresh native EST HTTPS identity from the deployment's protected ACME store.

Runs on the host, never exports key material, and restarts only the EST service
when the validated certificate/key pair changes. A private journal permits
recovery after interruption; it contains no credentials.
"""
import argparse
import base64
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


def protected(path, directory=False):
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('Unsafe protected TLS storage')


def put(path, data):
    staged = path.with_name(path.name + '.new')
    if staged.exists():
        protected(staged)
        staged.unlink()
    descriptor = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        staged.replace(path)
    finally:
        if staged.exists(): staged.unlink()


def validate(cert, key, hostname):
    subprocess.run(['openssl','x509','-in',str(cert),'-checkend','86400','-noout'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    result = subprocess.run(['openssl','x509','-in',str(cert),'-checkhost',hostname,'-noout'],
                   check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if result.returncode or b'does match certificate' not in result.stdout:
        raise ValueError('TLS hostname mismatch')
    cert_public = subprocess.check_output(['openssl','x509','-in',str(cert),'-pubkey','-noout'],stderr=subprocess.DEVNULL)
    key_public = subprocess.check_output(['openssl','pkey','-in',str(key),'-pubout'],stderr=subprocess.DEVNULL)
    if cert_public != key_public: raise ValueError('TLS certificate/key mismatch')
    subprocess.run(['openssl','pkey','-in',str(key),'-check','-noout'],check=True,
                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


def refresh(acme, hostname, destination, restart):
    acme, destination = Path(acme), Path(destination)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*',hostname): raise ValueError('Invalid TLS hostname')
    protected(acme)
    protected(destination,True)
    lock = os.open(destination/'refresh.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX)
        pending = destination/'refresh.pending'
        # Recovery always restores the previously valid pair before attempting
        # another update. No root/issuer/device key is touched.
        if pending.exists():
            protected(pending)
            for name in ('cert.pem','key.pem'):
                backup=destination/(name+'.previous')
                protected(backup)
                put(destination/name,backup.read_bytes())
            restart()
            pending.unlink()
        matches=[]
        for provider in json.loads(acme.read_text()).values():
            if isinstance(provider,dict):
                for item in provider.get('Certificates',[]):
                    domain=item.get('domain',{})
                    if hostname in [domain.get('main'),*domain.get('sans',[])]: matches.append(item)
        if len(matches)!=1: raise ValueError('Expected one matching ACME identity')
        pair={name:base64.b64decode(matches[0][field],validate=True)
              for name,field in [('cert.pem','certificate'),('key.pem','key')]}
        if any(not 0<len(data)<=65536 for data in pair.values()): raise ValueError('Invalid TLS identity size')
        previous={}
        for name in pair:
            protected(destination/name)
            previous[name]=(destination/name).read_bytes()
        if pair==previous: return False
        with tempfile.TemporaryDirectory(prefix='.tls-validation-',dir=destination) as work:
            staged=Path(work)
            for name,data in pair.items(): put(staged/name,data)
            validate(staged/'cert.pem',staged/'key.pem',hostname)
        for name,data in previous.items(): put(destination/(name+'.previous'),data)
        put(pending,b'validated TLS refresh in progress\n')
        try:
            for name,data in pair.items(): put(destination/name,data)
            restart()
            pending.unlink()
        except Exception:
            for name,data in previous.items(): put(destination/name,data)
            restart()
            pending.unlink()
            raise
        return True
    finally:
        os.close(lock)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--acme',required=True,type=Path)
    parser.add_argument('--hostname',required=True)
    parser.add_argument('--destination',required=True,type=Path)
    parser.add_argument('--container',required=True)
    args=parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*',args.container): parser.error('Invalid container name')
    def restart():
        subprocess.run(['docker','restart',args.container],check=True,stdout=subprocess.DEVNULL)
    changed=refresh(args.acme,args.hostname,args.destination,restart)
    print('EST HTTPS identity refreshed.' if changed else 'EST HTTPS identity unchanged.')


if __name__=='__main__': main()
