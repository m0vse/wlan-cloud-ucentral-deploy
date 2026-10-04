import base64
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import tempfile
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from refresh_est_tls import refresh

class TLSRefreshTests(unittest.TestCase):
    def pair(self,hostname='fixture.example'):
        key=ec.generate_private_key(ec.SECP256R1())
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,hostname)])
        now=datetime.now(timezone.utc)
        cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(days=7)).add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]),False).sign(key,hashes.SHA256())
        return {'cert.pem':cert.public_bytes(serialization.Encoding.PEM),'key.pem':key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())}
    def acme(self,path,pair):
        path.write_text(json.dumps({'provider':{'Certificates':[{'domain':{'main':'fixture.example'},'certificate':base64.b64encode(pair['cert.pem']).decode(),'key':base64.b64encode(pair['key.pem']).decode()}]}}));path.chmod(0o600)
    def storage(self,path,pair):
        destination=path/'tls';destination.mkdir(mode=0o700)
        for name,data in pair.items(): (destination/name).write_bytes(data);(destination/name).chmod(0o600)
        acme=path/'acme.json';self.acme(acme,pair)
        return acme,destination
    def test_change_noop_failure_restore_and_interruption_recovery(self):
        with tempfile.TemporaryDirectory() as work:
            path=Path(work);old=self.pair();acme,destination=self.storage(path,old);calls=[]
            self.assertFalse(refresh(acme,'fixture.example',destination,lambda:calls.append('restart')))
            self.assertEqual(calls,[])
            new=self.pair();self.acme(acme,new)
            self.assertTrue(refresh(acme,'fixture.example',destination,lambda:calls.append('restart')))
            self.assertEqual(calls,['restart'])
            newer=self.pair();self.acme(acme,newer)
            def fail_once():
                calls.append('restart')
                if len(calls)==2: raise RuntimeError('synthetic restart failure')
            with self.assertRaises(RuntimeError):refresh(acme,'fixture.example',destination,fail_once)
            self.assertEqual((destination/'cert.pem').read_bytes(),new['cert.pem'])
            self.assertEqual((destination/'key.pem').read_bytes(),new['key.pem'])
            (destination/'cert.pem').write_bytes(newer['cert.pem'])
            pending=destination/'refresh.pending';pending.write_text('interrupted');pending.chmod(0o600)
            leftover=destination/'cert.pem.new';leftover.write_text('interrupted write');leftover.chmod(0o600)
            self.acme(acme,new)
            self.assertFalse(refresh(acme,'fixture.example',destination,lambda:calls.append('recover')))
            self.assertEqual((destination/'cert.pem').read_bytes(),new['cert.pem'])
            self.assertEqual((destination/'key.pem').read_bytes(),new['key.pem'])
            self.assertFalse(pending.exists())
    def test_wrong_hostname_key_and_unsafe_source_preserve_identity(self):
        with tempfile.TemporaryDirectory() as work:
            path=Path(work);old=self.pair();acme,destination=self.storage(path,old)
            mismatch=self.pair();mismatch['key.pem']=self.pair()['key.pem'];self.acme(acme,mismatch)
            with self.assertRaises(ValueError):refresh(acme,'fixture.example',destination,lambda:self.fail('must not restart'))
            self.acme(acme,self.pair('different.example'))
            with self.assertRaises(ValueError):refresh(acme,'fixture.example',destination,lambda:self.fail('must not restart'))
            acme.chmod(0o644)
            with self.assertRaises(ValueError):refresh(acme,'fixture.example',destination,lambda:self.fail('must not restart'))
            self.assertEqual((destination/'cert.pem').read_bytes(),old['cert.pem'])
