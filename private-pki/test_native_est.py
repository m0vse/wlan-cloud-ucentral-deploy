"""Standard EST exchange over real TLS, including retained-CA native renewal."""
import base64
import http.client
import ssl
import threading
import unittest
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from native_est import NativeEST, handler
from service import BoundedServer
import test_fixtures as fixtures
import test_issuer


class NativeESTTests(unittest.TestCase):
    setUp = test_issuer.IssuerTests.setUp
    request = test_issuer.IssuerTests.request
    write_authority = test_issuer.IssuerTests.write_authority
    load = test_issuer.IssuerTests.load

    def legacy(self):
        authority = fixtures.Authority()
        authority.root = fixtures.ca('SYNTHETIC RETAINED ROOT', authority.root_key, authority.root_key)
        subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'SYNTHETIC LEGACY'),
                             x509.NameAttribute(NameOID.COMMON_NAME, self.device)])
        leaf = (x509.CertificateBuilder().subject_name(subject).issuer_name(authority.root.subject)
            .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(self.clock - timedelta(minutes=1)).not_valid_after(self.clock + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
            .sign(authority.root_key, hashes.SHA256()))
        self.issuer.import_legacy(self.device, fixtures.pem(leaf), fixtures.pem(authority.root))
        return authority, leaf

    def csr_der(self, subject, key=None):
        return (x509.CertificateSigningRequestBuilder().subject_name(subject)
                .sign(key or self.key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))

    def test_native_full_subject_retry_revoke_and_key_substitution(self):
        _, old = self.legacy()
        adapter = NativeEST(self.issuer)
        peer = old.public_bytes(serialization.Encoding.DER)
        first = adapter.reenroll(peer, self.csr_der(old.subject))
        # Recreating the same EC CSR changes its signature, not its identity.
        self.assertEqual(first, adapter.reenroll(peer, self.csr_der(old.subject)))
        new = x509.load_pem_x509_certificate(first)
        self.assertEqual(new.subject, old.subject)
        new.verify_directly_issued_by(self.authority.device)
        with self.assertRaises(ValueError):
            adapter.reenroll(peer, self.csr_der(fixtures.name(self.device)))
        from cryptography.hazmat.primitives.asymmetric import ec
        with self.assertRaises(ValueError):
            adapter.reenroll(peer, self.csr_der(old.subject, ec.generate_private_key(ec.SECP256R1())))
        self.issuer.disable(self.device)
        with self.assertRaises(ValueError):
            adapter.reenroll(peer, self.csr_der(old.subject))

    def test_real_tls_standard_pkcs10_pkcs7_no_custom_headers(self):
        legacy, old = self.legacy()
        server_key = self.authority.device_key
        server_cert = (x509.CertificateBuilder().subject_name(fixtures.name('localhost'))
            .issuer_name(self.authority.root.subject).public_key(server_key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(self.clock-timedelta(minutes=1))
            .not_valid_after(self.clock+timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(self.authority.root_key, hashes.SHA256()))
        for filename, data in [('server.pem', fixtures.pem(server_cert)), ('server.key', fixtures.private(server_key)),
            ('client.pem', fixtures.pem(old)), ('client.key', fixtures.private(self.key)),
            ('trust.pem', fixtures.pem(self.authority.root)+fixtures.pem(legacy.root))]:
            (self.path/filename).write_bytes(data)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.path/'server.pem', self.path/'server.key')
        context.load_verify_locations(self.path/'trust.pem')
        context.verify_mode = ssl.CERT_OPTIONAL
        from onboarding import Onboarding
        from enrollment_campaign import Campaigns
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives.asymmetric import ec
        import test_ownership
        enrollment_serial = '001122334456'
        inventory, records, controller = test_ownership.OwnershipTests.fixtures(self)
        inventory.update(serialNumber=enrollment_serial,id='new-inventory')
        controller.inventory.return_value = inventory
        Onboarding(self.issuer.store,controller)
        campaigns=Campaigns(self.issuer,controller,Fernet(Fernet.generate_key()))
        batch=campaigns.create('root',[enrollment_serial],'Bearer synthetic','new-openwifi-enrollment')
        installer_key=batch['enrollmentKey']
        enrollment_ap_key=ec.generate_private_key(ec.SECP256R1())
        server = BoundedServer(('127.0.0.1', 0), handler(NativeEST(self.issuer, campaigns)))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        client = ssl.create_default_context(cafile=str(self.path/'trust.pem'))
        client.load_cert_chain(self.path/'client.pem', self.path/'client.key')
        def exchange(path, tls=client, body=None, authorization=None):
            connection = http.client.HTTPSConnection('localhost', server.server_port, context=tls, timeout=5)
            headers={'Content-Type':'application/pkcs10'}
            if authorization: headers['Authorization']=authorization
            connection.request('POST', path, body or base64.b64encode(self.csr_der(old.subject)), headers)
            reply = connection.getresponse()
            status, encoding, data = reply.status, reply.getheader('Content-Transfer-Encoding'), reply.read()
            connection.close()
            return status, encoding, data
        status, encoding, data = exchange('/.well-known/est/simplereenroll')
        self.assertEqual((status, encoding), (200, 'base64'))
        certs = pkcs7.load_der_pkcs7_certificates(base64.b64decode(data))
        leaf = next(c for c in certs if c.subject == old.subject)
        leaf.verify_directly_issued_by(self.authority.device)
        self.assertEqual(len(certs), 3)
        anonymous = ssl.create_default_context(cafile=str(self.path/'trust.pem'))
        self.assertEqual(exchange('/.well-known/est/simplereenroll', anonymous)[0], 403)
        bootstrap_body = base64.b64encode(self.csr_der(fixtures.name(enrollment_serial),enrollment_ap_key))
        authorization = 'Basic '+base64.b64encode((enrollment_serial+':'+installer_key).encode()).decode()
        status, encoding, bootstrap = exchange('/.well-known/est/simpleenroll', anonymous, bootstrap_body, authorization)
        self.assertEqual((status,encoding),(200,'base64'))
        enrolled = pkcs7.load_der_pkcs7_certificates(base64.b64decode(bootstrap))
        leaf = next(c for c in enrolled if c.subject==fixtures.name(enrollment_serial))
        leaf.verify_directly_issued_by(self.authority.device)
        self.assertEqual(bootstrap,exchange('/.well-known/est/simpleenroll',anonymous,bootstrap_body,authorization)[2])
        campaigns.cancel('root',batch['id'])
        self.assertEqual(exchange('/.well-known/est/simpleenroll',anonymous,bootstrap_body,authorization)[0],403)

        self.issuer.disable(self.device)
        self.assertEqual(exchange('/.well-known/est/simplereenroll')[0], 403)


if __name__ == '__main__': unittest.main()
