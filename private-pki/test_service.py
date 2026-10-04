import base64
import json
from datetime import timedelta
import http.client
import ssl
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import Mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID

from admin import Administration, Denied
from issuer import fingerprint
from service import IsolatedServer, RateLimit, handler, json_object
import test_fixtures as fixtures
import test_issuer


class ServiceTests(unittest.TestCase):
    setUp = test_issuer.IssuerTests.setUp
    request = test_issuer.IssuerTests.request
    write_authority = test_issuer.IssuerTests.write_authority
    load = test_issuer.IssuerTests.load

    def start(self, request_handler, context=None):
        server = IsolatedServer(("127.0.0.1", 0), request_handler, context)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"{'https' if context else 'http'}://localhost:{server.server_port}"

    def test_real_tls_bootstrap_renewal_revocation_and_isolation(self):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (x509.CertificateBuilder().subject_name(fixtures.name("localhost"))
                .issuer_name(self.authority.device.subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(self.clock - timedelta(minutes=1))
                .not_valid_after(self.clock + timedelta(days=2))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.authority.device_key.public_key()), False)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
                .sign(self.authority.device_key, hashes.SHA256()))
        for filename, data in (("tls.pem", fixtures.pem(cert) + fixtures.pem(self.authority.device)),
                               ("tls.key", fixtures.private(key)), ("client.key", fixtures.private(self.key))):
            (self.path / filename).write_bytes(data)
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.minimum_version = ssl.TLSVersion.TLSv1_2
        server_tls.load_cert_chain(self.path / "tls.pem", self.path / "tls.key")
        server_tls.load_verify_locations(self.path / "root")
        server_tls.verify_mode = ssl.CERT_OPTIONAL
        installer = Mock()
        url = self.start(handler(self.issuer, installer=installer), server_tls)
        client_tls = ssl.create_default_context(cafile=str(self.path / "root"))
        der_csr = x509.load_pem_x509_csr(self.csr).public_bytes(serialization.Encoding.DER)
        body = base64.b64encode(der_csr)
        token = self.issuer.authorize(self.device, self.csr)
        headers = {"Content-Type": "application/pkcs10", "Authorization": "Basic " + base64.b64encode(f"{self.device}:{token}".encode()).decode()}

        def send(path, headers, context=client_tls, request_body=body):
            request = urllib.request.Request(url + path, request_body, headers)
            with urllib.request.urlopen(request, context=context, timeout=5) as response:
                return response.read()

        response = send("/bootstrap", headers)
        certs = pkcs7.load_der_pkcs7_certificates(base64.b64decode(response))
        leaf = next(c for c in certs if c.subject == fixtures.name(self.device))
        (self.path / "client.pem").write_bytes(fixtures.pem(leaf) + fixtures.pem(self.authority.device))
        client_tls.load_cert_chain(self.path / "client.pem", self.path / "client.key")
        installer.bootstrap.return_value = fixtures.pem(leaf)
        installer_body = json.dumps({'serial': self.device, 'csr': self.csr.decode('ascii')}).encode()
        installer_headers = {'Content-Type': 'application/json', 'X-API-Key': 'synthetic-test-key'}
        send('/onboarding/bootstrap', installer_headers, request_body=installer_body)
        installer.bootstrap.assert_called_with('synthetic-test-key', self.device, self.csr)
        with self.assertRaises(urllib.error.HTTPError):
            send('/api/v1/pki/onboard', installer_headers, request_body=installer_body)
        renew_headers = {"Content-Type": "application/pkcs10", "X-Renewal-Attempt": "a" * 32}
        reply = send("/.well-known/est/simplereenroll", renew_headers)
        renewed = next(c for c in pkcs7.load_der_pkcs7_certificates(base64.b64decode(reply)) if c.subject == fixtures.name(self.device))
        self.assertNotEqual(leaf.serial_number, renewed.serial_number)
        self.assertEqual(reply, send("/.well-known/est/simplereenroll", renew_headers))
        self.issuer.revoke(fingerprint(leaf))
        with self.assertRaises(urllib.error.HTTPError) as refused:
            send("/.well-known/est/simplereenroll", renew_headers)
        self.assertEqual(refused.exception.code, 403)
        with self.assertRaises(urllib.error.HTTPError):
            send("/api/v1/pki/authorize", headers)
        with self.assertRaises(urllib.error.URLError):
            urllib.request.urlopen(urllib.request.Request(url.replace("localhost", "127.0.0.1") + "/bootstrap", body, headers), context=client_tls)
        anonymous = ssl.create_default_context(cafile=str(self.path / "root"))
        with self.assertRaises(urllib.error.HTTPError):
            send("/.well-known/est/simplereenroll", dict(renew_headers, **{"X-Client-Cert": base64.b64encode(leaf.public_bytes(serialization.Encoding.DER)).decode()}), anonymous)

    def test_portal_authentication_and_duplicate_framing(self):
        controller = Mock()
        controller.root.side_effect = Denied(401, "Sign in required")
        url = self.start(handler(self.issuer, Administration(self.issuer, controller), "admin"))
        with self.assertRaises(urllib.error.HTTPError) as refused:
            urllib.request.urlopen(urllib.request.Request(url + "/api/v1/pki/status", headers={"Authorization": "Bearer synthetic"}))
        self.assertEqual(refused.exception.code, 401)
        controller.inventory.assert_not_called()
        conn = http.client.HTTPConnection("localhost", int(url.rsplit(":", 1)[1]))
        conn.putrequest("POST", "/api/v1/pki/authorize")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", "2")
        conn.putheader("Content-Length", "2")
        conn.endheaders(b"{}")
        self.assertEqual(conn.getresponse().status, 400)
        conn.close()

    def test_real_tls_dual_root_overlap_and_old_only_refusal(self):
        token = self.issuer.authorize(self.device, self.csr)
        leaf_pem = self.issuer.bootstrap(self.device, token, self.csr)
        old_root = self.authority.root
        (self.path / "old-client.pem").write_bytes(leaf_pem + fixtures.pem(self.authority.device))
        (self.path / "old-client.key").write_bytes(fixtures.private(self.key))
        new = fixtures.Authority()
        self.write_authority(new)
        self.issuer = self.load()
        (self.path / "dual.pem").write_bytes(fixtures.pem(old_root) + fixtures.pem(new.root))
        (self.path / "old-root.pem").write_bytes(fixtures.pem(old_root))
        key = ec.generate_private_key(ec.SECP256R1())
        server_leaf = (x509.CertificateBuilder().subject_name(fixtures.name("localhost"))
                       .issuer_name(new.device.subject).public_key(key.public_key())
                       .serial_number(x509.random_serial_number()).not_valid_before(self.clock - timedelta(minutes=1))
                       .not_valid_after(self.clock + timedelta(days=2))
                       .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                       .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                       .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(new.device_key.public_key()), False)
                       .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
                       .sign(new.device_key, hashes.SHA256()))
        (self.path / "rotated-server.pem").write_bytes(fixtures.pem(server_leaf) + fixtures.pem(new.device))
        (self.path / "rotated-server.key").write_bytes(fixtures.private(key))
        server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_tls.minimum_version = ssl.TLSVersion.TLSv1_2
        server_tls.load_cert_chain(self.path / "rotated-server.pem", self.path / "rotated-server.key")
        server_tls.load_verify_locations(self.path / "dual.pem")
        server_tls.verify_mode = ssl.CERT_REQUIRED
        url = self.start(handler(self.issuer), server_tls)
        der_csr = x509.load_pem_x509_csr(self.csr).public_bytes(serialization.Encoding.DER)
        request = urllib.request.Request(url + "/.well-known/est/simplereenroll", base64.b64encode(der_csr),
            {"Content-Type": "application/pkcs10", "X-Renewal-Attempt": "a" * 32})
        old_only = ssl.create_default_context(cafile=str(self.path / "old-root.pem"))
        old_only.load_cert_chain(self.path / "old-client.pem", self.path / "old-client.key")
        with self.assertRaises(urllib.error.URLError):
            urllib.request.urlopen(request, context=old_only, timeout=5)
        dual = ssl.create_default_context(cafile=str(self.path / "dual.pem"))
        dual.load_cert_chain(self.path / "old-client.pem", self.path / "old-client.key")
        with urllib.request.urlopen(request, context=dual, timeout=5) as response:
            certs = pkcs7.load_der_pkcs7_certificates(base64.b64decode(response.read()))
        rotated = next(c for c in certs if c.subject == fixtures.name(self.device))
        rotated.verify_directly_issued_by(new.device)
        with self.issuer.store.connect() as db:
            self.assertIn(old_root.fingerprint(hashes.SHA256()),
                          [x509.load_pem_x509_certificate(row[0]).fingerprint(hashes.SHA256())
                           for row in db.execute("SELECT root FROM authorities")])

    def test_bounds_json_and_listener(self):
        stamp = [0]
        rate = RateLimit(lambda: stamp[0])
        self.assertTrue(all(rate.allow("same") for _ in range(12)))
        self.assertFalse(rate.allow("same"))
        stamp[0] = 61
        self.assertTrue(rate.allow("same"))
        with self.assertRaises(ValueError):
            json_object(b'{"serial":"one","serial":"two"}')
        with self.assertRaises(ValueError):
            IsolatedServer(("0.0.0.0", 0), handler(self.issuer))


if __name__ == "__main__":
    unittest.main()
