"""Synthetic issuer persistence, client renewal and root overlap tests."""
import concurrent.futures
from pathlib import Path
import tempfile
import unittest
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from issuer import Issuer, fingerprint

import test_fixtures as fixtures


class IssuerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.authority = fixtures.Authority()
        self.clock = fixtures.now()
        self.write_authority(self.authority)
        self.issuer = self.load()
        self.device = "001122334455"
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.csr = self.request(self.key)
        self.issuer.approve(self.device)

    def request(self, key, device=None):
        return (x509.CertificateSigningRequestBuilder().subject_name(fixtures.name(device or self.device))
                .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))

    def write_authority(self, authority):
        for filename, data in (("root", fixtures.pem(authority.root)), ("issuer", fixtures.pem(authority.device)),
                               ("key", fixtures.private(authority.device_key))):
            path = self.path / filename
            path.write_bytes(data)
            path.chmod(0o600)

    def load(self):
        return Issuer(self.path / "root", self.path / "issuer", self.path / "key",
                      self.path / "state" / "issuer.sqlite", lambda: self.clock)

    def issue(self):
        return self.issuer.bootstrap(self.device, self.issuer.authorize(self.device, self.csr), self.csr)

    @staticmethod
    def der(cert):
        return x509.load_pem_x509_certificate(cert).public_bytes(serialization.Encoding.DER)

    def test_bootstrap_concurrent_restart_and_key_binding(self):
        token = self.issuer.authorize(self.device, self.csr)
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            replies = list(pool.map(lambda _: self.issuer.bootstrap(self.device, token, self.csr), range(6)))
        self.assertEqual(len(set(replies)), 1)
        self.issuer = self.load()
        self.assertEqual(self.issuer.bootstrap(self.device, token, self.csr), replies[0])
        other = self.request(ec.generate_private_key(ec.SECP256R1()))
        with self.assertRaises(ValueError):
            self.issuer.bootstrap(self.device, token, other)
        cert = x509.load_pem_x509_certificate(replies[0])
        self.assertFalse(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        self.assertLessEqual(cert.not_valid_after_utc, self.clock + timedelta(days=365))

    def test_renewal_restart_retry_new_cycle_and_revocation(self):
        initial = self.issue()
        renewed = self.issuer.renew(self.der(initial), self.csr, "a" * 32)
        self.assertNotEqual(initial, renewed)
        self.issuer = self.load()
        self.assertEqual(renewed, self.issuer.renew(self.der(initial), self.csr, "a" * 32))
        next_leaf = self.issuer.renew(self.der(renewed), self.csr, "b" * 32)
        self.assertNotEqual(next_leaf, renewed)
        self.issuer.revoke(fingerprint(x509.load_pem_x509_certificate(renewed)))
        self.issuer = self.load()
        with self.assertRaises(ValueError):
            self.issuer.renew(self.der(renewed), self.csr, "c" * 32)
        with self.assertRaises(ValueError):
            self.issuer.renew(self.der(initial), self.csr, "a" * 32)

    def test_expired_client_requires_new_operator_grant(self):
        initial = self.issue()
        self.clock += timedelta(days=366)
        with self.assertRaises(ValueError):
            self.issuer.renew(self.der(initial), self.csr, "a" * 32)
        recovered = self.issue()
        self.assertNotEqual(initial, recovered)

    def test_root_rotation_overlap_old_client_renews_under_new_root(self):
        old = self.issue()
        new = fixtures.Authority()
        self.write_authority(new)
        self.issuer = self.load()
        rotated = self.issuer.renew(self.der(old), self.csr, "a" * 32)
        cert = x509.load_pem_x509_certificate(rotated)
        cert.verify_directly_issued_by(new.device)
        self.issuer.renew(self.der(old), self.csr, "b" * 32)
        with self.issuer.store.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM authorities").fetchone()[0], 2)

    def test_disabled_inventory_blocks_grants_and_renewal(self):
        old = self.issue()
        token = self.issuer.authorize(self.device, self.csr)
        self.issuer.disable(self.device)
        for call in (lambda: self.issuer.authorize(self.device, self.csr),
                     lambda: self.issuer.bootstrap(self.device, token, self.csr),
                     lambda: self.issuer.renew(self.der(old), self.csr, "a" * 32)):
            with self.assertRaises(ValueError):
                call()
        self.issuer.approve(self.device)
        with self.assertRaises(ValueError):
            self.issuer.bootstrap(self.device, token, self.csr)

    def test_revoked_bootstrap_reply_and_grant_expiry(self):
        token = self.issuer.authorize(self.device, self.csr)
        leaf = self.issuer.bootstrap(self.device, token, self.csr)
        self.issuer.revoke(fingerprint(x509.load_pem_x509_certificate(leaf)))
        with self.assertRaises(ValueError):
            self.issuer.bootstrap(self.device, token, self.csr)
        token = self.issuer.authorize(self.device, self.csr)
        self.clock += timedelta(seconds=601)
        with self.assertRaises(ValueError):
            self.issuer.bootstrap(self.device, token, self.csr)

    def test_renewal_key_substitution_and_unregistered_peer(self):
        initial = self.issue()
        other = self.request(ec.generate_private_key(ec.SECP256R1()))
        with self.assertRaises(ValueError):
            self.issuer.renew(self.der(initial), other, "a" * 32)
        other_authority = fixtures.Authority()
        self.write_authority(other_authority)
        other_store = self.path / "separate" / "db.sqlite"
        other_issuer = Issuer(self.path / "root", self.path / "issuer", self.path / "key", other_store)
        other_issuer.approve(self.device)
        peer = other_issuer.bootstrap(self.device, other_issuer.authorize(self.device, self.csr), self.csr)
        with self.assertRaises(ValueError):
            self.issuer.renew(self.der(peer), self.csr, "a" * 32)

    def test_wrong_key_permissions_and_expired_issuer_refused(self):
        (self.path / "key").chmod(0o644)
        with self.assertRaises(ValueError):
            self.load()
        self.write_authority(fixtures.Authority())
        (self.path / "key").write_bytes(fixtures.private(self.authority.device_key))
        with self.assertRaises(ValueError):
            self.load()
        self.write_authority(self.authority)
        self.clock += timedelta(days=1826)
        with self.assertRaises(ValueError):
            self.load()

    def test_rsa_ap_and_invalid_subject(self):
        csr = self.request(rsa.generate_private_key(public_exponent=65537, key_size=2048))
        token = self.issuer.authorize(self.device, csr)
        self.issuer.bootstrap(self.device, token, csr)
        with self.assertRaises(ValueError):
            self.issuer.authorize(self.device, self.request(self.key, "001122334456"))


if __name__ == "__main__":
    unittest.main()
