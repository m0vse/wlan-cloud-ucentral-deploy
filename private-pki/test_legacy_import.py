from datetime import timedelta
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID
from issuer import fingerprint
import test_fixtures as fixtures
import test_issuer


class LegacyTests(unittest.TestCase):
    setUp = test_issuer.IssuerTests.setUp
    request = test_issuer.IssuerTests.request
    write_authority = test_issuer.IssuerTests.write_authority
    load = test_issuer.IssuerTests.load

    def test_public_legacy_import_renewal_no_legacy_key_and_no_unrevocation(self):
        legacy = fixtures.Authority()
        leaf = (x509.CertificateBuilder().subject_name(fixtures.name(self.device))
            .issuer_name(legacy.root.subject).public_key(self.key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(self.clock - timedelta(minutes=1))
            .not_valid_after(self.clock + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
            .sign(legacy.root_key, hashes.SHA256()))
        root, public_leaf = fixtures.pem(legacy.root), fixtures.pem(leaf)
        imported = self.issuer.import_legacy(self.device, public_leaf, root)
        self.assertEqual(imported, fingerprint(leaf))
        restarted = self.load()
        renewed = restarted.renew(leaf.public_bytes(serialization.Encoding.DER), self.csr, 'a' * 32)
        x509.load_pem_x509_certificate(renewed).verify_directly_issued_by(self.authority.device)
        with restarted.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM authorities').fetchone()[0], 2)
            self.assertEqual(db.execute('SELECT kind FROM issuance_origins WHERE leaf=?', (imported,)).fetchone()[0], 'legacy')
        restarted.revoke(imported)
        with self.assertRaises(ValueError):
            restarted.import_legacy(self.device, public_leaf, root)
        restarted.disable(self.device)
        with self.assertRaises(ValueError):
            restarted.import_legacy(self.device, public_leaf, root)
