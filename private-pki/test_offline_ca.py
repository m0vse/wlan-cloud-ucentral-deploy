from datetime import datetime, timedelta, timezone
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.x509.oid import NameOID
from offline_ca import make_root, recover, sign_device_issuer, years_later


class OfflineTests(unittest.TestCase):
    def test_encrypted_backup_recovery_and_issuer_key_renewal(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            password = base / 'separately-held-secret'
            password.write_bytes(secrets.token_urlsafe(48).encode())
            password.chmod(0o600)
            stamp = datetime(2026, 10, 4, tzinfo=timezone.utc)
            manifest = make_root(base / 'offline-primary', password, stamp)
            self.assertEqual(manifest['name'], 'Shine Systems CA')
            self.assertEqual(datetime.fromtimestamp(manifest['expires'], timezone.utc).year, 2046)
            encrypted = (base / 'offline-primary/root-key.encrypted.pem').read_bytes()
            self.assertTrue(encrypted.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'))
            recovered_public = subprocess.run(['openssl', 'pkey', '-in', str(base / 'offline-primary/root-key.encrypted.pem'),
                '-passin', 'file:' + str(password), '-pubout', '-outform', 'DER'], capture_output=True, check=True).stdout
            with self.assertRaises(TypeError):
                serialization.load_pem_private_key(encrypted, None)
            shutil.copytree(base / 'offline-primary', base / 'offline-backup')
            root_key, root, _ = recover(base / 'offline-backup', password, stamp,
                expected_fingerprint=manifest['fingerprint'])
            self.assertEqual(recovered_public, root.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
            issuers = []
            for cycle in (0, 4):
                # Each renewal has a new online issuer key; only its CSR goes offline.
                issuer_key = ec.generate_private_key(ec.SECP384R1())
                name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Shine Systems Device Issuing CA')])
                csr = x509.CertificateSigningRequestBuilder().subject_name(name).sign(issuer_key, hashes.SHA256())
                cert = x509.load_pem_x509_certificate(sign_device_issuer(base / 'offline-backup', password,
                    csr.public_bytes(serialization.Encoding.PEM), stamp.replace(year=stamp.year + cycle)))
                root.public_key().verify(cert.signature, cert.tbs_certificate_bytes,
                    padding.PKCS1v15(), cert.signature_hash_algorithm)
                self.assertFalse(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length)
                self.assertEqual(cert.not_valid_after_utc.year, stamp.year + cycle + 5)
                issuers.append(cert)
            self.assertNotEqual(issuers[0].fingerprint(hashes.SHA256()), issuers[1].fingerprint(hashes.SHA256()))
            with self.assertRaises(ValueError):
                recover(base / 'offline-backup', password, stamp, expected_fingerprint='a' * 64)
            password.write_bytes(secrets.token_urlsafe(48).encode())
            with self.assertRaises(ValueError):
                recover(base / 'offline-backup', password, stamp)

    def test_no_overwrite_unsafe_input_corruption_and_leap_date(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            password = base / 'secret'
            password.write_bytes(secrets.token_urlsafe(48).encode())
            password.chmod(0o644)
            with self.assertRaises(ValueError):
                make_root(base / 'root', password)
            self.assertFalse((base / 'root').exists())
            password.chmod(0o600)
            password.write_bytes(b'binary-secret-with-embedded\x00-character' * 2)
            with self.assertRaises(ValueError):
                make_root(base / 'invalid-secret-root', password)
            password.write_bytes(secrets.token_urlsafe(48).encode())
            stamp = datetime(2028, 2, 29, tzinfo=timezone.utc)
            make_root(base / 'root', password, stamp)
            with self.assertRaises(FileExistsError):
                make_root(base / 'root', password, stamp)
            self.assertEqual(years_later(stamp, 5).day, 28)
            path = base / 'root/root-cert.pem'
            path.write_bytes(path.read_bytes() + b'corruption')
            with self.assertRaises(ValueError):
                recover(base / 'root', password, stamp)


if __name__ == '__main__':
    unittest.main()
