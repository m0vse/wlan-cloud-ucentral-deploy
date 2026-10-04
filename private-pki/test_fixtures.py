"""Disposable PKI fixtures, adapted from wlan-ap's isolated lifecycle tests."""
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def now():
    return datetime.now(timezone.utc)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def private(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def ca(subject, key, signer, issuer=None, days=7305):
    stamp = now()
    return (x509.CertificateBuilder().subject_name(name(subject))
            .issuer_name(issuer.subject if issuer else name(subject))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(stamp - timedelta(minutes=1)).not_valid_after(stamp + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0 if issuer else 1), True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), False)
            .sign(signer, hashes.SHA256()))


class Authority:
    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP384R1())
        self.root = ca("SYNTHETIC 20 YEAR ROOT", self.root_key, self.root_key)
        self.device_key = ec.generate_private_key(ec.SECP256R1())
        self.device = ca("SYNTHETIC DEVICE ISSUER", self.device_key, self.root_key, self.root, 1825)
