"""Offline ceremony helpers. Never imported by the online issuer service.

Caller supplies an approved offline destination and a separately kept recovery
secret file. Root private material remains in memory or encrypted PKCS8 only.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import re
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.x509.oid import NameOID


def read_private(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 65536:
            raise ValueError('Unsafe offline input')
        return os.read(fd, 65537)
    finally:
        os.close(fd)


def write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def secret(path):
    value = read_private(path)
    if re.fullmatch(b'[A-Za-z0-9_-]{32,1024}', value) is None:
        raise ValueError('Use a separately stored URL-safe recovery secret of at least 32 characters, without whitespace')
    return value


def years_later(stamp, years):
    try:
        return stamp.replace(year=stamp.year + years)
    except ValueError:
        return stamp.replace(year=stamp.year + years, day=28)


def make_root(destination, recovery_secret_path, clock=None):
    destination = Path(destination)
    password = secret(recovery_secret_path)
    # A new directory prevents accidental overwrite of an existing authority.
    destination.mkdir(mode=0o700, exist_ok=False)
    stamp = clock or datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Shine Systems CA')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(stamp - timedelta(minutes=5))
        .not_valid_after(years_later(stamp, 20))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
        .sign(key, hashes.SHA256()))
    encrypted = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password))
    public = cert.public_bytes(serialization.Encoding.PEM)
    write_new(destination / 'root-key.encrypted.pem', encrypted)
    write_new(destination / 'root-cert.pem', public)
    manifest = {'schema': 'openwifi.offline-ca-backup.v1', 'name': 'Shine Systems CA',
        'fingerprint': cert.fingerprint(hashes.SHA256()).hex(),
        'expires': int(cert.not_valid_after_utc.timestamp()),
        'files': {'root-key.encrypted.pem': hashlib.sha256(encrypted).hexdigest(),
                  'root-cert.pem': hashlib.sha256(public).hexdigest()}}
    write_new(destination / 'backup-manifest.json', (json.dumps(manifest, sort_keys=True) + '\n').encode())
    fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return manifest


def recover(root_directory, recovery_secret_path, clock=None, expected_fingerprint=None):
    directory = Path(root_directory)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('Unsafe offline root directory')
    manifest = json.loads(read_private(directory / 'backup-manifest.json'))
    if manifest.get('schema') != 'openwifi.offline-ca-backup.v1' or set(manifest.get('files', {})) != {'root-key.encrypted.pem', 'root-cert.pem'}:
        raise ValueError('Invalid backup manifest')
    files = {name: read_private(directory / name) for name in manifest['files']}
    if any(hashlib.sha256(data).hexdigest() != manifest['files'][name] for name, data in files.items()):
        raise ValueError('Backup checksum mismatch')
    if b'BEGIN ENCRYPTED PRIVATE KEY' not in files['root-key.encrypted.pem']:
        raise ValueError('Root backup must be encrypted')
    key = serialization.load_pem_private_key(files['root-key.encrypted.pem'], secret(recovery_secret_path))
    cert = x509.load_pem_x509_certificate(files['root-cert.pem'])
    if cert.fingerprint(hashes.SHA256()).hex() != manifest.get('fingerprint'):
        raise ValueError('Backup fingerprint mismatch')
    if expected_fingerprint is not None and manifest['fingerprint'] != expected_fingerprint:
        raise ValueError('Backup does not match separately recorded root fingerprint')
    public = lambda value: value.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if public(key.public_key()) != public(cert.public_key()) or cert.subject != cert.issuer:
        raise ValueError('Root key/certificate mismatch')
    key.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
    stamp = clock or datetime.now(timezone.utc)
    if not cert.not_valid_before_utc <= stamp < cert.not_valid_after_utc:
        raise ValueError('Root outside validity window')
    if cert.subject != x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Shine Systems CA')]):
        raise ValueError('Unexpected root identity')
    if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
        raise ValueError('Root is not a CA')
    if not cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
        raise ValueError('Root cannot sign certificates')
    return key, cert, manifest


def sign_device_issuer(root_directory, recovery_secret_path, csr_pem, clock=None):
    key, root, manifest = recover(root_directory, recovery_secret_path, clock)
    csr = x509.load_pem_x509_csr(csr_pem)
    if not csr.is_signature_valid:
        raise ValueError('Invalid issuing CA request')
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Shine Systems Device Issuing CA')])
    if csr.subject != name:
        raise ValueError('Unexpected issuing CA identity')
    public_key = csr.public_key()
    if not ((isinstance(public_key, rsa.RSAPublicKey) and 3072 <= public_key.key_size <= 4096)
            or (isinstance(public_key, ec.EllipticCurvePublicKey) and isinstance(public_key.curve, ec.SECP384R1))):
        raise ValueError('Unsupported issuing CA key')
    stamp = clock or datetime.now(timezone.utc)
    # Root rollover is a separate overlap operation; issuer renewal preserves root.
    expiry = min(years_later(stamp, 5), root.not_valid_after_utc)
    if expiry <= stamp + timedelta(days=365):
        raise ValueError('Root rollover required before another issuing CA')
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(root.subject)
        .public_key(public_key).serial_number(x509.random_serial_number())
        .not_valid_before(stamp - timedelta(minutes=5)).not_valid_after(expiry)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
        .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)
