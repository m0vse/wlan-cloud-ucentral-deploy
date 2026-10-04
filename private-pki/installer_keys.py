"""Per-job installer credentials. Only a trusted installer adapter receives keys.

No browser endpoint exposes these credentials. Approval has no clock expiry;
completion/cancellation and fresh ownership checks control use instead.
"""
import hashlib
import json
import secrets
from cryptography.fernet import Fernet
from issuer import Issuer, private_read
from cryptography.hazmat.primitives import serialization
from ownership import snapshot


class InstallerKeys:
    def __init__(self, jobs, encryption_key_path):
        self.jobs = jobs
        self.cipher = Fernet(private_read(encryption_key_path))
        with jobs.store.connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS installer_keys(
                job TEXT PRIMARY KEY, digest BLOB UNIQUE NOT NULL,
                encrypted BLOB NOT NULL, csr_digest BLOB)''')

    def create(self, job):
        """Called by the protected installer, never by the public portal response."""
        with self.jobs.lock, self.jobs.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM onboarding_jobs WHERE id=?', (job,)).fetchone()
            if not row or row['state'] not in ('waiting', 'running'):
                raise ValueError('Onboarding request is not active')
            previous = db.execute('SELECT encrypted FROM installer_keys WHERE job=?', (job,)).fetchone()
            if previous:
                return self.cipher.decrypt(previous['encrypted']).decode('ascii')
            key = secrets.token_urlsafe(48)
            db.execute('INSERT INTO installer_keys VALUES (?,?,?,NULL)',
                       (job, hashlib.sha256(key.encode('ascii')).digest(), self.cipher.encrypt(key.encode('ascii'))))
            return key

    def bind(self, key, serial, csr_pem, authorization):
        """Fresh controller authority plus an immutable first CSR, atomically bound.

The caller must parse and verify the CSR signature before calling this method,
then run qualification/issuance checks; this method alone never issues a leaf.
"""
        if not isinstance(key, str) or len(key) != 64:
            raise ValueError('Invalid installer key')
        self.jobs.store.check_serial(serial)
        csr_der = Issuer.csr(serial, csr_pem).public_bytes(serialization.Encoding.DER)
        current = snapshot(self.jobs.controller,
            self.jobs.controller.inventory(serial, authorization), authorization)
        encoded = json.dumps(current, sort_keys=True, separators=(',', ':'))
        digest = hashlib.sha256(key.encode('ascii')).digest()
        csr_digest = hashlib.sha256(csr_der).digest()
        with self.jobs.lock, self.jobs.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('''SELECT j.*,k.csr_digest FROM installer_keys k
                JOIN onboarding_jobs j ON j.id=k.job WHERE k.digest=?''', (digest,)).fetchone()
            if not row or row['serial'] != serial or row['state'] not in ('waiting', 'running'):
                raise ValueError('Installer key is not authorized for this AP')
            if row['ownership'] != encoded:
                raise ValueError('AP ownership changed')
            if row['csr_digest'] is not None and row['csr_digest'] != csr_digest:
                raise ValueError('Installer key is already bound to another CSR')
            db.execute('UPDATE installer_keys SET csr_digest=? WHERE job=?', (csr_digest, row['id']))
            return row['id']
