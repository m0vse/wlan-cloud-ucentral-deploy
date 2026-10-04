"""Protected issuer core. No listener, authority generation, or gateway adapter.

Private root keys never enter this process. The operator supplies a validated
issuing key and chain; the durable grant implementation comes from wlan-ap's
isolated private-PKI tests. Callers must authenticate administration separately.
"""
import hashlib
import os
import re
import stat
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from enrollment_store import EnrollmentStore


def fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def private_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("unsafe issuer input")
        with os.fdopen(fd, "rb", closefd=False) as source:
            data = source.read(65537)
        if len(data) > 65536:
            raise ValueError("oversized issuer input")
        return data
    finally:
        os.close(fd)


def public(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


class Issuer:
    def __init__(self, root_path, issuer_path, key_path, state_path, clock=None, authorization_guard=None):
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.authorization_guard = authorization_guard
        self.root = x509.load_pem_x509_certificate(private_read(root_path))
        self.ca = x509.load_pem_x509_certificate(private_read(issuer_path))
        self.key = serialization.load_pem_private_key(private_read(key_path), password=None)
        self._check_chain()
        if public(self.key.public_key()) != public(self.ca.public_key()):
            raise ValueError("issuer key mismatch")
        self.authority = fingerprint(self.ca)
        self.store = EnrollmentStore(state_path, lambda: self.clock().timestamp())
        with self.store.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS issued(
                    fingerprint TEXT PRIMARY KEY, device TEXT NOT NULL,
                    issuer TEXT NOT NULL, certificate BLOB NOT NULL,
                    expires INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS renewal_replies(
                    request TEXT PRIMARY KEY, response BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS authorities(
                    fingerprint TEXT PRIMARY KEY, certificate BLOB NOT NULL, root BLOB NOT NULL);
                CREATE TABLE IF NOT EXISTS issuance_origins(
                    leaf TEXT PRIMARY KEY, kind TEXT NOT NULL, predecessor TEXT);
                CREATE TABLE IF NOT EXISTS migration_grants(
                    digest BLOB PRIMARY KEY, binding TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS migration_leaves(
                    leaf TEXT PRIMARY KEY, binding TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS management_acceptances(
                    challenge TEXT PRIMARY KEY, device TEXT NOT NULL, leaf TEXT NOT NULL,
                    issuer TEXT NOT NULL, root TEXT NOT NULL, kind TEXT NOT NULL,
                    accepted INTEGER NOT NULL, session INTEGER NOT NULL, policy INTEGER NOT NULL);
            """)
            db.execute("INSERT OR IGNORE INTO authorities VALUES (?,?,?)",
                       (self.authority, self.ca.public_bytes(serialization.Encoding.PEM), self.root.public_bytes(serialization.Encoding.PEM)))

    def _check_chain(self):
        self.root.verify_directly_issued_by(self.root)
        self.ca.verify_directly_issued_by(self.root)
        for cert in (self.root, self.ca):
            if not cert.not_valid_before_utc <= self.clock() < cert.not_valid_after_utc:
                raise ValueError("expired or future authority")
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            if not bc.ca or not ku.key_cert_sign:
                raise ValueError("invalid authority constraints")
        if self.ca.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length != 0:
            raise ValueError("device issuer must forbid subordinate authorities")
        root_limit = self.root.extensions.get_extension_for_class(x509.BasicConstraints).value.path_length
        if root_limit is not None and root_limit < 1:
            raise ValueError("root forbids device issuer")

    @staticmethod
    def csr(device, data, subject=None):
        EnrollmentStore.check_serial(device)
        if not isinstance(data, bytes) or len(data) > 16384:
            raise ValueError("invalid CSR size")
        csr = x509.load_pem_x509_csr(data)
        if not csr.is_signature_valid or csr.subject != (subject if subject is not None else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device)])):
            raise ValueError("CSR identity or proof rejected")
        key = csr.public_key()
        if not ((isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name == "secp256r1") or
                (isinstance(key, rsa.RSAPublicKey) and 2048 <= key.key_size <= 4096)):
            raise ValueError("unsupported AP key")
        return csr

    def approve(self, device):
        self.store.approve(device)

    def import_legacy(self, device, certificate_pem, trusted_root_pem):
        """Operator-reviewed public leaf under preconfigured retained trust.

        Caller supplies the retained root from protected deployment policy,
        never an AP/browser claim. No legacy signing key is loaded or needed.
        """
        self.store.check_serial(device)
        root = x509.load_pem_x509_certificate(trusted_root_pem)
        root.verify_directly_issued_by(root)
        if not root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("Invalid retained CA")
        # A pre-existing pinned CA may omit KeyUsage (valid legacy X.509).
        # If it is present it must permit signing. New CAs remain strict.
        try:
            if not root.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
                raise ValueError("Invalid retained CA key usage")
        except x509.ExtensionNotFound:
            pass
        peer = x509.load_pem_x509_certificate(certificate_pem)
        peer.verify_directly_issued_by(root)
        names = peer.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(names) != 1 or names[0].value != device:
            raise ValueError("Retained certificate identity mismatch")
        if peer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca or ExtendedKeyUsageOID.CLIENT_AUTH not in peer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
            raise ValueError("Retained certificate client purpose required")
        if not all(cert.not_valid_before_utc <= self.clock() < cert.not_valid_after_utc for cert in (root, peer)):
            raise ValueError("Expired retained identity requires recovery")
        authority, leaf = fingerprint(root), fingerprint(peer)
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            enabled = db.execute("SELECT enabled FROM inventory WHERE serial=?", (device,)).fetchone()
            if not enabled or enabled[0] != 1:
                raise ValueError("Explicit active inventory approval required")
            db.execute("INSERT OR IGNORE INTO authorities VALUES (?,?,?)", (authority, trusted_root_pem, trusted_root_pem))
            # Preserve prior revocation; import must never silently un-revoke.
            db.execute("INSERT OR IGNORE INTO issued VALUES (?,?,?,?,?,0)",
                (leaf, device, authority, peer.public_bytes(serialization.Encoding.PEM), int(peer.not_valid_after_utc.timestamp())))
            db.execute("INSERT OR IGNORE INTO issuance_origins VALUES (?, 'legacy', NULL)", (leaf,))
            self._check_peer(db, peer)
            db.execute("INSERT INTO audit(stamp,event,serial) VALUES (?,?,?)",
                (int(self.clock().timestamp()), "retained-identity-imported:" + leaf, device))
        return leaf

    def disable(self, device):
        self.store.check_serial(device)
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE inventory SET enabled=0 WHERE serial=?", (device,))
            db.execute("DELETE FROM grants WHERE serial=?", (device,))
            db.execute("INSERT INTO audit(stamp,event,serial) VALUES (?,?,?)",
                       (int(self.clock().timestamp()), "inventory-disabled", device))

    def authorize(self, device, csr_pem):
        self._check_chain()
        csr = self.csr(device, csr_pem)
        digest = hashlib.sha256(csr.public_bytes(serialization.Encoding.DER)).digest()
        return self.store.authorize(device, digest, self.authority)

    def _issue(self, db, device, csr, kind="bootstrap", predecessor=None):
        self._check_chain()
        stamp = self.clock()
        expiry = min(stamp + timedelta(days=365), self.ca.not_valid_after_utc, self.root.not_valid_after_utc)
        if expiry <= stamp + timedelta(minutes=5):
            raise ValueError("issuer too close to expiry")
        cert = (x509.CertificateBuilder().subject_name(csr.subject).issuer_name(self.ca.subject)
                .public_key(csr.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(stamp - timedelta(seconds=60)).not_valid_after(expiry)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), False)
                .sign(self.key, hashes.SHA256()))
        result = cert.public_bytes(serialization.Encoding.PEM)
        db.execute("INSERT INTO issued VALUES (?,?,?,?,?,0)",
                   (fingerprint(cert), device, self.authority, result, int(expiry.timestamp())))
        db.execute("INSERT INTO issuance_origins VALUES (?,?,?)", (fingerprint(cert), kind, predecessor))
        db.execute("INSERT INTO audit(stamp,event,serial) VALUES (?,?,?)",
                   (int(stamp.timestamp()), "certificate-issued", device))
        return result

    def bootstrap(self, device, token, csr_pem):
        self._check_chain()
        csr = self.csr(device, csr_pem)
        if not isinstance(token, str) or not 20 <= len(token) <= 128:
            raise ValueError("invalid grant")
        digest = hashlib.sha256(csr.public_bytes(serialization.Encoding.DER)).digest()
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            grant = db.execute("SELECT * FROM grants WHERE digest=?", (hashlib.sha256(token.encode()).digest(),)).fetchone()
            approved = db.execute("SELECT enabled FROM inventory WHERE serial=?", (device,)).fetchone()
            if not grant or not approved or approved[0] != 1 or grant["serial"] != device or grant["authority"] != self.authority or grant["expires"] <= self.clock().timestamp() or grant["csr"] != digest:
                raise ValueError("enrollment authorization rejected")
            binding = db.execute("SELECT binding FROM migration_grants WHERE digest=?", (grant["digest"],)).fetchone()
            if self.authorization_guard is not None:
                if not binding:
                    raise ValueError("Reviewed migration binding required")
                self.authorization_guard.migration(device, binding[0], db)
            if grant["response"] is not None:
                peer = x509.load_pem_x509_certificate(grant["response"])
                self._check_peer(db, peer)
                return grant["response"]
            response = self._issue(db, device, csr)
            if binding:
                issued = x509.load_pem_x509_certificate(response)
                db.execute("INSERT INTO migration_leaves VALUES (?,?)", (fingerprint(issued), binding[0]))
            db.execute("UPDATE grants SET response=? WHERE digest=?", (response, grant["digest"]))
            return response

    def _check_peer(self, db, peer):
        row = db.execute("SELECT * FROM issued WHERE fingerprint=?", (fingerprint(peer),)).fetchone()
        if not row or row["revoked"] or not peer.not_valid_before_utc <= self.clock() < peer.not_valid_after_utc:
            raise ValueError("unregistered, revoked or expired certificate")
        inventory = db.execute("SELECT enabled FROM inventory WHERE serial=?", (row["device"],)).fetchone()
        if not inventory or inventory[0] != 1:
            raise ValueError("disabled inventory")
        if self.authorization_guard is not None:
            self.authorization_guard.identity(row["device"], db)
        issuer_row = db.execute("SELECT certificate,root FROM authorities WHERE fingerprint=?", (row["issuer"],)).fetchone()
        issuer = x509.load_pem_x509_certificate(issuer_row[0])
        root = x509.load_pem_x509_certificate(issuer_row[1])
        issuer.verify_directly_issued_by(root)
        peer.verify_directly_issued_by(issuer)
        if not all(c.not_valid_before_utc <= self.clock() < c.not_valid_after_utc for c in (issuer, root)):
            raise ValueError("expired peer issuer")
        if peer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca or ExtendedKeyUsageOID.CLIENT_AUTH not in peer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
            raise ValueError("invalid client purpose")
        return row["device"]

    def renew(self, peer_der, csr_pem, attempt, native_subject=False):
        if not isinstance(attempt, str) or not re.fullmatch(r"[0-9a-f]{32}", attempt):
            raise ValueError("fresh renewal attempt required")
        peer = x509.load_der_x509_certificate(peer_der)  # supplied by authenticated TLS transport
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            device = self._check_peer(db, peer)
            csr = self.csr(device, csr_pem, peer.subject if native_subject else None)
            if public(peer.public_key()) != public(csr.public_key()):
                raise ValueError("renewal key differs from authenticated key")
            # Native EST retries can regenerate an ECDSA signature for the same
            # verified subject/key. Cache the authenticated request semantics.
            request_data = (csr.subject.public_bytes() + public(csr.public_key())) if native_subject else csr.public_bytes(serialization.Encoding.DER)
            request = fingerprint(peer) + hashlib.sha256(request_data).hexdigest() + self.authority + attempt
            cached = db.execute("SELECT response FROM renewal_replies WHERE request=?", (request,)).fetchone()
            if cached:
                self._check_peer(db, x509.load_pem_x509_certificate(cached[0]))
                return cached[0]
            response = self._issue(db, device, csr, "renewal", fingerprint(peer))
            db.execute("INSERT INTO renewal_replies VALUES (?,?)", (request, response))
            return response

    def revoke(self, leaf_fingerprint):
        if not isinstance(leaf_fingerprint, str) or not re.fullmatch(r"[0-9a-f]{64}", leaf_fingerprint):
            raise ValueError("invalid fingerprint")
        with self.store.connect() as db:
            row = db.execute("SELECT device FROM issued WHERE fingerprint=?", (leaf_fingerprint,)).fetchone()
            if not row:
                raise ValueError("unknown certificate")
            db.execute("UPDATE issued SET revoked=1 WHERE fingerprint=?", (leaf_fingerprint,))
            db.execute("INSERT INTO audit(stamp,event,serial) VALUES (?,?,?)",
                       (int(self.clock().timestamp()), "certificate-revoked:" + leaf_fingerprint, row[0]))
        # This core enforces renewal denial. Gateway distribution is still required.
