"""Durable enrollment state reused from wlan-ap's isolated PKI reference.

Tokens are stored only as SHA256 digests. Complete CSR/issuer-bound grants and
issued responses commit in one SQLite transaction, including retry after a
process restart. Inventory approval is a separate trusted operator action.
"""
import hashlib
from contextlib import contextmanager
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import time


class EnrollmentStore:
    def __init__(self, path, clock=time.time):
        self.path = Path(path)
        self.clock = clock
        os.umask(0o077)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.path.parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("unsafe enrollment state directory")
        if self.path.exists() or self.path.is_symlink():
            info = self.path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError("unsafe enrollment state file")
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS inventory(serial TEXT PRIMARY KEY, enabled INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS grants(
                    digest BLOB PRIMARY KEY, serial TEXT NOT NULL, csr BLOB NOT NULL,
                    authority TEXT NOT NULL, expires INTEGER NOT NULL, response BLOB);
                CREATE TABLE IF NOT EXISTS revoked(serial TEXT PRIMARY KEY);
                CREATE TABLE IF NOT EXISTS audit(
                    id INTEGER PRIMARY KEY, stamp INTEGER NOT NULL, event TEXT NOT NULL, serial TEXT NOT NULL);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.execute("PRAGMA synchronous=FULL")
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def check_serial(serial):
        if not isinstance(serial, str) or not re.fullmatch(r"[0-9a-f]{12}", serial):
            raise ValueError("invalid inventory identity")

    def approve(self, serial):
        # Local trusted operator action, never approval based on bare MAC/CSR.
        self.check_serial(serial)
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO inventory VALUES (?,1)", (serial,))
            db.execute("INSERT INTO audit(stamp,event,serial) VALUES (?,?,?)", (int(self.clock()), "inventory-approved", serial))

    def authorize(self, serial, csr_digest, authority, lifetime=600):
        self.check_serial(serial)
        if len(csr_digest) != 32 or not 1 <= lifetime <= 600:
            raise ValueError("invalid enrollment policy")
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).digest()
        with self.connect() as db:
            approved = db.execute("SELECT enabled FROM inventory WHERE serial=?", (serial,)).fetchone()
            if not approved or approved[0] != 1:
                raise ValueError("inventory authorization required")
            db.execute("INSERT INTO grants VALUES (?,?,?,?,?,NULL)",
                       (digest, serial, csr_digest, authority, int(self.clock()) + lifetime))
            db.execute("INSERT INTO audit(stamp,event,serial) VALUES (?,?,?)", (int(self.clock()), "grant-authorized", serial))
        return token

    def redeem(self, serial, token, csr_digest, authority, issue):
        self.check_serial(serial)
        digest = hashlib.sha256(token.encode()).digest()
        # Serialize issuance itself, not just writing the cached response.
        # Crash before commit consumes no grant; after commit retry returns it.
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            grant = db.execute("SELECT * FROM grants WHERE digest=?", (digest,)).fetchone()
            approved = db.execute("SELECT enabled FROM inventory WHERE serial=?", (serial,)).fetchone()
            if not grant or not approved or approved[0] != 1 or grant["serial"] != serial or \
                    grant["authority"] != authority or grant["expires"] <= self.clock() or \
                    not secrets.compare_digest(grant["csr"], csr_digest):
                raise ValueError("enrollment authorization rejected")
            if grant["response"] is not None:
                return grant["response"]
            response = issue()
            if not isinstance(response, bytes) or not response or len(response) > 65536:
                raise ValueError("invalid issuer response")
            db.execute("UPDATE grants SET response=? WHERE digest=?", (response, digest))
            db.execute("INSERT INTO audit(stamp,event,serial) VALUES (?,?,?)", (int(self.clock()), "grant-issued", serial))
            return response

    def revoke(self, certificate_serial):
        with self.connect() as db:
            db.execute("INSERT OR IGNORE INTO revoked VALUES (?)", (format(certificate_serial, "x"),))

    def is_revoked(self, certificate_serial):
        with self.connect() as db:
            return db.execute("SELECT 1 FROM revoked WHERE serial=?", (format(certificate_serial, "x"),)).fetchone() is not None
