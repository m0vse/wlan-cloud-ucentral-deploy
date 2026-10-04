"""Publish a short-lived, versioned gateway policy from the issuer ledger.

The directory is a private deployment input, mounted read-only by the gateway
as a directory so atomic replacement remains visible. It contains no key/token.
The gateway must have an explicitly matched file owner/group configuration.
"""
import json
import fcntl
import os
from pathlib import Path
import stat
import tempfile

from cryptography import x509


def publish(issuer, directory, lifetime=60):
    if type(lifetime) is not int or not 5 <= lifetime <= 300:
        raise ValueError("invalid gateway policy lifetime")
    path = Path(directory)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o027:
        raise ValueError("unsafe gateway policy directory")
    lock = os.open(path / "policy.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("unsafe policy publisher lock")
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _publish_locked(issuer, path, lifetime)
    finally:
        os.close(lock)


def _publish_locked(issuer, path, lifetime):
    with issuer.store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("CREATE TABLE IF NOT EXISTS gateway_policy_version(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL)")
        db.execute("INSERT OR IGNORE INTO gateway_policy_version VALUES (1,0)")
        db.execute("UPDATE gateway_policy_version SET version=version+1 WHERE id=1")
        version = db.execute("SELECT version FROM gateway_policy_version WHERE id=1").fetchone()[0]
    with issuer.store.connect() as db:
        db.execute("BEGIN IMMEDIATE")
        inventory = {row["serial"]: {"enabled": row["enabled"] == 1, "fingerprints": []}
                     for row in db.execute("SELECT serial,enabled FROM inventory")}
        revoked = []
        for row in db.execute("SELECT * FROM issued"):
            if row["revoked"]:
                revoked.append(row["fingerprint"])
                continue
            try:
                cert = x509.load_pem_x509_certificate(row["certificate"])
                device = issuer._check_peer(db, cert)
                inventory[device]["fingerprints"].append(row["fingerprint"])
            except (ValueError, x509.ExtensionNotFound):
                continue
        policy = {"schemaVersion": 1, "version": version,
                  "expires": int(issuer.clock().timestamp()) + lifetime,
                  "inventory": inventory, "revoked": revoked}
        data = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
        if len(data) > 1024 * 1024:
            raise ValueError("gateway policy capacity exceeded")
        fd, temporary = tempfile.mkstemp(prefix=".policy-", dir=path)
        try:
            with os.fdopen(fd, "wb") as output:
                os.fchmod(output.fileno(), 0o640)
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path / "policy.json")
            directory_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return policy
