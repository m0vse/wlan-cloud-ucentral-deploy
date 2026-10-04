"""Fresh controller ownership and version-bound migration authorization.

The controller adapter uses a protected server credential. No browser ownership
snapshot is accepted, and ordinary renewal does not consult SKU qualification.
"""
import hashlib
import json
import secrets
from cryptography.hazmat.primitives import serialization
from ownership import snapshot


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


class AuthorizationGuard:
    def __init__(self, issuer, controller, credential, lifecycle, registry):
        self.issuer, self.controller, self.credential = issuer, controller, credential
        self.lifecycle, self.registry = lifecycle, registry

    def current(self, device):
        authorization = self.credential()
        inventory = self.controller.inventory(device, authorization)
        ownership = snapshot(self.controller, inventory, authorization)
        return inventory, ownership

    def identity(self, device, db):
        _, ownership = self.current(device)
        return self.lifecycle.check(device, ownership, db)

    def binding(self, device, operation, db):
        inventory, ownership = self.current(device)
        version = self.lifecycle.check(device, ownership, db)
        qualified = self.registry.check(device, inventory, operation, db)
        return {'operation': operation, 'ownership': ownership,
                'lifecycleVersion': version, **qualified}

    def migration(self, device, encoded, db):
        expected = json.loads(encoded)
        if self.binding(device, expected['operation'], db) != expected:
            raise ValueError('Migration approval or ownership changed; review required')

    def authorize(self, actor, device, csr_pem, operation):
        self.issuer.store.check_serial(device)
        if not isinstance(actor, str) or not actor or len(actor) > 128:
            raise ValueError('Authenticated operator required')
        self.issuer._check_chain()
        csr = self.issuer.csr(device, csr_pem)
        csr_digest = hashlib.sha256(csr.public_bytes(serialization.Encoding.DER)).digest()
        token = secrets.token_urlsafe(32)
        digest = hashlib.sha256(token.encode()).digest()
        with self.issuer.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            # All checks precede grant/audit writes, in the same transaction.
            binding = self.binding(device, operation, db)
            stamp = int(self.issuer.clock().timestamp())
            db.execute('INSERT INTO grants VALUES (?,?,?,?,?,NULL)',
                       (digest, device, csr_digest, self.issuer.authority, stamp + 600))
            db.execute('INSERT INTO migration_grants VALUES (?,?)', (digest, encode(binding)))
            db.execute('INSERT INTO operator_audit(stamp,actor,action,target) VALUES (?,?,?,?)',
                       (stamp, actor, 'enrollment-authorized', device))
        return token

    def activation(self, device, leaf, db):
        origin = db.execute('SELECT kind FROM issuance_origins WHERE leaf=?', (leaf,)).fetchone()
        # Renewal only requires active ownership, checked by Issuer._check_peer.
        if origin and origin[0] == 'renewal':
            return
        binding = db.execute('SELECT binding FROM migration_leaves WHERE leaf=?', (leaf,)).fetchone()
        if not binding:
            raise ValueError('Reviewed candidate migration binding required')
        self.migration(device, binding[0], db)
