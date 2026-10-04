import copy
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from authorization_guard import AuthorizationGuard
from lifecycle import Lifecycle
from admin import Administration
from issuer import fingerprint
import test_issuer


class Registry:
    def __init__(self):
        self.version = 1
        self.allowed = True

    def check(self, device, inventory, operation, db):
        if not self.allowed or operation != 'production-stock-openwrt-migration':
            raise ValueError('Unqualified operation')
        return {'hardwareVersion': 1, 'qualification': 'synthetic',
                'qualificationVersion': self.version}


class GuardTests(unittest.TestCase):
    setUp = test_issuer.IssuerTests.setUp
    request = test_issuer.IssuerTests.request
    write_authority = test_issuer.IssuerTests.write_authority
    load = test_issuer.IssuerTests.load

    def prepare(self):
        lifecycle = Lifecycle(self.issuer.store)
        owner = {'serial': self.device, 'inventoryId': 'inventory-one'}
        lifecycle.approve('root', self.device, owner, True, True, False)
        registry = Registry()
        guard = AuthorizationGuard(self.issuer, None, None, lifecycle, registry)
        guard.current = lambda device: ({'serialNumber': device}, copy.deepcopy(owner))
        Administration(self.issuer, None)  # creates protected operator audit table
        self.issuer.authorization_guard = guard
        return guard, registry, owner

    def test_grant_change_and_retry_revalidation_without_failed_writes(self):
        guard, registry, owner = self.prepare()
        operation = 'production-stock-openwrt-migration'
        token = guard.authorize('root', self.device, self.csr, operation)
        registry.version += 1
        with self.assertRaises(ValueError):
            self.issuer.bootstrap(self.device, token, self.csr)
        with self.issuer.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM issued').fetchone()[0], 0)
        token = guard.authorize('root', self.device, self.csr, operation)
        leaf = self.issuer.bootstrap(self.device, token, self.csr)
        owner['inventoryId'] = 'inventory-replaced'
        with self.assertRaises(ValueError):
            self.issuer.bootstrap(self.device, token, self.csr)
        with self.issuer.store.connect() as db:
            with self.assertRaises(ValueError):
                guard.activation(self.device, fingerprint(x509.load_pem_x509_certificate(leaf)), db)

    def test_renewal_independent_of_migration_qualification_but_not_ownership(self):
        guard, registry, owner = self.prepare()
        token = guard.authorize('root', self.device, self.csr, 'production-stock-openwrt-migration')
        leaf = self.issuer.bootstrap(self.device, token, self.csr)
        peer = x509.load_pem_x509_certificate(leaf).public_bytes(serialization.Encoding.DER)
        registry.allowed = False
        renewed = self.issuer.renew(peer, self.csr, 'a' * 32)
        self.assertNotEqual(leaf, renewed)
        owner['inventoryId'] = 'different'
        with self.assertRaises(ValueError):
            self.issuer.renew(peer, self.csr, 'b' * 32)

    def test_unqualified_authorization_has_no_grant_or_audit_writes(self):
        guard, registry, _ = self.prepare()
        with self.assertRaises(ValueError):
            guard.authorize('root', self.device, self.csr, 'production-oem-migration')
        with self.issuer.store.connect() as db:
            for table in ('grants', 'migration_grants', 'operator_audit'):
                self.assertEqual(db.execute('SELECT count(*) FROM ' + table).fetchone()[0], 0)
