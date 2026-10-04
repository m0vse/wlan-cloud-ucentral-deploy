import copy
import unittest
from urllib.parse import parse_qs, urlsplit
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from fleet_gate import FleetGate
from issuer import fingerprint
from lifecycle import Lifecycle
import test_fixtures
import test_issuer


class Controller:
    def __init__(self, inventory, devices, state):
        self.inventory_rows, self.devices, self.state = inventory, devices, state
        self.calls = []
        self.bad_count = False

    def fetch(self, port, route, authorization):
        self.calls.append((port, route))
        parsed = urlsplit(route)
        if parsed.path.startswith('device/'):
            return copy.deepcopy(self.state)
        rows, key = (self.inventory_rows, 'taglist') if port == 16005 else (self.devices, 'devices')
        query = parse_qs(parsed.query)
        if query.get('countOnly') == ['true']:
            return {'count': len(rows) + int(self.bad_count)}
        offset, limit = int(query['offset'][0]), int(query['limit'][0])
        return {key: copy.deepcopy(rows[offset:offset + limit])}

    def inventory(self, device, authorization):
        return copy.deepcopy(next(row for row in self.inventory_rows if row['serialNumber'] == device))


class FleetTests(unittest.TestCase):
    setUp = test_issuer.IssuerTests.setUp
    request = test_issuer.IssuerTests.request
    write_authority = test_issuer.IssuerTests.write_authority
    load = test_issuer.IssuerTests.load

    def prepare(self):
        old_root = fingerprint(self.issuer.root)
        old_leaf = self.issuer.bootstrap(self.device, self.issuer.authorize(self.device, self.csr), self.csr)
        self.write_authority(test_fixtures.Authority())
        self.issuer = self.load()
        leaf = self.issuer.renew(x509.load_pem_x509_certificate(old_leaf).public_bytes(serialization.Encoding.DER), self.csr, 'a' * 32)
        leaf_fp = fingerprint(x509.load_pem_x509_certificate(leaf))
        record = {'serialNumber': self.device, 'id': 'inventory-one', 'entity': 'entity-one', 'venue': '', 'subscriber': ''}
        owner = {'serial': self.device, 'inventoryId': record['id'],
                 'direct': {key: record[key] for key in ('entity', 'venue', 'subscriber')}}
        lifecycle = Lifecycle(self.issuer.store)
        lifecycle.approve('root', self.device, owner, True, True, False)
        state = {'deviceInfo': {'serialNumber': self.device}, 'connectionInfo': {
            'connected': True, 'verifiedCertificate': 'VERIFIED',
            'privateLeafSha256': leaf_fp, 'sessionId': 44}}
        controller = Controller([record], [record], state)
        snapshot = lambda controller, inventory, authorization: {
            'serial': inventory['serialNumber'], 'inventoryId': inventory['id'],
            'direct': {key: inventory[key] for key in ('entity', 'venue', 'subscriber')}}
        gate = FleetGate(self.issuer, controller, lifecycle, snapshot)
        with self.issuer.store.connect() as db:
            db.execute('INSERT INTO management_acceptances VALUES (?,?,?,?,?,?,?,?,?)',
                ('synthetic-receipt', self.device, leaf_fp, self.issuer.authority,
                 fingerprint(self.issuer.root), 'renewal', int(self.clock.timestamp()), 44, 1))
        return gate, controller, lifecycle, owner, old_root

    def test_complete_pagination_and_invalid_count_duplicate_refusal(self):
        gate, controller, _, _, _ = self.prepare()
        controller.inventory_rows = [{'serialNumber': format(i, '012x'), 'id': str(i)} for i in range(105)]
        self.assertEqual(len(gate.scan(16005, 'inventory', 'taglist', 'Bearer synthetic')), 105)
        self.assertTrue(any('offset=100' in route for _, route in controller.calls))
        controller.bad_count = True
        with self.assertRaises(ValueError):
            gate.scan(16005, 'inventory', 'taglist', 'Bearer synthetic')
        controller.bad_count = False
        controller.inventory_rows[-1] = controller.inventory_rows[0]
        with self.assertRaises(ValueError):
            gate.scan(16005, 'inventory', 'taglist', 'Bearer synthetic')

    def test_new_root_renewal_current_session_then_offline_and_stale_block(self):
        gate, controller, _, _, old_root = self.prepare()
        self.assertTrue(gate.review('Bearer synthetic', old_root)['ready'])
        controller.state['connectionInfo']['connected'] = False
        self.assertFalse(gate.review('Bearer synthetic', old_root)['ready'])
        controller.state['connectionInfo']['connected'] = True
        controller.state['connectionInfo']['sessionId'] = 45
        self.assertFalse(gate.review('Bearer synthetic', old_root)['ready'])
        with self.assertRaises(ValueError):
            gate.review('Bearer synthetic', fingerprint(self.issuer.root))

    def test_ledger_only_missing_identity_and_explicit_retirement(self):
        gate, controller, lifecycle, owner, old_root = self.prepare()
        controller.inventory_rows = []
        controller.devices = []
        self.assertFalse(gate.review('Bearer synthetic', old_root)['ready'])
        lifecycle.approve('root', self.device, owner, False, False, True)
        review = gate.review('Bearer synthetic', old_root)
        self.assertTrue(review['ready'])
        self.assertEqual(review['explicitlyRetired'], [self.device])
        controller.inventory_rows = [{'serialNumber': self.device, 'id': 'replacement', 'entity': 'entity-one', 'venue': '', 'subscriber': ''}]
        self.assertFalse(gate.review('Bearer synthetic', old_root)['ready'])

    def test_retired_device_still_connected_remains_a_blocker(self):
        gate, controller, lifecycle, owner, old_root = self.prepare()
        lifecycle.approve('root', self.device, owner, False, False, True)
        self.assertFalse(gate.review('Bearer synthetic', old_root)['ready'])
        controller.state['connectionInfo']['connected'] = False
        self.assertTrue(gate.review('Bearer synthetic', old_root)['ready'])
