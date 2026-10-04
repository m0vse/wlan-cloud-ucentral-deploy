import copy
import unittest
from lifecycle import Lifecycle
import test_issuer


class LifecycleTests(unittest.TestCase):
    setUp = test_issuer.IssuerTests.setUp
    request = test_issuer.IssuerTests.request
    write_authority = test_issuer.IssuerTests.write_authority
    load = test_issuer.IssuerTests.load

    def test_explicit_state_owner_change_disable_and_individual_retirement(self):
        lifecycle = Lifecycle(self.issuer.store)
        owner = {'serial': self.device, 'inventoryId': 'synthetic-inventory',
                 'direct': {'entity': '', 'venue': 'synthetic-venue', 'subscriber': ''}}
        with self.assertRaises(ValueError):
            lifecycle.check(self.device, owner)
        lifecycle.approve('operator', self.device, owner, True, True, False)
        self.assertEqual(lifecycle.check(self.device, owner), 1)
        for field in ('inventoryId', 'direct'):
            changed = copy.deepcopy(owner)
            changed[field] = 'different'
            with self.assertRaises(ValueError):
                lifecycle.check(self.device, changed)
        token = self.issuer.authorize(self.device, self.csr)
        lifecycle.approve('operator', self.device, owner, True, False, False)
        with self.assertRaises(ValueError):
            self.issuer.bootstrap(self.device, token, self.csr)
        lifecycle.approve('operator', self.device, owner, False, False, True)
        self.assertTrue(lifecycle.view(self.device)['retired'])
        with self.assertRaises(ValueError):
            lifecycle.check(self.device, owner)
        with self.assertRaises(ValueError):
            lifecycle.approve('operator', self.device, owner, True, True, True)
        with self.assertRaises(ValueError):
            lifecycle.approve('operator', self.device, owner, 1, True, False)
        self.assertEqual(Lifecycle(self.load().store).view(self.device)['version'], 3)
