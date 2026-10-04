import unittest
from unittest.mock import Mock
from admin import Denied
from issuer import fingerprint
from portal_runtime import PortalAdministration
import test_issuer


class PortalRuntimeTests(unittest.TestCase):
    setUp = test_issuer.IssuerTests.setUp
    request = test_issuer.IssuerTests.request
    write_authority = test_issuer.IssuerTests.write_authority
    load = test_issuer.IssuerTests.load

    def test_live_status_does_not_claim_prepared_authority_is_active(self):
        controller = Mock()
        controller.root.return_value = 'reviewing-root'
        admin = PortalAdministration(self.issuer, controller, [self.path / 'root'])
        status = admin.call('Bearer synthetic', 'status', {})
        self.assertEqual(status['phase'], 'prepared')
        self.assertEqual(status['activeRoot'], '')
        self.assertEqual(status['activeIssuer'], '')
        self.assertEqual(status['preparedIssuer'], self.issuer.authority)
        self.assertEqual(status['preparedRoot'], fingerprint(self.issuer.root))
        self.assertEqual({root['state'] for root in status['roots']}, {'prepared', 'retained'})
        self.assertEqual(status['gatewayEnforcement'], 'not-integrated')
        controller.root.assert_called_once_with('Bearer synthetic')

    def test_current_controller_denial_prevents_registry_mutation(self):
        controller = Mock()
        controller.root.side_effect = Denied(403, 'Root required')
        admin = PortalAdministration(self.issuer, controller, [self.path / 'root'])
        for operation, request in [('status', {}), ('audit', {}),
                                   ('approve-hardware', {'record': {}})]:
            with self.assertRaises(Denied):
                admin.call('Bearer synthetic', operation, request)
        controller.inventory.assert_not_called()


if __name__ == '__main__':
    unittest.main()
