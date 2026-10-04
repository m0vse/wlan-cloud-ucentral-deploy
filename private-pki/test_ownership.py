import copy
import unittest
from unittest.mock import Mock
from ownership import snapshot


class OwnershipTests(unittest.TestCase):
    def fixtures(self):
        inventory = {'id': 'inventory-id', 'serialNumber': '001122334455',
            'entity': '', 'venue': 'child-venue', 'subscriber': ''}
        records = {
            (16005, 'venue/child-venue'): {'id': 'child-venue', 'parent': 'parent-venue', 'entity': ''},
            (16005, 'venue/parent-venue'): {'id': 'parent-venue', 'parent': '', 'entity': 'child-entity'},
            (16005, 'entity/child-entity'): {'id': 'child-entity', 'parent': '0000-0000-0000', 'entity': ''},
            (16005, 'entity/0000-0000-0000'): {'id': '0000-0000-0000', 'parent': '', 'entity': ''},
        }
        controller = Mock()
        controller.fetch.side_effect = lambda port, route, authorization: records[(port, route)]
        return inventory, records, controller

    def test_venue_inheritance_and_preserved_tuple(self):
        inventory, records, controller = self.fixtures()
        result = snapshot(controller, inventory, 'Bearer synthetic')
        self.assertEqual(result['effectiveEntity'], 'child-entity')
        self.assertEqual(result['direct']['entity'], '')
        self.assertEqual(len(result['venueAncestry']), 2)
        self.assertEqual(len(result['entityAncestry']), 2)
        self.assertIsNone(result['subscriber'])
        self.assertTrue(all(call.args[0] == 16005 for call in controller.fetch.call_args_list))

    def test_missing_changed_conflicting_cycles_and_subscriber_status(self):
        inventory, records, controller = self.fixtures()
        for changed in (dict(inventory, id=''), dict(inventory, venue='../escape'), dict(inventory, entity='conflicting-entity')):
            with self.assertRaises(ValueError):
                snapshot(controller, changed, 'Bearer synthetic')
        records[(16005, 'venue/parent-venue')]['parent'] = 'child-venue'
        with self.assertRaises(ValueError):
            snapshot(controller, inventory, 'Bearer synthetic')
        inventory, records, controller = self.fixtures()
        inventory['subscriber'] = 'subscriber-id'
        records[(16001, 'subuser/subscriber-id')] = {'id': 'subscriber-id', 'owner': 'operator-id', 'userRole': 'subscriber', 'suspended': False, 'blackListed': False}
        records[(16001, 'user/operator-id')] = {'id': 'operator-id', 'suspended': False, 'blackListed': False}
        self.assertEqual(snapshot(controller, inventory, 'Bearer synthetic')['subscriber']['owner'], 'operator-id')
        records[(16001, 'subuser/subscriber-id')]['userRole'] = 'root'
        with self.assertRaises(ValueError):
            snapshot(controller, inventory, 'Bearer synthetic')
        records[(16001, 'subuser/subscriber-id')]['userRole'] = 'subscriber'
        for key in ('suspended', 'blackListed'):
            records[(16001, 'subuser/subscriber-id')][key] = True
            with self.assertRaises(ValueError):
                snapshot(controller, inventory, 'Bearer synthetic')
            records[(16001, 'subuser/subscriber-id')][key] = False
        records[(16001, 'user/operator-id')]['id'] = 'wrong'
        with self.assertRaises(ValueError):
            snapshot(controller, inventory, 'Bearer synthetic')
