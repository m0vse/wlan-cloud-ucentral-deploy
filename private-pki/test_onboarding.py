from datetime import timedelta
import sqlite3
import unittest
from onboarding import Onboarding
import test_ownership
import test_issuer


class OnboardingTests(unittest.TestCase):
    setUp = test_issuer.IssuerTests.setUp
    request = test_issuer.IssuerTests.request
    write_authority = test_issuer.IssuerTests.write_authority
    load = test_issuer.IssuerTests.load

    def prepare(self):
        inventory, records, controller = test_ownership.OwnershipTests.fixtures(self)
        controller.inventory.return_value = inventory
        return Onboarding(self.issuer.store, controller), inventory, controller

    def test_approval_has_no_time_window_and_survives_restart(self):
        jobs, inventory, controller = self.prepare()
        first = jobs.start('root', self.device, 'Bearer synthetic')
        self.assertEqual(first['state'], 'waiting')
        self.assertEqual(jobs.start('root', self.device, 'Bearer synthetic')['id'], first['id'])
        self.clock += timedelta(days=90)
        restored = Onboarding(self.load().store, controller)
        self.assertEqual(restored.list()[0]['id'], first['id'])
        self.assertEqual(restored.start('root', self.device, 'Bearer synthetic')['id'], first['id'])
        self.assertEqual(restored.lifecycle.view(self.device)['version'], 1)
        with self.issuer.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM grants').fetchone()[0], 0)
        self.assertNotIn('Bearer', str(restored.list()))
        self.assertNotIn('ownership', str(restored.list()))

    def test_cancel_and_changed_inventory_do_not_inherit_approval(self):
        jobs, inventory, controller = self.prepare()
        first = jobs.start('root', self.device, 'Bearer synthetic')
        inventory['id'] = 'replacement-inventory'
        with self.assertRaises(ValueError):
            jobs.start('root', self.device, 'Bearer synthetic')
        self.assertEqual(jobs.cancel('root', first['id'])['state'], 'cancelled')
        self.assertEqual(jobs.cancel('root', first['id'])['state'], 'cancelled')
        second = jobs.start('root', self.device, 'Bearer synthetic')
        self.assertNotEqual(first['id'], second['id'])

    def test_failed_job_commit_does_not_leave_a_lifecycle_approval(self):
        jobs, inventory, controller = self.prepare()
        with self.issuer.store.connect() as db:
            db.execute("CREATE TRIGGER reject_onboarding_audit BEFORE INSERT ON operator_audit BEGIN SELECT RAISE(ABORT, 'synthetic commit failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            jobs.start('root', self.device, 'Bearer synthetic')
        self.assertEqual(jobs.list(), [])
        self.assertIsNone(jobs.lifecycle.view(self.device))


if __name__ == '__main__':
    unittest.main()
