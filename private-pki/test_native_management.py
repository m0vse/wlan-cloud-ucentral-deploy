import unittest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from native_management import NativeManagement
from ownership import snapshot
from test_onboarding import OnboardingTests


class NativeManagementTests(unittest.TestCase):
    setUp = OnboardingTests.setUp
    request = OnboardingTests.request
    write_authority = OnboardingTests.write_authority
    load = OnboardingTests.load
    prepare = OnboardingTests.prepare

    def ready(self):
        jobs, inventory, controller = self.prepare()
        original_fetch = controller.fetch.side_effect
        ownership = snapshot(controller, inventory, 'Bearer synthetic')
        jobs.lifecycle.approve('root', self.device, ownership, True, True, False)
        leaf = self.issuer.bootstrap(self.device, self.issuer.authorize(self.device,self.csr),self.csr)
        peer = x509.load_pem_x509_certificate(leaf)
        connection = {'connected':True, 'verifiedCertificate':'VERIFIED', 'sessionId':1,
                      'certificateExpiryDate':int(peer.not_valid_after_utc.timestamp()),
                      'certificateIssuerName':peer.issuer.rfc4514_string()}
        controller.fetch.side_effect = lambda port, route, auth: ({'connectionInfo':connection}
            if port == 16002 else original_fetch(port,route,auth))
        controller.request.return_value = {'errorCode':0,'UUID':'native-command-id'}
        return jobs, inventory, controller, leaf, connection, NativeManagement(self.issuer,controller,jobs)

    def test_native_command_once_then_actual_session_matches_new_leaf(self):
        jobs, inventory, controller, old, connection, native = self.ready()
        job = native.request('root',self.device,'Bearer synthetic','renew')
        self.assertEqual(job['state'],'running')
        native.request('root',self.device,'Bearer synthetic','renew')
        self.assertEqual(controller.request.call_count,1)
        # Native GW passes Params unchanged; the AP action handler requires
        # 'serial', not the command result's 'serialNumber' field.
        controller.request.assert_called_once_with(16002,f'device/{self.device}/reenroll','Bearer synthetic',
            method='POST',body={'serial':self.device,'when':0},timeout=30)
        certificates = [{'device':self.device,'fingerprint':self.fingerprint(old)}]
        native.reconcile('Bearer synthetic',certificates)
        self.assertEqual(jobs.list()[0]['state'],'running')
        # Different certificate observed after the native client reconnects.
        from datetime import timedelta
        self.clock += timedelta(seconds=2)
        new = self.issuer.renew(x509.load_pem_x509_certificate(old).public_bytes(serialization.Encoding.DER),self.csr,'a'*32)
        connection.update(sessionId=2,certificateExpiryDate=int(x509.load_pem_x509_certificate(new).not_valid_after_utc.timestamp()))
        certificates.append({'device':self.device,'fingerprint':self.fingerprint(new)})
        native.reconcile('Bearer synthetic',certificates)
        self.assertEqual(jobs.list()[0]['state'],'complete')
        self.assertTrue(certificates[-1]['nativeConnected'])
        self.assertNotIn('Bearer',str(jobs.list()))

    @staticmethod
    def fingerprint(pem):
        from issuer import fingerprint
        return fingerprint(x509.load_pem_x509_certificate(pem))

    def test_disabled_or_changed_owner_prevents_native_command(self):
        jobs, inventory, controller, old, connection, native = self.ready()
        self.issuer.disable(self.device)
        with self.assertRaises(ValueError): native.request('root',self.device,'Bearer synthetic','renew')
        controller.request.assert_not_called()
        self.issuer.approve(self.device)
        inventory['id']='changed-inventory'
        with self.assertRaises(ValueError): native.request('root',self.device,'Bearer synthetic','renew')
        certificates=[{'device':self.device,'fingerprint':self.fingerprint(old)}]
        native.reconcile('Bearer synthetic',certificates)
        self.assertIn('nativeError',certificates[0])
        with self.issuer.store.connect() as db:
            self.assertEqual(db.execute('SELECT enabled FROM inventory WHERE serial=?',(self.device,)).fetchone()[0],0)

    def test_rpc_timeout_keeps_durable_check_state_without_resubmission(self):
        jobs, inventory, controller, old, connection, native = self.ready()
        controller.request.side_effect=TimeoutError('synthetic network timeout')
        with self.assertRaises(TimeoutError): native.request('root',self.device,'Bearer synthetic','renew')
        self.assertEqual(jobs.list()[0]['state'],'running')
        native.request('root',self.device,'Bearer synthetic','renew')
        self.assertEqual(controller.request.call_count,1)

    def test_explicit_native_failure_is_terminal_and_operator_can_retry(self):
        jobs,inventory,controller,old,connection,native=self.ready()
        controller.request.return_value={'errorCode':1,'UUID':'failed-native-command'}
        job=native.request('root',self.device,'Bearer synthetic','renew')
        self.assertEqual(job['state'],'failed')
        controller.request.return_value={'errorCode':0,'UUID':'retry-native-command'}
        retried=native.request('root',self.device,'Bearer synthetic','renew')
        self.assertEqual(retried['state'],'running')
        self.assertNotEqual(job['id'],retried['id'])
        self.assertEqual(controller.request.call_count,2)

    def test_delete_replaced_entry_preserves_signing_history_and_protects_current(self):
        from admin import Denied
        from datetime import timedelta
        jobs, inventory, controller, old, connection, native = self.ready()
        old_fp = self.fingerprint(old)
        with self.assertRaises(Denied):
            native.delete('root', old_fp, 'Bearer synthetic')
        self.clock += timedelta(seconds=2)
        new = self.issuer.renew(x509.load_pem_x509_certificate(old).public_bytes(serialization.Encoding.DER),self.csr,'b'*32)
        new_fp = self.fingerprint(new)
        connection['certificateExpiryDate'] = int(x509.load_pem_x509_certificate(new).not_valid_after_utc.timestamp())
        rows = [{'device':self.device,'fingerprint':old_fp},{'device':self.device,'fingerprint':new_fp}]
        native.reconcile('Bearer synthetic', rows)
        self.assertTrue(rows[0]['canDelete'])
        self.assertFalse(rows[1]['canDelete'])
        native.delete('root', old_fp, 'Bearer synthetic')
        native.reconcile('Bearer synthetic', rows)
        self.assertEqual([row['fingerprint'] for row in rows], [new_fp])
        with self.issuer.store.connect() as db:
            self.assertIsNotNone(db.execute('SELECT 1 FROM issued WHERE fingerprint=?', (old_fp,)).fetchone())
        with self.assertRaises(Denied):
            native.delete('root', new_fp, 'Bearer synthetic')
        connection['connected'] = False
        with self.assertRaises(Denied):
            native.delete('root', old_fp, 'Bearer synthetic')
        # A rollback makes the formerly hidden certificate visible again.
        connection.update(connected=True,certificateExpiryDate=int(x509.load_pem_x509_certificate(old).not_valid_after_utc.timestamp()))
        rows = [{'device':self.device,'fingerprint':old_fp}]
        native.reconcile('Bearer synthetic', rows)
        self.assertTrue(rows[0]['nativeConnected'])

    def test_delete_refuses_running_renewal_and_changed_ownership(self):
        from admin import Denied
        jobs, inventory, controller, old, connection, native = self.ready()
        native.request('root', self.device, 'Bearer synthetic', 'renew')
        from datetime import timedelta
        self.clock += timedelta(seconds=2)
        new = self.issuer.renew(x509.load_pem_x509_certificate(old).public_bytes(serialization.Encoding.DER),self.csr,'c'*32)
        with self.assertRaises(Denied):
            native.delete('root', self.fingerprint(new), 'Bearer synthetic')
        inventory['id'] = 'changed'
        with self.assertRaises(ValueError):
            native.delete('root', self.fingerprint(new), 'Bearer synthetic')
