import base64,datetime,json,unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import ec
from test_enrollment_campaign import CampaignTests

class CommonAdmissionTests(CampaignTests):
    def test_migration_key_enrolls_without_registry_and_preserves_historical_metadata(self):
        campaigns,_=self.campaigns();batch=campaigns.create('root',[self.device],'Bearer synthetic','migration')
        with patch.object(campaigns.registry,'check',side_effect=AssertionError('Registry must not gate enrollment')):
            leaf=campaigns.bootstrap(batch['enrollmentKey'],self.device,self.build_csr(self.device,self.key))
            with self.issuer.store.connect() as db:
                db.execute('update campaign_members set qualification=? where campaign=? and serial=?',('[{"historical":"retained"}]',batch['id'],self.device))
            self.assertEqual(leaf,campaigns.bootstrap(batch['enrollmentKey'],self.device,self.build_csr(self.device,self.key)))
            with self.issuer.store.connect() as db:self.assertEqual(db.execute('select qualification from campaign_members where campaign=? and serial=?',(batch['id'],self.device)).fetchone()[0],'[{"historical":"retained"}]')

    def test_unauthorized_key_serial_cn_signature_and_new_spki_fail(self):
        campaigns,_=self.campaigns();batch=campaigns.create('root',[self.device],'Bearer synthetic','migration')
        good=self.build_csr(self.device,self.key)
        der=bytearray(base64.b64decode(b''.join(good.splitlines()[1:-1])));der[-1]^=1
        bad=b'-----BEGIN CERTIFICATE REQUEST-----\n'+base64.encodebytes(der)+b'-----END CERTIFICATE REQUEST-----\n'
        for key,serial,csr in [('x'*64,self.device,good),(batch['enrollmentKey'],'aabbccddeeff',self.build_csr('aabbccddeeff',self.key)),(batch['enrollmentKey'],self.device,self.build_csr('aabbccddeeff',self.key)),(batch['enrollmentKey'],self.device,bad)]:
            with self.assertRaises(ValueError):campaigns.bootstrap(key,serial,csr)
        campaigns.bootstrap(batch['enrollmentKey'],self.device,good)
        with self.assertRaises(ValueError):campaigns.bootstrap(batch['enrollmentKey'],self.device,self.build_csr(self.device,ec.generate_private_key(ec.SECP256R1())))

    def test_cancel_old_rotated_key_disabled_retired_and_changed_owner_fail(self):
        for failure in ['cancel','rotate','disabled','retired','ownership']:
            with self.subTest(failure=failure):
                self.setUp();campaigns,_=self.campaigns();batch=campaigns.create('root',[self.device],'Bearer synthetic','migration')
                if failure=='cancel':campaigns.cancel('root',batch['id'])
                elif failure=='rotate':campaigns.rotate('root',batch['id'],'Bearer synthetic')
                else:
                    with self.issuer.store.connect() as db:
                        if failure=='disabled':db.execute('update inventory set enabled=0 where serial=?',(self.device,))
                        elif failure=='retired':db.execute('update identity_lifecycle set retired=1 where serial=?',(self.device,))
                        else:db.execute('update identity_lifecycle set ownership=? where serial=?',(json.dumps({'serial':self.device,'inventoryId':'changed'}),self.device))
                with self.assertRaises(ValueError):campaigns.bootstrap(batch['enrollmentKey'],self.device,self.build_csr(self.device,self.key))

    def test_expired_or_revoked_cached_leaf_cannot_trigger_new_issuance(self):
        for failure in ['expired','revoked']:
            with self.subTest(failure=failure):
                self.setUp();campaigns,_=self.campaigns();batch=campaigns.create('root',[self.device],'Bearer synthetic','migration');csr=self.build_csr(self.device,self.key)
                campaigns.bootstrap(batch['enrollmentKey'],self.device,csr)
                if failure=='revoked':
                    with self.issuer.store.connect() as db:db.execute('update issued set revoked=1 where device=?',(self.device,))
                else:
                    now=self.issuer.clock();self.issuer.clock=lambda:now+datetime.timedelta(days=400)
                with self.assertRaises(ValueError):campaigns.bootstrap(batch['enrollmentKey'],self.device,csr)
                with self.issuer.store.connect() as db:self.assertEqual(db.execute('select count(*) from issued where device=?',(self.device,)).fetchone()[0],1)

if __name__=='__main__':unittest.main()
