from concurrent.futures import ThreadPoolExecutor
import copy
import unittest
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from enrollment_campaign import Campaigns
from test_onboarding import OnboardingTests
import test_fixtures as fixtures


class CampaignTests(unittest.TestCase):
    setUp=OnboardingTests.setUp
    request=OnboardingTests.request
    write_authority=OnboardingTests.write_authority
    load=OnboardingTests.load
    prepare=OnboardingTests.prepare

    def campaigns(self):
        jobs, inventory, controller=self.prepare()
        def lookup(serial, auth):
            result=copy.deepcopy(inventory)
            result.update(serialNumber=serial,id='inventory-'+serial)
            return result
        controller.inventory.side_effect=lookup
        return Campaigns(self.issuer,controller,Fernet(Fernet.generate_key())),controller

    @staticmethod
    def build_csr(serial,key):
        return x509.CertificateSigningRequestBuilder().subject_name(fixtures.name(serial)).sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM)

    def test_one_key_100_distinct_ap_keys_and_certificates(self):
        campaigns,controller=self.campaigns()
        serials=[f'{i:012x}' for i in range(100,200)]
        batch=campaigns.create('root',serials,'Bearer synthetic','new-openwifi-enrollment')
        requests=[(serial,ec.generate_private_key(ec.SECP256R1())) for serial in serials]
        def enroll(item):
            serial,key=item
            return campaigns.bootstrap(batch['enrollmentKey'],serial,self.build_csr(serial,key))
        with ThreadPoolExecutor(max_workers=8) as workers:
            replies=list(workers.map(enroll,requests))
        certs=[x509.load_pem_x509_certificate(pem) for pem in replies]
        self.assertEqual(len({c.serial_number for c in certs}),100)
        self.assertEqual(len({c.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo) for c in certs}),100)
        self.assertEqual(campaigns.list()[0]['enrolled'],100)
        self.assertNotIn(batch['enrollmentKey'],str(campaigns.list()))
        self.assertNotIn('Bearer',str(campaigns.list()))
        for cert in certs: cert.verify_directly_issued_by(self.authority.device)

    def test_retry_rotation_cancel_do_not_break_issued_native_renewal(self):
        campaigns,controller=self.campaigns()
        batch=campaigns.create('root',[self.device,'001122334456'],'Bearer synthetic','new-openwifi-enrollment')
        key=batch['enrollmentKey']
        leaf=campaigns.bootstrap(key,self.device,self.build_csr(self.device,self.key))
        # Same signed contents with a new ECDSA signature remain a safe retry.
        self.assertEqual(leaf,campaigns.bootstrap(key,self.device,self.build_csr(self.device,self.key)))
        with self.assertRaises(ValueError): campaigns.bootstrap(key,self.device,self.build_csr(self.device,ec.generate_private_key(ec.SECP256R1())))
        with self.assertRaises(ValueError): campaigns.bootstrap(key,'aabbccddeeff',self.build_csr('aabbccddeeff',self.key))
        rotated=campaigns.rotate('root',batch['id'],'Bearer synthetic')['enrollmentKey']
        with self.assertRaises(ValueError): campaigns.bootstrap(key,self.device,self.build_csr(self.device,self.key))
        self.assertEqual(leaf,campaigns.bootstrap(rotated,self.device,self.build_csr(self.device,self.key)))
        campaigns.cancel('root',batch['id'])
        with self.assertRaises(ValueError): campaigns.bootstrap(rotated,'001122334456',self.build_csr('001122334456',self.key))
        renewed=self.issuer.renew(x509.load_pem_x509_certificate(leaf).public_bytes(serialization.Encoding.DER),self.build_csr(self.device,self.key),'a'*32)
        x509.load_pem_x509_certificate(renewed).verify_directly_issued_by(self.authority.device)

    def test_concurrent_first_key_binding_and_migration_key_without_manufacturing(self):
        campaigns,controller=self.campaigns()
        batch=campaigns.create('root',[self.device],'Bearer synthetic','new-openwifi-enrollment')
        requests=[self.build_csr(self.device,ec.generate_private_key(ec.SECP256R1())) for _ in range(2)]
        def attempt(csr):
            try: return campaigns.bootstrap(batch['enrollmentKey'],self.device,csr)
            except ValueError: return None
        with ThreadPoolExecutor(max_workers=2) as workers: results=list(workers.map(attempt,requests))
        self.assertEqual(sum(item is not None for item in results),1)
        migration=campaigns.create('root',['001122334456'],'Bearer synthetic','migration')
        leaf=campaigns.bootstrap(migration['enrollmentKey'],'001122334456',self.build_csr('001122334456',self.key))
        x509.load_pem_x509_certificate(leaf).verify_directly_issued_by(self.authority.device)
        with self.issuer.store.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM issued WHERE device=?',('001122334456',)).fetchone()[0],1)

    def test_shared_batch_preserves_independent_source_qualifications(self):
        from test_qualification_registry import RegistryTests
        campaigns,controller=self.campaigns()
        serials=[self.device,'001122334456']
        operations=['production-oem-migration','production-stock-openwrt-migration']
        records=[]
        for serial,operation in zip(serials,operations):
            inventory,hardware,qualification,runtime=RegistryTests.fixtures(self,operation)
            inventory['serialNumber']=serial
            hardware['serialNumber']=serial
            runtime['serial']=serial
            campaigns.registry.approve_hardware('root',inventory,hardware)
            identity,_=campaigns.registry.approve_qualification('root',qualification)
            campaigns.registry.approve_runtime('root',inventory,identity,runtime)
            records.append(qualification)
            with self.assertRaises(ValueError):
                campaigns.registry.check(serial,inventory,operations[1-operations.index(operation)])
        batch=campaigns.create('root',serials,'Bearer synthetic','migration')
        leaves=[campaigns.bootstrap(batch['enrollmentKey'],serial,self.build_csr(serial,self.key)) for serial in serials]
        campaigns.registry.approve_qualification('root',records[0])
        self.assertEqual(leaves[0],campaigns.bootstrap(batch['enrollmentKey'],serials[0],self.build_csr(serials[0],self.key)))
        self.assertEqual(leaves[1],campaigns.bootstrap(batch['enrollmentKey'],serials[1],self.build_csr(serials[1],self.key)))
