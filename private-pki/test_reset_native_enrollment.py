from pathlib import Path
import hashlib,json,sqlite3,unittest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from issuer import fingerprint
from test_enrollment_campaign import CampaignTests
import reset_native_enrollment as reset

class ResetTests(CampaignTests):
    def prepare_reset(self):
        campaigns,_=self.campaigns();batch=campaigns.create('root',[self.device,'001122334456'],'Bearer synthetic','migration')
        leaf=campaigns.bootstrap(batch['enrollmentKey'],self.device,self.build_csr(self.device,self.key))
        other=campaigns.bootstrap(batch['enrollmentKey'],'001122334456',self.build_csr('001122334456',self.key))
        path=self.issuer.store.path.resolve();fp=fingerprint(x509.load_pem_x509_certificate(leaf));return campaigns,batch,path,fp,other
    def apply_reset(self,path,fp,backup='reset-backup'):
        plan=reset.run(path,self.device,fp)
        return reset.run(path,self.device,fp,plan['binding'],True,self.path.resolve()/backup,True),plan

    def test_dry_run_changes_no_state_and_wrong_target_binding_refuses(self):
        campaigns,batch,path,fp,other=self.prepare_reset();before=path.read_bytes();plan=reset.run(path,self.device,fp)
        self.assertEqual(before,path.read_bytes());self.assertEqual(plan['state'],'dry-run')
        for serial,leaf in [('aabbccddeeff',fp),(self.device,'f'*64)]:
            with self.assertRaises(ValueError):reset.run(path,serial,leaf)
        with self.assertRaises(ValueError):reset.run(path,self.device,fp,'a'*64,True,self.path.resolve()/'bad',True)
        self.assertEqual(before,path.read_bytes())

    def test_reset_retains_history_old_key_denied_new_key_and_other_member_work(self):
        campaigns,batch,path,fp,other=self.prepare_reset();result,plan=self.apply_reset(path,fp)
        self.assertEqual(result['state'],'reset');self.assertFalse(result['gateway_revocation_enforced'])
        self.assertEqual(reset.run(path,self.device,fp,plan['binding'],True,self.path.resolve()/'unused',True)['state'],'already-reset')
        with self.assertRaises(ValueError):campaigns.bootstrap(batch['enrollmentKey'],self.device,self.build_csr(self.device,self.key))
        self.assertEqual(other,campaigns.bootstrap(batch['enrollmentKey'],'001122334456',self.build_csr('001122334456',self.key)))
        with self.issuer.store.connect() as db:
            old=db.execute('select certificate,revoked from issued where fingerprint=?',(fp,)).fetchone()
            self.assertEqual(old['revoked'],1);self.assertEqual(db.execute('select count(*) from issuance_origins where leaf=?',(fp,)).fetchone()[0],1)
        with self.assertRaises(ValueError):self.issuer.renew(x509.load_pem_x509_certificate(old['certificate']).public_bytes(Encoding.DER),self.build_csr(self.device,self.key),'a'*32)
        fresh=campaigns.create('root',[self.device],'Bearer synthetic','migration');newkey=ec.generate_private_key(ec.SECP256R1())
        leaf=campaigns.bootstrap(fresh['enrollmentKey'],self.device,self.build_csr(self.device,newkey))
        self.assertNotEqual(fingerprint(x509.load_pem_x509_certificate(leaf)),fp)
        with self.assertRaises(ValueError):reset.run(path,self.device,fp,plan['binding'],True,self.path.resolve()/'bad-again',True)

    def test_inflight_job_owner_change_unrevoked_issue_and_unsafe_backup_refuse(self):
        campaigns,batch,path,fp,other=self.prepare_reset()
        with self.assertRaises(ValueError):campaigns.create('root',[self.device],'Bearer synthetic','migration')
        with self.issuer.store.connect() as db:
            life=db.execute('select ownership from identity_lifecycle where serial=?',(self.device,)).fetchone()[0]
            db.execute("insert into onboarding_jobs(id,serial,actor,ownership,state,message,created,updated,kind) values(?,?,?,?,?,?,?,?,?)",('job',self.device,'root',life,'running','',0,0,'renew'))
        with self.assertRaises(ValueError):reset.run(path,self.device,fp)
        with self.issuer.store.connect() as db:db.execute("update onboarding_jobs set state='cancelled' where id='job'")
        plan=reset.run(path,self.device,fp)
        symlink=self.path.resolve()/'unsafe';symlink.symlink_to(self.path.resolve(),target_is_directory=True)
        with self.assertRaises(ValueError):reset.run(path,self.device,fp,plan['binding'],True,symlink,True)
        with self.issuer.store.connect() as db:db.execute('update identity_lifecycle set ownership=? where serial=?',(json.dumps({'serial':self.device,'inventoryId':'different'}),self.device))
        with self.assertRaises(ValueError):reset.run(path,self.device,fp)

    def test_backup_failure_and_transaction_failure_leave_target_unchanged(self):
        campaigns,batch,path,fp,other=self.prepare_reset();plan=reset.run(path,self.device,fp)
        with patch.object(reset.os,'open',side_effect=OSError('synthetic backup failure')):
            with self.assertRaises(OSError):reset.run(path,self.device,fp,plan['binding'],True,self.path.resolve()/'failed-backup',True)
        self.assertEqual(reset.run(path,self.device,fp)['binding'],plan['binding'])
        with self.issuer.store.connect() as db:db.execute("CREATE TRIGGER reset_failure BEFORE DELETE ON campaign_members BEGIN SELECT RAISE(ABORT,'synthetic reset interruption'); END")
        with self.assertRaises(sqlite3.Error):reset.run(path,self.device,fp,plan['binding'],True,self.path.resolve()/'failed-txn',True)
        self.assertEqual(reset.run(path,self.device,fp)['binding'],plan['binding'])

    def test_concurrent_change_after_preview_refuses_before_mutation(self):
        campaigns,batch,path,fp,other=self.prepare_reset();plan=reset.run(path,self.device,fp)
        with self.issuer.store.connect() as db:db.execute('update identity_lifecycle set version=version+1 where serial=?',(self.device,))
        with self.assertRaises(ValueError):reset.run(path,self.device,fp,plan['binding'],True,self.path.resolve()/'stale',True)
        with self.issuer.store.connect() as db:self.assertEqual(db.execute('select revoked from issued where fingerprint=?',(fp,)).fetchone()[0],0)

    def test_post_backup_binding_change_and_offline_missing_refuse(self):
        campaigns,batch,path,fp,other=self.prepare_reset();plan=reset.run(path,self.device,fp)
        with self.assertRaises(ValueError):reset.run(path,self.device,fp,plan['binding'],True,self.path.resolve()/'no-offline',False)
        original=reset.snapshot;calls=[0]
        def changed(db,serial,leaf):
            calls[0]+=1;result=original(db,serial,leaf)
            if calls[0]==3:result['binding']='f'*64
            return result
        with patch.object(reset,'snapshot',side_effect=changed):
            with self.assertRaises(ValueError):reset.run(path,self.device,fp,plan['binding'],True,self.path.resolve()/'post-backup-race',True)
        self.assertEqual(reset.run(path,self.device,fp)['binding'],plan['binding'])

    def test_orphan_target_member_refused_without_mutation(self):
        campaigns,batch,path,fp,other=self.prepare_reset()
        with self.issuer.store.connect() as db:
            owner=db.execute('select ownership from identity_lifecycle where serial=?',(self.device,)).fetchone()[0]
            db.execute('insert into campaign_members values(?,?,?,NULL,NULL,NULL)',('missing-parent',self.device,owner))
        before=path.read_bytes()
        with self.assertRaises(ValueError):reset.run(path,self.device,fp)
        self.assertEqual(path.read_bytes(),before)

    def test_postcommit_sync_reports_committed_reset_and_is_idempotent(self):
        campaigns,batch,path,fp,other=self.prepare_reset();plan=reset.run(path,self.device,fp);calls=[0]
        original=reset.os.sync
        def fail_after_commit():
            calls[0]+=1
            if calls[0]==2:raise OSError('synthetic post-commit sync failure')
            original()
        with patch.object(reset.os,'sync',side_effect=fail_after_commit):
            result=reset.run(path,self.device,fp,plan['binding'],True,self.path.resolve()/'sync-after-commit',True)
        self.assertEqual(result['state'],'reset');self.assertIn('reset committed',result['post_commit_sync'])
        self.assertEqual(reset.run(path,self.device,fp,plan['binding'])['state'],'already-reset')

    def test_optional_cache_binding_and_serial_scoped_cleanup(self):
        from activation import Activation
        from native_management import NativeManagement
        campaigns,batch,path,fp,other=self.prepare_reset();jobs,inv,controller=self.prepare()
        Activation(self.issuer,lambda _:{});NativeManagement(self.issuer,controller,jobs)
        otherfp=fingerprint(x509.load_pem_x509_certificate(other))
        with self.issuer.store.connect() as db:
            for serial,leaf,n in [(self.device,fp,'1'),('001122334456',otherfp,'2')]:
                owner=db.execute('select ownership from identity_lifecycle where serial=?',(serial,)).fetchone()[0]
                db.execute('insert into onboarding_jobs(id,serial,actor,ownership,state,message,created,updated,kind) values(?,?,?,?,?,?,?,?,?)',('job'+n,serial,'root',owner,'complete','',0,0,'renew'))
                db.execute('insert into native_commands values(?,?,?,?)',('job'+n,leaf,'command'+n,'complete'))
                digest=bytes.fromhex(n*64)
                db.execute('insert into grants values(?,?,?,?,?,NULL)',(digest,serial,digest,self.issuer.authority,100))
                db.execute('insert into migration_grants values(?,?)',(digest,json.dumps({'ownership':{'serial':serial}})))
                db.execute('insert into onboarding_grants values(?,?)',('job'+n,digest))
                db.execute('insert into activation_challenges values(?,?,?,?,?,?,?)',(n*64,serial,leaf,0,100,1,0))
                db.execute('insert into renewal_replies values(?,?)',(leaf+'cached',b'public cached response'))
        plan=reset.run(path,self.device,fp)
        with self.issuer.store.connect() as db:db.execute("update native_commands set command='changed' where job='job1'")
        with self.assertRaises(ValueError):reset.run(path,self.device,fp,plan['binding'],True,self.path.resolve()/'cache-race',True)
        result,plan=self.apply_reset(path,fp,'cache-reset')
        with self.issuer.store.connect() as db:
            for table in ['grants','migration_grants','onboarding_grants','activation_challenges','renewal_replies']:
                self.assertEqual(db.execute('select count(*) from '+table).fetchone()[0],1,table)
            self.assertEqual(db.execute("select state from native_commands where job='job1'").fetchone()[0],'cancelled')
            self.assertEqual(db.execute("select state from native_commands where job='job2'").fetchone()[0],'complete')
            self.assertEqual(db.execute('select count(*) from onboarding_jobs').fetchone()[0],2)

    def test_grant_response_only_change_refuses_old_binding(self):
        campaigns,batch,path,fp,other=self.prepare_reset()
        self.issuer.authorize(self.device,self.build_csr(self.device,self.key))
        plan=reset.run(path,self.device,fp)
        with self.issuer.store.connect() as db:db.execute('update grants set response=? where serial=?',(b'synthetic cached response',self.device))
        changed=reset.run(path,self.device,fp)
        self.assertNotEqual(changed['binding'],plan['binding'])
        with self.assertRaises(ValueError):reset.run(path,self.device,fp,plan['binding'],True,self.path.resolve()/'grant-response-race',True)
        self.assertEqual(reset.run(path,self.device,fp)['binding'],changed['binding'])
        with self.issuer.store.connect() as db:self.assertEqual(db.execute('select revoked from issued where fingerprint=?',(fp,)).fetchone()[0],0)

if __name__=='__main__':unittest.main()
