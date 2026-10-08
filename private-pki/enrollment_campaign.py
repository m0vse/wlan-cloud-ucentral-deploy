"""One portal enrollment key for a bulk-approved set of APs.

The shared key authorizes initial enrollment only. Each AP has its own local
private key and immutable signed CSR contents. Issued APs renew using mTLS.
"""
import hashlib
import json
import secrets
from concurrent.futures import ThreadPoolExecutor
from cryptography import x509
from issuer import Issuer
from lifecycle import Lifecycle
from ownership import snapshot
from qualification_registry import Registry


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


class Campaigns:
    def __init__(self, issuer, controller, cipher):
        self.issuer, self.controller, self.cipher = issuer, controller, cipher
        self.lifecycle = Lifecycle(issuer.store)
        self.registry = Registry(issuer.store)
        with issuer.store.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS enrollment_campaigns(
                    id TEXT PRIMARY KEY, digest BLOB UNIQUE NOT NULL,
                    encrypted BLOB NOT NULL, actor TEXT NOT NULL,
                    operation TEXT NOT NULL, active INTEGER NOT NULL,
                    created INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS campaign_members(
                    campaign TEXT NOT NULL, serial TEXT NOT NULL,
                    ownership TEXT NOT NULL, csr_digest BLOB,
                    response BLOB, qualification TEXT,
                    PRIMARY KEY(campaign,serial));
            ''')

    def create(self, actor, serials, authorization, operation='migration'):
        if operation not in ('migration', 'new-openwifi-enrollment'):
            raise ValueError('Invalid enrollment operation')
        if not isinstance(serials, list) or not 1 <= len(serials) <= 1000 or len(set(serials)) != len(serials):
            raise ValueError('Select one to 1000 distinct APs')
        for serial in serials: self.issuer.store.check_serial(serial)
        def resolve(serial):
            inventory = self.controller.inventory(serial, authorization)
            return serial, snapshot(self.controller, inventory, authorization)
        # Only this Root request uses the human session. Nothing stores it.
        with ThreadPoolExecutor(max_workers=8) as workers:
            approved = list(workers.map(resolve, serials))
        identity, key = secrets.token_hex(16), secrets.token_urlsafe(48)
        with self.issuer.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            for serial, ownership in approved:
                if db.execute('SELECT 1 FROM issued WHERE device=? LIMIT 1', (serial,)).fetchone():
                    raise ValueError('An AP is already enrolled; use native renewal or CA migration')
                if db.execute('''SELECT 1 FROM campaign_members m JOIN enrollment_campaigns c
                    ON m.campaign=c.id WHERE m.serial=? AND c.active=1''', (serial,)).fetchone():
                    raise ValueError('An AP already belongs to an active enrollment batch')
                self.lifecycle.approve(actor, serial, ownership, True, True, False, db)
                db.execute('INSERT INTO campaign_members VALUES (?,?,?,NULL,NULL,NULL)',
                           (identity,serial,encoded(ownership)))
            db.execute('INSERT INTO enrollment_campaigns VALUES (?,?,?,?,?,1,?)',
                       (identity,hashlib.sha256(key.encode()).digest(),self.cipher.encrypt(key.encode()),
                        actor,operation,int(self.issuer.clock().timestamp())))
            db.execute('INSERT INTO operator_audit(stamp,actor,action,target) VALUES (?,?,?,?)',
                       (int(self.issuer.clock().timestamp()),actor,'enrollment-batch-created',identity))
        return {'id':identity,'enrollmentKey':key,'devices':len(approved),'operation':operation}

    def cancel(self, actor, identity):
        if not isinstance(identity,str) or len(identity)!=32:
            raise ValueError('Invalid enrollment batch')
        with self.issuer.store.connect() as db:
            if not db.execute('SELECT 1 FROM enrollment_campaigns WHERE id=?',(identity,)).fetchone():
                raise ValueError('Unknown enrollment batch')
            db.execute('UPDATE enrollment_campaigns SET active=0 WHERE id=?',(identity,))
            db.execute('INSERT INTO operator_audit(stamp,actor,action,target) VALUES (?,?,?,?)',
                       (int(self.issuer.clock().timestamp()),actor,'enrollment-batch-cancelled',identity))
        return {'id':identity,'active':False}

    def rotate(self, actor, identity, authorization):
        with self.issuer.store.connect() as db:
            campaign=db.execute('SELECT active FROM enrollment_campaigns WHERE id=?',(identity,)).fetchone()
            members=list(db.execute('SELECT serial,ownership FROM campaign_members WHERE campaign=?',(identity,)))
        if not campaign or not campaign['active']: raise ValueError('Enrollment batch is inactive')
        def verify_member(member):
            inventory=self.controller.inventory(member['serial'],authorization)
            if snapshot(self.controller,inventory,authorization)!=json.loads(member['ownership']):
                raise ValueError('AP ownership changed; review required')
        with ThreadPoolExecutor(max_workers=8) as workers:
            list(workers.map(verify_member, members))
        key=secrets.token_urlsafe(48)
        with self.issuer.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('UPDATE enrollment_campaigns SET digest=?,encrypted=? WHERE id=? AND active=1',
                       (hashlib.sha256(key.encode()).digest(),self.cipher.encrypt(key.encode()),identity))
            if db.execute('SELECT changes()').fetchone()[0]!=1: raise ValueError('Enrollment batch is inactive')
            db.execute('INSERT INTO operator_audit(stamp,actor,action,target) VALUES (?,?,?,?)',
                       (int(self.issuer.clock().timestamp()),actor,'enrollment-batch-key-rotated',identity))
        return {'id':identity,'enrollmentKey':key,'devices':len(members)}

    def list(self):
        with self.issuer.store.connect() as db:
            return [dict(row) for row in db.execute('''SELECT c.id,c.active,c.operation,c.created,
                count(m.serial) AS devices,sum(m.response IS NOT NULL) AS enrolled
                FROM enrollment_campaigns c JOIN campaign_members m ON c.id=m.campaign
                GROUP BY c.id ORDER BY c.created DESC LIMIT 100''')]

    def bootstrap(self, key, serial, csr_pem):
        if not isinstance(key,str) or len(key)!=64: raise ValueError('Invalid enrollment key')
        csr = Issuer.csr(serial,csr_pem)
        # ECDSA signatures can differ when recreating an otherwise identical
        # request. Bind the signed contents, not signature randomness.
        csr_digest = hashlib.sha256(csr.tbs_certrequest_bytes).digest()
        with self.issuer.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            campaign = db.execute('SELECT * FROM enrollment_campaigns WHERE digest=?',
                                  (hashlib.sha256(key.encode()).digest(),)).fetchone()
            if not campaign or not campaign['active']: raise ValueError('Enrollment batch is inactive')
            member = db.execute('SELECT * FROM campaign_members WHERE campaign=? AND serial=?',
                                (campaign['id'],serial)).fetchone()
            if not member: raise ValueError('AP is outside this enrollment batch')
            self.lifecycle.check(serial,json.loads(member['ownership']),db)
            inventory = db.execute('SELECT enabled FROM inventory WHERE serial=?',(serial,)).fetchone()
            if not inventory or inventory[0]!=1: raise ValueError('AP enrollment is disabled')
            if member['csr_digest'] is not None and member['csr_digest']!=csr_digest:
                raise ValueError('AP is already bound to another enrollment request')
            # An active approved batch authorizes certificate enrollment.
            # Manufacturing/source qualification is an installer safety policy,
            # not a prerequisite for native EST certificate issuance.
            # Preserve historical qualification metadata on cached responses.
            if member['response'] is not None:
                self.issuer._check_peer(db,x509.load_pem_x509_certificate(member['response']))
                return member['response']
            response=self.issuer._issue(db,serial,csr)
            db.execute('UPDATE campaign_members SET csr_digest=?,response=?,qualification=? WHERE campaign=? AND serial=?',
                       (csr_digest,response,None,campaign['id'],serial))
            return response
