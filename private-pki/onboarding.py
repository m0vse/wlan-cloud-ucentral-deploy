"""Durable one-click onboarding intent. No operator time window or browser grant.

An approval survives service restarts until completion/cancellation. Inventory
ownership is captured from the controller and must be revalidated by the worker
before any certificate or AP change. This queue never pretends an AP was moved.
"""
import json
import secrets
import threading
from ownership import snapshot
from lifecycle import Lifecycle


class Onboarding:
    def __init__(self, store, controller):
        self.store, self.controller = store, controller
        self.lifecycle = Lifecycle(store)
        self.lock = threading.Lock()
        with store.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS operator_audit(
                    id INTEGER PRIMARY KEY, stamp INTEGER NOT NULL,
                    actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS onboarding_jobs(
                    id TEXT PRIMARY KEY, serial TEXT NOT NULL, actor TEXT NOT NULL,
                    ownership TEXT NOT NULL, state TEXT NOT NULL, message TEXT NOT NULL,
                    created INTEGER NOT NULL, updated INTEGER NOT NULL);
                CREATE UNIQUE INDEX IF NOT EXISTS active_onboarding_serial
                    ON onboarding_jobs(serial) WHERE state IN ('waiting','running');
                CREATE TABLE IF NOT EXISTS onboarding_grants(
                    job TEXT NOT NULL, digest BLOB PRIMARY KEY);
            ''')

    def start(self, actor, serial, authorization):
        self.store.check_serial(serial)
        inventory = self.controller.inventory(serial, authorization)
        ownership = snapshot(self.controller, inventory, authorization)
        encoded = json.dumps(ownership, sort_keys=True, separators=(',', ':'))
        with self.lock, self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            previous = db.execute("SELECT * FROM onboarding_jobs WHERE serial=? AND state IN ('waiting','running')", (serial,)).fetchone()
            if previous:
                if previous['ownership'] != encoded:
                    raise ValueError('AP ownership changed; cancel the previous request before onboarding again')
                return self.public(previous)
            self.lifecycle.approve(actor, serial, ownership, True, True, False, db)
            stamp, identity = int(self.store.clock()), secrets.token_hex(16)
            db.execute('INSERT INTO onboarding_jobs VALUES (?,?,?,?,?,?,?,?)',
                (identity, serial, actor, encoded, 'waiting', 'Waiting for controller setup.', stamp, stamp))
            db.execute('INSERT INTO operator_audit(stamp,actor,action,target) VALUES (?,?,?,?)',
                (stamp, actor, 'onboarding-requested', serial))
            row = db.execute('SELECT * FROM onboarding_jobs WHERE id=?', (identity,)).fetchone()
            return self.public(row)

    def cancel(self, actor, identity):
        if not isinstance(identity, str) or len(identity) != 32 or any(c not in '0123456789abcdef' for c in identity):
            raise ValueError('Invalid onboarding job')
        with self.lock, self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT * FROM onboarding_jobs WHERE id=?', (identity,)).fetchone()
            if not row:
                raise ValueError('Unknown onboarding request')
            if row['state'] not in ('waiting', 'cancelled'):
                raise ValueError('AP installation must finish or roll back before cancellation')
            db.execute('DELETE FROM grants WHERE digest IN (SELECT digest FROM onboarding_grants WHERE job=?)', (identity,))
            db.execute('DELETE FROM onboarding_grants WHERE job=?', (identity,))
            if row['state'] != 'cancelled':
                stamp = int(self.store.clock())
                db.execute("UPDATE onboarding_jobs SET state='cancelled',message='Cancelled.',updated=? WHERE id=?", (stamp, identity))
                db.execute('INSERT INTO operator_audit(stamp,actor,action,target) VALUES (?,?,?,?)',
                    (stamp, actor, 'onboarding-cancelled', row['serial']))
            return self.public(db.execute('SELECT * FROM onboarding_jobs WHERE id=?', (identity,)).fetchone())

    @staticmethod
    def public(row):
        return {field: row[field] for field in ('id', 'serial', 'state', 'message', 'created', 'updated')}

    def list(self):
        with self.store.connect() as db:
            return [self.public(row) for row in db.execute('SELECT * FROM onboarding_jobs ORDER BY updated DESC LIMIT 1000')]
