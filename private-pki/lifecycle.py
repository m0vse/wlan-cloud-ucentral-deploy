"""Explicit portal-approved identity lifecycle, separate from migration SKU gates."""
import json


class Lifecycle:
    def __init__(self, store):
        self.store = store
        with store.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS identity_lifecycle(
                    serial TEXT PRIMARY KEY, version INTEGER NOT NULL,
                    approved INTEGER NOT NULL CHECK(approved IN (0,1)),
                    enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
                    retired INTEGER NOT NULL CHECK(retired IN (0,1)),
                    ownership TEXT NOT NULL, actor TEXT NOT NULL, stamp INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS lifecycle_history(
                    id INTEGER PRIMARY KEY, serial TEXT NOT NULL, version INTEGER NOT NULL,
                    approved INTEGER NOT NULL, enabled INTEGER NOT NULL, retired INTEGER NOT NULL,
                    ownership TEXT NOT NULL, actor TEXT NOT NULL, stamp INTEGER NOT NULL);
            ''')

    def approve(self, actor, serial, ownership, approved, enabled, retired):
        self.store.check_serial(serial)
        if not isinstance(actor, str) or not actor or len(actor) > 128:
            raise ValueError('Authenticated lifecycle operator required')
        if any(type(value) is not bool for value in (approved, enabled, retired)):
            raise ValueError('Explicit boolean lifecycle fields required')
        if (enabled and not approved) or (retired and (enabled or approved)):
            raise ValueError('Conflicting identity lifecycle state')
        if not isinstance(ownership, dict) or ownership.get('serial') != serial or not ownership.get('inventoryId'):
            raise ValueError('Resolved authoritative inventory ownership required')
        encoded = json.dumps(ownership, sort_keys=True, separators=(',', ':'))
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            previous = db.execute('SELECT version FROM identity_lifecycle WHERE serial=?', (serial,)).fetchone()
            version = previous[0] + 1 if previous else 1
            row = (serial, version, int(approved), int(enabled), int(retired), encoded, actor, int(self.store.clock()))
            db.execute('INSERT OR REPLACE INTO identity_lifecycle VALUES (?,?,?,?,?,?,?,?)', row)
            db.execute('INSERT INTO lifecycle_history(serial,version,approved,enabled,retired,ownership,actor,stamp) VALUES (?,?,?,?,?,?,?,?)', row)
            db.execute('INSERT OR REPLACE INTO inventory VALUES (?,?)', (serial, int(approved and enabled and not retired)))
            if not approved or not enabled or retired:
                db.execute('DELETE FROM grants WHERE serial=?', (serial,))
            return version

    def check(self, serial, ownership, db=None):
        self.store.check_serial(serial)
        if db is None:
            with self.store.connect() as connection:
                return self.check(serial, ownership, connection)
        row = db.execute('SELECT * FROM identity_lifecycle WHERE serial=?', (serial,)).fetchone()
        if not row or row['approved'] != 1 or row['enabled'] != 1 or row['retired'] != 0:
            raise ValueError('Explicit active identity approval required')
        if json.loads(row['ownership']) != ownership:
            raise ValueError('Inventory identity or ownership changed; review required')
        return row['version']

    def view(self, serial):
        self.store.check_serial(serial)
        with self.store.connect() as db:
            row = db.execute('SELECT serial,version,approved,enabled,retired,actor,stamp FROM identity_lifecycle WHERE serial=?', (serial,)).fetchone()
        if not row:
            return None
        result = dict(row)
        for flag in ('approved', 'enabled', 'retired'):
            result[flag] = result[flag] == 1
        return result
