"""Private reviewed evidence, joined to existing provisioning inventory.

Only authenticated portal administration calls approval methods. They are not
AP endpoints. Version changes invalidate outstanding migration authorizations.
Migration checking has no writes; normal client renewal never calls this module.
"""
import hashlib
import json
import re
from migration_qualification import evaluate, RECORD_FIELDS, RUNTIME_FIELDS, OPERATIONS

HARDWARE_FIELDS = frozenset(('schema', 'serialNumber', 'exact_model', 'sku_hex',
    'hardware_revision', 'region', 'factory_product_id', 'evidence_sha256', 'evidence_method'))


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


class Registry:
    def __init__(self, store):
        self.store = store
        with store.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS hardware_evidence(
                    serial TEXT PRIMARY KEY, version INTEGER NOT NULL, record TEXT NOT NULL,
                    actor TEXT NOT NULL, approved INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS qualification_records(
                    identity TEXT PRIMARY KEY, version INTEGER NOT NULL, record TEXT NOT NULL,
                    actor TEXT NOT NULL, approved INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS runtime_evidence(
                    serial TEXT NOT NULL, operation TEXT NOT NULL, hardware INTEGER NOT NULL,
                    qualification TEXT NOT NULL, qualification_version INTEGER NOT NULL,
                    record TEXT NOT NULL, actor TEXT NOT NULL, approved INTEGER NOT NULL,
                    PRIMARY KEY(serial,operation));
                CREATE TABLE IF NOT EXISTS evidence_history(
                    id INTEGER PRIMARY KEY, kind TEXT NOT NULL, identity TEXT NOT NULL,
                    version INTEGER NOT NULL, record TEXT NOT NULL, actor TEXT NOT NULL,
                    approved INTEGER NOT NULL);
            ''')

    @staticmethod
    def actor(actor):
        if not isinstance(actor, str) or not actor or len(actor) > 128:
            raise ValueError('Authenticated approval actor required')

    @staticmethod
    def inventory(serial, inventory):
        if not isinstance(inventory, dict) or inventory.get('serialNumber') != serial:
            raise ValueError('Existing authoritative provisioning inventory required')

    @staticmethod
    def identity(record):
        values = [record[field] for field in ('operation', 'exact_model', 'sku_hex', 'hardware_revision')]
        return hashlib.sha256(encode(values).encode()).hexdigest()

    def approve_hardware(self, actor, inventory, record):
        self.actor(actor)
        if not isinstance(record, dict) or set(record) != HARDWARE_FIELDS:
            raise ValueError('Incomplete or unknown hardware evidence fields')
        serial = record['serialNumber']
        self.store.check_serial(serial)
        self.inventory(serial, inventory)
        if record['schema'] != 'openwifi.ap-hardware-evidence.v1' or record['evidence_method'] != 'reviewed-manufacturing-capture':
            raise ValueError('Reviewed manufacturing evidence required')
        if not isinstance(record['sku_hex'], str) or not re.fullmatch('[0-9a-f]{8}', record['sku_hex']):
            raise ValueError('Exact manufacturing SKU required')
        if not isinstance(record['evidence_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', record['evidence_sha256']):
            raise ValueError('Manufacturing evidence digest required')
        for field in ('exact_model', 'hardware_revision', 'region', 'factory_product_id'):
            value = record[field]
            if not isinstance(value, str) or not value.strip() or value != value.strip() or len(value) > 128:
                raise ValueError('Exact reviewed manufacturing identifiers required')
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            previous = db.execute('SELECT version FROM hardware_evidence WHERE serial=?', (serial,)).fetchone()
            version = previous[0] + 1 if previous else 1
            db.execute('INSERT OR REPLACE INTO hardware_evidence VALUES (?,?,?,?,?)',
                (serial, version, encode(record), actor, int(self.store.clock())))
            db.execute('INSERT INTO evidence_history(kind,identity,version,record,actor,approved) VALUES (?,?,?,?,?,?)',
                ('hardware', serial, version, encode(record), actor, int(self.store.clock())))
            return version

    def approve_qualification(self, actor, record):
        self.actor(actor)
        if not isinstance(record, dict) or set(record) != RECORD_FIELDS:
            raise ValueError('Incomplete or unknown qualification fields')
        # Use the canonical validator to check the entire approved record schema.
        inventory = {'serial': '001122334455', 'exact_model': record['exact_model'],
            'sku_hex': record['sku_hex'], 'hardware_revision': record['hardware_revision'],
            'region': record['region_compatibility'][0] if isinstance(record['region_compatibility'], list) and record['region_compatibility'] else ''}
        runtime = {field: inventory[field] if field in inventory else record[field] for field in RUNTIME_FIELDS}
        result = evaluate(record, inventory, runtime)
        if result['allowed'] is not True:
            raise ValueError(result['reason'])
        identity = self.identity(record)
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            previous = db.execute('SELECT version FROM qualification_records WHERE identity=?', (identity,)).fetchone()
            version = previous[0] + 1 if previous else 1
            db.execute('INSERT OR REPLACE INTO qualification_records VALUES (?,?,?,?,?)',
                (identity, version, encode(record), actor, int(self.store.clock())))
            db.execute('INSERT INTO evidence_history(kind,identity,version,record,actor,approved) VALUES (?,?,?,?,?,?)',
                ('qualification', identity, version, encode(record), actor, int(self.store.clock())))
            return identity, version

    def check(self, serial, inventory, operation, db=None):
        self.store.check_serial(serial)
        self.inventory(serial, inventory)
        if not isinstance(operation, str) or operation not in OPERATIONS:
            raise ValueError('Explicit qualified migration operation required')
        if db is None:
            with self.store.connect() as connection:
                return self.check(serial, inventory, operation, connection)
        hardware = db.execute('SELECT * FROM hardware_evidence WHERE serial=?', (serial,)).fetchone()
        runtime = db.execute('SELECT * FROM runtime_evidence WHERE serial=? AND operation=?', (serial, operation)).fetchone()
        if not hardware or not runtime or runtime['hardware'] != hardware['version']:
            raise ValueError('Current reviewed hardware/runtime evidence required')
        qualification = db.execute('SELECT * FROM qualification_records WHERE identity=?', (runtime['qualification'],)).fetchone()
        if not qualification or qualification['version'] != runtime['qualification_version']:
            raise ValueError('Current reviewed qualification required')
        normalized = json.loads(hardware['record'])
        normalized = {'serial': serial, **{field: normalized[field] for field in ('exact_model', 'sku_hex', 'hardware_revision', 'region')}}
        result = evaluate(json.loads(qualification['record']), normalized, json.loads(runtime['record']))
        if result['allowed'] is not True:
            raise ValueError(result['reason'])
        return {'hardwareVersion': hardware['version'], 'qualification': qualification['identity'],
                'qualificationVersion': qualification['version']}

    def approve_runtime(self, actor, inventory, identity, record):
        self.actor(actor)
        if not isinstance(record, dict) or set(record) != RUNTIME_FIELDS:
            raise ValueError('Incomplete or unknown verified runtime fields')
        serial, operation = record['serial'], record['operation']
        if not isinstance(operation, str) or operation not in OPERATIONS:
            raise ValueError('Explicit qualified migration operation required')
        self.store.check_serial(serial)
        self.inventory(serial, inventory)
        if not isinstance(identity, str) or not re.fullmatch('[0-9a-f]{64}', identity):
            raise ValueError('Approved qualification identity required')
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            hardware = db.execute('SELECT * FROM hardware_evidence WHERE serial=?', (serial,)).fetchone()
            qualification = db.execute('SELECT * FROM qualification_records WHERE identity=?', (identity,)).fetchone()
            if not hardware or not qualification:
                raise ValueError('Reviewed hardware and qualification required')
            normalized = json.loads(hardware['record'])
            normalized = {'serial': serial, **{field: normalized[field] for field in ('exact_model', 'sku_hex', 'hardware_revision', 'region')}}
            result = evaluate(json.loads(qualification['record']), normalized, record)
            if result['allowed'] is not True:
                raise ValueError(result['reason'])
            db.execute('INSERT OR REPLACE INTO runtime_evidence VALUES (?,?,?,?,?,?,?,?)',
                (serial, operation, hardware['version'], identity, qualification['version'],
                 encode(record), actor, int(self.store.clock())))
            db.execute('INSERT INTO evidence_history(kind,identity,version,record,actor,approved) VALUES (?,?,?,?,?,?)',
                ('runtime', serial + ':' + operation, qualification['version'], encode(record), actor, int(self.store.clock())))
            return self.check(serial, inventory, operation, db)

    def view(self, serial):
        self.store.check_serial(serial)
        with self.store.connect() as db:
            hardware = db.execute('SELECT * FROM hardware_evidence WHERE serial=?', (serial,)).fetchone()
            runtimes = [dict(row) for row in db.execute('SELECT * FROM runtime_evidence WHERE serial=?', (serial,))]
            qualifications = [dict(row) for row in db.execute('SELECT * FROM qualification_records ORDER BY approved DESC LIMIT 100')]
        rows = ([dict(hardware)] if hardware else []) + runtimes + qualifications
        for row in rows:
            row['record'] = json.loads(row['record'])
        return {'hardware': rows[0] if hardware else None, 'runtimes': runtimes,
                'qualifications': qualifications}
