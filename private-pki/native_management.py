"""Portal operations use native gateway reenroll and observed TLS session state."""
from concurrent.futures import ThreadPoolExecutor
from admin import Denied
from cryptography import x509
from ownership import snapshot


class NativeManagement:
    def __init__(self, issuer, controller, jobs):
        self.issuer, self.controller, self.jobs = issuer, controller, jobs
        with issuer.store.connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS native_commands(
                job TEXT PRIMARY KEY, previous_leaf TEXT NOT NULL,
                command TEXT, state TEXT NOT NULL)''')

    def connection(self, serial, authorization):
        device = self.controller.fetch(16002, f'device/{serial}?completeInfo=true', authorization)
        return device.get('connectionInfo', {})

    def matching_leaf(self, serial, connection, db):
        if connection.get('connected') is not True or connection.get('verifiedCertificate') != 'VERIFIED':
            return None
        # Native GW exposes issuer/expiry from its actual TLS peer. This is
        # session metadata matching, not a claim of DER fingerprint evidence.
        candidates = list(db.execute('SELECT * FROM issued WHERE device=? AND revoked=0 AND expires=?',
                                    (serial, connection.get('certificateExpiryDate', -1))))
        for row in candidates:
            cert = x509.load_pem_x509_certificate(row['certificate'])
            if cert.issuer.rfc4514_string() == connection.get('certificateIssuerName'):
                try: self.issuer._check_peer(db, cert)
                except ValueError: continue
                return row
        return None

    def request(self, actor, serial, authorization, operation):
        self.issuer.store.check_serial(serial)
        inventory = self.controller.inventory(serial, authorization)
        ownership = snapshot(self.controller, inventory, authorization)
        connection = self.connection(serial, authorization)
        with self.issuer.store.connect() as db:
            self.jobs.lifecycle.check(serial, ownership, db)
            previous = self.matching_leaf(serial, connection, db)
            if previous is None:
                raise ValueError('AP requires native certificate setup or a verified connection')
            if operation == 'renew' and previous['issuer'] != self.issuer.authority:
                raise ValueError('Move this AP to the new CA before renewal')
        job = self.jobs.start(actor, serial, authorization, operation)
        with self.jobs.lock, self.issuer.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute('SELECT 1 FROM native_commands WHERE job=?', (job['id'],)).fetchone():
                return job
            db.execute('INSERT INTO native_commands VALUES (?,?,NULL,?)',
                       (job['id'], previous['fingerprint'], 'submitted'))
            db.execute("UPDATE onboarding_jobs SET state='running',message='Renewing through OpenWiFi.',updated=? WHERE id=?",
                       (int(self.issuer.clock().timestamp()), job['id']))
        try:
            result = self.controller.request(16002, f'device/{serial}/reenroll', authorization,
                    method='POST', body={'serialNumber':serial, 'when':0}, timeout=30)
            if not isinstance(result, dict) or result.get('errorCode') != 0 or not result.get('UUID'):
                raise ValueError('Native renewal did not confirm success')
            with self.issuer.store.connect() as db:
                db.execute('UPDATE native_commands SET command=?,state=? WHERE job=?',
                           (result['UUID'], 'reconnecting', job['id']))
                db.execute("UPDATE onboarding_jobs SET message='Certificate issued. Waiting for the AP to reconnect.' WHERE id=?", (job['id'],))
        except Exception:
            # A timeout can occur after issuance. Do not resubmit implicitly.
            with self.issuer.store.connect() as db:
                db.execute("UPDATE native_commands SET state='check-required' WHERE job=?", (job['id'],))
                db.execute("UPDATE onboarding_jobs SET message='Checking the AP after the renewal request.' WHERE id=?", (job['id'],))
            raise
        return next(item for item in self.jobs.list() if item['id'] == job['id'])

    def reconcile(self, authorization, certificates):
        def inspect(serial):
            try:
                inventory = self.controller.inventory(serial, authorization)
                ownership = snapshot(self.controller, inventory, authorization)
                with self.issuer.store.connect() as db:
                    try: self.jobs.lifecycle.check(serial, ownership, db)
                    except ValueError:
                        db.execute('UPDATE inventory SET enabled=0 WHERE serial=?', (serial,))
                        return serial, {}, 'Inventory identity or ownership changed; signing is disabled until reviewed.'
                return serial, self.connection(serial, authorization), None
            except (Denied, ValueError):
                return serial, {}, 'Inventory reconciliation requires review.'
        serials = list(dict.fromkeys(cert['device'] for cert in certificates))
        with ThreadPoolExecutor(max_workers=8) as workers:
            observations = {serial: (connection, error)
                            for serial, connection, error in workers.map(inspect, serials)}
        connections = {serial: observation[0] for serial, observation in observations.items()}
        for cert in certificates:
            serial = cert['device']
            error = observations[serial][1]
            if error:
                cert['nativeError'] = error
                continue
            with self.issuer.store.connect() as db:
                matched = self.matching_leaf(serial, connections.get(serial, {}), db)
                if matched and matched['fingerprint'] == cert['fingerprint']:
                    cert['nativeConnected'] = True
                    cert['nativeSessionId'] = connections[serial].get('sessionId')
                    for job in db.execute('''SELECT j.id,n.previous_leaf FROM onboarding_jobs j
                        JOIN native_commands n ON j.id=n.job WHERE j.serial=? AND j.state='running' ''', (serial,)):
                        if matched['fingerprint'] != job['previous_leaf']:
                            db.execute("UPDATE onboarding_jobs SET state='complete',message='Certificate renewed and AP reconnected.',updated=? WHERE id=?",
                                       (int(self.issuer.clock().timestamp()),job['id']))
