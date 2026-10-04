"""Read-only complete fleet reconciliation before retaining/removing CA trust.

An offline or gateway-only device remains a blocker unless its exact identity
has an explicit human retirement. This module never modifies trust.
"""
import json
from cryptography import x509
from issuer import fingerprint


class FleetGate:
    def __init__(self, issuer, controller, lifecycle, ownership_snapshot):
        self.issuer, self.controller = issuer, controller
        self.lifecycle, self.ownership_snapshot = lifecycle, ownership_snapshot

    def scan(self, port, route, key, authorization):
        before = self.controller.fetch(port, route + '?countOnly=true', authorization).get('count')
        if type(before) is not int or not 0 <= before <= 100000:
            raise ValueError('Authoritative fleet count required')
        rows = {}
        offset = 0
        while True:
            page = self.controller.fetch(port, f'{route}?offset={offset}&limit=50', authorization).get(key)
            if not isinstance(page, list) or len(page) > 50:
                raise ValueError('Bounded complete fleet page required')
            for row in page:
                if not isinstance(row, dict):
                    raise ValueError('Invalid fleet identity')
                serial = row.get('serialNumber')
                self.issuer.store.check_serial(serial)
                if serial in rows:
                    raise ValueError('Duplicate or changed fleet pagination')
                rows[serial] = {field: row.get(field) for field in
                    ('serialNumber', 'id', 'entity', 'venue', 'subscriber', 'deviceType', 'platform')}
            offset += len(page)
            if len(page) < 50:
                break
            if offset > before:
                raise ValueError('Fleet changed during pagination')
        after = self.controller.fetch(port, route + '?countOnly=true', authorization).get('count')
        if type(after) is not int or before != after or len(rows) != before:
            raise ValueError('Incomplete or changed fleet census')
        return rows

    def census(self, authorization):
        def read():
            return {'provisioning': self.scan(16005, 'inventory', 'taglist', authorization),
                    'gateway': self.scan(16002, 'devices', 'devices', authorization)}
        first, second = read(), read()
        if first != second:
            raise ValueError('Fleet identities or ownership changed during reconciliation')
        return second

    def review(self, authorization, retained_root):
        if not isinstance(retained_root, str) or len(retained_root) != 64 or any(c not in '0123456789abcdef' for c in retained_root):
            raise ValueError('Exact retained root fingerprint required')
        if retained_root == fingerprint(self.issuer.root):
            raise ValueError('Active root cannot be retired')
        with self.issuer.store.connect() as db:
            known = {fingerprint(x509.load_pem_x509_certificate(row[0])) for row in db.execute('SELECT root FROM authorities')}
            issued_devices = {row[0] for row in db.execute('SELECT DISTINCT device FROM issued')}
        if retained_root not in known:
            raise ValueError('Unknown retained root')
        fleet = self.census(authorization)
        blockers, retired, accepted = [], [], []
        for device in sorted(set(fleet['provisioning']) | set(fleet['gateway']) | issued_devices):
            lifecycle = self.lifecycle.view(device)
            if lifecycle and lifecycle['retired']:
                # Retirement cannot silently transfer to a replacement record.
                with self.issuer.store.connect() as db:
                    row = db.execute('SELECT ownership FROM identity_lifecycle WHERE serial=?', (device,)).fetchone()
                recorded = json.loads(row[0])
                current = fleet['provisioning'].get(device)
                if current and (recorded.get('inventoryId') != current.get('id') or
                    recorded.get('direct') != {k: current.get(k) for k in ('entity', 'venue', 'subscriber')}):
                    blockers.append({'serial': device, 'reason': 'Retired inventory identity changed'})
                elif device in fleet['gateway'] and self.controller.fetch(16002,
                    f'device/{device}?completeInfo=true', authorization).get('connectionInfo', {}).get('connected') is not False:
                    blockers.append({'serial': device, 'reason': 'Retired gateway disconnection not verified'})
                else:
                    retired.append(device)
                continue
            try:
                if device not in fleet['provisioning']:
                    raise ValueError('Gateway device missing provisioning approval')
                inventory = self.controller.inventory(device, authorization)
                ownership = self.ownership_snapshot(self.controller, inventory, authorization)
                self.lifecycle.check(device, ownership)
                state = self.controller.fetch(16002, f'device/{device}?completeInfo=true', authorization)
                connection = state.get('connectionInfo', {})
                if state.get('deviceInfo', {}).get('serialNumber') != device or connection.get('connected') is not True or connection.get('verifiedCertificate') != 'VERIFIED':
                    raise ValueError('Fresh connected management verification required')
                leaf = connection.get('privateLeafSha256')
                with self.issuer.store.connect() as db:
                    certificate = db.execute('SELECT certificate FROM issued WHERE fingerprint=? AND device=?', (leaf, device)).fetchone()
                    receipt = db.execute('SELECT * FROM management_acceptances WHERE leaf=? AND device=? ORDER BY accepted DESC LIMIT 1', (leaf, device)).fetchone()
                    if not certificate:
                        raise ValueError('Current gateway leaf is not registered')
                    self.issuer._check_peer(db, x509.load_pem_x509_certificate(certificate[0]))
                    now = int(self.issuer.clock().timestamp())
                    if not receipt or receipt['root'] != fingerprint(self.issuer.root) or receipt['kind'] != 'renewal' or not 0 <= now - receipt['accepted'] <= 86400 or type(connection.get('sessionId')) is not int or receipt['session'] != connection['sessionId']:
                        raise ValueError('Current new-root session and tested renewal receipt required')
                accepted.append(device)
            except ValueError as error:
                blockers.append({'serial': device, 'reason': str(error)})
        # Repeat after session reads; this is a preview, not atomic trust removal.
        if self.census(authorization) != fleet:
            raise ValueError('Fleet changed while verifying management evidence')
        return {'retainedRoot': retained_root, 'ready': not blockers,
                'provisioningCount': len(fleet['provisioning']), 'gatewayCount': len(fleet['gateway']),
                'accepted': accepted, 'explicitlyRetired': retired, 'blockers': blockers}
