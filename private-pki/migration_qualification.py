# Canonical contract: m0vse/wlan-ap main 8615a9ec tools/oem-migration/qualification.py
# Vendored reviewed v1 snapshot; update with the canonical contract and tests.
"""Side-effect-free migration admission; private trusted records live elsewhere.

Callers must authenticate the operator, load a privately approved record, resolve
inventory server-side, and verify source runtime before invoking evaluate().
Requester claims and source profiles are never authoritative inventory evidence.
This module issues no grant, creates no inventory and changes no AP or registry.
"""
import re

SCHEMA = 'openwifi.oem-migration-qualification.v1'
OPERATIONS = frozenset(('production-oem-migration', 'production-stock-openwrt-migration'))
DIGEST_FIELDS = frozenset((
    'source_capability_contract_digest', 'installer_sha256', 'target_image_sha256',
    'shared_recovery_manifest_sha256', 'qualification_evidence_digest',
))
RECORD_FIELDS = frozenset((
    'schema', 'operation', 'status', 'exact_model', 'sku_hex', 'hardware_revision',
    'region_compatibility',
)) | DIGEST_FIELDS
INVENTORY_FIELDS = frozenset(('serial', 'exact_model', 'sku_hex', 'hardware_revision', 'region'))
RUNTIME_FIELDS = frozenset(('operation', 'serial', 'exact_model', 'sku_hex',
                            'hardware_revision', 'region')) | DIGEST_FIELDS


def _text(value):
    return isinstance(value, str) and bool(value.strip()) and value == value.strip()


def _digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def _deny(reason):
    return {'allowed': False, 'reason': reason}


def evaluate(trusted_record, authoritative_inventory, verified_runtime):
    """Return allowed/reason, without I/O or mutating any supplied object.

    The shared recovery digest is source-specific. Stock OpenWrt migration binds
    its qualified recovery/rollback set, not a prerequisite OEM qualification.
    The same identity enrollment protocol follows either allowed operation.
    """
    record = trusted_record
    inventory = authoritative_inventory
    runtime = verified_runtime
    if not isinstance(record, dict) or set(record) != RECORD_FIELDS:
        return _deny('missing, unknown or incomplete qualification record fields')
    if record['schema'] != SCHEMA:
        return _deny('unsupported qualification schema')
    if record['status'] == 'unsupported':
        return _deny('known model is unsupported; no production side effects permitted')
    if record['status'] != 'qualified':
        return _deny('migration is not qualified; no production side effects permitted')
    if not isinstance(record['operation'], str) or record['operation'] not in OPERATIONS:
        return _deny('unsupported migration operation')
    if any(not _digest(record[field]) for field in DIGEST_FIELDS):
        return _deny('invalid or absent qualified capability/artifact/evidence digest')
    if not isinstance(inventory, dict) or set(inventory) != INVENTORY_FIELDS:
        return _deny('missing, unknown or incomplete authoritative inventory fields')
    if not isinstance(runtime, dict) or set(runtime) != RUNTIME_FIELDS:
        return _deny('missing, unknown or incomplete verified runtime fields')
    if not isinstance(inventory['serial'], str) or not re.fullmatch('[0-9a-f]{12}', inventory['serial']):
        return _deny('inventory serial must be canonical lowercase 12-hex identity')
    if not isinstance(record['sku_hex'], str) or not re.fullmatch('[0-9a-f]{8}', record['sku_hex']):
        return _deny('invalid exact SKU')
    for field in ('exact_model', 'hardware_revision'):
        if not _text(record[field]):
            return _deny('missing exact model or hardware revision')
    regions = record['region_compatibility']
    if (not isinstance(regions, list) or not regions or
            any(not _text(region) for region in regions) or len(set(regions)) != len(regions)):
        return _deny('invalid qualified region list')
    for field in ('serial', 'exact_model', 'sku_hex', 'hardware_revision', 'region'):
        if not _text(inventory[field]) or runtime[field] != inventory[field]:
            return _deny('verified runtime does not match authoritative inventory')
    for field in ('exact_model', 'sku_hex', 'hardware_revision'):
        if inventory[field] != record[field]:
            return _deny('inventory does not match exact qualified hardware')
    if inventory['region'] not in regions:
        return _deny('inventory region is not qualified')
    if runtime['operation'] != record['operation']:
        return _deny('qualification applies to a different source migration operation')
    for field in DIGEST_FIELDS:
        if runtime[field] != record[field]:
            return _deny('verified runtime capability/artifact/evidence binding mismatch')
    return {'allowed': True, 'reason': 'exact trusted qualification and inventory/runtime bindings match'}
