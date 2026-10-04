import copy
import unittest
from qualification_registry import Registry
import test_issuer


class RegistryTests(unittest.TestCase):
    setUp = test_issuer.IssuerTests.setUp
    request = test_issuer.IssuerTests.request
    write_authority = test_issuer.IssuerTests.write_authority
    load = test_issuer.IssuerTests.load

    def fixtures(self, operation='production-stock-openwrt-migration'):
        hardware = {'schema': 'openwifi.ap-hardware-evidence.v1', 'serialNumber': self.device,
            'exact_model': 'Synthetic model', 'sku_hex': '01020304', 'hardware_revision': 'A',
            'region': 'synthetic-region', 'factory_product_id': 'synthetic-product',
            'evidence_sha256': 'a' * 64, 'evidence_method': 'reviewed-manufacturing-capture'}
        qualification = {'schema': 'openwifi.oem-migration-qualification.v1', 'operation': operation,
            'status': 'qualified', 'exact_model': hardware['exact_model'], 'sku_hex': hardware['sku_hex'],
            'hardware_revision': hardware['hardware_revision'], 'region_compatibility': [hardware['region']]}
        for field in ('source_capability_contract_digest', 'installer_sha256', 'target_image_sha256',
                      'shared_recovery_manifest_sha256', 'qualification_evidence_digest'):
            qualification[field] = 'b' * 64
        runtime = {field: qualification[field] for field in ('operation', 'source_capability_contract_digest',
            'installer_sha256', 'target_image_sha256', 'shared_recovery_manifest_sha256', 'qualification_evidence_digest')}
        runtime.update(serial=self.device, **{field: hardware[field] for field in ('exact_model', 'sku_hex', 'hardware_revision', 'region')})
        return {'serialNumber': self.device}, hardware, qualification, runtime

    def test_independent_stock_operation_durable_versions_and_no_check_writes(self):
        registry = Registry(self.issuer.store)
        inventory, hardware, qualification, runtime = self.fixtures()
        registry.approve_hardware('operator', inventory, hardware)
        identity, version = registry.approve_qualification('operator', qualification)
        result = registry.approve_runtime('operator', inventory, identity, runtime)
        self.assertEqual(result['hardwareVersion'], 1)
        before = self.issuer.store.path.read_bytes()
        self.assertEqual(registry.check(self.device, inventory, runtime['operation']), result)
        self.assertEqual(self.issuer.store.path.read_bytes(), before)
        with self.assertRaises(ValueError):
            registry.check(self.device, inventory, 'production-oem-migration')
        self.assertEqual(Registry(self.load().store).check(self.device, inventory, runtime['operation']), result)
        registry.approve_hardware('operator', inventory, hardware)
        with self.assertRaises(ValueError):
            registry.check(self.device, inventory, runtime['operation'])
        registry.approve_runtime('operator', inventory, identity, runtime)
        registry.approve_qualification('operator', qualification)
        with self.assertRaises(ValueError):
            registry.check(self.device, inventory, runtime['operation'])

    def test_unsupported_unqualified_missing_and_mismatched_records_no_writes(self):
        registry = Registry(self.issuer.store)
        inventory, hardware, qualification, runtime = self.fixtures('production-oem-migration')
        with self.assertRaises(ValueError):
            registry.check(self.device, inventory, runtime['operation'])
        for changed in (dict(qualification, status='unsupported'), dict(qualification, status='unqualified'),
                        dict(qualification, unknown=True), dict(qualification, sku_hex='guessed')):
            before = self.issuer.store.path.read_bytes()
            with self.assertRaises(ValueError):
                registry.approve_qualification('operator', changed)
            self.assertEqual(self.issuer.store.path.read_bytes(), before)
        with self.assertRaises(ValueError):
            registry.approve_hardware('operator', {'serialNumber': '001122334456'}, hardware)
        with self.assertRaises(ValueError):
            registry.approve_hardware('operator', inventory, dict(hardware, region=''))
        registry.approve_hardware('operator', inventory, hardware)
        identity, _ = registry.approve_qualification('operator', qualification)
        for changed in (dict(runtime, serial='001122334456'), dict(runtime, target_image_sha256='c' * 64),
                        dict(runtime, operation='production-stock-openwrt-migration'), dict(runtime, unknown=True)):
            before = self.issuer.store.path.read_bytes()
            with self.assertRaises(ValueError):
                registry.approve_runtime('operator', inventory, identity, changed)
            self.assertEqual(self.issuer.store.path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
