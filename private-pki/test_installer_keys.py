from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ec
from installer_keys import InstallerKeys
from test_onboarding import OnboardingTests


class InstallerKeyTests(OnboardingTests):
    def prepare_keys(self):
        jobs, inventory, controller = self.prepare()
        job = jobs.start('root', self.device, 'Bearer synthetic')['id']
        path = self.path / 'installer-encryption-key'
        path.write_bytes(Fernet.generate_key())
        path.chmod(0o600)
        return jobs, inventory, controller, job, path, InstallerKeys(jobs, path)

    def test_durable_key_private_storage_and_cancellation(self):
        jobs, inventory, controller, job, path, keys = self.prepare_keys()
        key = keys.create(job)
        self.clock += timedelta(days=90)
        restored = InstallerKeys(jobs, path)
        self.assertEqual(key, restored.create(job))
        self.assertEqual(job, restored.bind(key, self.device, self.csr, 'Bearer synthetic'))
        self.assertNotIn(key, str(jobs.list()))
        with jobs.store.connect() as db:
            stored = db.execute('SELECT * FROM installer_keys').fetchone()
            self.assertNotIn(key.encode(), stored['encrypted'])
        jobs.cancel('root', job)
        with self.assertRaises(ValueError):
            restored.bind(key, self.device, self.csr, 'Bearer synthetic')
        with self.assertRaises(ValueError):
            restored.create(job)

    def test_concurrent_csr_substitution_and_ownership(self):
        jobs, inventory, controller, job, path, keys = self.prepare_keys()
        key = keys.create(job)
        def attempt(csr):
            try:
                return keys.bind(key, self.device, csr, 'Bearer synthetic')
            except ValueError:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, (self.csr, self.request(ec.generate_private_key(ec.SECP256R1())))))
        self.assertEqual(results.count(job), 1)
        with self.assertRaises(ValueError):
            keys.bind(key, 'aabbccddeeff', self.csr, 'Bearer synthetic')
        inventory['id'] = 'replacement'
        with self.assertRaises(ValueError):
            keys.bind(key, self.device, self.csr, 'Bearer synthetic')
