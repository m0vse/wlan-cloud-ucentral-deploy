import concurrent.futures
import json
from datetime import timedelta
import unittest
from cryptography import x509
from issuer import fingerprint
from policy_publisher import publish
import test_issuer


class PublisherTests(unittest.TestCase):
    setUp = test_issuer.IssuerTests.setUp
    request = test_issuer.IssuerTests.request
    write_authority = test_issuer.IssuerTests.write_authority
    load = test_issuer.IssuerTests.load
    issue = test_issuer.IssuerTests.issue

    def test_admission_revocation_expiry_disable_and_recovery(self):
        directory = self.path / "gateway"
        directory.mkdir(mode=0o700)
        leaf = self.issue()
        pin = fingerprint(x509.load_pem_x509_certificate(leaf))
        initial = publish(self.issuer, directory)
        self.assertIn(pin, initial["inventory"][self.device]["fingerprints"])
        self.issuer.revoke(pin)
        revoked = publish(self.issuer, directory)
        self.assertGreater(revoked["version"], initial["version"])
        self.assertIn(pin, revoked["revoked"])
        self.assertNotIn(pin, revoked["inventory"][self.device]["fingerprints"])
        fresh = self.issue()
        new_pin = fingerprint(x509.load_pem_x509_certificate(fresh))
        self.assertIn(new_pin, publish(self.issuer, directory)["inventory"][self.device]["fingerprints"])
        self.clock += timedelta(days=366)
        self.assertEqual(publish(self.issuer, directory)["inventory"][self.device]["fingerprints"], [])
        self.issuer.disable(self.device)
        self.assertFalse(publish(self.issuer, directory)["inventory"][self.device]["enabled"])

    def test_concurrent_versions_are_durable_and_no_secrets(self):
        directory = self.path / "gateway"
        directory.mkdir(mode=0o700)
        token = self.issuer.authorize(self.device, self.csr)
        self.issuer.bootstrap(self.device, token, self.csr)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            snapshots = list(pool.map(lambda _: publish(self.issuer, directory), range(4)))
        final = json.loads((directory / "policy.json").read_bytes())
        self.assertEqual(final["version"], max(item["version"] for item in snapshots))
        self.assertNotIn(token, str(final))
        self.assertNotIn("PRIVATE KEY", str(final))
        self.issuer = self.load()
        self.assertGreater(publish(self.issuer, directory)["version"], final["version"])


if __name__ == "__main__":
    unittest.main()
