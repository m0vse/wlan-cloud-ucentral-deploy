from datetime import timedelta
import copy
import unittest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from activation import Activation
from policy_publisher import publish
import test_issuer


class ActivationTests(unittest.TestCase):
    setUp = test_issuer.IssuerTests.setUp
    request = test_issuer.IssuerTests.request
    write_authority = test_issuer.IssuerTests.write_authority
    load = test_issuer.IssuerTests.load
    issue = test_issuer.IssuerTests.issue

    def prepare(self):
        peer = x509.load_pem_x509_certificate(self.issue()).public_bytes(serialization.Encoding.DER)
        path = self.path / "gateway"
        path.mkdir(mode=0o700)
        publish(self.issuer, path)
        state = {}
        verifier = Activation(self.issuer, lambda serial: state)
        challenge = verifier.challenge(peer)
        stamp = int(self.clock.timestamp())
        state.update(deviceInfo={"serialNumber": self.device}, connectionInfo={
            "connected": True, "verifiedCertificate": "VERIFIED", "sessionId": 42,
            "privateLeafSha256": challenge["leafSha256"], "privateActivationNonce": challenge["nonce"],
            "started": stamp, "privateAcceptedAt": stamp, "privatePolicyVersion": challenge["minimumPolicyVersion"]})
        return peer, verifier, challenge, state

    def test_fresh_serial_leaf_nonce_session_and_single_consumption(self):
        peer, verifier, challenge, state = self.prepare()
        reply = verifier.verify(peer, challenge["nonce"])
        self.assertTrue(reply["managementAccepted"])
        self.assertEqual(reply["sessionId"], 42)
        with self.issuer.store.connect() as db:
            receipt = dict(db.execute("SELECT * FROM management_acceptances").fetchone())
        self.assertEqual(receipt["leaf"], challenge["leafSha256"])
        self.assertEqual(receipt["kind"], "bootstrap")
        self.assertNotIn(challenge["nonce"], str(receipt))
        with self.assertRaises(ValueError):
            verifier.verify(peer, challenge["nonce"])

    def test_renewal_acceptance_persists_authority_and_origin(self):
        peer, verifier, challenge, state = self.prepare()
        renewed = self.issuer.renew(peer, self.csr, "a" * 32)
        renewed_der = x509.load_pem_x509_certificate(renewed).public_bytes(serialization.Encoding.DER)
        publish(self.issuer, self.path / "gateway")
        fresh = verifier.challenge(renewed_der)
        state["connectionInfo"].update(privateLeafSha256=fresh["leafSha256"],
            privateActivationNonce=fresh["nonce"], privatePolicyVersion=fresh["minimumPolicyVersion"], sessionId=43)
        verifier.verify(renewed_der, fresh["nonce"])
        with self.issuer.store.connect() as db:
            receipt = dict(db.execute("SELECT * FROM management_acceptances").fetchone())
        self.assertEqual(receipt["kind"], "renewal")
        self.assertEqual(receipt["issuer"], self.issuer.authority)
        self.assertEqual(receipt["session"], 43)
        restarted = self.load()
        with restarted.store.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM management_acceptances").fetchone()[0], 1)

    def test_stale_tls_only_wrong_leaf_nonce_serial_and_unverified_refused(self):
        peer, verifier, challenge, state = self.prepare()
        original = copy.deepcopy(state)
        changes = [("connected", False), ("verifiedCertificate", "VALID_CERTIFICATE"),
                   ("privateLeafSha256", "a" * 64), ("privateActivationNonce", "b" * 64),
                   ("started", int(self.clock.timestamp()) - 1), ("sessionId", 0),
                   ("privatePolicyVersion", 0), ("privateAcceptedAt", int(self.clock.timestamp()) + 1)]
        for key, value in changes:
            state["connectionInfo"] = dict(original["connectionInfo"], **{key: value})
            with self.assertRaises(ValueError):
                verifier.verify(peer, challenge["nonce"])
        state.update(copy.deepcopy(original))
        state["deviceInfo"]["serialNumber"] = "001122334456"
        with self.assertRaises(ValueError):
            verifier.verify(peer, challenge["nonce"])
        state.update(original)
        self.clock += timedelta(seconds=31)
        with self.assertRaises(ValueError):
            verifier.verify(peer, challenge["nonce"])


if __name__ == "__main__":
    unittest.main()
