import unittest
from unittest.mock import Mock, patch
from admin import Administration, Controller, Denied
import test_issuer


class AdminTests(unittest.TestCase):
    setUp = test_issuer.IssuerTests.setUp
    request = test_issuer.IssuerTests.request
    write_authority = test_issuer.IssuerTests.write_authority
    load = test_issuer.IssuerTests.load
    def test_authentication_precedes_inventory_and_issuer(self):
        controller = Mock()
        controller.root.side_effect = Denied(403, "refused")
        admin = Administration(self.issuer, controller)
        with patch.object(self.issuer, "approve") as approve:
            with self.assertRaises(Denied):
                admin.call("Bearer wrong", "authorize", {"serial": self.device, "csr": self.csr.decode()})
            approve.assert_not_called()
        controller.inventory.assert_not_called()

    def test_inventory_required_audit_actor_no_token_and_status(self):
        controller = Mock()
        controller.root.return_value = "synthetic-operator"
        admin = Administration(self.issuer, controller)
        request = {"serial": self.device, "csr": self.csr.decode()}
        grant = admin.call("Bearer synthetic", "authorize", request)
        self.issuer.bootstrap(self.device, grant["authorization"], self.csr)
        controller.inventory.assert_called_once_with(self.device, "Bearer synthetic")
        events = admin.call("Bearer synthetic", "audit", {})["events"]
        self.assertTrue(all(row["actor"] == "synthetic-operator" for row in events))
        self.assertNotIn(grant["authorization"], str(events))
        status = admin.call("Bearer synthetic", "status", {})
        self.assertEqual(len(status["certificates"]), 1)
        self.assertEqual(status["gatewayEnforcement"], "not-integrated")
        with self.assertRaises(Denied):
            admin.call("Bearer synthetic", "revoke", {"fingerprint": "a" * 64})

    def test_sec_validation_rejects_ui_role_and_insecure_origin(self):
        controller = Controller("https://controller.example.invalid")
        for user in ({"id": "operator", "userRole": "admin"},
                     {"id": "operator", "userRole": "root", "suspended": True},
                     {"id": "operator", "userRole": "root", "blackListed": True},
                     {"userRole": "root"}):
            with patch.object(controller, "fetch", return_value=user):
                with self.assertRaises(Denied):
                    controller.root("Bearer synthetic")
        for origin in ("http://controller.example.invalid", "https://user:password@controller.example.invalid", "https://controller.example.invalid/path"):
            with self.assertRaises(ValueError):
                Controller(origin)


if __name__ == "__main__":
    unittest.main()
