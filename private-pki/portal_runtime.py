"""Private-network portal administration, using the current validated Root session.

No AP listener and no automatic enrollment/renewal activation. The prepared
issuer and retained public trust are reported separately. Human tokens are
validated on every request and never stored. Deploy behind the portal TLS proxy.
"""
import argparse
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from admin import Administration, Controller, Denied
from issuer import Issuer, fingerprint, private_read
from qualification_registry import Registry
from service import BoundedServer, handler
from onboarding import Onboarding


class PortalAdministration(Administration):
    def __init__(self, issuer, controller, retained_roots, observations=None):
        super().__init__(issuer, controller, registry=Registry(issuer.store))
        self.retained = []
        self.observations = Path(observations) if observations else None
        self.onboarding = Onboarding(issuer.store, controller)
        for path in retained_roots:
            root = x509.load_pem_x509_certificate(private_read(path))
            root.verify_directly_issued_by(root)
            if not root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError("retained root is not a CA")
            self.retained.append(root)

    def call(self, authorization, operation, request):
        if operation in ('onboard', 'cancel-onboarding'):
            actor = self.controller.root(authorization)
            if operation == 'onboard' and isinstance(request, dict) and set(request) == {'serial'}:
                return self.onboarding.start(actor, request['serial'], authorization)
            if operation == 'cancel-onboarding' and isinstance(request, dict) and set(request) == {'job'}:
                return self.onboarding.cancel(actor, request['job'])
            raise Denied(400, 'Invalid onboarding request')
        result = super().call(authorization, operation, request)
        if operation == "status":
            result["phase"] = "prepared"
            result["preparedIssuer"] = self.issuer.authority
            result["preparedRoot"] = fingerprint(self.issuer.root)
            result["activeRoot"] = ""
            result["activeIssuer"] = ""
            for root in result["roots"]:
                root["state"] = "prepared"
            for root in self.retained:
                names = root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                result["roots"].append({"fingerprint": fingerprint(root),
                    "name": names[0].value if names else root.subject.rfc4514_string(),
                    "expires": int(root.not_valid_after_utc.timestamp()), "state": "retained"})
            result["setup"] = {"state": "controller-integration-pending",
                "message": "Certificate service is connected. Controller service-account restrictions and AP activation are being integrated."}
            result['onboarding'] = self.onboarding.list()
            result['onboardingApproval'] = 'until-completed-or-cancelled'
            if self.observations:
                for path in sorted(self.observations.glob('*.pem')):
                    device = path.stem
                    self.issuer.store.check_serial(device)
                    self.controller.inventory(device, authorization)
                    leaf = x509.load_pem_x509_certificate(private_read(path))
                    names = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    if len(names) != 1 or names[0].value != device or leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca or ExtendedKeyUsageOID.CLIENT_AUTH not in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
                        raise ValueError('observed public certificate identity or purpose mismatch')
                    authority = None
                    for root in self.retained:
                        if leaf.issuer == root.subject:
                            leaf.verify_directly_issued_by(root)
                            authority = fingerprint(root)
                            break
                    if not authority:
                        raise ValueError('observed certificate outside retained trust')
                    result['certificates'].append({'fingerprint': fingerprint(leaf),
                        'device': device, 'issuer': authority, 'expires': int(leaf.not_valid_after_utc.timestamp()),
                        'revoked': 0, 'issuanceKind': 'observed-retained', 'observed': True})
        return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--controller", required=True)
    parser.add_argument("--issuer-directory", type=Path, required=True)
    parser.add_argument("--retained-root", action="append", required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--observations")
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()
    directory = args.issuer_directory
    issuer = Issuer(directory / "root-cert.pem", directory / "issuer-cert.pem",
        directory / "issuer-key.pem", args.state)
    administration = PortalAdministration(issuer, Controller(args.controller), args.retained_root, args.observations)
    server = BoundedServer(("0.0.0.0", args.port), handler(issuer, administration, mode="admin"))
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
