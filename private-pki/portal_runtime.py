"""Root-authenticated portal administration and optional native EST listener.

The AP listener implements standard EST only; it never exposes portal management.
Existing OpenWiFi handles reenroll, expiry scheduling and reconnection. Root
sessions are revalidated on management requests and are never persisted.
"""
import argparse
import ssl
import threading
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from admin import Administration, Controller, Denied
from issuer import Issuer, fingerprint, private_read
from qualification_registry import Registry
from service import BoundedServer, handler
from onboarding import Onboarding
from cryptography.fernet import Fernet
from enrollment_campaign import Campaigns
from native_est import NativeEST, handler as est_handler
from native_management import NativeManagement


class PortalAdministration(Administration):
    def __init__(self, issuer, controller, retained_roots, observations=None):
        super().__init__(issuer, controller, registry=Registry(issuer.store))
        self.retained = []
        self.observations = Path(observations) if observations else None
        self.onboarding = Onboarding(issuer.store, controller)
        self.native = None
        self.campaigns = None
        self.est_server = None
        for path in retained_roots:
            root = x509.load_pem_x509_certificate(private_read(path))
            root.verify_directly_issued_by(root)
            if not root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError("retained root is not a CA")
            self.retained.append(root)

    def call(self, authorization, operation, request):
        if operation in ('create-enrollment-key','cancel-enrollment-key','rotate-enrollment-key'):
            actor = self.controller.root(authorization)
            if not self.campaigns:
                raise Denied(503, 'Enrollment keys are not enabled')
            if operation == 'create-enrollment-key' and isinstance(request,dict) and set(request)=={'serials','operation'}:
                result=self.campaigns.create(actor,request['serials'],authorization,request['operation'])
                return {**result,'server':self.est_server}
            if isinstance(request,dict) and set(request)=={'id'}:
                if operation == 'cancel-enrollment-key':
                    return self.campaigns.cancel(actor,request['id'])
                if operation == 'rotate-enrollment-key':
                    return {**self.campaigns.rotate(actor,request['id'],authorization),'server':self.est_server}
            raise Denied(400, 'Invalid enrollment key request')
        if operation in ('onboard', 'move-ca', 'renew', 'cancel-onboarding'):
            actor = self.controller.root(authorization)
            if operation in ('onboard', 'move-ca', 'renew') and isinstance(request, dict) and set(request) == {'serial'}:
                if self.native and operation in ('renew', 'move-ca'):
                    return self.native.request(actor, request['serial'], authorization, operation)
                return self.onboarding.start(actor, request['serial'], authorization, operation)
            if operation == 'cancel-onboarding' and isinstance(request, dict) and set(request) == {'job'}:
                return self.onboarding.cancel(actor, request['job'])
            raise Denied(400, 'Invalid onboarding request')
        result = super().call(authorization, operation, request)
        if operation == "status":
            result["phase"] = "native" if self.native else "prepared"
            result["preparedIssuer"] = self.issuer.authority
            result["preparedRoot"] = fingerprint(self.issuer.root)
            result["activeRoot"] = fingerprint(self.issuer.root) if self.native else ""
            result["activeIssuer"] = self.issuer.authority if self.native else ""
            for root in result["roots"]:
                root["state"] = "active" if self.native and root["fingerprint"] == fingerprint(self.issuer.root) else "retained" if self.native else "prepared"
            for root in self.retained:
                names = root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if self.native:
                    result["roots"] = [r for r in result["roots"] if r["fingerprint"] != fingerprint(root)]
                result["roots"].append({"fingerprint": fingerprint(root),
                    "name": names[0].value if names else root.subject.rfc4514_string(),
                    "expires": int(root.not_valid_after_utc.timestamp()), "state": "retained"})
            result["setup"] = {"state": "controller-integration-pending",
                "message": "Certificate service is connected. Controller service-account restrictions and AP activation are being integrated."}
            if self.native:
                self.native.reconcile(authorization, result['certificates'])
                result['nativeRenewalReady'] = True
                result['nativeEnrollmentReady'] = True
                result['setup'] = {'state':'native', 'message':'Native certificate enrollment and renewal are enabled.'}
            result['enrollmentBatches'] = self.campaigns.list() if self.campaigns else []
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
                    if any(c['fingerprint'] == fingerprint(leaf) for c in result['certificates']):
                        continue
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
    parser.add_argument('--est-port', type=int)
    parser.add_argument('--est-tls-directory', type=Path)
    parser.add_argument('--installer-encryption-key', type=Path)
    args = parser.parse_args()
    directory = args.issuer_directory
    issuer = Issuer(directory / "root-cert.pem", directory / "issuer-cert.pem",
        directory / "issuer-key.pem", args.state)
    administration = PortalAdministration(issuer, Controller(args.controller), args.retained_root, args.observations)
    est_server = None
    if args.est_port:
        if not args.est_tls_directory or not args.installer_encryption_key:
            parser.error('EST TLS directory and installer encryption key are required')
        directory = args.est_tls_directory
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        private_read(directory/'key.pem')
        context.load_cert_chain(directory/'cert.pem', directory/'key.pem')
        trust = issuer.ca.public_bytes(serialization.Encoding.PEM) + issuer.root.public_bytes(serialization.Encoding.PEM)
        trust += b''.join(private_read(path) for path in args.retained_root)
        context.load_verify_locations(cadata=trust.decode('ascii'))
        context.verify_mode = ssl.CERT_OPTIONAL
        administration.campaigns = Campaigns(issuer, administration.controller, Fernet(private_read(args.installer_encryption_key)))
        from urllib.parse import urlsplit
        administration.est_server = urlsplit(args.controller).hostname + ':' + str(args.est_port)
        installer = administration.campaigns
        administration.native = NativeManagement(issuer, administration.controller, administration.onboarding)
        est_server = BoundedServer(('0.0.0.0', args.est_port), est_handler(NativeEST(issuer, installer)), context)
        threading.Thread(target=est_server.serve_forever, daemon=True).start()
    server = BoundedServer(("0.0.0.0", args.port), handler(issuer, administration, mode="admin"))
    try:
        server.serve_forever()
    finally:
        server.server_close()
        if est_server:
            est_server.shutdown()
            est_server.server_close()


if __name__ == "__main__":
    main()
