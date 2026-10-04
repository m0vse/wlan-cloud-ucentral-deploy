"""Portal administration core; authentication is checked before issuer access.

No browser-supplied role, identity DER, or inventory approval is trusted.
The HTTP adapter must supply a bounded JSON object and a Bearer header.
"""
import json
import re
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from cryptography import x509
from cryptography.x509.oid import NameOID
from issuer import fingerprint
from ownership import snapshot


class Denied(Exception):
    def __init__(self, status, message):
        self.status = status
        super().__init__(message)


class Controller:
    def __init__(self, origin):
        parsed = urlsplit(origin)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.port:
            raise ValueError("explicit HTTPS controller origin required")
        self.origin = origin.rstrip("/")

    def request(self, port, route, authorization, method="GET", body=None, timeout=5):
        request = urllib.request.Request(f"{self.origin}:{port}/api/v1/{route}",
            headers={**({"Authorization": authorization} if authorization else {}), "Accept": "application/json", "Content-Type": "application/json"},
            method=method, data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read(65537)
            if len(body) > 65536:
                raise ValueError("oversized controller response")
            data = json.loads(body)
            if not isinstance(data, (dict, list)):
                raise ValueError("invalid controller response")
            return data
        except urllib.error.HTTPError as error:
            raise Denied(401 if error.code in (401, 403) else 502, "Controller request refused") from None
        except (urllib.error.URLError, TimeoutError, ValueError):
            raise Denied(502, "Controller unavailable") from None

    def fetch(self, port, route, authorization):
        data = self.request(port, route, authorization)
        if not isinstance(data, dict):
            raise Denied(502, "Invalid controller response")
        return data

    def root(self, authorization):
        if not isinstance(authorization, str) or len(authorization) > 8192 or not re.fullmatch(r"Bearer [A-Za-z0-9._~+/-]+=*", authorization):
            raise Denied(401, "Sign in required")
        user = self.fetch(16001, "oauth2?me=true", authorization)
        if user.get("userRole") != "root" or user.get("suspended") or user.get("blackListed"):
            raise Denied(403, "Root access required")
        actor = user.get("id")
        if not isinstance(actor, str) or not actor or len(actor) > 128:
            raise Denied(403, "Authenticated operator identity required")
        return actor

    def inventory(self, device, authorization):
        # config=true returns configuration only, not the inventory identity.
        inventory = self.fetch(16005, f"inventory/{device}", authorization)
        if inventory.get("serialNumber") != device:
            raise Denied(403, "Provisioning inventory identity required")
        return inventory


class Administration:
    def __init__(self, issuer, controller, qualification=None, registry=None, fleet_gate=None):
        self.issuer, self.controller = issuer, controller
        self.qualification = qualification or (lambda device, inventory: False)
        self.registry = registry
        self.fleet_gate = fleet_gate
        with issuer.store.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS operator_audit(
                id INTEGER PRIMARY KEY, stamp INTEGER NOT NULL,
                actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL)""")

    def _audit(self, actor, action, target):
        with self.issuer.store.connect() as db:
            db.execute("INSERT INTO operator_audit(stamp,actor,action,target) VALUES (?,?,?,?)",
                       (int(self.issuer.clock().timestamp()), actor, action, target))

    def call(self, authorization, operation, request):
        actor = self.controller.root(authorization)
        if not isinstance(request, dict):
            raise Denied(400, "Invalid request")
        if operation == "retirement-review" and set(request) == {"root"}:
            if self.fleet_gate is None:
                raise Denied(503, "Complete fleet review adapter unavailable")
            return self.fleet_gate.review(authorization, request["root"])
        if operation == "approve-identity" and set(request) == {"serial", "approved", "enabled", "retired"}:
            guard = self.issuer.authorization_guard
            if guard is None:
                raise Denied(503, "Authoritative lifecycle adapter unavailable")
            device = request["serial"]
            self.issuer.store.check_serial(device)
            inventory = self.controller.inventory(device, authorization)
            ownership = snapshot(self.controller, inventory, authorization)
            version = guard.lifecycle.approve(actor, device, ownership,
                request["approved"], request["enabled"], request["retired"])
            self._audit(actor, "identity-lifecycle-reviewed", device)
            return {"serial": device, "version": version}
        if operation == "authorize" and set(request) == {"serial", "csr", "operation"}:
            guard = self.issuer.authorization_guard
            if guard is None:
                raise Denied(503, "Authoritative migration adapter unavailable")
            device, csr = request["serial"], request["csr"]
            self.issuer.store.check_serial(device)
            if not isinstance(csr, str) or len(csr) > 16384:
                raise Denied(400, "Invalid CSR")
            token = guard.authorize(actor, device, csr.encode("ascii"), request["operation"])
            return {"authorization": token, "expiresIn": 600, "serial": device}
        if operation in ("evidence", "approve-hardware", "approve-qualification", "approve-runtime"):
            if self.registry is None:
                raise Denied(503, "Private evidence registry unavailable")
            if operation == "evidence" and set(request) == {"serial"}:
                self.controller.inventory(request["serial"], authorization)
                return self.registry.view(request["serial"])
            if operation == "approve-hardware" and set(request) == {"record"} and isinstance(request["record"], dict):
                record = request["record"]
                device = record.get("serialNumber")
                self.issuer.store.check_serial(device)
                inventory = self.controller.inventory(device, authorization)
                version = self.registry.approve_hardware(actor, inventory, record)
                self._audit(actor, "hardware-evidence-approved", device)
                return {"version": version, "serial": device}
            if operation == "approve-qualification" and set(request) == {"record"}:
                identity, version = self.registry.approve_qualification(actor, request["record"])
                self._audit(actor, "migration-qualification-approved", identity)
                return {"identity": identity, "version": version}
            if operation == "approve-runtime" and set(request) == {"identity", "record"} and isinstance(request["record"], dict):
                record = request["record"]
                device = record.get("serial")
                self.issuer.store.check_serial(device)
                inventory = self.controller.inventory(device, authorization)
                binding = self.registry.approve_runtime(actor, inventory, request["identity"], record)
                self._audit(actor, "migration-runtime-approved", device)
                return binding
            raise Denied(400, "Invalid evidence review request")
        if operation == "status" and not request:
            with self.issuer.store.connect() as db:
                certificates = [dict(row) for row in db.execute(
                    """SELECT fingerprint,device,issuer,expires,revoked,
                        (SELECT max(accepted) FROM management_acceptances WHERE leaf=fingerprint) AS managementAcceptedAt,
                        (SELECT kind FROM issuance_origins WHERE leaf=fingerprint) AS issuanceKind
                        FROM issued ORDER BY device,expires DESC LIMIT 1000""")]
                authority_rows = list(db.execute("SELECT fingerprint,root FROM authorities"))
                issuers = [row[0] for row in authority_rows]
                roots = {}
                for row in authority_rows:
                    root = x509.load_pem_x509_certificate(row[1])
                    names = root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    roots[fingerprint(root)] = {"fingerprint": fingerprint(root),
                        "name": names[0].value if names else root.subject.rfc4514_string(),
                        "expires": int(root.not_valid_after_utc.timestamp())}
            return {"certificates": certificates, "issuers": issuers,
                    "roots": list(roots.values()), "activeRoot": fingerprint(self.issuer.root),
                    "activeIssuer": self.issuer.authority, "gatewayEnforcement": "not-integrated"}
        if operation == "audit" and not request:
            with self.issuer.store.connect() as db:
                return {"events": [dict(row) for row in db.execute(
                    "SELECT stamp,actor,action,target FROM operator_audit ORDER BY id DESC LIMIT 500")]}
        if operation == "authorize" and set(request) == {"serial", "csr"}:
            if self.issuer.authorization_guard is not None:
                raise Denied(400, "Explicit migration operation required")
            device, csr = request["serial"], request["csr"]
            self.issuer.store.check_serial(device)
            if not isinstance(csr, str) or len(csr) > 16384:
                raise Denied(400, "Invalid CSR")
            # Validate CSR before approval, then require existing controller inventory.
            self.issuer.csr(device, csr.encode("ascii"))
            inventory = self.controller.inventory(device, authorization)
            if self.qualification(device, inventory) is not True:
                raise Denied(403, "Exact model migration is not qualified")
            self._audit(actor, "enrollment-authorize-requested", device)
            self.issuer.approve(device)
            token = self.issuer.authorize(device, csr.encode("ascii"))
            self._audit(actor, "enrollment-authorized", device)
            return {"authorization": token, "expiresIn": 600, "serial": device}
        # Do not present renewal-only revocation as gateway enforcement.
        if operation in ("revoke", "disable", "retire-root"):
            raise Denied(503, "Gateway lifecycle enforcement is not yet integrated")
        raise Denied(404, "Unknown lifecycle operation")
