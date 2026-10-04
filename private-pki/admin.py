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

    def fetch(self, port, route, authorization):
        request = urllib.request.Request(f"{self.origin}:{port}/api/v1/{route}",
            headers={"Authorization": authorization, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                body = response.read(65537)
            if len(body) > 65536:
                raise ValueError("oversized controller response")
            data = json.loads(body)
            if not isinstance(data, dict):
                raise ValueError("invalid controller response")
            return data
        except urllib.error.HTTPError as error:
            raise Denied(401 if error.code in (401, 403) else 502, "Controller request refused") from None
        except (urllib.error.URLError, TimeoutError, ValueError):
            raise Denied(502, "Controller unavailable") from None

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
        inventory = self.fetch(16005, f"inventory/{device}?config=true&explain=true", authorization)
        if inventory.get("serialNumber") != device:
            raise Denied(403, "Provisioning inventory identity required")
        return inventory


class Administration:
    def __init__(self, issuer, controller):
        self.issuer, self.controller = issuer, controller
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
        if operation == "status" and not request:
            with self.issuer.store.connect() as db:
                certificates = [dict(row) for row in db.execute(
                    "SELECT fingerprint,device,issuer,expires,revoked FROM issued ORDER BY device,expires DESC LIMIT 1000")]
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
            device, csr = request["serial"], request["csr"]
            self.issuer.store.check_serial(device)
            if not isinstance(csr, str) or len(csr) > 16384:
                raise Denied(400, "Invalid CSR")
            # Validate CSR before approval, then require existing controller inventory.
            self.issuer.csr(device, csr.encode("ascii"))
            self.controller.inventory(device, authorization)
            self._audit(actor, "enrollment-authorize-requested", device)
            self.issuer.approve(device)
            token = self.issuer.authorize(device, csr.encode("ascii"))
            self._audit(actor, "enrollment-authorized", device)
            return {"authorization": token, "expiresIn": 600, "serial": device}
        # Do not present renewal-only revocation as gateway enforcement.
        if operation in ("revoke", "disable", "retire-root"):
            raise Denied(503, "Gateway lifecycle enforcement is not yet integrated")
        raise Denied(404, "Unknown lifecycle operation")
