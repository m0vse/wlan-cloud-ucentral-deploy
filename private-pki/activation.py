"""Fresh normal-management proof; trusted gateway adapter still needs deployment.

Candidate mTLS authorization alone never consumes a challenge or commits an AP
credential. The verifier reads the actual gateway's authenticated connection API.
"""
import hashlib
import secrets
from cryptography import x509
from issuer import fingerprint


class Activation:
    def __init__(self, issuer, gateway_state):
        self.issuer, self.gateway_state = issuer, gateway_state
        with issuer.store.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS activation_challenges(
                nonce TEXT PRIMARY KEY, device TEXT NOT NULL, leaf TEXT NOT NULL,
                created INTEGER NOT NULL, expires INTEGER NOT NULL,
                policy INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0)""")

    def challenge(self, peer_der):
        peer = x509.load_der_x509_certificate(peer_der)
        nonce = secrets.token_hex(32)
        stamp = int(self.issuer.clock().timestamp())
        with self.issuer.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            device = self.issuer._check_peer(db, peer)
            if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='gateway_policy_version'").fetchone():
                raise ValueError("gateway policy publication required")
            version = db.execute("SELECT version FROM gateway_policy_version WHERE id=1").fetchone()
            if not version or version[0] < 1:
                raise ValueError("gateway policy publication required")
            db.execute("DELETE FROM activation_challenges WHERE expires<=?", (stamp,))
            if db.execute("SELECT count(*) FROM activation_challenges").fetchone()[0] >= 128:
                raise ValueError("activation challenge capacity exceeded")
            expiry = min(stamp + 30, int(peer.not_valid_after_utc.timestamp()))
            db.execute("INSERT INTO activation_challenges VALUES (?,?,?,?,?,?,0)",
                (hashlib.sha256(nonce.encode()).hexdigest(), device, fingerprint(peer), stamp, expiry, version[0]))
        return {"nonce": nonce, "serial": device, "leafSha256": fingerprint(peer),
                "createdAt": stamp, "expiresAt": expiry, "minimumPolicyVersion": version[0],
                "managementAccepted": False}

    def verify(self, peer_der, nonce):
        if not isinstance(nonce, str) or len(nonce) != 64 or any(c not in "0123456789abcdef" for c in nonce):
            raise ValueError("invalid activation challenge")
        peer = x509.load_der_x509_certificate(peer_der)
        with self.issuer.store.connect() as db:
            device = self.issuer._check_peer(db, peer)
            challenge = db.execute("SELECT * FROM activation_challenges WHERE nonce=?",
                (hashlib.sha256(nonce.encode()).hexdigest(),)).fetchone()
            if not challenge or challenge["consumed"] or challenge["expires"] <= int(self.issuer.clock().timestamp()) or challenge["device"] != device or challenge["leaf"] != fingerprint(peer):
                raise ValueError("activation challenge refused")
        # This callable must use verified TLS and server-side controller credentials.
        # Never accept gateway state or certificate fingerprints from the AP body.
        state = self.gateway_state(device)
        if not isinstance(state, dict) or not isinstance(state.get("deviceInfo"), dict) or not isinstance(state.get("connectionInfo"), dict):
            raise ValueError("invalid gateway state")
        stamp = int(self.issuer.clock().timestamp())
        with self.issuer.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.issuer._check_peer(db, peer)
            challenge = db.execute("SELECT * FROM activation_challenges WHERE nonce=?",
                (hashlib.sha256(nonce.encode()).hexdigest(),)).fetchone()
            if not challenge or challenge["consumed"] or challenge["expires"] <= stamp or challenge["device"] != device or challenge["leaf"] != fingerprint(peer):
                raise ValueError("activation challenge refused")
            info, connection = state.get("deviceInfo", {}), state.get("connectionInfo", {})
            times = [connection.get(k) for k in ("started", "privateAcceptedAt", "sessionId", "privatePolicyVersion")]
            if any(type(value) is not int for value in times):
                raise ValueError("invalid management acceptance")
            started, accepted, session, version = times
            if info.get("serialNumber") != device or connection.get("connected") is not True or connection.get("verifiedCertificate") != "VERIFIED" or connection.get("privateLeafSha256") != fingerprint(peer) or connection.get("privateActivationNonce") != nonce or session <= 0 or version < challenge["policy"] or not challenge["created"] <= started <= accepted <= stamp or accepted >= challenge["expires"]:
                raise ValueError("fresh candidate management acceptance required")
            db.execute("UPDATE activation_challenges SET consumed=1 WHERE nonce=?", (challenge["nonce"],))
            db.execute("INSERT INTO audit(stamp,event,serial) VALUES (?,?,?)",
                       (stamp, "candidate-management-accepted:" + fingerprint(peer), device))
        return {"serial": device, "leafSha256": fingerprint(peer), "nonce": nonce,
                "sessionId": session, "acceptedAt": accepted, "managementAccepted": True}
