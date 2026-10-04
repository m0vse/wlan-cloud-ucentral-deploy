# Private AP certificate lifecycle — implementation in progress

The issuer core loads an existing protected device issuing key and certificate
under a public private root. It never generates authorities on startup and never
loads a root signing key. Private inputs must be owned by the service user and
have mode 0600. No private material or deployment host defaults belong here.

`enrollment_store.py` is reused from wlan-ap's earlier isolated PKI tests.
`issuer.py` adds an issuance ledger, issuer-qualified certificate fingerprints,
transactional issuance with hashed CSR-bound grants, persistent renewal retries,
RSA2048–4096/P-256 AP keys, validity caps, and revocation/disabled-inventory checks.
The CSR signature proves possession; an authenticated operator must separately
approve inventory and authorize the exact CSR. Recovery uses a new operator grant.

`admin.py` adds OWSEC-verified root access, existing provisioning inventory
binding and actor-attributed audit records. `service.py` exposes separate bounded
loopback administration and real-TLS enrollment test adapters. Peer certificates
come from the TLS socket. No trust is placed in forwarded certificate headers.
There is no production startup command or public binding. Revocation controls
remain unavailable in administration until gateway enforcement exists.

Run `python3 -B -m unittest -v test_issuer test_admin test_service` with
cryptography 50.0.1 or compatible. Sixteen distinct tests pass locally including
real loopback TLS bootstrap, client renewal and dual-root migration. The rollover
fixture uses same-name authorities with explicit SKI/AKI binding and verifies
old-only trust rejection and old-client/new-issuer reissuance. Loopback listeners require host
network permission in sandboxed environments.
Fixtures create disposable synthetic twenty-year roots. Tests do not access APs,
existing trust, private production issuers, cloud databases or gateway sessions.

Outstanding integration gates:

- Production service loading, protected deployment, portal routing, rate-limit
  fleet tuning, audit retention and deployment recovery. The tested adapters
  do not establish production service readiness or EST conformance.
- Gateway admission before side effects, fresh serial/leaf/session acceptance,
  authenticated revocation distribution and current-session disconnection.
- AP key/CSR generation during authenticated installation, durable generation
  staging/rollback, hostname-verified DHCP224-first/private-default discovery.
- Provisioning portal lifecycle screens and existing inventory/config integration.
- Offline production twenty-year root named exactly **Shine Systems CA**, separate renewable device issuer,
  backups and overlap with existing test CA; retire old trust only after every AP
  has migrated with current certificate and fresh gateway proof recorded.
- Scoped recoverable E410 issuance, reboot retention, renewal, revocation/recovery.

The test core deliberately has no public listener and no deploy activation.
Revocation currently blocks issuer renewal only; gateway enforcement is pending.
No production certificate replacement or end-to-end acceptance is claimed.
