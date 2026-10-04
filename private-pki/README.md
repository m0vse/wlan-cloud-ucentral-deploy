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

`policy_publisher.py` atomically publishes short-lived, versioned public leaf
pins from the private ledger. Revoked, disabled and expired identities are
excluded. A gateway must mount the directory, rather than an individual file,
to observe atomic replacement. `activation.py` consumes a short-lived challenge
only after a trusted gateway reader reports a fresh, verified session bound to
the exact serial, leaf and nonce. Challenge issuance and TLS connection alone
are insufficient. The current activation tests use a synthetic gateway reader;
`gateway_reader.py` adds a hostname-verified HTTPS gateway reader using a
protected deployment credential. Production credential provisioning, routing
and AP activation remain pending.

The protected qualification registry records reviewed manufacturing evidence and
independent OEM/stock release and runtime records. `authorization_guard.py` binds
grants to their exact versions, explicit lifecycle approval and resolved current
inventory ownership in the same transaction. Redemption, retries and activation
revalidate this binding before writes. Missing or changed evidence denies migration. OEM and stock
OpenWrt qualification are separate operations; normal authenticated renewal is
independent of migration qualification. Authoritative manufacturing evidence
uses the private portal-managed registry joined to existing provisioning
inventory, never guessed from deviceType, locale or radio country.

`fleet_gate.py` provides a read-only root retirement preview. It checks complete
count-verified paginated inventory and gateway lists, repeats the census to catch
identity changes, and includes ledger-only devices. Offline status never retires
an AP. Active identities require a current verified new-root session and recorded
renewal acceptance; explicitly retired identities must retain the same record and
ownership and have confirmed gateway disconnection. This preview does not remove
trust or replace the final deployment gate.

Run `python3 -B -m unittest -v test_issuer test_admin test_service test_policy_publisher test_activation test_gateway_reader test_offline_ca test_qualification_registry test_ownership test_lifecycle test_legacy_import test_authorization_guard test_fleet_gate` with
cryptography 50.0.1 or compatible. Thirty-nine distinct tests pass locally including
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
- Root retirement requires complete fleet reconciliation and fresh management
  acceptance, with explicit individual retirement for removed devices. The real
  twenty-year **Shine Systems CA** and separate five-year device issuer were
  created; encrypted root backups were handed off and temporary online root
  exports removed. Production AP trust and identity migration remain pending.
- Scoped recoverable E410 issuance, reboot retention, renewal, revocation/recovery.

The test core deliberately has no public listener and no deploy activation.
The actual gateway admission, revocation and dual-root session tests pass in an
isolated container; production gateway enforcement and AP activation are pending.
No production certificate replacement or end-to-end acceptance is claimed.
