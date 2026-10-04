# Offline root creation, recovery and issuing CA renewal

The intended root is **Shine Systems CA**, valid for twenty calendar years.
The helper tests use disposable synthetic material. Real root creation and its
temporary transfer locations are tracked in the private operational handover.
The old Test CA, its directory, certificates
and gateway trust remain in place throughout migration.

Before real creation, the operator must select the primary offline/removable
storage and a separate offline backup destination. Keep a recovery secret on
separate storage; never enter it into a chat, Git repository, controller
configuration, container image or command-line argument. The recovery secret
file must be owner-only and contain at least 32 URL-safe characters without
whitespace. Random binary passwords do not interoperate with OpenSSL's
line-oriented password-file reader. The root ceremony runs
on an offline trusted machine. Verify its clock before signing.

`offline_ca.py` is an offline helper, separate from the issuer service. It creates
an RSA4096 self-signed CA with exactly the approved name and twenty-year validity,
certificate-signing key usage, a single issuing-CA level and SKI/AKI identifiers.
It writes only an encrypted PKCS8 root key, public certificate and backup
manifest into a new owner-only directory. The root key is never written in
plaintext. Existing destinations cannot be overwritten. The recovery secret
is read from a protected file and never printed.

Copy the encrypted key, public certificate and manifest to the separate backup
while still offline. Independently record the root certificate fingerprint.
Recover from that backup, using the separately held secret and independently
recorded fingerprint; validate checksums, root signature, validity and matching
public key. Prove recovery by signing a disposable issuing-CA CSR and verifying
its signature and constraints. Confirm a successful recovery before accepting
the production root. Unmount and remove root and recovery-secret storage after
the ceremony. Export only the public root certificate to the online system.

The online device issuing CA uses a separate protected key. Generate that key
in the dedicated issuer's private runtime secret storage; export only its CSR
to the offline signing machine. Its exact name is **Shine Systems Device Issuing
CA**. The helper accepts a valid RSA3072–4096 or P-384 request, replaces requested
extensions with CA constraints, and signs a five-year certificate capped by the
root expiry. It refuses another issuer when the root has less than a year left.
Transfer only the signed issuer certificate and public root back online. The
root private key and its encrypted backup stay offline.

Renew the issuing CA before expiry with a fresh issuing key and CSR. Recover
the same root offline, sign the new issuer and verify its root binding. Install
the new issuer as the active signer while retaining old issuer certificates
and trust for existing clients. AP certificates remain independently renewable;
they do not inherit twenty-year validity. The issuer tests exercise authenticated
client renewal, persisted retries and old-client renewal under a new authority.
The offline tests exercise backup recovery and two fresh issuing keys under the
same root. Existing leaf and issuer trust must overlap during either change.

Root rollover is a separate operation: distribute both public roots, renew APs,
and record fresh gateway acceptance and renewal for each AP. Reconcile the full
paginated provisioning inventory across all entities/venues with gateway device
and session records. Include offline deployed APs; offline status is never
retirement. Any exclusion must be an explicit individual human retirement.
Remove old trust only after the reviewed complete fleet gate passes. Keep the
old root, certificates and rollback configuration until that gate is satisfied.

The production root and device issuer were created after tested recovery. The
user confirmed two independent cloud backup copies and removed the temporary
server exports; server-side absence was verified. The root recovery secret is
not a service credential. Production deployment still requires dedicated online
service credentials, portal controls,
complete fleet evidence and scoped AP activation/reboot/rollback verification.
No real root creation, old trust removal or online root-key storage is authorized
by running the synthetic tests.
