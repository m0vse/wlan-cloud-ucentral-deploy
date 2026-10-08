# Native OpenWiFi certificate enrollment and renewal

The provisioning portal validates the existing OWSEC Root session on every
management request; no human session token is stored. APs use standard EST,
PKCS10 and PKCS7. Renewal authenticates the actual TLS client certificate.
Forwarded certificate headers are not accepted. The service loads only the
protected device issuer key/certificate and public root, never a root private key.

The production root has twenty-year validity and a separate renewable five-year
issuer. Tested encrypted root recovery and issuer renewal are documented in
OFFLINE-CA-RUNBOOK.md. Existing CA trust remains installed while APs migrate;
offline status never implies retirement.

## One enrollment key per batch

Use the existing inventory CSV import or select pending APs, create one key,
and reuse that key in the appropriate qualified local migration installer.
There is no operator countdown or per-AP key generation. Every AP generates its
own private key and CSR locally. Keys stay out of firmware, Git, URLs and logs.

Root portal API endpoints:

- POST /api/v1/pki/create-enrollment-key: serials array and operation `migration`
  or `new-openwifi-enrollment`; returns id, enrollmentKey, devices and server.
- POST /api/v1/pki/rotate-enrollment-key: id; replaces the shared bootstrap key.
- POST /api/v1/pki/cancel-enrollment-key: id; disables bootstrap/retries for that
  batch, without disabling issued certificates or their normal mTLS renewal.
- POST /api/v1/pki/renew or move-ca: serial; invokes existing native gateway
  reenroll. Durable progress follows verified native session metadata. An
  ambiguous command timeout is checked, not automatically resubmitted.

Certificate references are full SHA256 fingerprints, separate from AP serials.
Native gateway observation matches verified serial, issuer, expiry and session;
it does not claim that the gateway exposes a DER certificate fingerprint.

Campaign membership binds approved inventory ownership and immutable signed CSR
contents. Safe retries return the same leaf, including regenerated ECDSA
signatures. An active approved batch key authorizes native enrollment for its
members without manufacturing or source-qualification records. Ownership,
enabled inventory, signed CSR identity and first-key binding remain enforced.
Installer model, image, slot, storage and backup checks remain separate from
certificate admission. Historical qualification metadata is retained without
blocking safe certificate retries. A shared enrollment key is neither firmware
authorization nor a Root API credential.

## Native AP interface

The deployment EST listener exposes /.well-known/est/cacerts, simpleenroll and
simplereenroll. Bootstrap uses Basic canonicalSerial:sharedKey; renewal uses the
AP certificate/key. The actual AP native EST client handles both.

Root-owned /certificates/est.json contains server and tls_ca. Root600
/certificates/est-bootstrap.conf contains curl Basic credentials, without shell
evaluation or a password in arguments. Native mount_certs runs before reading
these settings; normal overlay boots may not have mounted that volume yet.

Runtime identity is /etc/ucentral/operational.pem, client issuer trust is
operational.ca, and durable copies live under /certificates. Renewal validates
subject, unique local key, expiry, client purpose and issuer chain before atomic
replacement. Gateway SERVER trust is independent: an approved public endpoint
can use the shipped system CA bundle; a private endpoint needs separately
approved trust. Hostname validation stays enabled. Native cloud discovery owns
expiry scheduling and reconnection; there is no separate renewal worker or
activation nonce handshake.

The unused per-AP installer-key implementation is removed. Historical isolated
policy/activation test modules are not enabled by portal_runtime and are not a
production protocol or a migration prerequisite. Useful generic qualification,
cryptography and recovery coverage remains available.

## Verification and migration gate

Run python3 -B -m unittest discover -q in this directory with cryptography50 or
compatible and loopback network permission. Tests cover real TLS EST, one shared
key with100 unique AP keys/certificates, concurrent binding, retry, rotation,
cancellation, independent source qualification, native commands and offline CA
recovery. Test authorities are disposable; tests do not read production keys.

The reserved E410 passed actual old-CA to new-CA renewal, subsequent renewal,
failed-service identity preservation, reboot persistence, automatic certificate
volume mounting after reboot, gateway authentication and resumed health100.
The original unique AP key was unchanged. Initial client parsing/validation and
persistence also passed an isolated on-AP ucode fixture with synthetic transport
responses; this is not a flashed migration proof.

Full OEM/stock migration handoff remains unfinished. The stock bridge requires
an empty shared certificate store, so pre-staging native enrollment there before
the writer is invalid. Family owners must qualify installer-created identity
handoff across sysupgrade -n, preserving no-old-config policy, active rollback
bank and existing bank-health checks. Local completion uses a fresh sole native
client, validated intended identity and newly received/applied configuration
from that session; stale connected/config data is insufficient. Portal gateway
corroboration remains independent and requires no installer Root credential.
Firmware builds remain held until that handoff is tested. A real signed-in Root
portal renewal click is a separate user verification step.
