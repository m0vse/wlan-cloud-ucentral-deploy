# Clients service release checks

Use the combined permission-aware parser, not an older telemetry-only copy.
`server.py` and all three test suites are mirrored in the controller UI
repository's `clients-api` directory. Keep both copies synchronized.

Required checks before replacing a release:

- Run `python -B -m unittest -v test_server.py test_access_http.py test_mlo.py test_details.py`
  against the actual candidate image, not just a source checkout.
- Verify negotiated MLO grouping, compact link metadata, real average RSSI and
  exact logical-radio references together with scoped access and revocation.
- Compare fresh telemetry output with the previous qualified MLO parser; older
  AP and non-MLO client output must remain unchanged.
- Check runtime file/settings differences against the deployed image. Do not
  replace dependencies or permission handling while fixing the parser.

After replacing the clients container, the web proxy may retain its old Docker
address. Validate and gracefully reload that proxy without restarting the gateway:

```sh
docker exec openwifi-owgw-ui-1 nginx -t
docker exec openwifi-owgw-ui-1 nginx -s reload
```

Acceptance must use the controller browser's actual `/clients-api/associations`
URL, not only the internal service port. Check authenticated MLO output, an
unauthenticated 401, existing admin/scoped access and unchanged AP connectivity.
Do not force AP reconnects or alter their configuration to test this read-only
service. Preserve the old images and compose override for recovery.

## Client details

`GET /clients-api/client?mac=aa:bb:cc:dd:ee:ff` is read-only and uses the same
authenticated `clients.read` device scope as the association view. Scope is
checked again after collection, before joining identities or returning history.
The browser never supplies an AP allowlist or related MAC addresses.

Click a Clients row or its MAC to open Overview, Associations, Roaming and Traffic.
AP links and the existing compact MLO disclosure retain their own actions.
Only explicitly negotiated MLD/link identities are joined; randomized addresses
are not guessed. Raw JSON is available below the tabs.

History is reconstructed from up to 200 retained reports per accessible AP,
queried only when details are opened/refreshed. This adds no collector, database
migration, retention change, scan or AP command. Older records and observation
gaps can be missing. Association endings and AP transitions are observations,
not confirmed disassociation/roaming events. Traffic deltas never bridge sessions,
counter resets, missing counters, duplicate times or gaps over ten minutes.
Byte counters are AP-reported, not a second copy of per-link MLO traffic.

Run `node test-client-details.cjs` and
`node test-client-details-interactions.cjs` with the retained UI test dependencies.
The latter uses the real Clients page, row handler, modal, query and tab components
with synthetic HTTP responses, including MLO/ordinary selection and 403 clearing.
