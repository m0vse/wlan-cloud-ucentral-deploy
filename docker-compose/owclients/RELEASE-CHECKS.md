# Clients service release checks

Use the combined permission-aware parser, not an older telemetry-only copy.
`server.py` and all three test suites are mirrored in the controller UI
repository's `clients-api` directory. Keep both copies synchronized.

Required checks before replacing a release:

- Run `python -B -m unittest -v test_server.py test_access_http.py test_mlo.py`
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
