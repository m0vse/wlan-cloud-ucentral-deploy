#!/usr/bin/env python3
import base64
import json
import os
import sys

source, hostname, cert_path, key_path = sys.argv[1:]
with open(source, "r", encoding="utf-8") as handle:
    store = json.load(handle)

for resolver in store.values():
    if not isinstance(resolver, dict):
        continue
    for entry in resolver.get("Certificates", []):
        if entry.get("domain", {}).get("main") != hostname:
            continue
        certificate = base64.b64decode(entry["certificate"])
        private_key = base64.b64decode(entry["key"])
        for path, content, mode in (
            (cert_path, certificate, 0o644),
            (key_path, private_key, 0o600),
        ):
            temporary = f"{path}.new"
            with open(temporary, "wb") as handle:
                handle.write(content)
            os.chmod(temporary, mode)
            os.replace(temporary, path)
        break
    else:
        continue
    break
else:
    raise SystemExit(f"No ACME certificate found for {hostname}")
