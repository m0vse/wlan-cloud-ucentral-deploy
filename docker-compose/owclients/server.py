"""Read-only association view. Authorisation is verified by owsec on every request."""
import concurrent.futures
import ipaddress
import json
import math
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ORIGIN = os.environ.get("CONTROLLER_ORIGIN", "https://openwifi.shinesystems.co.uk")
PORTS = {"sec": 16001, "gw": 16002, "prov": 16005}
MAX_BYTES = 16 * 1024 * 1024
HISTORY_SAMPLES = 24
DETAIL_SAMPLES = 200


class ApiError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


def fetch(service, path, authorization, body=None):
    payload = None if body is None else json.dumps(body, allow_nan=False).encode()
    request = urllib.request.Request(
        f"{ORIGIN}:{PORTS[service]}/api/v1/{path}",
        data=payload,
        headers={"Authorization": authorization, "Accept": "application/json",
                 **({"Content-Type": "application/json"} if body is not None else {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            payload = response.read(MAX_BYTES + 1)
            if len(payload) > MAX_BYTES:
                raise ApiError(502, "Controller response exceeds the view limit")
            return json.loads(payload)
    except urllib.error.HTTPError as error:
        raise ApiError(error.code, "Controller request failed") from None
    except (urllib.error.URLError, TimeoutError, ValueError):
        raise ApiError(502, "Controller is unavailable") from None


def require_root(authorization):
    user = authenticated_user(authorization)
    if user.get("userRole") != "root":
        raise ApiError(403, "Root access required")


def authenticated_user(authorization):
    if not re.fullmatch(r"Bearer [A-Za-z0-9._~+/-]+=*", authorization or ""):
        raise ApiError(401, "Sign in required")
    user = fetch("sec", "oauth2?me=true", authorization)
    if not isinstance(user, dict) or user.get("suspended") is not False or user.get("blackListed") is not False:
        raise ApiError(403, "Access unavailable")
    if not isinstance(user.get("id"), str) or not user["id"] or not isinstance(user.get("userRole"), str):
        raise ApiError(403, "Access unavailable")
    return user


def client_devices(authorization, user):
    """The provisioner derives ownership; browser filters never grant access."""
    result = fetch("prov", "access/check", authorization,
                   {"userId": user["id"], "capability": "clients.read", "listDevices": True})
    if not isinstance(result, dict) or not isinstance(result.get("devices"), list):
        raise ApiError(502, "Invalid access response")
    devices, seen = [], set()
    for device in result["devices"]:
        if not isinstance(device, dict) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", str(device.get("serialNumber", ""))):
            raise ApiError(502, "Invalid access response")
        serial = device["serialNumber"]
        if serial not in seen:
            seen.add(serial)
            devices.append(device)
    if len(devices) > 10000:
        raise ApiError(502, "Device limit exceeded")
    return devices


def number(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) else None


def operating_band(radio):
    frequencies = radio.get("frequency")
    frequency = frequencies[0] if isinstance(frequencies, list) and frequencies else frequencies
    frequency = number(frequency)
    if frequency is not None:
        if 5925 <= frequency <= 7125:
            return "6G"
        if 4900 <= frequency < 5925:
            return "5G"
        if 2400 <= frequency <= 2500:
            return "2G"
        if 57000 <= frequency <= 71000:
            return "60G"
    bands = radio.get("band") or []
    if isinstance(bands, str):
        bands = [bands]
    bands = {"5G" if band.startswith("5G") else band for band in bands if isinstance(band, str) and band}
    return next(iter(bands)) if len(bands) == 1 else "Unknown"


def usable_addresses(values, version):
    """Keep observed addresses, preferring routable scope over link-local scope."""
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, list):
        return []
    parsed = []
    for value in values:
        if not isinstance(value, str):
            continue
        try:
            address = ipaddress.ip_address(value.strip())
        except ValueError:
            continue
        if address.version != version or address.is_unspecified or address.is_loopback or address.is_multicast:
            continue
        if str(address) == "255.255.255.255":
            continue
        if address not in parsed:
            parsed.append(address)
    preferred = [address for address in parsed if not address.is_link_local]
    return [str(address) for address in preferred or parsed]


def client_addresses(client, observed, version):
    direct = usable_addresses(client.get(f"ipaddr_v{version}"), version)
    fallback = usable_addresses(observed.get(f"ipv{version}_addresses"), version)
    # A stale link-local association must not conceal a usable neighbour address.
    preferred_direct = usable_addresses([v for v in direct if not ipaddress.ip_address(v).is_link_local], version)
    return preferred_direct or usable_addresses(direct + fallback, version)


def valid_mac(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value):
        return None
    value = value.lower()
    return value if value != "00:00:00:00:00:00" and not int(value[:2], 16) & 1 else None


def negotiated_mlo(client):
    """Accept negotiated peer metadata, not the AP's MLO capabilities."""
    raw = client.get("mlo")
    if not isinstance(raw, dict) or raw.get("counters_scope") != "mld":
        return None
    mld = valid_mac(raw.get("mld_address"))
    if not mld or mld != valid_mac(client.get("station")):
        return None
    links = raw.get("links")
    if not isinstance(links, list) or not 2 <= len(links) <= 16:
        return None
    result, ids, addresses = [], set(), set()
    for link in links:
        if not isinstance(link, dict):
            return None
        link_id = link.get("link_id")
        address, bssid = valid_mac(link.get("address")), valid_mac(link.get("bssid"))
        frequency = number(link.get("frequency"))
        band = operating_band({"frequency": frequency})
        if (isinstance(link_id, bool) or not isinstance(link_id, int) or not 0 <= link_id <= 15
                or link_id in ids or not address or address in addresses or not bssid
                or band not in ("2G", "5G", "6G")):
            return None
        ids.add(link_id)
        addresses.add(address)
        result.append({"linkId": link_id, "mac": address, "bssid": bssid, "frequency": frequency,
                       "band": band, "channel": number(link.get("channel"))})
    return {"mldAddress": mld, "links": sorted(result, key=lambda link: link["linkId"]), "countersScope": "mld"}


def associations(state, detailed=False):
    radios = state.get("radios") or []
    result = {}
    for interface in state.get("interfaces") or []:
        addresses = {str(c.get("mac", "")).lower(): c for c in interface.get("clients") or []}
        for ssid in interface.get("ssids") or []:
            reference = str((ssid.get("radio") or {}).get("$ref", ""))
            match = re.fullmatch(r"#?/radios/(\d+)", reference)
            radio = radios[int(match[1])] if match and int(match[1]) < len(radios) else {}
            if not radio:
                radio = next((r for r in radios if ssid.get("phy") and r.get("phy") == ssid["phy"]), {})
            band = operating_band(radio)
            for client in ssid.get("associations") or []:
                if client.get("authorized") is False:
                    continue  # Authentication attempts are not connected clients.
                mac = str(client.get("station", "")).lower()
                if not mac:
                    continue
                bssid = str(ssid.get("bssid") or client.get("bssid") or ssid.get("iface") or "")
                ipv4 = client_addresses(client, addresses.get(mac, {}), 4)
                ipv6 = client_addresses(client, addresses.get(mac, {}), 6)
                ip = ", ".join(ipv4 + ipv6)
                mlo = negotiated_mlo(client)
                key = (mlo["mldAddress"], "mlo:" + str(ssid.get("ssid", ""))) if mlo else (mac, bssid)
                row = {
                    "mac": mac, "bssid": bssid, "ssid": ssid.get("ssid", ""),
                    "band": band, "channel": radio.get("channel"), "ip": ip,
                    "ipv4Addresses": ipv4, "ipv6Addresses": ipv6,
                    "signal": number(client.get("rssi")),
                    "rxRate": number((client.get("rx_rate") or {}).get("bitrate")),
                    "txRate": number((client.get("tx_rate") or {}).get("bitrate")),
                    "connectedSeconds": number(client.get("connected")),
                }
                if detailed:
                    hostname = client.get("hostname") or addresses.get(mac, {}).get("hostname")
                    if isinstance(hostname, str) and len(hostname) <= 255:
                        row["hostname"] = hostname
                    for name in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "tx_retries", "tx_failed",
                                 "rx_drop_misc", "inactive", "snr", "rssi_avg"):
                        value = number(client.get(name))
                        if value is not None and (value >= 0 or name in ("rssi_avg", "snr")):
                            row[name] = value
                    for name in ("mode", "authentication", "encryption", "cipher"):
                        if isinstance(client.get(name), str):
                            row[name] = client[name]
                    row["flags"] = {name: client[name] for name in ("authorized", "authenticated", "associated", "wmm", "wme", "mfp", "wds", "tdls")
                                    if isinstance(client.get(name), bool)}
                    row["rates"] = {direction: {key: value for key, value in (client.get(direction) or {}).items()
                                                if key in ("bitrate", "mcs", "nss", "he_mcs", "vht_mcs", "eht_mcs", "bw", "sgi")
                                                and isinstance(value, (int, float, bool)) and
                                                (isinstance(value, bool) or number(value) is not None)}
                                    for direction in ("rx_rate", "tx_rate") if isinstance(client.get(direction), dict)}
                if mlo:
                    row.update(mlo=mlo, band="MLO", channel=None)
                    if row["signal"] in (None, 0):
                        average = number(client.get("rssi_avg"))
                        row["signal"] = average if average is not None and -127 <= average < 0 else None
                        if row["signal"] is not None:
                            row["signalSource"] = "average"
                result[key] = row
    return result


def sessions(samples, metadata, detailed=False):
    """End times are observed disappearance, not an invented disassociation timestamp."""
    active, rows = {}, []
    valid = sorted((s for s in samples if number(s.get("recorded")) is not None), key=lambda s: s["recorded"])
    for sample in valid:
        state = sample.get("data") or {}
        if isinstance(state, str):
            state = json.loads(state)
        if not isinstance(state, dict) or "interfaces" not in state:
            continue  # Partial/missing telemetry is not evidence that a client left.
        timestamp = sample["recorded"]
        current = associations(state, detailed=detailed)
        for key in list(active):
            old = active[key]
            reset = key in current and current[key]["connectedSeconds"] is not None and old["connectedSeconds"] is not None and current[key]["connectedSeconds"] < old["connectedSeconds"]
            if key not in current or reset:
                old["endTime"] = timestamp
                del active[key]
        for key, client in current.items():
            if key not in active:
                duration = client["connectedSeconds"]
                row = dict(metadata, **client, startTime=max(0, timestamp - duration) if duration is not None else None,
                           lastSeen=timestamp, endTime=None)
                row["id"] = f"{metadata['apSerial']}:{key[0]}:{key[1]}:{timestamp}"
                rows.append(row)
                active[key] = row
            else:
                active[key].update(client, lastSeen=timestamp)
            if detailed:
                # Keep per-client observations, never another station's raw report.
                row = active[key]
                row.setdefault("observations", []).append(dict(client, recorded=timestamp))
                row.setdefault("firstSeen", timestamp)
    return rows


def get_devices(authorization):
    devices = []
    for offset in range(0, 10000, 500):
        data = fetch("gw", f"devices?deviceWithStatus=true&platform=ap&limit=500&offset={offset}", authorization)
        batch = data.get("devicesWithStatus")
        if not isinstance(batch, list):
            raise ApiError(502, "Invalid device response")
        devices.extend(batch)
        if len(batch) < 500:
            return devices
    raise ApiError(502, "Device limit exceeded; narrow the deployment scope")


def device_rows(device, authorization, historic, restricted=False, detailed=False):
    serial = str(device.get("serialNumber", ""))
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", serial):
        return [], None, "Invalid AP serial"
    partial = []
    try:
        inventory = fetch("prov", f"inventory/{serial}" + ("" if restricted else "?withExtendedInfo=true"), authorization)
    except ApiError:
        inventory = {}
        partial.append("Inventory unavailable")
    extended = inventory.get("extendedInfo") or {}
    venue = extended.get("venue") or {}
    entity = extended.get("entity") or {}
    venue_id = inventory.get("venue") or device.get("venue") or venue.get("id") or ""
    entity_id = inventory.get("entity") or device.get("entity") or entity.get("id") or ""
    if venue_id and not entity_id:
        try:
            site = fetch("prov", f"venue/{urllib.parse.quote(venue_id, safe='')}", authorization)
            entity_id = site.get("entity") or ""
            venue = dict(site, name=venue.get("name") or site.get("name", ""))
        except ApiError:
            partial.append("Venue entity unavailable")
    if entity_id and not entity.get("name"):
        try:
            entity = fetch("prov", f"entity/{urllib.parse.quote(entity_id, safe='')}", authorization)
        except ApiError:
            partial.append("Entity name unavailable")
    metadata = {
        "apSerial": serial, "apName": inventory.get("name") or device.get("name") or serial,
        "apConnected": device.get("connected") is True,
        "venueId": venue_id, "venueName": venue.get("name") or venue_id or "Unassigned",
        "entityId": entity_id, "entityName": entity.get("name") or entity_id or "Unassigned",
    }
    try:
        limit = DETAIL_SAMPLES if detailed else HISTORY_SAMPLES if historic else 1
        samples = fetch("gw", f"device/{serial}/statistics?newest=true&limit={limit}", authorization).get("data")
        if not isinstance(samples, list):
            raise ApiError(502, "Invalid statistics response")
        rows = sessions(samples, metadata, detailed=detailed)
        if not samples:
            partial.append("No association report")
        return rows, metadata, "; ".join(partial)
    except (ApiError, ValueError, TypeError):
        return [], metadata, "Association reports unavailable"


def collect(authorization, params, detail_mac=None):
    user = authenticated_user(authorization)  # Before ALL inventory/statistics access.
    restricted = user["userRole"] != "root"
    historic = detail_mac is not None or params.get("historic", ["false"])[0] == "true"
    devices = client_devices(authorization, user) if restricted else get_devices(authorization)
    rows, aps, errors = [], [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        for result in pool.map(lambda device: device_rows(device, authorization, historic, restricted=restricted,
                                                        **({"detailed": True} if detail_mac else {})), devices):
            values, ap, error = result
            rows.extend(values)
            if ap:
                aps.append(ap)
            if error:
                errors.append({"apSerial": (ap or {}).get("apSerial", ""), "message": error})
    if restricted or detail_mac:
        # A request may span telemetry calls: discard data revoked while it ran.
        current = authenticated_user(authorization)
        if current["id"] != user["id"]:
            raise ApiError(403, "Access unavailable")
        allowed = {device["serialNumber"] for device in (
            devices if current["userRole"] == "root" else client_devices(authorization, current))}
        rows = [row for row in rows if row["apSerial"] in allowed]
        aps = [ap for ap in aps if ap["apSerial"] in allowed]
        errors = [error for error in errors if error["apSerial"] in allowed]
    if detail_mac:
        return client_detail(detail_mac, rows, errors)
    for field, param in [("entityId", "entity"), ("venueId", "venue"), ("apSerial", "ap"), ("band", "band")]:
        value = params.get(param, [""])[0]
        if value:
            rows = [row for row in rows if row[field] == value]
    if not historic:
        rows = [row for row in rows if row["endTime"] is None]
    return {"rows": rows, "aps": aps, "errors": errors, "generatedAt": int(time.time()),
            "historySamples": HISTORY_SAMPLES if historic else 1}


def client_detail(mac, rows, errors):
    """Join only explicitly negotiated MLD/link addresses within authorised data."""
    identities = {mac}
    def addresses(row):
        return {v for v in [valid_mac(row.get("mac")),
                           (row.get("mlo") or {}).get("mldAddress"),
                           *[link.get("mac") for link in (row.get("mlo") or {}).get("links", [])]] if v}
    # Identity sets are bounded by retained, authorised telemetry, not browser hints.
    changed = True
    while changed:
        before = len(identities)
        for row in rows:
            found = addresses(row)
            if identities & found:
                identities.update(found)
        changed = len(identities) != before
    selected = [row for row in rows if identities & addresses(row)]
    selected.sort(key=lambda row: (row.get("firstSeen", row["lastSeen"]), row["apSerial"], row["id"]))
    observations = []
    for row in selected:
        for point in row.get("observations", []):
            observations.append(dict(point, apSerial=row["apSerial"], apName=row["apName"], sessionId=row["id"]))
    observations.sort(key=lambda point: (point["recorded"], point["apSerial"]))
    # These are observed AP changes, not fabricated 802.11 roaming events.
    by_time = {}
    for point in observations:
        by_time.setdefault(point["recorded"], []).append(point)
    transitions, previous = [], None
    for timestamp, points in sorted(by_time.items()):
        if len({(p["apSerial"], p.get("bssid"), p.get("ssid")) for p in points}) != 1:
            previous = None  # Simultaneous reports cannot establish a roam order.
            continue
        point = points[0]
        if previous and previous["ssid"] == point["ssid"] and previous["apSerial"] != point["apSerial"]:
            transitions.append({"recorded": timestamp, "fromAP": previous["apName"], "toAP": point["apName"],
                                "fromSerial": previous["apSerial"], "toSerial": point["apSerial"], "inferred": True})
        previous = point
    return {"mac": mac, "addresses": sorted(identities), "sessions": selected,
            "observations": observations, "transitions": transitions, "errors": errors,
            "generatedAt": int(time.time()), "historySamples": DETAIL_SAMPLES,
            "coverage": {"from": min(by_time) if by_time else None, "to": max(by_time) if by_time else None},
            "limits": "Up to 200 retained reports per accessible AP. Gaps and older activity may be missing. End times and AP changes are inferred from reports; counters are AP-reported."}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # Do not log headers, tokens, query strings or private client data.

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path)
        try:
            if path.path == "/healthz":
                return self.respond(200, {"status": "ok"})
            if path.path == "/clients-api/client":
                params = urllib.parse.parse_qs(path.query)
                mac = valid_mac(params.get("mac", [""])[0])
                if not mac:
                    raise ApiError(400, "Valid client MAC required")
                return self.respond(200, collect(self.headers.get("Authorization"), {}, detail_mac=mac))
            if path.path != "/clients-api/associations":
                raise ApiError(404, "Not found")
            data = collect(self.headers.get("Authorization"), urllib.parse.parse_qs(path.query))
            self.respond(200, data)
        except ApiError as error:
            self.respond(error.status if error.status in (400, 401, 403, 404) else 502, {"error": error.message})
        except Exception:
            self.respond(502, {"error": "Unable to load association reports"})

    def respond(self, status, data):
        payload = json.dumps(data, allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
