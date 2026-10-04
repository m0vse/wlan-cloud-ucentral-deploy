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


class ApiError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


def fetch(service, path, authorization):
    request = urllib.request.Request(
        f"{ORIGIN}:{PORTS[service]}/api/v1/{path}",
        headers={"Authorization": authorization, "Accept": "application/json"},
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
    if not re.fullmatch(r"Bearer [A-Za-z0-9._~+/-]+=*", authorization or ""):
        raise ApiError(401, "Sign in required")
    user = fetch("sec", "oauth2?me=true", authorization)
    if user.get("userRole") != "root" or user.get("suspended") or user.get("blackListed"):
        raise ApiError(403, "Root access required")


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


def associations(state):
    radios = state.get("radios") or []
    result = {}
    for interface in state.get("interfaces") or []:
        addresses = {str(c.get("mac", "")).lower(): c for c in interface.get("clients") or []}
        for ssid in interface.get("ssids") or []:
            radio = next((r for r in radios if ssid.get("phy") and r.get("phy") == ssid["phy"]), {})
            if not radio:
                reference = str((ssid.get("radio") or {}).get("$ref", ""))
                match = re.search(r"/(\d+)$", reference)
                if match and int(match[1]) < len(radios):
                    radio = radios[int(match[1])]
            band = operating_band(radio)
            for client in ssid.get("associations") or []:
                mac = str(client.get("station", "")).lower()
                if not mac:
                    continue
                bssid = str(ssid.get("bssid") or client.get("bssid") or ssid.get("iface") or "")
                ipv4 = client_addresses(client, addresses.get(mac, {}), 4)
                ipv6 = client_addresses(client, addresses.get(mac, {}), 6)
                ip = ", ".join(ipv4 + ipv6)
                result[(mac, bssid)] = {
                    "mac": mac, "bssid": bssid, "ssid": ssid.get("ssid", ""),
                    "band": band, "channel": radio.get("channel"), "ip": ip,
                    "ipv4Addresses": ipv4, "ipv6Addresses": ipv6,
                    "signal": number(client.get("rssi")),
                    "rxRate": number((client.get("rx_rate") or {}).get("bitrate")),
                    "txRate": number((client.get("tx_rate") or {}).get("bitrate")),
                    "connectedSeconds": number(client.get("connected")),
                }
    return result


def sessions(samples, metadata):
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
        current = associations(state)
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


def device_rows(device, authorization, historic):
    serial = str(device.get("serialNumber", ""))
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", serial):
        return [], None, "Invalid AP serial"
    partial = []
    try:
        inventory = fetch("prov", f"inventory/{serial}?withExtendedInfo=true", authorization)
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
        samples = fetch("gw", f"device/{serial}/statistics?newest=true&limit={HISTORY_SAMPLES if historic else 1}", authorization).get("data")
        if not isinstance(samples, list):
            raise ApiError(502, "Invalid statistics response")
        rows = sessions(samples, metadata)
        if not samples:
            partial.append("No association report")
        return rows, metadata, "; ".join(partial)
    except (ApiError, ValueError, TypeError):
        return [], metadata, "Association reports unavailable"


def collect(authorization, params):
    require_root(authorization)  # Must precede ALL inventory/statistics access.
    historic = params.get("historic", ["false"])[0] == "true"
    devices = get_devices(authorization)
    rows, aps, errors = [], [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        for result in pool.map(lambda device: device_rows(device, authorization, historic), devices):
            values, ap, error = result
            rows.extend(values)
            if ap:
                aps.append(ap)
            if error:
                errors.append({"apSerial": (ap or {}).get("apSerial", ""), "message": error})
    for field, param in [("entityId", "entity"), ("venueId", "venue"), ("apSerial", "ap"), ("band", "band")]:
        value = params.get(param, [""])[0]
        if value:
            rows = [row for row in rows if row[field] == value]
    if not historic:
        rows = [row for row in rows if row["endTime"] is None]
    return {"rows": rows, "aps": aps, "errors": errors, "generatedAt": int(time.time()),
            "historySamples": HISTORY_SAMPLES if historic else 1}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # Do not log headers, tokens, query strings or private client data.

    def do_GET(self):
        path = urllib.parse.urlsplit(self.path)
        try:
            if path.path == "/healthz":
                return self.respond(200, {"status": "ok"})
            if path.path != "/clients-api/associations":
                raise ApiError(404, "Not found")
            data = collect(self.headers.get("Authorization"), urllib.parse.parse_qs(path.query))
            self.respond(200, data)
        except ApiError as error:
            self.respond(error.status if error.status in (401, 403, 404) else 502, {"error": error.message})
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
