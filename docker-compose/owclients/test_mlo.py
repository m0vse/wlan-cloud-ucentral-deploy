import unittest
from unittest.mock import patch
import server


def sample(recorded, clients, partial=False):
    state = {"radios": [{"phy": "phy0", "band": ["6G"], "channel": 37}]}
    if not partial:
        state["interfaces"] = [{"clients": [{"mac": "aa:bb", "ipv4_addresses": ["192.0.2.1"]}],
                                "ssids": [{"ssid": "Test", "phy": "phy0", "bssid": "aa:cc", "associations": clients}]}]
    return {"recorded": recorded, "data": state}


class ClientsTests(unittest.TestCase):
    def mlo_client(self):
        return {"station": "02:00:00:00:10:00", "authorized": True, "connected": 20,
                "mlo": {"mld_address": "02:00:00:00:10:00", "counters_scope": "mld", "links": [
                    {"link_id": 0, "address": "02:00:00:00:11:00", "bssid": "02:00:00:00:21:00", "frequency": 5765, "channel": 153},
                    {"link_id": 1, "address": "02:00:00:00:12:00", "bssid": "02:00:00:00:22:00", "frequency": 6135, "channel": 37}]}}

    def test_negotiated_mlo_single_peer_and_link_details(self):
        client = self.mlo_client()
        state = sample(100, [client])["data"]
        ssid = state["interfaces"][0]["ssids"][0]
        state["interfaces"][0]["ssids"].append(dict(ssid, bssid="02:00:00:00:22:00"))
        rows = server.sessions([{"recorded": 100, "data": state}], {"apSerial": "test"})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["band"], "MLO")
        self.assertIsNone(rows[0]["channel"])
        self.assertEqual([link["band"] for link in rows[0]["mlo"]["links"]], ["5G", "6G"])
        self.assertEqual(rows[0]["startTime"], 80)

    def test_ap_mlo_capability_does_not_label_ordinary_client(self):
        state = sample(100, [{"station": "aa:bb"}])["data"]
        state["radios"][0]["mlo_links"] = [{"link_id": 0}, {"link_id": 1}]
        row = next(iter(server.associations(state).values()))
        self.assertEqual(row["band"], "6G")
        self.assertNotIn("mlo", row)

    def test_invalid_mlo_metadata_falls_back_without_losing_client(self):
        import copy
        for mutate in (lambda m: m.update(mld_address="02:00:00:00:00:01"),
                       lambda m: m.update(counters_scope="link"),
                       lambda m: m.update(links=m["links"][:1]),
                       lambda m: m["links"][1].update(link_id=0),
                       lambda m: m["links"][1].update(address=m["links"][0]["address"]),
                       lambda m: m["links"][1].update(frequency=None),
                       lambda m: m["links"][1].update(bssid="bad"),
                       lambda m: m["links"][1].update(link_id=True)):
            client = copy.deepcopy(self.mlo_client())
            mutate(client["mlo"])
            row = next(iter(server.associations(sample(100, [client])["data"]).values()))
            self.assertEqual(row["band"], "6G")
            self.assertNotIn("mlo", row)

    def test_mlo_link_change_does_not_invent_reassociation(self):
        import copy
        client = self.mlo_client()
        next_client = copy.deepcopy(client)
        next_client["connected"] = 30
        next_client["mlo"]["links"][1]["frequency"] = 6275
        rows = server.sessions([sample(100, [client]), sample(110, [next_client])], {"apSerial": "test"})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["mlo"]["links"][1]["frequency"], 6275)
        self.assertEqual(rows[0]["lastSeen"], 110)

    def test_mlo_signal_uses_real_average_not_zero_or_ack_signal(self):
        client = self.mlo_client()
        client.update(rssi=0, rssi_avg=-49, ack_signal=-46)
        row = next(iter(server.associations(sample(100, [client])["data"]).values()))
        self.assertEqual(row["signal"], -49)
        self.assertEqual(row["signalSource"], "average")
        for average in (None, 0, False, "-49", -200):
            client["rssi_avg"] = average
            row = next(iter(server.associations(sample(100, [client])["data"]).values()))
            self.assertIsNone(row["signal"])
        client.update(rssi=-55, rssi_avg=-49)
        row = next(iter(server.associations(sample(100, [client])["data"]).values()))
        self.assertEqual(row["signal"], -55)
        self.assertNotIn("signalSource", row)
        client.pop("mlo")
        client["rssi"] = 0
        row = next(iter(server.associations(sample(100, [client])["data"]).values()))
        self.assertEqual(row["signal"], 0, "ordinary/older client reporting unchanged")
        self.assertNotIn("signalSource", row)

    def test_authentication_precedes_any_data_access(self):
        for value in (None, "", "Basic abc", "Bearer bad\nheader"):
            with patch.object(server, "fetch") as fetch:
                with self.assertRaises(server.ApiError) as error:
                    server.collect(value, {})
                self.assertEqual(error.exception.status, 401)
                fetch.assert_not_called()

    def test_nonroot_and_suspended_users_denied(self):
        for user in ({"userRole": "admin"}, {"userRole": "root", "suspended": True}, {"userRole": "root", "blackListed": True}, {}):
            with patch.object(server, "fetch", return_value=user) as fetch:
                with self.assertRaises(server.ApiError) as error:
                    server.collect("Bearer test", {})
                self.assertEqual(error.exception.status, 403)
                self.assertEqual(fetch.call_count, 1)
                self.assertEqual(fetch.call_args.args[:2], ("sec", "oauth2?me=true"))

    def test_security_failure_fails_closed(self):
        with patch.object(server, "fetch", side_effect=server.ApiError(502, "Unavailable")), patch.object(server, "get_devices") as devices:
            with self.assertRaises(server.ApiError):
                server.collect("Bearer test", {})
            devices.assert_not_called()

    def test_current_client_and_phy_band(self):
        rows = server.sessions([sample(100, [{"station": "AA:BB", "connected": 20, "rssi": -55}])], {"apSerial": "test"})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["band"], "6G")
        self.assertEqual(rows[0]["ip"], "192.0.2.1")
        self.assertEqual(rows[0]["startTime"], 80)
        self.assertIsNone(rows[0]["endTime"])

    def test_observed_end_and_reassociation_are_separate_rows(self):
        samples = [sample(100, [{"station": "aa:bb", "connected": 20}]), sample(110, []), sample(120, [{"station": "aa:bb", "connected": 5}])]
        rows = server.sessions(samples[::-1], {"apSerial": "test"})
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["endTime"], 110)
        self.assertIsNone(rows[1]["endTime"])
        self.assertNotEqual(rows[0]["id"], rows[1]["id"])

    def test_duration_reset_starts_new_association(self):
        rows = server.sessions([sample(100, [{"station": "aa:bb", "connected": 20}]), sample(110, [{"station": "aa:bb", "connected": 3}])], {"apSerial": "test"})
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["endTime"], 110)

    def test_partial_report_does_not_end_client(self):
        rows = server.sessions([sample(100, [{"station": "aa:bb"}]), sample(110, [], partial=True)], {"apSerial": "test"})
        self.assertIsNone(rows[0]["endTime"])

    def test_radio_reference_and_duplicate_mac_on_distinct_bssids(self):
        data = sample(100, [{"station": "aa:bb"}])["data"]
        ssid = data["interfaces"][0]["ssids"][0]
        ssid.pop("phy")
        ssid["radio"] = {"$ref": "#/radios/0"}
        data["interfaces"][0]["ssids"].append(dict(ssid, bssid="aa:dd"))
        rows = server.sessions([{"recorded": 100, "data": data}], {"apSerial": "test"})
        self.assertEqual(len(rows), 2)
        self.assertEqual([r["band"] for r in rows], ["6G", "6G"])

    def test_logical_radio_reference_wins_over_shared_phy(self):
        data = sample(100, [{"station": "aa:bb"}])["data"]
        data["radios"] = [{"phy": "phy1", "frequency": [5765], "channel": 153},
                          {"phy": "phy1", "frequency": [6135], "channel": 37}]
        ssid = data["interfaces"][0]["ssids"][0]
        ssid.update(phy="phy1", radio={"$ref": "#/radios/1"})
        row = next(iter(server.associations(data).values()))
        self.assertEqual((row["band"], row["channel"]), ("6G", 37))
        ssid["radio"] = {"$ref": "#/radios/99"}
        self.assertEqual(next(iter(server.associations(data).values()))["band"], "5G")

    def test_existing_operating_frequency_wins_over_multiband_capabilities(self):
        for frequency, expected in ((2462, "2G"), (5745, "5G"), (6135, "6G"), (60480, "60G")):
            self.assertEqual(server.operating_band({"frequency": [frequency], "band": ["5G", "6G"]}), expected)
        self.assertEqual(server.operating_band({"band": ["5G-upper"]}), "5G")
        self.assertEqual(server.operating_band({"band": ["5G", "6G"]}), "Unknown")

    def test_authentication_attempt_not_a_connected_client(self):
        data = sample(100, [{"station": "aa:bb", "authorized": False}])["data"]
        self.assertEqual(server.associations(data), {})
        data["interfaces"][0]["ssids"][0]["associations"][0].pop("authorized")
        self.assertEqual(len(server.associations(data)), 1, "older APs without authorization metadata still report")

    def test_existing_ipv4_ipv6_and_link_local_preference(self):
        data = sample(100, [{"station": "aa:bb", "ipaddr_v4": "169.254.1.2", "ipaddr_v6": "2001:db8::2"}])["data"]
        data["interfaces"][0]["clients"][0]["ipv4_addresses"] = ["169.254.5.6", "192.0.2.1"]
        row = next(iter(server.associations(data).values()))
        self.assertEqual(row["ipv4Addresses"], ["192.0.2.1"])
        self.assertEqual(row["ipv6Addresses"], ["2001:db8::2"])
        self.assertEqual(row["ip"], "192.0.2.1, 2001:db8::2")
        self.assertEqual(server.usable_addresses(["bad", "0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255", "169.254.1.2"], 4), ["169.254.1.2"])
        self.assertEqual(server.usable_addresses(["::", "::1", "ff02::1", "fe80::1", "2001:db8::2", "2001:db8::2"], 6), ["2001:db8::2"])

    def test_filters_and_default_excludes_ended(self):
        root = {"id": "synthetic-root", "userRole": "root", "suspended": False, "blackListed": False}
        rows = [{"endTime": None, "entityId": "customer", "venueId": "site", "apSerial": "test", "band": "6G"},
                {"endTime": 100, "entityId": "customer", "venueId": "site", "apSerial": "test", "band": "6G"}]
        with patch.object(server, "fetch", return_value=root), patch.object(server, "get_devices", return_value=[{}]), patch.object(server, "device_rows", return_value=(rows, {"apSerial": "test"}, "")):
            self.assertEqual(len(server.collect("Bearer test", {})["rows"]), 1)
            self.assertEqual(len(server.collect("Bearer test", {"historic": ["true"]})["rows"]), 2)
            self.assertEqual(len(server.collect("Bearer test", {"band": ["5G"]})["rows"]), 0)
            self.assertEqual(len(server.collect("Bearer test", {"entity": ["other"]})["rows"]), 0)


if __name__ == "__main__":
    unittest.main()
