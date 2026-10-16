import json
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch
import server
from test_access_http import ClientHttpTests, Peer

MAC = '00:11:22:33:44:55'
META = {'apSerial': 'ap-a', 'apName': 'AP A', 'apConnected': True}


def sample(timestamp, clients):
    return {'recorded': timestamp, 'data': {'interfaces': [{'ssids': [
        {'ssid': 'Test', 'bssid': '00:11:22:aa:bb:cc', 'associations': clients}]}]}}


class DetailTests(unittest.TestCase):
    def test_observations_and_private_fields(self):
        values = [sample(100, [{'station': MAC, 'connected': 20, 'rx_bytes': 100, 'tx_bytes': 200, 'password': 'never'}]),
                  sample(110, [{'station': MAC, 'connected': 30, 'rx_bytes': 120}]), sample(120, [])]
        rows = server.sessions(values, META, detailed=True)
        d = server.client_detail(MAC, rows, [])
        self.assertEqual(d['sessions'][0]['startTime'], 80)
        self.assertEqual(d['sessions'][0]['endTime'], 120)
        self.assertEqual([p['recorded'] for p in d['observations']], [100, 110])
        self.assertEqual(d['observations'][0]['rx_bytes'], 100)
        self.assertNotIn('never', json.dumps(d))
        self.assertEqual(d['coverage'], {'from': 100, 'to': 110})

    def test_only_explicit_mlo_identity_aliases(self):
        from test_mlo import ClientsTests
        client = ClientsTests().mlo_client()
        rows = server.sessions([sample(100, [client, {'station': MAC}])], META, detailed=True)
        alias = client['mlo']['links'][0]['address']
        d = server.client_detail(alias, rows, [])
        self.assertEqual(len(d['sessions']), 1)
        self.assertIn(client['station'], d['addresses'])
        self.assertNotIn(MAC, d['addresses'])
        self.assertEqual(server.client_detail('00:11:22:33:44:66', rows, [])['sessions'], [])

    def test_observed_ap_change_not_same_ap_band_change(self):
        a = server.sessions([sample(100, [{'station': MAC}])], META, detailed=True)
        b = server.sessions([sample(110, [{'station': MAC}])], dict(META, apSerial='ap-b', apName='AP B'), detailed=True)
        d = server.client_detail(MAC, a+b, [])
        self.assertEqual(len(d['transitions']), 1)
        self.assertTrue(d['transitions'][0]['inferred'])
        self.assertEqual(server.client_detail(MAC, a+a, [])['transitions'], [])

    def test_simultaneous_ap_reports_do_not_invent_roam_order(self):
        a = server.sessions([sample(100, [{'station': MAC}])], META, detailed=True)
        b = server.sessions([sample(100, [{'station': MAC}])], dict(META, apSerial='ap-b'), detailed=True)
        self.assertEqual(server.client_detail(MAC, a+b, [])['transitions'], [])

    def test_revocation_before_identity_join(self):
        user = {'id': 'test', 'userRole': 'csr'}
        rows = server.sessions([sample(100, [{'station': MAC}])], META, detailed=True)
        with patch.object(server, 'authenticated_user', return_value=user), \
             patch.object(server, 'client_devices', side_effect=[[{'serialNumber': 'ap-a'}], []]), \
             patch.object(server, 'device_rows', return_value=(rows, META, '')):
            d = server.collect('Bearer synthetic', {}, detail_mac=MAC)
        self.assertEqual(d['sessions'], [])
        self.assertEqual(d['observations'], [])
        self.assertEqual(d['transitions'], [])

    def test_negative_and_invalid_counters_excluded(self):
        row = next(iter(server.associations(sample(100, [{'station': MAC, 'rx_bytes': float('nan'),
                                                        'tx_bytes': True}])['data'], detailed=True).values()))
        self.assertNotIn('rx_bytes', row)
        self.assertNotIn('tx_bytes', row)

    def test_hostname_flags_and_rate_allowlist(self):
        row = next(iter(server.associations(sample(100, [{'station': MAC, 'hostname': 'Test phone',
            'rx_bytes': -1, 'rssi_avg': -50, 'authorized': True,
            'rx_rate': {'bitrate': 900, 'mcs': 9, 'secret': 'never'}}])['data'], detailed=True).values()))
        self.assertEqual(row['hostname'], 'Test phone')
        self.assertEqual(row['flags'], {'authorized': True})
        self.assertEqual(row['rates']['rx_rate'], {'bitrate': 900, 'mcs': 9})
        self.assertNotIn('rx_bytes', row)
        self.assertEqual(row['rssi_avg'], -50)


class DetailsHttpTests(ClientHttpTests):
    def detail_request(self, mac=MAC, auth='Bearer synthetic'):
        req = urllib.request.Request(f'http://127.0.0.1:{self.client.server_port}/clients-api/client?mac={mac}',
                                     headers={} if auth is None else {'Authorization': auth})
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.load(r)

    def test_detail_http_scoped_real_handler(self):
        d = self.detail_request()
        self.assertEqual(d['mac'], MAC)
        self.assertEqual(len(d['sessions']), 1)
        self.assertEqual(d['historySamples'], 200)
        self.assertTrue(any('limit=200' in path for path, _ in Peer.calls))
        self.assertFalse(any(path.startswith('/api/v1/devices?') for path, _ in Peer.calls))

    def test_detail_no_auth_before_controller_data(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.detail_request(auth=None)
        self.assertEqual(ctx.exception.code, 401)
        self.assertEqual(Peer.calls, [])

    def test_detail_invalid_mac_and_revoked_scope(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.detail_request(mac='not-a-mac')
        self.assertEqual(ctx.exception.code, 400)
        self.peer.revoke_after_statistics = True
        self.assertEqual(self.detail_request()['sessions'], [])


if __name__ == '__main__':
    unittest.main()
