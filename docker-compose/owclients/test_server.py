import unittest
from unittest.mock import patch
import server


class AccessTests(unittest.TestCase):
    USER = {'id': 'scoped-user', 'userRole': 'csr', 'suspended': False, 'blackListed': False}

    def test_restricted_scope_precedes_telemetry_and_never_lists_gateway(self):
        calls = []
        def fake(service, path, auth, body=None):
            calls.append((service, path, body))
            if path == 'oauth2?me=true':
                return self.USER.copy()
            if path == 'access/check':
                self.assertEqual(body['userId'], self.USER['id'])
                self.assertEqual(body['capability'], 'clients.read')
                return {'devices': [{'serialNumber': 'ap-a'}]}
            self.fail('Unexpected data fetch')
        def telemetry(device, auth, historic, restricted=False):
            self.assertTrue(restricted)
            self.assertEqual(calls[1][1], 'access/check')
            self.assertEqual(device['serialNumber'], 'ap-a')
            return [{'apSerial': 'ap-a', 'endTime': None}], {'apSerial': 'ap-a'}, ''
        with patch.object(server, 'fetch', side_effect=fake), patch.object(server, 'device_rows', side_effect=telemetry):
            result = server.collect('Bearer test', {})
        self.assertEqual(len(result['rows']), 1)
        self.assertEqual([c[1] for c in calls], ['oauth2?me=true', 'access/check', 'oauth2?me=true', 'access/check'])

    def test_revocation_during_collection_removes_rows_metadata_and_errors(self):
        with patch.object(server, 'authenticated_user', return_value=self.USER), \
             patch.object(server, 'client_devices', side_effect=[[{'serialNumber': 'ap-a'}], []]), \
             patch.object(server, 'device_rows', return_value=([{'apSerial': 'ap-a', 'endTime': None}], {'apSerial': 'ap-a'}, 'private failure')):
            result = server.collect('Bearer test', {})
        for field in ('rows', 'aps', 'errors'):
            self.assertEqual(result[field], [])

    def test_denial_precedes_all_inventory(self):
        for mutation in ({'suspended': True}, {'blackListed': True}, {'suspended': 'false'}, {'id': ''}):
            with patch.object(server, 'fetch', return_value=dict(self.USER, **mutation)) as fetch, \
                 patch.object(server, 'device_rows') as telemetry:
                with self.assertRaises(server.ApiError):
                    server.collect('Bearer test', {})
                self.assertEqual(fetch.call_count, 1)
                telemetry.assert_not_called()

    def test_malformed_snapshot_fails_closed(self):
        for response in ({}, {'devices': None}, {'devices': [{'serialNumber': '../escape'}]}, {'devices': [None]}):
            with patch.object(server, 'fetch', return_value=response):
                with self.assertRaises(server.ApiError):
                    server.client_devices('Bearer test', self.USER)

    def test_root_path_preserves_existing_global_view(self):
        root = dict(self.USER, userRole='root')
        with patch.object(server, 'authenticated_user', return_value=root), \
             patch.object(server, 'get_devices', return_value=[]) as devices, \
             patch.object(server, 'client_devices') as scoped:
            server.collect('Bearer test', {})
        devices.assert_called_once_with('Bearer test')
        scoped.assert_not_called()


class OperatingBandTests(unittest.TestCase):
    def test_live_frequency_precedes_capabilities(self):
        for frequency, expected in [(6155, '6G'), (6415, '6G'), (5935, '6G'),
                                    (5580, '5G'), (2412, '2G'), (60480, '60G')]:
            self.assertEqual(server.operating_band({'frequency': [frequency], 'band': ['5G', '6G']}), expected)

    def test_fallback_is_not_ambiguous(self):
        self.assertEqual(server.operating_band({'band': ['5G', '6G']}), 'Unknown')
        self.assertEqual(server.operating_band({'channel': 41}), 'Unknown')
        self.assertEqual(server.operating_band({'band': ['5G-lower']}), '5G')
        self.assertEqual(server.operating_band({'band': '2G'}), '2G')
        self.assertEqual(server.operating_band({'frequency': [float('nan')], 'band': ['6G']}), '6G')

    def test_actual_client_association_mapping(self):
        state = {
            'radios': [{'phy': 'switchable', 'channel': 41, 'frequency': [6155, 6145], 'band': ['5G', '6G']}],
            'interfaces': [{'ssids': [{'phy': 'switchable', 'ssid': 'Phil 6Ghz', 'bssid': 'test-bssid',
                                      'associations': [{'station': '00:11:22:33:44:55'}]}]}],
        }
        row = next(iter(server.associations(state).values()))
        self.assertEqual(row['band'], '6G')
        self.assertEqual(row['channel'], 41)
        state['interfaces'][0]['ssids'][0].pop('phy')
        state['interfaces'][0]['ssids'][0]['radio'] = {'$ref': '/radios/0'}
        self.assertEqual(next(iter(server.associations(state).values()))['band'], '6G')

    def test_authorization_still_required(self):
        with self.assertRaises(server.ApiError) as error:
            server.require_root(None)
        self.assertEqual(error.exception.status, 401)

    def test_nest_link_local_history_is_filtered(self):
        values = ['169.254.107.20', '169.254.10.252', '169.254.183.127',
                  '169.254.196.16', '169.254.40.89', '192.168.99.119']
        self.assertEqual(server.client_addresses({}, {'ipv4_addresses': values}, 4), ['192.168.99.119'])

    def test_dual_stack_and_address_validation(self):
        observed = {'ipv4_addresses': ['192.168.99.119'],
                    'ipv6_addresses': ['fe80::1', 'fd00::123', 'fd00::0123', '2001:db8::2']}
        self.assertEqual(server.client_addresses({}, observed, 6), ['fd00::123', '2001:db8::2'])
        self.assertEqual(server.usable_addresses(['bad', None, '::', '::1', 'ff02::1', '192.168.1.1'], 6), [])
        self.assertEqual(server.usable_addresses(['0.0.0.0', '127.0.0.1', '224.0.0.1', '255.255.255.255'], 4), [])

    def test_direct_address_precedence_and_link_local_fallback(self):
        observed = {'ipv4_addresses': ['192.168.99.119'], 'ipv6_addresses': ['fe80::1']}
        self.assertEqual(server.client_addresses({'ipaddr_v4': '192.168.99.120'}, observed, 4), ['192.168.99.120'])
        self.assertEqual(server.client_addresses({'ipaddr_v4': '169.254.1.1'}, observed, 4), ['192.168.99.119'])
        self.assertEqual(server.client_addresses({}, observed, 6), ['fe80::1'])

    def test_association_exports_both_versions(self):
        state = {'interfaces': [{'clients': [{'mac': '18:b4:30:13:af:e9',
                 'ipv4_addresses': ['169.254.1.1', '192.168.99.119'], 'ipv6_addresses': ['fd00::123']}],
                 'ssids': [{'associations': [{'station': '18:b4:30:13:af:e9'}]}]}]}
        row = next(iter(server.associations(state).values()))
        self.assertEqual(row['ipv4Addresses'], ['192.168.99.119'])
        self.assertEqual(row['ipv6Addresses'], ['fd00::123'])
        self.assertEqual(row['ip'], '192.168.99.119, fd00::123')

    def test_unauthorized_stations_are_not_connected_clients(self):
        clients = [{'station': 'failed', 'authorized': False},
                   {'station': 'connected', 'authorized': True}, {'station': 'legacy'}]
        state = {'interfaces': [{'ssids': [{'associations': clients}]}]}
        self.assertEqual({row['mac'] for row in server.associations(state).values()}, {'connected', 'legacy'})


if __name__ == '__main__':
    unittest.main()
