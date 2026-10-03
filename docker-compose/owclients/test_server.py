import unittest
import server


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


if __name__ == '__main__':
    unittest.main()
