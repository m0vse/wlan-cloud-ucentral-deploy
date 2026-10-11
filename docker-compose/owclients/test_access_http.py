"""HTTP integration using synthetic controller peers, never live APs/users."""
import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import server


class Peer(BaseHTTPRequestHandler):
    calls = []
    revoked = False
    role = 'csr'

    def log_message(self, *_):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.calls.append((self.path, body))
        if body != {'userId': 'synthetic-user', 'capability': 'clients.read', 'listDevices': True}:
            return self.reply(403, {})
        self.reply(200, {'devices': [] if self.revoked else [{'serialNumber': 'ap-a'}], 'policyRevision': 1})

    def do_GET(self):
        self.calls.append((self.path, None))
        if self.headers.get('Authorization') != 'Bearer synthetic':
            return self.reply(401, {})
        path = self.path.removeprefix('/api/v1/')
        if path == 'oauth2?me=true':
            return self.reply(200, {'id': 'synthetic-user', 'userRole': self.role,
                                    'suspended': False, 'blackListed': False})
        if path.startswith('devices?'):
            return self.reply(200, {'devicesWithStatus': [{'serialNumber': 'ap-a', 'connected': True}]})
        if path in ('inventory/ap-a', 'inventory/ap-a?withExtendedInfo=true'):
            return self.reply(200, {'name': 'Synthetic AP'})
        if path.startswith('device/ap-a/statistics?'):
            self.reply(200, {'data': [{'recorded': 100, 'data': {'interfaces': [
                {'ssids': [{'associations': [{'station': '00:11:22:33:44:55', 'connected': 1}]}]}]}}]})
            if getattr(self.server, 'revoke_after_statistics', False):
                Peer.revoked = True
            return
        self.reply(404, {})

    def reply(self, status, obj):
        payload = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class ClientHttpTests(unittest.TestCase):
    def setUp(self):
        Peer.calls, Peer.revoked, Peer.role = [], False, 'csr'
        self.peer = ThreadingHTTPServer(('127.0.0.1', 0), Peer)
        self.client = ThreadingHTTPServer(('127.0.0.1', 0), server.Handler)
        for instance in (self.peer, self.client):
            threading.Thread(target=instance.serve_forever, daemon=True).start()
        self.origin = patch.object(server, 'ORIGIN', 'http://127.0.0.1')
        self.ports = patch.object(server, 'PORTS', dict.fromkeys(('sec', 'prov', 'gw'), self.peer.server_port))
        self.origin.start()
        self.ports.start()

    def tearDown(self):
        for instance in (self.client, self.peer):
            instance.shutdown()
            instance.server_close()
        self.ports.stop()
        self.origin.stop()

    def request(self, auth='Bearer synthetic'):
        request = urllib.request.Request(f'http://127.0.0.1:{self.client.server_port}/clients-api/associations',
                                         headers={} if auth is None else {'Authorization': auth})
        with urllib.request.urlopen(request, timeout=5) as response:
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
            return json.load(response)

    def test_scoped_http_response_never_reads_global_gateway(self):
        result = self.request()
        self.assertEqual(len(result['rows']), 1)
        self.assertFalse(any(path.startswith('/api/v1/devices?') for path, _ in Peer.calls))
        self.assertIn(('/api/v1/inventory/ap-a', None), Peer.calls)
        self.assertNotIn(('/api/v1/inventory/ap-a?withExtendedInfo=true', None), Peer.calls)
        self.assertEqual(sum(path == '/api/v1/access/check' for path, _ in Peer.calls), 2)

    def test_root_http_response_keeps_original_path(self):
        Peer.role = 'root'
        self.assertEqual(len(self.request()['rows']), 1)
        self.assertTrue(any(path.startswith('/api/v1/devices?') for path, _ in Peer.calls))
        self.assertFalse(any(path == '/api/v1/access/check' for path, _ in Peer.calls))

    def test_revoked_http_result_contains_no_ap_or_clients(self):
        self.peer.revoke_after_statistics = True
        result = self.request()
        self.assertEqual(result['rows'], [])
        self.assertEqual(result['aps'], [])

    def test_no_token_does_not_contact_controller(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request(None)
        self.assertEqual(error.exception.code, 401)
        self.assertEqual(Peer.calls, [])


if __name__ == '__main__':
    unittest.main()
