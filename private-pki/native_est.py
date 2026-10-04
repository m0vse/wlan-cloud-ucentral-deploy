"""RFC7030 adapter for the shipped OpenWiFi est_client; no parallel AP lifecycle."""
import base64
import hashlib
import http.server
import ssl
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from service import RateLimit, pkcs7_reply

class NativeEST:
    def __init__(self, issuer, installer=None):
        self.issuer, self.installer = issuer, installer

    def reenroll(self, peer_der, csr_der):
        peer = x509.load_der_x509_certificate(peer_der)
        csr = x509.load_der_x509_csr(csr_der)
        # The built-in client keeps the entire existing subject and unique key.
        # Normalize signature randomness so a lost reply can be retried safely.
        request = peer.public_bytes(serialization.Encoding.DER) + csr.subject.public_bytes() + csr.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        attempt = hashlib.sha256(request + self.issuer.clock().date().isoformat().encode()).hexdigest()[:32]
        return self.issuer.renew(peer_der, csr.public_bytes(serialization.Encoding.PEM), attempt, native_subject=True)

    def enroll(self, serial, key, csr_der):
        if self.installer is None: raise ValueError('Installer enrollment is not configured')
        csr = x509.load_der_x509_csr(csr_der)
        return self.installer.bootstrap(key, serial, csr.public_bytes(serialization.Encoding.PEM))

def handler(adapter):
    limit = RateLimit(global_limit=1200, identity_limit=600)
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def reply(self, status, data=b'', mime='application/json'):
            self.send_response(status)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            if mime.startswith('application/pkcs7-mime'): self.send_header('Content-Transfer-Encoding', 'base64')
            self.end_headers(); self.wfile.write(data)
        def do_GET(self):
            if not isinstance(self.connection, ssl.SSLSocket): return self.reply(403)
            if not limit.allow(self.client_address[0]): return self.reply(429)
            if self.path != '/.well-known/est/cacerts': return self.reply(404)
            self.reply(200, pkcs7_reply(adapter.issuer), 'application/pkcs7-mime; smime-type=certs-only')
        def do_POST(self):
            try:
                if not isinstance(self.connection, ssl.SSLSocket): return self.reply(403)
                if not limit.allow(self.client_address[0]): return self.reply(429)
                if self.path not in ('/.well-known/est/simpleenroll', '/.well-known/est/simplereenroll'): return self.reply(404)
                lengths=self.headers.get_all('Content-Length', [])
                if len(lengths)!=1 or not lengths[0].isascii() or not lengths[0].isdecimal() or self.headers.get('Transfer-Encoding') or not 1 <= int(lengths[0]) <= 16384:
                    return self.reply(400)
                if self.headers.get('Content-Type') != 'application/pkcs10': return self.reply(415)
                body=self.rfile.read(int(lengths[0]))
                if len(body) != int(lengths[0]): return self.reply(400)
                csr=base64.b64decode(b''.join(body.split()), validate=True)
                if self.path.endswith('/simplereenroll'):
                    peer=self.connection.getpeercert(binary_form=True)
                    if not peer: return self.reply(403)
                    leaf=adapter.reenroll(peer, csr)
                else:
                    auth=self.headers.get_all('Authorization', [])
                    if len(auth)!=1 or not auth[0].startswith('Basic ') or len(auth[0])>512: return self.reply(403)
                    serial,key=base64.b64decode(auth[0][6:],validate=True).decode('ascii').split(':',1)
                    leaf=adapter.enroll(serial,key,csr)
                self.reply(200, pkcs7_reply(adapter.issuer,leaf), 'application/pkcs7-mime; smime-type=certs-only')
            except (ValueError, TypeError, UnicodeError, InvalidSignature, x509.ExtensionNotFound):
                self.reply(403, b'{"error":"Certificate request refused"}')
    return Handler
