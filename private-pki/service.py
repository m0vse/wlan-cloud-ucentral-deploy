"""Bounded isolated HTTP/TLS adapter. No automatic production startup.

Separate admin and AP listeners: AP requests never reach portal administration.
The peer DER comes exclusively from the TLS socket, never headers/JSON.
"""
import base64
from collections import OrderedDict, deque
import http.server
import json
import ssl
import threading
import time

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from admin import Denied


class RateLimit:
    def __init__(self, clock=time.monotonic):
        self.clock, self.lock = clock, threading.Lock()
        self.global_requests, self.identities = deque(), OrderedDict()

    def allow(self, identity):
        with self.lock:
            stamp = self.clock()
            for queue in (self.global_requests, *self.identities.values()):
                while queue and queue[0] <= stamp - 60:
                    queue.popleft()
            for key in list(self.identities):
                if not self.identities[key]:
                    del self.identities[key]
            if len(self.global_requests) >= 120 or (identity not in self.identities and len(self.identities) >= 256):
                return False
            queue = self.identities.setdefault(identity, deque())
            if len(queue) >= 12:
                return False
            queue.append(stamp)
            self.global_requests.append(stamp)
            return True


def json_object(body):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    value = json.loads(body, object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise ValueError("JSON object required")
    return value


def pkcs7_reply(issuer, certificate=None):
    certificates = [issuer.ca, issuer.root]
    if certificate is not None:
        certificates.insert(0, x509.load_pem_x509_certificate(certificate))
    return base64.b64encode(pkcs7.serialize_certificates(certificates, serialization.Encoding.DER))


def handler(issuer, administration=None, mode="ap", activation=None):
    if mode not in ("ap", "admin") or (mode == "admin" and administration is None):
        raise ValueError("invalid listener mode")
    rate = RateLimit()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *_):
            pass  # Never log Bearer/grant headers, CSR bodies or private keys.

        def reply(self, status, body=b"", content_type="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            if content_type.startswith("application/pkcs7-mime"):
                self.send_header("Content-Transfer-Encoding", "base64")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def body(self):
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get_all("Transfer-Encoding") or len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal():
                raise Denied(400, "Invalid framing")
            length = int(lengths[0])
            if not 1 <= length <= 32768:
                raise Denied(413, "Invalid request size")
            body = self.rfile.read(length)
            if len(body) != length:
                raise Denied(400, "Incomplete request")
            return body

        def peer(self):
            if not isinstance(self.connection, ssl.SSLSocket):
                return None
            return self.connection.getpeercert(binary_form=True)

        def dispatch(self):
            # Bound by observed connection address, not caller-supplied identity.
            if not rate.allow(self.client_address[0]):
                raise Denied(429, "Request limit exceeded")
            if mode == "admin":
                prefix = "/api/v1/pki/"
                if not self.path.startswith(prefix):
                    raise Denied(404, "Unknown administration path")
                operation = self.path[len(prefix):]
                if self.command == "GET" and operation in ("status", "audit"):
                    request = {}
                elif self.command == "POST" and operation in ("authorize", "evidence", "approve-hardware", "approve-qualification", "approve-runtime", "approve-identity"):
                    if self.headers.get("Content-Type") != "application/json":
                        raise Denied(415, "JSON required")
                    request = json_object(self.body())
                else:
                    raise Denied(404, "Unknown administration operation")
                if len(self.headers.get_all("Authorization", [])) != 1:
                    raise Denied(401, "Sign in required")
                result = administration.call(self.headers.get("Authorization"), operation, request)
                self.reply(200, json.dumps(result).encode())
                return
            if not isinstance(self.connection, ssl.SSLSocket):
                raise Denied(403, "TLS required")
            if self.command == "POST" and self.path in ("/activation/challenge", "/activation/verify"):
                if activation is None:
                    raise Denied(503, "Management acceptance adapter unavailable")
                if self.headers.get("Content-Type") != "application/json" or not self.peer():
                    raise Denied(403, "Authenticated activation request required")
                request = json_object(self.body())
                if self.path == "/activation/challenge" and not request:
                    result = activation.challenge(self.peer())
                elif self.path == "/activation/verify" and set(request) == {"nonce"}:
                    result = activation.verify(self.peer(), request["nonce"])
                else:
                    raise Denied(400, "Invalid activation request")
                self.reply(200, json.dumps(result).encode())
                return
            if self.command == "GET" and self.path == "/.well-known/est/cacerts":
                self.reply(200, pkcs7_reply(issuer), "application/pkcs7-mime; smime-type=certs-only")
                return
            if self.command != "POST" or self.path not in ("/bootstrap", "/.well-known/est/simplereenroll"):
                raise Denied(404, "Unknown enrollment operation")
            if self.headers.get("Content-Type") != "application/pkcs10":
                raise Denied(415, "PKCS10 required")
            csr = x509.load_der_x509_csr(base64.b64decode(b"".join(self.body().split()), validate=True))
            csr_pem = csr.public_bytes(serialization.Encoding.PEM)
            if self.path == "/bootstrap":
                headers = self.headers.get_all("Authorization", [])
                if len(headers) != 1 or not headers[0].startswith("Basic ") or len(headers[0]) > 512:
                    raise Denied(403, "Enrollment authorization required")
                device, token = base64.b64decode(headers[0][6:], validate=True).decode("ascii").split(":", 1)
                certificate = issuer.bootstrap(device, token, csr_pem)
            else:
                peer = self.peer()
                if not peer:
                    raise Denied(403, "Client TLS certificate required")
                attempts = self.headers.get_all("X-Renewal-Attempt", [])
                if len(attempts) != 1:
                    raise Denied(400, "Renewal attempt required")
                certificate = issuer.renew(peer, csr_pem, attempts[0])
            self.reply(200, pkcs7_reply(issuer, certificate), "application/pkcs7-mime; smime-type=certs-only")

        def handle_request(self):
            try:
                self.dispatch()
            except Denied as error:
                self.reply(error.status, json.dumps({"error": str(error)}).encode())
            except (ValueError, TypeError, UnicodeError, KeyError, x509.ExtensionNotFound, RecursionError, InvalidSignature):
                self.reply(403, b'{"error":"Request refused"}')

        do_GET = handle_request
        do_POST = handle_request

    return Handler


class IsolatedServer(http.server.HTTPServer):
    """At most eight handshakes/requests, each with a five-second timeout."""
    def __init__(self, address, request_handler, tls_context=None):
        if address[0] != "127.0.0.1":
            raise ValueError("isolated listener must use loopback")
        if tls_context is not None and tls_context.verify_mode not in (ssl.CERT_OPTIONAL, ssl.CERT_REQUIRED):
            raise ValueError("TLS client chain verification required")
        self.tls_context, self.workers = tls_context, threading.BoundedSemaphore(8)
        super().__init__(address, request_handler)

    def process_request(self, request, address):
        if not self.workers.acquire(blocking=False):
            self.shutdown_request(request)
            return
        threading.Thread(target=self.worker, args=(request, address), daemon=True).start()

    def worker(self, request, address):
        try:
            request.settimeout(5)
            if self.tls_context is not None:
                request = self.tls_context.wrap_socket(request, server_side=True)
            self.finish_request(request, address)
        except (OSError, ssl.SSLError):
            pass
        finally:
            self.shutdown_request(request)
            self.workers.release()
