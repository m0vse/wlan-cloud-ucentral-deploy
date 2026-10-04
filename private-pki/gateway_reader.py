"""Protected backend gateway state reader for activation evidence.

The service credential is deployment-supplied, owner-only and absent from AP
requests, browser state and source. Controller.fetch verifies HTTPS hostnames.
"""
import re
from issuer import private_read


class GatewayReader:
    def __init__(self, controller, credential_path):
        self.controller = controller
        token = private_read(credential_path).decode('ascii').strip()
        if len(token) > 8192 or not re.fullmatch(r'[A-Za-z0-9._~+/-]+=*', token):
            raise ValueError('Invalid protected gateway credential')
        self.authorization = 'Bearer ' + token

    def __call__(self, serial):
        if not isinstance(serial, str) or not re.fullmatch('[0-9a-f]{12}', serial):
            raise ValueError('Invalid gateway inventory identity')
        return self.controller.fetch(16002, f'device/{serial}?completeInfo=true', self.authorization)

    def __repr__(self):
        return 'GatewayReader(protected credential)'
