from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock
from gateway_reader import GatewayReader


class ReaderTests(unittest.TestCase):
    def test_private_credential_and_exact_read_only_route(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'credential'
            path.write_text('synthetic-token')
            path.chmod(0o600)
            controller = Mock()
            controller.fetch.return_value = {'synthetic': True}
            reader = GatewayReader(controller, path)
            self.assertEqual(reader('001122334455'), {'synthetic': True})
            controller.fetch.assert_called_once_with(16002,
                'device/001122334455?completeInfo=true', 'Bearer synthetic-token')
            self.assertNotIn('synthetic-token', repr(reader))
            controller.fetch.reset_mock()
            for serial in ('../other', '001122334455?applyConfiguration=true', None):
                with self.assertRaises(ValueError):
                    reader(serial)
            controller.fetch.assert_not_called()
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                GatewayReader(controller, path)


if __name__ == '__main__':
    unittest.main()
