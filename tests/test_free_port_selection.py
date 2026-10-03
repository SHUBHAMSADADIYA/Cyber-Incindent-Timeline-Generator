import socket
import unittest

from run import find_available_port


class FreePortSelectionTests(unittest.TestCase):
    def test_find_available_port_skips_in_use_ports(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", port))
            result = find_available_port("127.0.0.1", port)
            self.assertNotEqual(result, port)
            self.assertGreaterEqual(result, 1)
            self.assertLessEqual(result, 65535)


if __name__ == "__main__":
    unittest.main()
