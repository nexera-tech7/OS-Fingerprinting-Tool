import pytest
from unittest.mock import patch, MagicMock
from src.scanner.ports import scan_port, PortResult


class TestPortResult:
    def test_open_port(self):
        r = PortResult(port=80, state="open", service="http", banner="nginx")
        assert r.port == 80
        assert r.state == "open"
        assert r.service == "http"
        assert r.banner == "nginx"

    def test_closed_port(self):
        r = PortResult(port=3389, state="closed", service="rdp")
        assert r.state == "closed"
        assert r.banner == ""


class TestScanPort:
    @patch("src.scanner.ports.socket.create_connection")
    def test_open_port(self, mock_conn):
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = OSError
        mock_sock.__enter__ = lambda s: mock_sock
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        result = scan_port("127.0.0.1", 80, timeout=1.0)
        assert result.state == "open"
        assert result.port == 80

    @patch("src.scanner.ports.socket.create_connection", side_effect=ConnectionRefusedError)
    def test_closed_port(self, mock_conn):
        result = scan_port("127.0.0.1", 9999, timeout=1.0)
        assert result.state == "closed"

    @patch("src.scanner.ports.socket.create_connection", side_effect=TimeoutError)
    def test_filtered_port(self, mock_conn):
        result = scan_port("127.0.0.1", 9999, timeout=1.0)
        assert result.state == "filtered"
