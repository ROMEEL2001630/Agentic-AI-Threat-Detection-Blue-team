import json
import threading
import unittest
from http.client import HTTPConnection
from unittest.mock import patch
from http.server import ThreadingHTTPServer

from dashboard import Handler, ROOT, triage


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.alerts = json.loads((ROOT / 'sample_alerts.json').read_text())

    def test_priority_and_source_provenance(self):
        results = triage(self.alerts)
        self.assertEqual(results[0]['alert']['id'], 'ALRT-1003')
        self.assertEqual(results[0]['source_row'], 3)
        self.assertEqual(results[0]['score'], 75)
        for result in results:
            self.assertEqual(result['alert'], self.alerts[result['source_row'] - 1])

    def test_offline_even_with_configured_keys(self):
        with patch('soc_triage_assistant.enrich_ip', side_effect=AssertionError('Network called')):
            results = triage(self.alerts)
        self.assertEqual(results[1]['enrichment'][0]['source'], 'offline')

    def test_invalid_imports(self):
        for payload in ({}, [], [None], [{'id': 'x'}], self.alerts * 200):
            with self.subTest(payload_type=type(payload)), self.assertRaises(ValueError):
                triage(payload)
        for key, value in [('entities', []), ('asset_criticality', 1), ('severity', 'urgent')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                triage([{**self.alerts[0], key: value}])

    def test_http_boundaries(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        connection = HTTPConnection(*server.server_address, timeout=5)
        try:
            connection.request('POST', '/api/triage', json.dumps(self.alerts), {'Content-Type': 'application/json'})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read())['actions_executed'], 0)
            connection.request('POST', '/api/triage', '[]', {'Origin': 'https://untrusted.example'})
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
            connection.request('GET', '/../../config.example.env')
            response = connection.getresponse()
            self.assertEqual(response.status, 404)
            response.read()
            connection.request('GET', '/')
            response = connection.getresponse()
            self.assertIn("script-src 'self'", response.getheader('Content-Security-Policy'))
            self.assertIn(b'AEGIS', response.read())
        finally:
            connection.close()
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    unittest.main()
