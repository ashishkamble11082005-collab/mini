import base64
import hashlib
import unittest
from unittest.mock import Mock, patch
from threat_intelligence.engine import ThreatIntelligenceEngine
from threat_intelligence.attachment_analysis import hash_attachment
from threat_intelligence.url_reputation import normalize_url
from threat_intelligence.virustotal import VirusTotalClient


class TestThreatIntelligence(unittest.TestCase):
    def test_normalize_url(self):
        self.assertEqual(normalize_url("HTTPS://Example.COM/login#fragment"),
                         "https://example.com/login")

    def test_url_id(self):
        url = "https://example.com/login"
        expected = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        self.assertEqual(VirusTotalClient.url_id(url), expected)

    def test_attachment_hash(self):
        data = b"ShieldMail test attachment"
        result = hash_attachment(data)
        self.assertEqual(result["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(result["sha1"], hashlib.sha1(data).hexdigest())
        self.assertEqual(result["md5"], hashlib.md5(data).hexdigest())

        def test_engine_local_url_intelligence(self):
         engine = ThreatIntelligenceEngine()

         result = engine.analyze(
            urls=["http://192.168.1.50/admin"]
        )

         self.assertEqual(result["status"], "DISABLED")
         self.assertEqual(result["summary"]["url_count"], 1)
         self.assertEqual(result["summary"]["local_findings"], 2)

         finding_types = {
            finding["type"]
            for finding in result["findings"]
        }

         self.assertIn("ip_address_url", finding_types)
         self.assertIn("insecure_http", finding_types)

    @patch("threat_intelligence.virustotal.requests.get")
    def test_url_not_found(self, mock_get):
        mock_get.return_value = Mock(status_code=404, ok=False)
        result = VirusTotalClient(api_key="test-key").get_url_report("https://example.com")
        self.assertEqual(result["status"], "NOT_FOUND")

    @patch("threat_intelligence.virustotal.requests.get")
    def test_file_not_found(self, mock_get):
        mock_get.return_value = Mock(status_code=404, ok=False)
        result = VirusTotalClient(api_key="test-key").get_file_report("a" * 64)
        self.assertEqual(result["status"], "NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
