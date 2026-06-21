from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from scans.models import ScanLog
from scans.services.formatters import format_naabu, parse_nmap_exploits
from scans.services.live_log import module_status_for_scan
from scans.services.pipeline import create_scan, validate_pipeline


class AnonymousIndexRedirectTest(TestCase):
    def test_index_redirects_to_login(self):
        response = self.client.get(reverse("scans:index"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)


class LiveScanFeedTest(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="liveuser", password="pass12345")
        self.scan = create_scan(user, {
            "domain": "example.com",
            "choices": ["2", "4"],
        })

    def test_create_scan_adds_queue_log(self):
        self.assertTrue(
            ScanLog.objects.filter(scan=self.scan, message__icontains="kuyruğa").exists()
        )

    def test_module_status_pending(self):
        statuses = module_status_for_scan(self.scan)
        self.assertEqual(len(statuses), 2)


class PipelineValidationTest(TestCase):
    def test_wayback_requires_subfinder(self):
        with self.assertRaises(ValueError):
            validate_pipeline(["3"])

    def test_httpx_requires_subfinder(self):
        with self.assertRaises(ValueError):
            validate_pipeline(["4", "5"])


class FormatterTest(TestCase):
    def test_format_naabu_colors_ports(self):
        html = format_naabu("example.com:443\nexample.com:80")
        self.assertIn("output-port", html)
        self.assertIn("443", html)

    def test_parse_nmap_exploits(self):
        text = "CVE-2021-1234 VULNERABLE exploit available"
        findings = parse_nmap_exploits(text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cve"], "CVE-2021-1234")
