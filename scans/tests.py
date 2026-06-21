from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from scans.models import ScanLog
from scans.services.formatters import format_naabu, parse_nmap_exploits, strip_html_output
from scans.services.live_log import module_status_for_scan
from scans.services.pipeline import (
    apply_subdomain_selection,
    create_scan,
    validate_pipeline,
)
from scans.models import Scan


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

    def test_strip_html_output(self):
        raw = '<div class="output-line"><span class="output-host">a.com</span></div>'
        self.assertEqual(strip_html_output(raw), "a.com")


class SubdomainSelectionTest(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="seluser", password="pass12345")
        self.scan = create_scan(user, {
            "domain": "example.com",
            "choices": ["2", "3", "4"],
        })
        self.scan.status = Scan.Status.AWAITING_SUBDOMAIN_SELECTION
        self.scan.config = {
            **self.scan.config,
            "discovered_subdomains": ["a.example.com", "b.example.com"],
        }
        self.scan.save()

    def test_apply_subdomain_selection(self):
        apply_subdomain_selection(
            self.scan,
            ["a.example.com"],
            run_wayback=True,
            run_httpx=True,
            run_nuclei=False,
            run_katana=False,
        )
        self.scan.refresh_from_db()
        self.assertEqual(self.scan.config["selected_subdomains"], ["a.example.com"])
        self.assertEqual(self.scan.status, Scan.Status.RUNNING)
