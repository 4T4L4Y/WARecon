from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from scans.models import ScanLog
from scans.services.formatters import format_naabu, format_dnsx, parse_nmap_exploits, strip_html_output
from scans.services.output_utils import extract_urls_from_text, strip_ansi
from scans.services.live_log import module_status_for_scan
from scans.services.scan_control import (
    check_abort,
    request_skip_module,
    skip_available,
    skip_step_id,
    skip_steps_match,
)
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

    def test_format_dnsx_strips_ansi(self):
        raw = "smtp.beymen.com [\x1b[35mA\x1b[0m] [\x1b[32m213.14.96.219\x1b[0m]"
        html = format_dnsx(raw)
        self.assertIn("smtp.beymen.com", html)
        self.assertIn("213.14.96.219", html)
        self.assertNotIn("\x1b", html)

    def test_extract_urls_from_httpx(self):
        text = "https://beymen.com [301,301,200]\n=== host ===\n"
        urls = extract_urls_from_text(text)
        self.assertEqual(urls, ["https://beymen.com"])

    def test_parse_httpx_tech_tags(self):
        from scans.services.output_utils import parse_httpx_tech_tags

        text = (
            "https://example.com [200] [Cloudflare]\n"
            "https://docs.example.com [200] [HackerOne] [Gatsby,React,webpack]\n"
        )
        tags = parse_httpx_tech_tags(text)
        self.assertIn("cloudflare", tags)
        self.assertIn("gatsby", tags)
        self.assertIn("react", tags)
        self.assertIn("webpack", tags)


    def test_naabu_ports_flat(self):
        from scans.services import tools

        items = tools.naabu_ports_flat("a.com:80\na.com:443\nb.com:22\n")
        self.assertEqual(len(items), 3)
        self.assertEqual(items[0]["id"], "a.com:80")

    def test_apply_port_selection(self):
        from scans.services.pipeline import apply_port_selection

        user = get_user_model().objects.create_user(username="portuser", password="pass12345")
        scan = create_scan(user, {"domain": "example.com", "choices": ["1"]})
        apply_port_selection(scan, ["example.com:443", "example.com:80"], run_nmap=True)
        scan.refresh_from_db()
        self.assertTrue(scan.config["port_selection_done"])
        self.assertEqual(len(scan.config["selected_ports"]), 2)
        self.assertTrue(scan.config["run_nmap"])
        self.assertEqual(scan.status, Scan.Status.RUNNING)


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


class SkipModuleControlTest(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="skipuser", password="pass12345")
        self.scan = create_scan(user, {
            "domain": "example.com",
            "choices": ["1", "2"],
        })

    def test_nmap_ui_id_maps_to_pipeline_step(self):
        self.assertEqual(skip_step_id("8"), "1")
        self.assertTrue(skip_steps_match("8", "1"))
        self.assertTrue(skip_steps_match("1", "8"))

    def test_request_skip_normalizes_nmap(self):
        self.scan.current_module = "8"
        self.scan.status = Scan.Status.RUNNING
        self.scan.save()
        request_skip_module(self.scan, "8")
        self.scan.refresh_from_db()
        self.assertEqual(self.scan.skip_module_requested, "1")

    def test_check_abort_during_nmap_phase(self):
        self.scan.skip_module_requested = "1"
        self.scan.save()
        self.assertEqual(check_abort(self.scan.pk, "1"), "skip")

    def test_skip_available_uses_pipeline_step_timer(self):
        from datetime import datetime, timedelta, timezone

        from scans.models import UserProfile

        profile, _ = UserProfile.objects.get_or_create(user=self.scan.user)
        profile.skip_module_after_seconds = 60
        profile.save(update_fields=["skip_module_after_seconds"])
        self.scan.status = Scan.Status.RUNNING
        self.scan.current_module = "8"
        started = datetime.now(timezone.utc) - timedelta(seconds=130)
        self.scan.config = {
            **self.scan.config,
            "module_started_at": {"1": started.isoformat()},
        }
        self.scan.save()
        self.assertTrue(skip_available(self.scan))

        started = datetime.now(timezone.utc) - timedelta(seconds=45)
        self.scan.config["module_started_at"] = {"1": started.isoformat()}
        self.scan.save()
        self.assertFalse(skip_available(self.scan))

    def test_web_substep_skip_match(self):
        from scans.services.scan_control import WEB_SUBMODULE_IDS, check_abort

        self.scan.skip_module_requested = "3"
        self.scan.save()
        self.assertEqual(check_abort(self.scan.pk, "3"), "skip")
        self.assertIn("3", WEB_SUBMODULE_IDS)
