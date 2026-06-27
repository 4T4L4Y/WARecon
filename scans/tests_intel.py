"""OSINT / Threat Intelligence testleri."""

from unittest.mock import AsyncMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from scans.models import Scan, SubdomainIntelResult
from scans.services.live_subdomains import collect_live_subdomains
from scans.services.subdomain_intel import (
    IntelSignals,
    calculate_risk_score,
    threat_level_from_score,
)


class LiveSubdomainFilterTest(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="inteluser", password="pass12345")
        self.scan = Scan.objects.create(
            user=user,
            domain="example.com",
            raw_input="example.com",
            modules=["2", "4", "1"],
            config={
                "discovered_subdomains": ["live.example.com", "dead.example.com"],
                "selected_subdomains": ["live.example.com", "dead.example.com"],
            },
            status=Scan.Status.COMPLETED,
        )

    def test_filters_dead_without_httpx_or_ports(self):
        from scans.models import ScanModuleResult

        ScanModuleResult.objects.create(
            scan=self.scan,
            module=ScanModuleResult.Module.HTTPX,
            output="=== live.example.com ===\nhttps://live.example.com [200]\n",
        )
        live = collect_live_subdomains(self.scan)
        hosts = {item["host"] for item in live}
        self.assertIn("live.example.com", hosts)
        self.assertNotIn("dead.example.com", hosts)

    def test_naabu_port_443_counts_as_live(self):
        from scans.models import ScanModuleResult

        ScanModuleResult.objects.create(
            scan=self.scan,
            module=ScanModuleResult.Module.NAABU,
            output="dead.example.com:443\n",
        )
        live = collect_live_subdomains(self.scan)
        dead = next((x for x in live if x["host"] == "dead.example.com"), None)
        self.assertIsNotNone(dead)
        self.assertIn("port443", dead["reasons"])


class RiskScoringTest(TestCase):
    def test_high_pulse_and_malware_score(self):
        signals = IntelSignals(pulse_count=12, malware_count=3, malicious_votes=4)
        score = calculate_risk_score(signals)
        self.assertGreaterEqual(score, 50)
        self.assertIn(
            threat_level_from_score(score),
            (SubdomainIntelResult.ThreatLevel.HIGH, SubdomainIntelResult.ThreatLevel.CRITICAL),
        )

    def test_clean_host_low_score(self):
        signals = IntelSignals()
        score = calculate_risk_score(signals)
        self.assertLess(score, 25)
        self.assertEqual(threat_level_from_score(score), SubdomainIntelResult.ThreatLevel.LOW)


@override_settings(OTX_API_KEY="")
class IntelJobNoKeyTest(TestCase):
    def test_skips_without_api_key(self):
        from scans.services.subdomain_intel import run_subdomain_intel

        user = get_user_model().objects.create_user(username="nointel", password="pass12345")
        scan = Scan.objects.create(
            user=user,
            domain="example.com",
            raw_input="example.com",
            modules=["2"],
            status=Scan.Status.COMPLETED,
        )
        result = run_subdomain_intel(scan.pk)
        self.assertFalse(result["ok"])
        scan.refresh_from_db()
        self.assertEqual(scan.config["intel"]["status"], "skipped")
