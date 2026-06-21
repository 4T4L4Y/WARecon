from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from scans.models import ScanLog
from scans.services.live_log import module_status_for_scan
from scans.services.pipeline import create_scan


class AnonymousIndexRedirectTest(TestCase):
    def test_index_redirects_to_login(self):
        response = self.client.get(reverse("scans:index"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)
        self.assertIn("next=", response.url)


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
        self.assertTrue(all(item["state"] == "pending" for item in statuses))
