from django.test import TestCase
from django.urls import reverse


class AnonymousIndexRedirectTest(TestCase):
    def test_index_redirects_to_login(self):
        response = self.client.get(reverse("scans:index"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)
        self.assertIn("next=", response.url)
