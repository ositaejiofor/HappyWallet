from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse


User = get_user_model()


class SecurityHomeViewTests(TestCase):
    """Tests for the authenticated Security page."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="security-test-user",
            email="security@example.com",
            password="StrongTestPassword123!",
        )

        self.url = reverse("security:home")

    def test_security_page_requires_authentication(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 302)

        self.assertIn(
            reverse("accounts:login"),
            response.url,
        )

    def test_security_page_renders_for_authenticated_user(self):
        self.client.force_login(self.user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)

        self.assertTemplateUsed(
            response,
            "security/home.html",
        )

    def test_security_page_contains_security_controls(self):
        self.client.force_login(self.user)

        response = self.client.get(self.url)

        self.assertContains(
            response,
            "Account Authentication",
        )

        self.assertContains(
            response,
            "Wallet Protection",
        )

        self.assertContains(
            response,
            "Security Monitoring",
        )

        self.assertContains(
            response,
            "Audit Logging",
        )

        self.assertContains(
            response,
            "Rate Limiting",
        )

    def test_security_page_does_not_show_sensitive_wallet_material(self):
        self.client.force_login(self.user)

        response = self.client.get(self.url)

        self.assertNotContains(
            response,
            "Private Key:",
        )

        self.assertNotContains(
            response,
            "Seed Phrase:",
        )

        self.assertNotContains(
            response,
            "Mnemonic:",
        )

        self.assertNotContains(
            response,
            "Encryption Key:",
        )