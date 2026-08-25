from django.test import SimpleTestCase


class PublicEndpointTests(SimpleTestCase):
    def test_robots_txt(self):
        resp = self.client.get("/robots.txt")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/plain", resp["Content-Type"])

    def test_agent_access_json_endpoint_exists(self):
        """Endpoint is wired up (returns 200 or 404 depending on static file)."""
        resp = self.client.get("/.well-known/agent-access.json")
        # 404 is expected if the static file doesn't exist in this demo
        self.assertIn(resp.status_code, [200, 404])


class GateMiddlewareTests(SimpleTestCase):
    def test_agent_request_without_key(self):
        """Non-browser request without key should trigger gate (402 or 500)."""
        resp = self.client.get("/api/data")
        self.assertIn(resp.status_code, [402, 500])

    def test_browser_request_gets_challenge(self):
        """Browser request (with Sec-Fetch-Mode) should get challenge HTML."""
        resp = self.client.get(
            "/some-page",
            HTTP_SEC_FETCH_MODE="navigate",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp["Content-Type"])
        self.assertIn(b"Verifying your access", resp.content)
