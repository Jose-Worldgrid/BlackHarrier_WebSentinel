import unittest
from unittest.mock import patch

from scanner.csrf import scan_csrf_from_pages
from scanner.dom_xss import scan_dom_xss
from scanner.browser_auth import analyze_direct_response
from scanner.sqli import analyze_boolean_difference
from scanner.sqli import scan_sqli_pages
from scanner.xss import scan_reflected_xss_pages


class FakeResponse:
    def __init__(self, text="", status_code=200, headers=None, url="https://example.test"):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "text/html"}
        self.url = url


class BooleanResponse:
    def __init__(self, text, status_code=200, url="https://example.test/login"):
        self.text = text
        self.status_code = status_code
        self.url = url


class CountingHttpClient:
    def __init__(self):
        self.calls = 0

    def get(self, url, **kwargs):
        self.calls += 1
        return FakeResponse(text="no reflection here", url=url)

    def post(self, url, **kwargs):
        self.calls += 1
        return FakeResponse(text="no reflection here", url=url)


class StaticHttpClient:
    def __init__(self, text):
        self.text = text

    def get(self, url, **kwargs):
        return FakeResponse(text=self.text, url=url)


class ScannerRegressionTests(unittest.TestCase):
    def test_xss_respects_max_payloads(self):
        page = {
            "url": "https://example.test/search?q=term",
            "html": """
                <html><body>
                    <form method='post' action='/submit'>
                        <input type='text' name='q' />
                    </form>
                </body></html>
            """,
        }

        full_client = CountingHttpClient()
        limited_client = CountingHttpClient()

        with patch("scanner.xss.HttpClient", return_value=full_client):
            scan_reflected_xss_pages([page])

        with patch("scanner.xss.HttpClient", return_value=limited_client):
            scan_reflected_xss_pages([page], max_payloads=1)

        self.assertGreater(full_client.calls, limited_client.calls,
            msg="Limited scan should make fewer HTTP calls than full scan")

    def test_sqli_respects_max_payloads(self):
        page = {
            "url": "https://example.test/login",
            "html": """
                <html><body>
                    <form method='post' action='/login'>
                        <input type='text' name='username' />
                        <input type='password' name='password' />
                    </form>
                </body></html>
            """,
        }

        full_client = CountingHttpClient()
        limited_client = CountingHttpClient()

        with patch("scanner.sqli.HttpClient", return_value=full_client):
            scan_sqli_pages([page])

        with patch("scanner.sqli.HttpClient", return_value=limited_client):
            scan_sqli_pages([page], max_payloads=1)

        self.assertGreater(full_client.calls, limited_client.calls,
            msg="Limited scan should make fewer HTTP calls than full scan")

    def test_boolean_sql_injection_requires_structural_difference(self):
        true_response = BooleanResponse(
            text="<html><body>Welcome back! Login successful.</body></html>",
            status_code=200,
            url="https://example.test/login",
        )
        false_response = BooleanResponse(
            text="<html><body>Welcome back! Login failed.</body></html>",
            status_code=200,
            url="https://example.test/login",
        )

        vulnerable, evidence = analyze_boolean_difference(true_response, false_response)

        self.assertFalse(vulnerable)
        self.assertIn("Sin diferencia concluyente", evidence)

    def test_boolean_sql_injection_detects_real_redirect_difference(self):
        true_response = BooleanResponse(
            text="<html><body>Welcome dashboard</body></html>",
            status_code=302,
            url="https://example.test/dashboard",
        )
        false_response = BooleanResponse(
            text="<html><body>Invalid credentials</body></html>",
            status_code=200,
            url="https://example.test/login",
        )

        vulnerable, evidence = analyze_boolean_difference(true_response, false_response)

        self.assertTrue(vulnerable)
        self.assertIn("cambio estructural", evidence.lower())

    def test_auth_direct_api_requires_stronger_evidence(self):
        class DirectResponse:
            def __init__(self, text, status_code=200, url="https://example.test/login"):
                self.text = text
                self.status_code = status_code
                self.url = url

        response = DirectResponse(
            text="<html><body>Welcome back</body></html>",
            status_code=200,
            url="https://example.test/login",
        )

        analyzed = analyze_direct_response("https://example.test/login", "' OR 1=1", response, "json")

        self.assertFalse(analyzed["possible_bypass"])

    def test_csrf_marks_missing_token_as_finding(self):
        page = {
            "url": "https://example.test/checkout",
            "html": """
                <html><body>
                    <form method='post' action='/pay'>
                        <input type='text' name='amount' />
                    </form>
                </body></html>
            """,
        }

        results = scan_csrf_from_pages([page])

        self.assertEqual(results[0]["status"], "Hallazgo")
        self.assertEqual(results[0]["severity"], "Alta")

    def test_dom_xss_sink_only_is_low_severity(self):
        page = {
            "url": "https://example.test/app",
            "html": """
                <html><body>
                    <script>
                        function render(x) { element.innerHTML = x; }
                    </script>
                </body></html>
            """,
        }

        with patch("scanner.dom_xss.HttpClient", return_value=StaticHttpClient("")):
            results = scan_dom_xss([page])

        sink_result = next(item for item in results if item["control"].startswith("Sink DOM detectado"))

        self.assertEqual(sink_result["status"], "Comprobado")
        self.assertEqual(sink_result["severity"], "Baja")

    def test_dom_xss_source_sink_correlation_is_reported(self):
        page = {
            "url": "https://example.test/app",
            "html": """
                <html><body>
                    <script>
                        const p = location.search;
                        document.write(p);
                    </script>
                </body></html>
            """,
        }

        with patch("scanner.dom_xss.HttpClient", return_value=StaticHttpClient("")):
            results = scan_dom_xss([page])

        correlation_result = next(item for item in results if item["control"] == "Posible XSS DOM por correlación source/sink")

        self.assertEqual(correlation_result["status"], "Posible hallazgo")
        self.assertIn(correlation_result["severity"], {"Alta", "Media"})


if __name__ == "__main__":
    unittest.main()
