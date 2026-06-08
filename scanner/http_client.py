# Modulo cliente HTTP comun con control de reintentos, SSL y captura de solicitudes.

import time
import warnings
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3





DEFAULT_TIMEOUT = 15
DEFAULT_DELAY = 0.35
DEFAULT_VERIFY_SSL = True
DEFAULT_PROXY_URL = None


def configure_defaults(timeout=None, delay=None, verify_ssl=None, proxy_url=None):
    global DEFAULT_TIMEOUT, DEFAULT_DELAY, DEFAULT_VERIFY_SSL, DEFAULT_PROXY_URL

    if timeout is not None:
        DEFAULT_TIMEOUT = timeout

    if delay is not None:
        DEFAULT_DELAY = delay

    if verify_ssl is not None:
        DEFAULT_VERIFY_SSL = verify_ssl

    DEFAULT_PROXY_URL = proxy_url or None


def get_default_proxy_url():
    return DEFAULT_PROXY_URL


class HttpClient:
    def __init__(self, timeout=None, delay=None, verify_ssl=None, proxy_url=None, capture_http=False, capture_limit=1000):
        self.timeout = DEFAULT_TIMEOUT if timeout is None else timeout
        self.delay = DEFAULT_DELAY if delay is None else delay
        self.verify_ssl = DEFAULT_VERIFY_SSL if verify_ssl is None else verify_ssl
        self.proxy_url = DEFAULT_PROXY_URL if proxy_url is None else proxy_url
        self.capture_http = bool(capture_http)
        self.capture_limit = max(100, int(capture_limit or 1000))
        self.request_history = []
        self.session = requests.Session()

        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                      "application/json;q=0.8,*/*;q=0.7",
            "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
            "Connection": "keep-alive",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
        })

        retry = Retry(
            total=1,
            connect=1,
            read=1,
            backoff_factor=0.15,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD", "OPTIONS"]
        )

        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        if self.proxy_url:
            self.session.proxies.update({
                "http": self.proxy_url,
                "https": self.proxy_url,
            })

    def enable_http_capture(self, enabled=True, limit=None):
        self.capture_http = bool(enabled)
        if limit is not None:
            self.capture_limit = max(100, int(limit or self.capture_limit))

    def clear_http_history(self):
        self.request_history = []

    def _record_http_event(self, event):
        if not self.capture_http:
            return
        self.request_history.append(event)
        if len(self.request_history) > self.capture_limit:
            self.request_history = self.request_history[-self.capture_limit:]

    def _request(self, method, url, **kwargs):
        method_name = str(getattr(method, "__name__", "get") or "get").upper()
        started = time.time()
        response = None
        error_text = ""

        verify = kwargs.get("verify", self.verify_ssl)
        try:
            if verify is False:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
                    response = method(url, **kwargs)
            else:
                response = method(url, **kwargs)
            return response
        except Exception as exc:
            error_text = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            duration_ms = int((time.time() - started) * 1000)
            request_blob = ""
            response_blob = ""
            if "data" in kwargs and kwargs.get("data") is not None:
                request_blob = str(kwargs.get("data"))
            elif "json" in kwargs and kwargs.get("json") is not None:
                request_blob = str(kwargs.get("json"))

            if response is not None:
                try:
                    content_type = str(response.headers.get("Content-Type", "") or "").lower()
                    if any(token in content_type for token in ["json", "text", "xml", "html", "javascript"]):
                        response_blob = str(response.text or "")[:700]
                except Exception:
                    response_blob = ""

            event = {
                "method": method_name,
                "url": str(url or ""),
                "final_url": str(getattr(response, "url", url) or ""),
                "status_code": int(getattr(response, "status_code", 0) or 0),
                "duration_ms": duration_ms,
                "content_type": str(getattr(response, "headers", {}).get("Content-Type", "") if response is not None else ""),
                "request_body_preview": request_blob[:300],
                "response_body_preview": response_blob,
                "response_server": str(getattr(response, "headers", {}).get("Server", "") if response is not None else ""),
                "response_powered_by": str(getattr(response, "headers", {}).get("X-Powered-By", "") if response is not None else ""),
                "session_cookie_names": sorted([c.name for c in self.session.cookies])[:12],
                "error": error_text,
            }
            self._record_http_event(event)

    def normalize_url(self, url):
        parsed = urlparse(url)

        if not parsed.scheme:
            return "https://" + url

        return url

    def get(self, url, **kwargs):
        time.sleep(self.delay)
        url = self.normalize_url(url)

        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", self.verify_ssl)

        return self._request(self.session.get, url, **kwargs)

    def post(self, url, **kwargs):
        time.sleep(self.delay)
        url = self.normalize_url(url)

        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", self.verify_ssl)

        return self._request(self.session.post, url, **kwargs)

    def head(self, url, **kwargs):
        time.sleep(self.delay)
        url = self.normalize_url(url)

        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", self.verify_ssl)

        return self._request(self.session.head, url, **kwargs)

    def options(self, url, **kwargs):
        time.sleep(self.delay)
        url = self.normalize_url(url)

        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", self.verify_ssl)

        return self._request(self.session.options, url, **kwargs)
