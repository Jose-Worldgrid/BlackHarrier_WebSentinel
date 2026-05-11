import time
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
    def __init__(self, timeout=None, delay=None, verify_ssl=None, proxy_url=None):
        self.timeout = DEFAULT_TIMEOUT if timeout is None else timeout
        self.delay = DEFAULT_DELAY if delay is None else delay
        self.verify_ssl = DEFAULT_VERIFY_SSL if verify_ssl is None else verify_ssl
        self.proxy_url = DEFAULT_PROXY_URL if proxy_url is None else proxy_url
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

        return self.session.get(url, **kwargs)

    def post(self, url, **kwargs):
        time.sleep(self.delay)
        url = self.normalize_url(url)

        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", self.verify_ssl)

        return self.session.post(url, **kwargs)

    def head(self, url, **kwargs):
        time.sleep(self.delay)
        url = self.normalize_url(url)

        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", self.verify_ssl)

        return self.session.head(url, **kwargs)

    def options(self, url, **kwargs):
        time.sleep(self.delay)
        url = self.normalize_url(url)

        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", self.verify_ssl)

        return self.session.options(url, **kwargs)