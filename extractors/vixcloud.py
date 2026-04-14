import logging
import random
import re
import time
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

from aiohttp import ClientSession, ClientTimeout, TCPConnector
from aiohttp_socks import ProxyConnector
from playwright.async_api import async_playwright

logger = logging.getLogger(__name__)


class ExtractorError(Exception):
    pass


class VixCloudExtractor:
    """VixCloud URL extractor."""

    def __init__(self, request_headers: dict, proxies: list = None):
        self.request_headers = request_headers
        self.base_headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.5",
        }
        self.session = None
        self.mediaflow_endpoint = "hls_proxy"
        self.proxies = proxies or []

    def _get_random_proxy(self):
        return random.choice(self.proxies) if self.proxies else None

    @staticmethod
    def _raise_if_embed_expired(url: str):
        parsed = urlparse(url)
        if "/embed/" not in parsed.path:
            return
        expires = parse_qs(parsed.query).get("expires", [None])[0]
        if not expires:
            return
        try:
            expires_ts = int(expires)
        except (TypeError, ValueError):
            return
        now_ts = int(time.time())
        if expires_ts <= now_ts:
            raise ExtractorError(
                f"Expired VixCloud embed URL (expired at {expires_ts}, current {now_ts}). "
                "Use a fresh embed URL or the upstream page that generated it."
            )

    def _build_request_headers(self, url: str, request_headers: dict | None = None) -> dict:
        headers = dict(self.base_headers)
        source_headers = request_headers or self.request_headers or {}

        for header_name in [
            "Cookie",
            "cookie",
            "Accept-Language",
            "accept-language",
            "User-Agent",
            "user-agent",
        ]:
            if header_name in source_headers:
                normalized_name = header_name.title()
                if header_name.lower() == "user-agent":
                    normalized_name = "User-Agent"
                headers[normalized_name] = source_headers[header_name]

        headers["Referer"] = url
        return headers

    @staticmethod
    def _extract_script_text(html: str) -> str | None:
        body_match = re.search(r"<body[^>]*>(?P<body>[\s\S]*?)</body>", html, re.IGNORECASE)
        search_area = body_match.group("body") if body_match else html

        script_matches = re.findall(
            r"<script[^>]*>(?P<script>[\s\S]*?)</script>",
            search_area,
            re.IGNORECASE,
        )
        for script in script_matches:
            if "window.masterPlaylist" in script or "'token':" in script or '"token":' in script:
                return script
        return script_matches[0] if script_matches else None

    @staticmethod
    def _extract_playlist_components(html: str) -> tuple[str, str, str, str | None] | None:
        script = VixCloudExtractor._extract_script_text(html)
        search_text = script or html
        if "window.masterPlaylist" not in search_text and "'token':" not in search_text and '"token":' not in search_text:
            return None

        playlist_url_match = re.search(
            r"window\.masterPlaylist[\s\S]*?url\s*:\s*['\"](?P<url>[^'\"]+)['\"]",
            search_text,
        )
        token_match = re.search(
            r"window\.masterPlaylist[\s\S]*?['\"]token['\"]\s*:\s*['\"](?P<token>[^'\"]+)['\"]",
            search_text,
        )
        expires_match = re.search(
            r"window\.masterPlaylist[\s\S]*?['\"]expires['\"]\s*:\s*['\"](?P<expires>[^'\"]+)['\"]",
            search_text,
        )
        asn_match = re.search(
            r"window\.masterPlaylist[\s\S]*?['\"]asn['\"]\s*:\s*['\"](?P<asn>[^'\"]*)['\"]",
            search_text,
        )

        if not playlist_url_match:
            playlist_url_match = re.search(
                r"url\s*:\s*['\"](?P<url>https?://[^'\"]+/playlist/[^'\"]+)['\"]",
                search_text,
            )
        if not token_match:
            token_match = re.search(
                r"['\"]token['\"]\s*:\s*['\"](?P<token>[^'\"]+)['\"]",
                search_text,
            )
        if not expires_match:
            expires_match = re.search(
                r"['\"]expires['\"]\s*:\s*['\"](?P<expires>\d+)['\"]",
                search_text,
            )
        if not asn_match:
            asn_match = re.search(
                r"['\"]asn['\"]\s*:\s*['\"](?P<asn>[^'\"]*)['\"]",
                search_text,
            )

        if not playlist_url_match or not token_match or not expires_match:
            return None

        return (
            playlist_url_match.group("url").replace("\\/", "/"),
            token_match.group("token"),
            expires_match.group("expires"),
            asn_match.group("asn") if asn_match else None,
        )

    @staticmethod
    def _parse_cookie_header(cookie_header: str, domain: str) -> list[dict]:
        cookies = []
        for item in cookie_header.split(";"):
            if "=" not in item:
                continue
            name, value = item.split("=", 1)
            name = name.strip()
            value = value.strip()
            if not name:
                continue
            cookies.append(
                {
                    "name": name,
                    "value": value,
                    "domain": domain,
                    "path": "/",
                }
            )
        return cookies

    @staticmethod
    def _build_embed_playlist_url(url: str) -> str | None:
        match = re.search(r"/embed/(?P<video_id>\d+)", url)
        if not match:
            return None
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}/playlist/{match.group('video_id')}?b=1"

    async def _fetch_html_via_browser(
        self, url: str, request_headers: dict | None = None
    ) -> tuple[str, str | None]:
        source_headers = request_headers or self.request_headers or {}
        user_agent = (
            source_headers.get("User-Agent")
            or source_headers.get("user-agent")
            or self.base_headers["user-agent"]
        )
        locale = (
            source_headers.get("Accept-Language")
            or source_headers.get("accept-language")
            or self.base_headers["accept-language"]
        )
        parsed = urlparse(url)

        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--autoplay-policy=no-user-gesture-required",
                ],
            )
            context = await browser.new_context(
                user_agent=user_agent,
                locale=locale.split(",")[0],
                viewport={"width": 1366, "height": 768},
            )

            cookie_header = source_headers.get("Cookie") or source_headers.get("cookie")
            if cookie_header:
                cookies = self._parse_cookie_header(cookie_header, parsed.hostname or "vixcloud.co")
                if cookies:
                    await context.add_cookies(cookies)

            page = await context.new_page()
            playlist_request_url: str | None = None

            async def on_response(response):
                nonlocal playlist_request_url
                try:
                    if "/playlist/" in response.url and response.status == 200:
                        playlist_request_url = response.url
                except Exception:
                    pass

            page.on("response", on_response)
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            await page.wait_for_timeout(3000)
            html = await page.content()
            await context.close()
            await browser.close()
            return html, playlist_request_url

    async def _get_session(self):
        if self.session is None or self.session.closed:
            timeout = ClientTimeout(total=60, connect=30, sock_read=30)
            proxy = self._get_random_proxy()
            if proxy:
                connector = ProxyConnector.from_url(proxy)
            else:
                connector = TCPConnector(
                    limit=0,
                    limit_per_host=0,
                    keepalive_timeout=60,
                    enable_cleanup_closed=True,
                    force_close=False,
                    use_dns_cache=True,
                )
            self.session = ClientSession(
                timeout=timeout,
                connector=connector,
                headers={"User-Agent": self.base_headers["user-agent"]},
            )
        return self.session

    async def extract(self, url: str, **kwargs) -> dict:
        """Extract VixCloud URL."""
        request_headers = kwargs.get("request_headers") or self.request_headers or {}
        input_query = parse_qs(urlparse(url).query)
        self._raise_if_embed_expired(url)

        if "/playlist/" in url:
            referer = request_headers.get("Referer") or request_headers.get("referer")
            stream_headers = dict(self.base_headers)
            if referer:
                stream_headers["referer"] = referer
                parsed_ref = urlparse(referer)
                stream_headers["origin"] = f"{parsed_ref.scheme}://{parsed_ref.netloc}"
            cookie = request_headers.get("Cookie") or request_headers.get("cookie")
            if cookie:
                stream_headers["cookie"] = cookie
            return {
                "destination_url": url,
                "request_headers": stream_headers,
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }

        session = await self._get_session()
        headers = self._build_request_headers(url, request_headers)

        async with session.get(url, headers=headers) as response:
            html = await response.text()

        components = None
        if response.status != 403:
            components = self._extract_playlist_components(html)

        if components is None:
            try:
                browser_html, browser_playlist_url = await self._fetch_html_via_browser(
                    url, request_headers
                )
                components = self._extract_playlist_components(browser_html)
                html = browser_html
                if components is None and browser_playlist_url:
                    parsed_playlist = urlparse(browser_playlist_url)
                    query_params = parse_qs(parsed_playlist.query)
                    token = query_params.get("token", [None])[0]
                    expires = query_params.get("expires", [None])[0]
                    asn = query_params.get("asn", [None])[0]
                    playlist_url = (
                        f"{parsed_playlist.scheme}://{parsed_playlist.netloc}{parsed_playlist.path}"
                    )
                    if token and expires:
                        components = (playlist_url, token, expires, asn)
            except Exception as exc:
                if response.status == 403:
                    raise ExtractorError(
                        f"VixCloud extraction failed: upstream returned 403 Forbidden ({exc})"
                    ) from exc

        token_from_input = input_query.get("token", [None])[0]
        expires_from_input = input_query.get("expires", [None])[0]
        asn_from_input = input_query.get("asn", [None])[0]

        if components is None:
            if token_from_input and expires_from_input:
                playlist_url = self._build_embed_playlist_url(url)
                if playlist_url:
                    components = (
                        playlist_url,
                        token_from_input,
                        expires_from_input,
                        asn_from_input,
                    )
            if components is None:
                raise ExtractorError("VixCloud extraction failed: token/expires missing")

        playlist_url, token, expires, asn = components
        token = token or token_from_input
        expires = expires or expires_from_input
        asn = asn or asn_from_input

        if "/embed/" in url and not playlist_url:
            fallback_playlist_url = self._build_embed_playlist_url(url)
            if fallback_playlist_url:
                playlist_url = fallback_playlist_url

        if not token or not expires:
            raise ExtractorError(
                "VixCloud extraction failed: missing token/expires in both page and input URL"
            )

        separator = "&" if "?" in playlist_url else "?"
        final_url = (
            f"{playlist_url}{separator}token={token}"
            f"&expires={expires}"
        )
        if asn:
            final_url += f"&asn={asn}"

        if "window.canPlayFHD = true" in html and "canPlayFHD=1" not in final_url:
            final_url += "&h=1"
        elif input_query.get("canPlayFHD", ["0"])[0] == "1" and "canPlayFHD=1" not in final_url:
            final_url += "&h=1"

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        stream_headers = dict(self.base_headers)
        stream_headers["referer"] = url
        stream_headers["origin"] = origin
        cookie = request_headers.get("Cookie") or request_headers.get("cookie")
        if cookie:
            stream_headers["cookie"] = cookie

        return {
            "destination_url": urljoin(url, final_url),
            "request_headers": stream_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
