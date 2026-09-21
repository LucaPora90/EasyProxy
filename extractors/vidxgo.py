"""
VidXgo extractor.

Decodes the obfuscated player at v.vidxgo.co / vidxgo.* and returns the master
HLS playlist. CDN signed URLs on the .ts segments have a ~5 min TTL. Always
re-fetches the embed page on each extract() call to get fresh tokens.
"""

import base64
import logging
import re
from urllib.parse import urlparse, parse_qs, unquote

import config as _cfg
from config import get_ordered_proxies_for_url, should_allow_direct_fallback

logger = logging.getLogger(__name__)


class ExtractorError(Exception):
    pass



def _parse_e_expiry(url: str) -> float | None:
    """Extract the `e=` ms-epoch param from a signed VidXgo CDN URL."""
    try:
        qs = urlparse(url).query
        raw = parse_qs(qs).get("e", [None])[0]
        if not raw:
            return None
        return float(raw) / 1000.0
    except Exception:
        return None

# Hardcoded playback domain for CDN Referer/Origin headers.
DEFAULT_PLAYBACK_DOMAIN = "https://v.vidxgo.co"

# Header used during the embed page fetch. The site is currently strict about
# this referer; sending the playback origin instead yields an empty body.
EMBED_FETCH_REFERER = "https://v.vidxgo.co/"

# Pattern that locates the obfuscated block:
#   var X='KEY',d=atob('B64PAYLOAD'),...
_OBFUSCATED_RE = re.compile(
    r"var\s+\w+\s*=\s*'([^']*)'\s*,\s*d\s*=\s*atob\(\s*'([^']*)'",
    re.S,
)
# Pattern that locates the resolved m3u8 inside the decoded payload.
_CURRENT_SRC_RE = re.compile(
    r'\bcurrentSrc\s*=\s*["\'](https?:[^"\']+?\.m3u8[^"\']*)["\']',
    re.S,
)
# All <script> tags, capturing their inner contents.
_SCRIPT_TAG_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.S | re.I)


class VidXgoExtractor:
    """VidXgo embed -> HLS extractor with auto-refresh manifest."""

    def __init__(self, request_headers: dict, proxies: list = None, extractor_name: str = "vidxgo"):
        self.request_headers = request_headers or {}
        self.extractor_name = extractor_name
        self.proxies = proxies or []
        self.selected_proxy = None
        self.session = None
        self._curl_session = None
        self._curl_impersonate = None
        self.mediaflow_endpoint = "hls_proxy"

        # Headers used for fetching the embed page.
        # NOTE: the host enforces presence of Sec-Fetch-* headers; without them
        # it returns a 403 "blocked" HTML page even with the right Referer.
        self.embed_headers = {
            "user-agent": (
                "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) "
                "Gecko/20100101 Firefox/150.0"
            ),
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "it-IT,it;q=0.9,en;q=0.8",
            "referer": EMBED_FETCH_REFERER,
            "sec-fetch-dest": "iframe",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "same-origin",
            "sec-fetch-storage-access": "active",
            "upgrade-insecure-requests": "1",
        }

        # Headers used by EP when fetching the m3u8 + segments from the CDN.
        # These are also returned to the player as the per-stream headers.
        # NOTE: the CDN (cdn.v1.media-*.d2b.you) also enforces Sec-Fetch-*
        # validation; without them every signed URL returns 403.
        self.playback_headers = {
            "user-agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/139.0.0.0 Safari/537.36"
            ),
            "accept": "*/*",
            "accept-language": "it-IT,it;q=0.9,en;q=0.8",
            "referer": f"{DEFAULT_PLAYBACK_DOMAIN}/",
            "origin": DEFAULT_PLAYBACK_DOMAIN,
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "cross-site",
        }

    # ------------------------------------------------------------------ proxies

    @staticmethod
    def _normalize_proxy_url(proxy_value: str) -> str:
        proxy_value = unquote(proxy_value).strip()
        # WARP is local-DNS SOCKS5. Do not turn it into socks5h: wireproxy
        # remote DNS is the source of the observed timeout.
        if proxy_value.startswith("socks5://"):
            return proxy_value
        if proxy_value.startswith("socks4a://"):
            return proxy_value.replace("socks4a://", "socks4://", 1)
        return proxy_value

    def _get_proxies_for_url(self, url: str, bypass_warp: bool = False) -> list[str]:
        return get_ordered_proxies_for_url(
            url,
            self.extractor_name,
            self.proxies,
            bypass_warp=bypass_warp,
        )

    # ------------------------------------------------------------------ fetch

    async def _get_curl_session(self, proxy_url=None, impersonate="chrome124"):
        """Reuse the curl_cffi connection pool during one extraction."""
        curl_options = _cfg.get_curl_ipv4_options(proxy_url).get("curl_options") or {}
        if self._curl_session is None or self._curl_impersonate != impersonate:
            if self._curl_session is not None:
                await self._curl_session.close()
            try:
                from curl_cffi.requests import AsyncSession as CurlAsyncSession
            except ImportError as exc:
                raise ExtractorError("VidXgo: curl_cffi is required") from exc
            self._curl_session = CurlAsyncSession(
                impersonate=impersonate,
                curl_options=curl_options,
            )
            self._curl_impersonate = impersonate
        else:
            self._curl_session.curl_options = curl_options
        return self._curl_session

    async def _fetch(self, url: str, headers: dict, bypass_warp: bool = False) -> str:
        """GET `url` through the configured network routes."""
        paths = self._get_proxies_for_url(url, bypass_warp=bypass_warp)
        if should_allow_direct_fallback(paths, bypass_warp=bypass_warp):
            paths.append(None)
        logger.info(
            "vidxgo fetch routes for %s: %s",
            url,
            ", ".join(proxy or "direct" for proxy in paths) or "none",
        )
        curl_headers = {
            key: value for key, value in headers.items()
            if key.lower() != "user-agent"
        }
        last_error = None
        for impersonate in ("chrome131", "chrome124", "chrome120"):
            for proxy in paths:
                proxy_url = self._normalize_proxy_url(proxy) if proxy else None
                request_kwargs = {
                    "proxies": {"http": proxy_url, "https": proxy_url}
                } if proxy_url else {}
                try:
                    logger.info(
                        "vidxgo curl fetch via %s for %s (imp=%s)",
                        proxy_url or "direct",
                        url,
                        impersonate,
                    )
                    session = await self._get_curl_session(proxy_url, impersonate)
                    resp = await session.get(
                        url,
                        headers=curl_headers,
                        timeout=25,
                        verify=False,
                        allow_redirects=True,
                        **request_kwargs,
                    )
                    if 200 <= resp.status_code < 300:
                        self.selected_proxy = proxy_url
                        return resp.text
                    last_error = ExtractorError(
                        f"curl_cffi HTTP {resp.status_code} via {proxy_url or 'direct'}"
                    )
                except Exception as e:
                    last_error = e
                    logger.debug(
                        "vidxgo curl fetch failed via %s (imp=%s): %s",
                        proxy_url or "direct",
                        impersonate,
                        e,
                    )

        if last_error:
            raise ExtractorError(f"VidXgo: fetch failed for {url}: {last_error}")
        raise ExtractorError(f"VidXgo: fetch failed for {url}: {last_error}")

    # ------------------------------------------------------------------ decode

    @staticmethod
    def _decode_embed(html: str) -> str:
        """Reproduce the TS decoder: script[5] -> XOR(key, atob(payload)) -> m3u8."""
        scripts = _SCRIPT_TAG_RE.findall(html or "")
        # The obfuscated block is historically at index 5; fall back to scanning
        # all scripts if the layout changes.
        candidates: list[str] = []
        if len(scripts) > 5:
            candidates.append(scripts[5])
        candidates.extend(s for i, s in enumerate(scripts) if i != 5)

        for script in candidates:
            m = _OBFUSCATED_RE.search(script)
            if not m:
                continue
            key = m.group(1)
            b64_payload = m.group(2)
            if not key or not b64_payload:
                continue
            try:
                decoded = base64.b64decode(b64_payload)
            except Exception:
                continue
            key_bytes = key.encode("utf-8")
            klen = len(key_bytes)
            if klen == 0:
                continue
            xored = bytes(b ^ key_bytes[i % klen] for i, b in enumerate(decoded))
            try:
                decoded_str = xored.decode("utf-8", errors="ignore")
            except Exception:
                continue
            cm = _CURRENT_SRC_RE.search(decoded_str)
            if cm:
                return cm.group(1).replace("\\", "")
        if "player-container" in html and "corrupt" in html:
            raise ExtractorError("VidXgo: source is marked corrupt or not available")
        raise ExtractorError("VidXgo: could not locate currentSrc m3u8 in any decoded script")

    # ------------------------------------------------------------------ public API

    async def extract(self, url: str, **kwargs) -> dict:
        """
        Extract the HLS playlist for a VidXgo embed page.

        `url` is the embed URL, e.g. https://v.vidxgo.co/tt1234567 or
        https://v.vidxgo.co/tt1234567/1/2 for series.
        """
        force_refresh = bool(kwargs.get("force_refresh"))
        background_refresh = bool(kwargs.get("background_refresh"))
        request_headers = kwargs.get("request_headers") or {}

        vd_domain = DEFAULT_PLAYBACK_DOMAIN
        playback_headers = {
            **self.playback_headers,
            "referer": f"{vd_domain}/",
"origin": vd_domain,
        }

        bypass_warp = bool(kwargs.get("bypass_warp"))
        # 1. Fetch embed page.
        embed_headers = {**self.embed_headers, **{k.lower(): v for k, v in request_headers.items() if k.lower() == "cookie"}}
        html = await self._fetch(url, embed_headers, bypass_warp=bypass_warp)
        if not html:
            raise ExtractorError(f"VidXgo: empty embed page for {url}")

        # 2. Decode.
        m3u8_url = self._decode_embed(html)
        logger.info(f"vidxgo: extracted m3u8 for {url} -> {m3u8_url[:80]}...")

        # 3. Fetch the master. Variant selection (all variants or only the
        # highest one) is decided by the proxy rewriter via max_res.
        master_text = await self._fetch(m3u8_url, playback_headers, bypass_warp=bypass_warp)
        if "#EXTM3U" not in master_text:
            raise ExtractorError("VidXgo: extracted URL did not return a valid HLS manifest")

        captured_map: dict[str, str] = {m3u8_url: master_text}
        if force_refresh:
            # Segment recovery needs media playlists, not just the master.
            from urllib.parse import urljoin

            pending = [(m3u8_url, master_text)]
            seen = {m3u8_url}
            while pending and len(seen) < 16:
                parent_url, manifest = pending.pop(0)
                variant_next = False
                for line in manifest.splitlines():
                    line = line.strip()
                    child = None
                    if line.startswith("#EXT-X-STREAM-INF:"):
                        variant_next = True
                        continue
                    if line.startswith("#EXT-X-MEDIA:"):
                        match = re.search(r'URI="([^"]+)"', line)
                        child = match.group(1) if match else None
                    elif line and not line.startswith("#"):
                        if variant_next:
                            child = line
                        variant_next = False
                    if not child:
                        continue
                    child_url = urljoin(parent_url, child)
                    if child_url in seen or len(seen) >= 16:
                        continue
                    seen.add(child_url)
                    try:
                        child_text = await self._fetch(child_url, playback_headers, bypass_warp=bypass_warp)
                    except Exception as exc:
                        logger.debug("VidXgo recovery playlist fetch failed: %s", exc)
                        continue
                    if "#EXTM3U" in child_text:
                        captured_map[child_url] = child_text
                        pending.append((child_url, child_text))

        result = {
            "destination_url": m3u8_url,
            "request_headers": playback_headers,
            "captured_manifest": master_text,
            "captured_manifests": captured_map,
            "mediaflow_endpoint": self.mediaflow_endpoint,
            "selected_proxy": self.selected_proxy,
            "disable_ssl": True,
        }
        return result

    async def close(self):
        if self._curl_session is not None:
            try:
                await self._curl_session.close()
            except Exception:
                pass
            self._curl_session = None
            self._curl_impersonate = None
        if self.session and not self.session.closed:
            await self.session.close()
