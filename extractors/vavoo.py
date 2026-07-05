import asyncio
import logging
import re
import socket
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from typing import Optional, Dict, Any
from urllib.parse import urlparse, parse_qs
from config import get_connector_for_proxy
import config as _cfg

logger = logging.getLogger(__name__)

_RESOLVE_URL = "https://vavoo.to/mediahubmx-resolve.json"


class ExtractorError(Exception):
    pass


class VavooExtractor:
    """Vavoo URL extractor — resolves vavoo.to play URLs to clean HLS via lokke.app auth."""
    
    def __init__(self, request_headers: dict, proxies: list = None):
        self.request_headers = request_headers
        self.base_headers = {
            "user-agent": "okhttp/4.11.0"
        }
        self.session = None
        self._session_lock = asyncio.Lock()
        self.mediaflow_endpoint = "proxy_stream_endpoint"
        self.proxies = proxies or _cfg.GLOBAL_PROXIES
        self._proxy = None  # scelto una volta, non cambia

    async def _get_session(self):
        async with self._session_lock:
            if self.session is not None and not self.session.closed:
                return self.session

            if self._proxy is None and self.proxies:
                import random
                self._proxy = random.choice(self.proxies)

            timeout = ClientTimeout(total=60, connect=30, sock_read=30)

            if self._proxy:
                logger.debug(f"Using proxy for Vavoo session: {self._proxy}")
                connector = get_connector_for_proxy(self._proxy, family=socket.AF_INET)
            else:
                connector = TCPConnector(
                    limit=0,
                    limit_per_host=0,
                    keepalive_timeout=60,
                    enable_cleanup_closed=True,
                    force_close=False,
                    use_dns_cache=True,
                    family=socket.AF_INET
                )

            self.session = ClientSession(
                timeout=timeout,
                connector=connector,
                headers={'User-Agent': self.base_headers["user-agent"]}
            )
        return self.session

    async def _resolve_via_mediahubmx(self, url: str) -> Optional[str]:
        """Resolve vavoo URL to stream URL via mediahubmx-resolve.json (same-origin style)."""
        # Normalize /watch?live=X to /vavoo-iptv/play/X
        if "/watch" in url:
            params = parse_qs(urlparse(url).query)
            live_id = params.get('live', [None])[0]
            if live_id:
                url = f"https://vavoo.to/vavoo-iptv/play/{live_id}"

        # Normalize /play/X to /vavoo-iptv/play/X
        m = re.search(r'/play/([^/?#]+)', url)
        if m:
            url = f"https://vavoo.to/vavoo-iptv/play/{m.group(1)}"

        session = await self._get_session()
        headers = {
            "Origin": "https://vavoo.to",
            "Referer": "https://vavoo.to/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
            "Accept": "application/json",
            "Content-Type": "application/json; charset=utf-8",
        }
        body = {"language": "de", "region": "DE", "url": url}
        try:
            async with session.post(_RESOLVE_URL, json=body, headers=headers, timeout=ClientTimeout(total=12), ssl=False) as resp:
                if resp.status != 200:
                    logger.warning(f"Resolve returned status {resp.status}")
                    return None
                data = await resp.json()
                if isinstance(data, list) and data and data[0].get("url"):
                    return str(data[0]["url"])
                if isinstance(data, dict):
                    if data.get("url"):
                        return str(data["url"])
                    if data.get("data", {}).get("url"):
                        return str(data["data"]["url"])
                return None
        except Exception as e:
            logger.warning(f"Resolve exception: {e}")
            return None

    async def extract(self, url: str, **kwargs) -> Dict[str, Any]:
        if "vavoo.to" not in url:
            raise ExtractorError("Not a valid Vavoo URL")

        resolved_url = await self._resolve_via_mediahubmx(url)
        if not resolved_url:
            raise ExtractorError("Vavoo resolve failed")

        logger.info(f"Resolved via mediahubmx: {resolved_url[:80]}...")

        return {
            "destination_url": resolved_url,
            "request_headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Referer": "https://vavoo.to",
                "Origin": "https://vavoo.to",
                "X-EasyProxy-Disable-SSL": "1",
            },
            "mediaflow_endpoint": self.mediaflow_endpoint,
            "disable_ssl": True,
        }

    async def close(self):
        async with self._session_lock:
            if self.session and not self.session.closed:
                await self.session.close()
            self.session = None
