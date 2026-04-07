import logging
import random
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from aiohttp_socks import ProxyConnector
from utils.packed import eval_solver

logger = logging.getLogger(__name__)

class ExtractorError(Exception):
    pass

class MixdropExtractor:
    """Mixdrop URL extractor."""

    def __init__(self, request_headers: dict, proxies: list = None):
        self.request_headers = request_headers
        self.base_headers = {
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        }
        self.session = None
        self.mediaflow_endpoint = "proxy_stream_endpoint"
        self.proxies = proxies or []

    def _get_random_proxy(self):
        return random.choice(self.proxies) if self.proxies else None

    async def _get_session(self):
        if self.session is None or self.session.closed:
            timeout = ClientTimeout(total=60, connect=30, sock_read=30)
            proxy = self._get_random_proxy()
            if proxy:
                connector = ProxyConnector.from_url(proxy)
            else:
                connector = TCPConnector(limit=0, limit_per_host=0, keepalive_timeout=60, enable_cleanup_closed=True, force_close=False, use_dns_cache=True)

            self.session = ClientSession(timeout=timeout, connector=connector, headers={'User-Agent': self.base_headers["user-agent"]})
        return self.session

    async def extract(self, url: str, **kwargs) -> dict:
        """Extract Mixdrop URL."""
        # Normalize URL to .ps domain and remove trailing segments
        if "club" in url:
            url = url.replace("club", "ps").split("/2")[0]
        elif "ag" in url:
            url = url.replace("ag", "ps").split("/2")[0]
        elif any(domain in url for domain in ["mdy48tn97.com", "mixdrop.to", "mixdrop.co", "m1xdrop.net"]):
            # Handle alternative domains
            for domain in ["mdy48tn97.com", "mixdrop.to", "mixdrop.co", "m1xdrop.net"]:
                if domain in url:
                    url = url.replace(domain, "mixdrop.ps").split("/2")[0]
                    break

        headers = {"accept-language": "en-US,en;q=0.5", "referer": url}
        
        # Multiple patterns to try in order of likelihood
        patterns = [
            r'MDCore.wurl ?= ?\"(.*?)\"',  # Primary pattern
            r'wurl ?= ?\"(.*?)\"',          # Simplified pattern
            r'src: ?\"(.*?)\"',             # Alternative pattern
            r'file: ?\"(.*?)\"',            # Another alternative
            r'https?://[^\"\']+\.mp4[^\"\']*'  # Direct MP4 URL pattern
        ]

        session = await self._get_session()
        
        try:
            final_url = await eval_solver(session, url, headers, patterns)
            
            # Validate extracted URL
            if not final_url or len(final_url) < 10:
                raise ExtractorError(f"Extracted URL appears invalid: {final_url}")
            
            logger.info(f"Successfully extracted Mixdrop URL: {final_url[:50]}...")
            
            self.base_headers["referer"] = url
            return {
                "destination_url": final_url,
                "request_headers": self.base_headers,
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }
        except Exception as e:
            error_message = str(e)
            # Per errori di video non trovato, non loggare il traceback perché sono errori attesi
            if "not found" in error_message.lower() or "unavailable" in error_message.lower():
                logger.warning(f"Mixdrop video not available at {url}: {error_message}")
            else:
                logger.error(f"Failed to extract Mixdrop URL from {url}: {error_message}")
            raise ExtractorError(f"Mixdrop extraction failed: {str(e)}") from e

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
