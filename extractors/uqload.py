import logging
import re
from urllib.parse import urljoin, urlparse
from extractors.base import BaseExtractor, ExtractorError

logger = logging.getLogger(__name__)

class UqloadExtractor(BaseExtractor):
    """Uqload URL extractor."""

    # Full browser-like headers required to bypass Cloudflare/bot checks on uqload
    BROWSER_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
    }

    # Regex patterns tried in order — first the exact mediaflow pattern, then flexible fallbacks
    SOURCE_PATTERNS = [
        r'sources: \["(.*?)"\]',                              # mediaflow exact — works on most uqload pages
        r'sources\s*:\s*\[\s*["\']([^"\']+)["\']',          # flexible spacing/quotes variant
        r'"?sources"?\s*:\s*\[\s*["\']([^"\']+)["\']',      # with optional quotes on key
        r'file\s*:\s*["\']([^"\']+\.mp4[^"\']*)["\']',      # fallback: file: "...mp4..."
        r'src\s*:\s*["\']([^"\']+\.mp4[^"\']*)["\']',       # src: "...mp4..."
        r'video_url\s*=\s*["\']([^"\']+)["\']',              # var video_url = "..."
        r'player\.src\s*\(\s*["\']([^"\']+)["\']',           # player.src("...")
        r'(?:https?://[a-z0-9.-]*uqload[a-z.]*)/[a-z0-9/]+\.mp4[^"\'<\s]*',  # raw mp4 URL on page
    ]

    def __init__(self, request_headers: dict, proxies: list = None):
        super().__init__(request_headers, proxies, extractor_name="uqload")
        self.mediaflow_endpoint = "proxy_stream_endpoint"

    async def extract(self, url: str, **kwargs) -> dict:
        """Extract Uqload video URL."""
        logger.debug(f"[Uqload] Fetching embed page: {url}")

        resp = await self._make_request(url, headers=self.BROWSER_HEADERS)
        text = resp.text
        final_url = resp.url

        logger.debug(f"[Uqload] Page length: {len(text)} chars, final URL: {final_url}")

        # Check for common error pages
        text_lower = text.lower()
        if (
            "file was deleted" in text_lower
            or "file not found" in text_lower
            or "not found" in text_lower
            or "no longer available" in text_lower
            or "has been deleted" in text_lower
        ):
            raise ExtractorError(f"Uqload video removed/not found: {url}")

        video_url = None
        for i, pattern in enumerate(self.SOURCE_PATTERNS):
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                video_url = m.group(1).strip() if m.lastindex else m.group(0).strip()
                logger.debug(f"[Uqload] Pattern #{i} matched: {video_url[:80]}...")
                break

        if not video_url:
            # Log more context to help debug
            logger.warning(f"[Uqload] No pattern matched for {url}")
            logger.warning(f"[Uqload] Page title: {re.search(r'<title>(.*?)</title>', text, re.I)}")
            logger.warning(f"[Uqload] Page snippet (first 500): {text[:500]!r}")
            # Also log any script blocks that might contain the video URL
            scripts = re.findall(r'<script[^>]*>(.*?)</script>', text, re.DOTALL | re.IGNORECASE)
            for idx, script in enumerate(scripts):
                if 'source' in script.lower() or 'file' in script.lower() or '.mp4' in script.lower():
                    logger.warning(f"[Uqload] Relevant script #{idx}: {script[:300]!r}")
            raise ExtractorError(f"Failed to extract video URL from uqload page: {url}")

        origin = urljoin(url, "/")
        return {
            "destination_url": video_url,
            "request_headers": {
                "user-agent": self.BROWSER_HEADERS["User-Agent"],
                "referer": origin,
                "origin": origin,
            },
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
