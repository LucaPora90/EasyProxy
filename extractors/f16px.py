import re
import base64
import json
from urllib.parse import urlparse
from extractors.base import BaseExtractor, ExtractorError
from utils import python_aesgcm

class F16PxExtractor(BaseExtractor):
    """F16Px URL extractor with AES-GCM decryption support."""

    def __init__(self, request_headers: dict, proxies: list = None):
        super().__init__(request_headers, proxies, extractor_name="f16px")

    @staticmethod
    def _b64url_decode(value: str) -> bytes:
        """Decode base64url to bytes."""
        # base64url -> base64
        value = value.replace("-", "+").replace("_", "/")
        padding = (-len(value)) % 4
        if padding:
            value += "=" * padding
        return base64.b64decode(value)

    def _join_key_parts(self, parts) -> bytes:
        """Join multiple base64url-encoded key parts into a single key."""
        return b"".join(self._b64url_decode(p) for p in parts)

    async def extract(self, url: str, **kwargs) -> dict:
        """Extract F16Px URL."""
        parsed = urlparse(url)
        host = parsed.netloc
        origin = f"{parsed.scheme}://{parsed.netloc}"

        match = re.search(r"/e/([A-Za-z0-9]+)", parsed.path or "")
        if not match:
            raise ExtractorError("F16PX: Invalid embed URL")

        media_id = match.group(1)
        api_url = f"https://{host}/api/videos/{media_id}/embed/playback"

        headers = self.base_headers.copy()
        headers["referer"] = f"https://{host}/"

        resp = await self._make_request(api_url, headers=headers)
        try:
            data = json.loads(resp.text)
        except Exception:
            raise ExtractorError("F16PX: Invalid JSON response")

        # Case 1: plain sources
        if "sources" in data and data["sources"]:
            src = data["sources"][0].get("url")
            if not src:
                raise ExtractorError("F16PX: Empty source URL")
            return {
                "destination_url": src,
                "request_headers": headers,
                "mediaflow_endpoint": self.mediaflow_endpoint,
            }

        # Case 2: encrypted playback
        pb = data.get("playback")
        if not pb:
            raise ExtractorError("F16PX: No playback data")

        try:
            iv = self._b64url_decode(pb["iv"])  # nonce
            key = self._join_key_parts(pb["key_parts"])  # AES key
            payload = self._b64url_decode(pb["payload"])  # ciphertext + tag

            cipher = python_aesgcm.new(key)
            decrypted = cipher.open(iv, payload)  # AAD = '' like ResolveURL

            if decrypted is None:
                raise ExtractorError("F16PX: GCM authentication failed")

            decrypted_json = json.loads(decrypted.decode("utf-8", "ignore"))

        except ExtractorError:
            raise
        except Exception as e:
            raise ExtractorError(f"F16PX: Decryption failed ({e})")

        sources = decrypted_json.get("sources") or []
        if not sources:
            raise ExtractorError("F16PX: No sources after decryption")

        best = sources[0].get("url")
        if not best:
            raise ExtractorError("F16PX: Empty source URL after decryption")

        self.base_headers.clear()
        self.base_headers["referer"] = f"{origin}/"
        self.base_headers["origin"] = origin
        self.base_headers["Accept-Language"] = "en-US,en;q=0.5"
        self.base_headers["Accept"] = "*/*"
        self.base_headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0"

        return {
            "destination_url": best,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
