import base64
import json
import logging
import re
from urllib.parse import urljoin
from extractors.base import BaseExtractor, ExtractorError

logger = logging.getLogger(__name__)

class VoeExtractor(BaseExtractor):
    def __init__(self, request_headers: dict, proxies: list = None):
        super().__init__(request_headers, proxies, extractor_name="voe")

    async def extract(self, url: str, redirect_count: int = 0, **kwargs) -> dict:
        resp = await self._make_request(url)
        text = resp.text

        # See https://github.com/Gujal00/ResolveURL/blob/master/script.module.resolveurl/lib/resolveurl/plugins/voesx.py
        redirect_pattern = r'''window\.location\.href\s*=\s*'([^']+)'''
        redirect_match = re.search(redirect_pattern, text, re.DOTALL)
        if redirect_match:
            if redirect_count >= 5:
                raise ExtractorError("VOE: too many redirects")
            return await self.extract(redirect_match.group(1), redirect_count=redirect_count + 1)

        code_and_script_pattern = r'json">\["([^"]+)"]</script>\s*<script\s*src="([^"]+)'
        code_and_script_match = re.search(code_and_script_pattern, text, re.DOTALL)
        if code_and_script_match:
            return await self._extract_obfuscated(url, text, code_and_script_match)

        return await self._extract_direct(url, text)

    async def _extract_obfuscated(self, url: str, text: str, match: re.Match) -> dict:
        script_url = urljoin(url, match.group(2))
        resp_script = await self._make_request(script_url)
        script_text = resp_script.text

        luts_pattern = r"(\[(?:'\W{2}'[,\]]){1,9})"
        luts_match = re.search(luts_pattern, script_text, re.DOTALL)
        if not luts_match:
            raise ExtractorError("VOE: unable to locate LUTs in external script")

        data = self.voe_decode(match.group(1), luts_match.group(1))

        final_url = data.get('source')
        if not final_url:
            raise ExtractorError("VOE: failed to extract video URL")

        self.base_headers["referer"] = url
        return {
            "destination_url": final_url,
            "request_headers": self.base_headers,
            "mediaflow_endpoint": "hls_proxy",
        }

    async def _extract_direct(self, url: str, text: str) -> dict:
        # Check for var source = '...' (direct mp4)
        m = re.search(r"var\s+source\s*=\s*'([^']+)'", text)
        if m:
            final_url = m.group(1)
            self.base_headers["referer"] = url
            return {
                "destination_url": final_url,
                "request_headers": self.base_headers,
                "mediaflow_endpoint": "hls_proxy",
            }

        # Check for hls source
        m = re.search(r"""hls['"]:\s*['"]([^'"]+)""", text)
        if m:
            final_url = m.group(1)
            self.base_headers["referer"] = url
            return {
                "destination_url": final_url,
                "request_headers": self.base_headers,
                "mediaflow_endpoint": "hls_proxy",
            }

        # Check for mp4 source with height label
        m = re.search(r"""mp4['"]:\s*['"]([^'"]+)['"],\s*['"]video_height['"]:\s*(\d+)""", text)
        if m:
            final_url = m.group(1)
            self.base_headers["referer"] = url
            return {
                "destination_url": final_url,
                "request_headers": self.base_headers,
                "mediaflow_endpoint": "hls_proxy",
            }

        logger.warning(f"VOE: no pattern matched, html length={len(text)}, first 500 chars: {text[:500]}")
        raise ExtractorError("VOE: unable to locate obfuscated payload or external script URL")

    @staticmethod
    def voe_decode(ct: str, luts: str) -> dict:
        lut = [''.join([('\\' + x) if x in '.*+?^${}()|[]\\' else x for x in i]) for i in luts[2:-2].split("','")]
        txt = ''
        for i in ct:
            x = ord(i)
            if 64 < x < 91:
                x = (x - 52) % 26 + 65
            elif 96 < x < 123:
                x = (x - 84) % 26 + 97
            txt += chr(x)
        for i in lut:
            txt = re.sub(i, '', txt)
        ct = base64.b64decode(txt).decode('utf-8')
        txt = ''.join([chr(ord(i) - 3) for i in ct])
        txt = base64.b64decode(txt[::-1]).decode('utf-8')
        return json.loads(txt)

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()