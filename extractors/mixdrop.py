import asyncio
import logging
import re
import time
import base64
import os
from urllib.parse import urlparse, urljoin, urlencode

import aiohttp
from bs4 import BeautifulSoup, SoupStrainer
from aiohttp_socks import ProxyConnector

from config import (
    FLARESOLVERR_URL, 
    FLARESOLVERR_TIMEOUT, 
    get_proxy_for_url, 
    TRANSPORT_ROUTES, 
    get_solver_proxy_url, 
    GLOBAL_PROXIES,
    get_connector_for_proxy
)
from utils.cookie_cache import CookieCache
from utils.solver_manager import solver_manager
from utils.proxy_manager import FreeProxyManager

logger = logging.getLogger(__name__)

class ExtractorError(Exception):
    pass

class Settings:
    flaresolverr_url = FLARESOLVERR_URL
    flaresolverr_timeout = FLARESOLVERR_TIMEOUT

settings = Settings()

class MixdropExtractor:
    _result_cache = {} # {(url, bypass_warp): (result, timestamp)}

    def __init__(self, request_headers: dict = None, proxies: list = None, bypass_warp: bool = False):
        self.request_headers = request_headers or {}
        self.base_headers = self.request_headers.copy()
        if "User-Agent" not in self.base_headers and "user-agent" not in self.base_headers:
             self.base_headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        self.proxies = proxies or GLOBAL_PROXIES
        self.cookie_cache = CookieCache("universal")
        self.mediaflow_endpoint = "proxy_stream_endpoint"
        self.bypass_warp_active = bypass_warp
        self.session = None
        self.proxy_manager = FreeProxyManager.get_instance(
            "mixdrop",
            [
                "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/all/data.txt",
                "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text",
                "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
                "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
                "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
                "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
                "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
                "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies.txt",
                "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
                "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt",
                "https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt",
                "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
                "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt"
            ]
        )

    async def _get_session(self, proxy: str = None) -> aiohttp.ClientSession:
        """Create a session, optionally with a proxy connector."""
        connector = None
        if proxy:
            connector = get_connector_for_proxy(proxy)
        
        if proxy:
            return aiohttp.ClientSession(headers=self.base_headers, connector=connector)
            
        if self.session is None or self.session.closed:
            self.session = aiohttp.ClientSession(headers=self.base_headers)
        return self.session

    async def _request_flaresolverr(self, cmd: str, url: str = None, post_data: str = None, session_id: str = None, wait: int = 0, headers: dict | None = None) -> dict:
        endpoint = f"{settings.flaresolverr_url.rstrip('/')}/v1"
        payload = {"cmd": cmd, "maxTimeout": (settings.flaresolverr_timeout + 60) * 1000}
        if wait > 0: payload["wait"] = wait
        fs_headers = {}
        if url: 
            payload["url"] = url
            proxy = get_proxy_for_url(url, TRANSPORT_ROUTES, self.proxies, bypass_warp=self.bypass_warp_active)
            if proxy:
                payload["proxy"] = {"url": proxy}
                fs_headers["X-Proxy-Server"] = get_solver_proxy_url(proxy)
        if post_data: payload["postData"] = post_data
        if session_id: payload["session"] = session_id
        if headers: payload["headers"] = headers
        async with aiohttp.ClientSession() as fs_session:
            async with fs_session.post(endpoint, json=payload, headers=fs_headers, timeout=settings.flaresolverr_timeout + 95) as resp:
                data = await resp.json()
        if data.get("status") != "ok": raise ExtractorError(f"FlareSolverr: {data.get('message')}")
        return data

    def _step_headers(self, ua: str, referer: str | None = None) -> dict:
        headers = {"User-Agent": ua}
        if referer:
            headers["Referer"] = referer
        return headers

    async def _light_fetch(
        self,
        headers: dict,
        cookies: dict,
        session_id: str,
        target_url: str,
        post_data: dict | None = None,
        referer: str | None = None,
        force_flaresolverr: bool = False,
    ) -> tuple[str | None, str]:
        request_headers = dict(headers)
        if referer:
            request_headers["Referer"] = referer
            
        if force_flaresolverr:
            try:
                fs_cmd = "request.post" if post_data else "request.get"
                fs_res = await self._request_flaresolverr(fs_cmd, target_url, urlencode(post_data) if post_data else None, session_id=session_id, headers=request_headers)
                sol = fs_res.get("solution", {})
                cookies.update({c["name"]: c["value"] for c in sol.get("cookies", [])})
                return sol.get("response", ""), sol.get("url", target_url)
            except Exception:
                return None, target_url

        # Determine initial preferred proxy (WARP/Route)
        preferred_proxy = get_proxy_for_url(target_url, TRANSPORT_ROUTES, self.proxies, self.bypass_warp_active)
        
        attempts = []
        if preferred_proxy:
            attempts.append(preferred_proxy)
        attempts.append(None) # Direct
        
        for p in attempts:
            try:
                async with await self._get_session(proxy=p) as session:
                    if post_data:
                        async with session.post(target_url, data=post_data, cookies=cookies, headers=request_headers, timeout=12) as r:
                            text = await r.text()
                            if r.status == 200 and not any(m in text.lower() for m in ["cf-challenge", "ray id", "checking your browser"]):
                                cookies.update({k: v.value for k, v in r.cookies.items()})
                                return text, str(r.url)
                    else:
                        async with session.get(target_url, cookies=cookies, headers=request_headers, timeout=12) as r:
                            text = await r.text()
                            if r.status == 200 and not any(m in text.lower() for m in ["cf-challenge", "ray id", "checking your browser"]):
                                cookies.update({k: v.value for k, v in r.cookies.items()})
                                return text, str(r.url)
            except Exception as e:
                logger.debug(f"Attempt with proxy {p} failed: {e}")
                continue

        # Fallback to Free Proxies
        try:
            if any(d in target_url.lower() for d in ["safego.cc", "clicka.cc", "clicka", "uprot.net"]):
                free_proxies = await self.proxy_manager.get_proxies(lambda x: True)
                for p in free_proxies[:2]:
                    try:
                        async with await self._get_session(proxy=p) as free_session:
                            if post_data:
                                async with free_session.post(target_url, data=post_data, cookies=cookies, headers=request_headers, timeout=15) as r:
                                    if r.status == 200:
                                        cookies.update({k: v.value for k, v in r.cookies.items()})
                                        return await r.text(), str(r.url)
                            else:
                                async with free_session.get(target_url, cookies=cookies, headers=request_headers, timeout=15) as r:
                                    if r.status == 200:
                                        cookies.update({k: v.value for k, v in r.cookies.items()})
                                        return await r.text(), str(r.url)
                    except: continue
        except Exception as pe:
            logger.debug(f"Free proxy error: {pe}")

        # Final Fallback to FlareSolverr
        try:
            fs_cmd = "request.post" if post_data else "request.get"
            fs_res = await self._request_flaresolverr(fs_cmd, target_url, urlencode(post_data) if post_data else None, session_id=session_id, headers=request_headers)
            sol = fs_res.get("solution", {})
            cookies.update({c["name"]: c["value"] for c in sol.get("cookies", [])})
            return sol.get("response", ""), sol.get("url", target_url)
        except Exception:
            return None, target_url

    def _unpack(self, packed_js: str) -> str:
        try:
            match = re.search(r'}\(\'(.*)\',(\d+),(\d+),\'(.*)\'\.split\(\'\|\'\)', packed_js)
            if not match:
                match = re.search(r'\}\(([\s\S]*?),\s*(\d+),\s*(\d+),\s*\'([\s\S]*?)\'\.split\(\'\|\'\)', packed_js)
            if not match: return packed_js
            p, a, c, k = match.groups()
            p = p.strip("'\"")
            a, c, k = int(a), int(c), k.split('|')
            def e(c):
                res = ""
                if c >= a: res = e(c // a)
                return res + "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"[c % a]
            d = {e(i): (k[i] if k[i] else e(i)) for i in range(c)}
            for i in range(c):
                if str(i) not in d: d[str(i)] = k[i] if k[i] else str(i)
            return re.sub(r'\b(\w+)\b', lambda m: d.get(m.group(1), m.group(1)), p)
        except Exception as e:
            logger.debug(f"Unpack failed: {e}")
            return packed_js

    async def extract(self, url: str, **kwargs) -> dict:
        normalized_url = url.strip().replace(" ", "%20")
        cache_key = (normalized_url, self.bypass_warp_active)
        if cache_key in MixdropExtractor._result_cache:
            result, timestamp = MixdropExtractor._result_cache[cache_key]
            if time.time() - timestamp < 600:
                logger.info(f"🚀 [Cache Hit] Using cached extraction result for: {normalized_url}")
                return result

        logger.info(f"🔍 [Cache Miss] Extracting new link for: {normalized_url}")
        proxy = get_proxy_for_url(normalized_url, TRANSPORT_ROUTES, self.proxies, self.bypass_warp_active)
        is_redirector_url = any(d in normalized_url.lower() for d in ["safego.cc", "clicka.cc", "clicka", "uprot.net"])
        redirect_session_id = await solver_manager.get_persistent_session("redirector:clicka-safego", proxy) if is_redirector_url else None
        final_session_id = await solver_manager.get_persistent_session("mixdrop", proxy)
        session_id = redirect_session_id or final_session_id
        is_persistent = True
        try:
            ua, cookies = self.base_headers.get("User-Agent"), {}
            if is_redirector_url:
                url, ua, cookies = await self._solve_redirector_hybrid(url, session_id)

            session_id = final_session_id
            if "/f/" in url: url = url.replace("/f/", "/e/")
            if "/mix/" in url: url = url.replace("/mix/", "/e/")
            
            mirrors = [
                url,
                url.replace("mixdrop.co", "mixdrop.vip"),
                url.replace("mixdrop.co", "m1xdrop.bz"),
                url.replace("mixdrop.co", "mixdrop.ch"),
                url.replace("mixdrop.co", "mixdrop.ps"),
                url.replace("mixdrop.co", "mixdrop.ag"),
            ]
            
            for current_url in mirrors:
                try:
                    headers = self._step_headers(ua, current_url)
                    for _ in range(2):
                        html, ua_res = None, ua
                        
                        # 1. Preferred Proxy / Direct
                        pref_p = get_proxy_for_url(current_url, TRANSPORT_ROUTES, self.proxies, self.bypass_warp_active)
                        try:
                            async with await self._get_session(proxy=pref_p) as session:
                                async with session.get(current_url, cookies=cookies, headers=headers, timeout=8) as r:
                                    if r.status == 200: html = await r.text()
                        except: pass

                        # 2. FlareSolverr Fallback
                        if not html or "Cloudflare" in html or "robot" in html.lower():
                            res = await self._request_flaresolverr("request.get", current_url, session_id=session_id, wait=0, headers=headers)
                            solution = res.get("solution", {})
                            html, ua_res = solution.get("response", ""), solution.get("userAgent", ua)
                            headers["User-Agent"] = ua_res
                            cookies.update({c["name"]: c["value"] for c in solution.get("cookies", [])})
                        
                        if "robot" in html.lower() and "captcha" in html.lower():
                            soup = BeautifulSoup(html, "lxml")
                            form = soup.find("form")
                            if form:
                                post_fields = {inp.get("name"): inp.get("value", "") for inp in form.find_all("input") if inp.get("name")}
                                if post_fields:
                                    html, current_url = await self._light_fetch(headers, cookies, session_id, current_url, post_data=post_fields, referer=current_url)
                                    if not html: break
                        
                        if "eval(function(p,a,c,k,e,d)" in html:
                            for block in re.findall(r'eval\(function\(p,a,c,k,e,d\).*?\}\(.*\)\)', html, re.S):
                                html += "\n" + self._unpack(block)

                        patterns = [
                            r'(?:MDCore|vsConfig)\.wurl\s*=\s*["\']([^"\']+)["\']', 
                            r'source\s*src\s*=\s*["\']([^"\']+)["\']', 
                            r'file:\s*["\']([^"\']+)["\']', 
                            r'["\'](https?://[^\s"\']+\.(?:mp4|m3u8)[^\s"\']*)["\']',
                            r'wurl\s*:\s*["\']([^"\']+)["\']'
                        ]
                        for p in patterns:
                            match = re.search(p, html)
                            if match:
                                v_url = match.group(1)
                                if v_url.startswith("//"): v_url = "https:" + v_url
                                result = self._build_result(v_url, current_url, ua_res, cookies=cookies)
                                MixdropExtractor._result_cache[cache_key] = (result, time.time())
                                return result

                        soup = BeautifulSoup(html, "lxml")
                        iframe = soup.find("iframe", src=re.compile(r'/e/|/emb', re.I))
                        if iframe:
                            current_url = urljoin(current_url, iframe["src"])
                            continue
                        break
                except Exception as e:
                    logger.debug(f"Mirror {current_url} failed: {e}")
                    continue

            raise ExtractorError("Mixdrop: Video source not found")
        finally:
            if redirect_session_id:
                await solver_manager.release_session(redirect_session_id, is_persistent)
            if final_session_id and final_session_id != redirect_session_id:
                await solver_manager.release_session(final_session_id, is_persistent)

    async def _solve_redirector_hybrid(self, url: str, session_id: str) -> tuple:
        res = await self._request_flaresolverr("request.get", url, session_id=session_id, headers=self._step_headers(self.base_headers.get("User-Agent"), url))
        solution = res.get("solution", {})
        ua, cookies = solution.get("userAgent"), {c["name"]: c["value"] for c in solution.get("cookies", [])}
        html, current_url = solution.get("response", ""), solution.get("url", url)
        
        headers = self._step_headers(ua, url)
        use_flaresolverr_only = True

        for step in range(8):
            if not any(d in current_url.lower() for d in ["safego.cc", "clicka.cc", "clicka", "uprot.net"]): break
            soup = BeautifulSoup(html, "lxml")
            
            # 1. Handle CAPTCHA if present
            img_tag = soup.find("img", src=re.compile(r'data:image/png;base64,|captcha\.php'))
            if img_tag:
                logger.info(f"🧩 Numeric captcha detected on {current_url[:40]}...")
                import ddddocr
                ocr = ddddocr.DdddOcr(show_ad=False)
                captcha_data = None
                if "base64," in img_tag["src"]:
                    try: captcha_data = base64.b64decode(img_tag["src"].split(",")[1])
                    except: pass
                else:
                    captcha_data = await self._binary_fetch(urljoin(current_url, img_tag["src"]), session_id, ua, current_url, cookies)

                if captcha_data:
                    captcha = re.sub(r'[^0-9]', '', ocr.classification(captcha_data)).replace('o','0').replace('l','1')
                    logger.info(f"🤖 OCR Prediction: {captcha}")
                    form = soup.find("form")
                    post_fields = {inp.get("name"): inp.get("value", "") for inp in form.find_all("input") if inp.get("name")} if form else {}
                    for key in ["code", "captch5", "captcha"]:
                        if key in post_fields or (form and form.find("input", {"name": key})):
                            post_fields[key] = captcha
                            break
                    else: post_fields["code"] = captcha
                    
                    await asyncio.sleep(3.0) 
                    html, current_url = await self._light_fetch(headers, cookies, session_id, current_url, post_data=post_fields, referer=current_url, force_flaresolverr=use_flaresolverr_only)
                    if not html: break
                    soup = BeautifulSoup(html, "lxml")
                    headers["Referer"] = current_url
                    if current_url and any(d in current_url.lower() for d in ["safego.cc", "clicka.cc", "clicka", "uprot.net"]):
                        use_flaresolverr_only = True
                    logger.info(f"✅ Captcha submitted, current URL: {current_url}")
                    
                    if soup.find("img", src=re.compile(r'data:image/png;base64,|captcha\.php')):
                        logger.warning("⚠️ Captcha still present after submission, retrying solver...")
                        continue
                else:
                    logger.warning("❌ Failed to download captcha image.")

            # 2. Handle buttons
            next_url = None
            button_markers = ["proceed", "continue", "prosegui", "avanti", "click here", "clicca qui", "step", "passaggio", "vai al"]
            
            for attempt in range(15):
                meta_refresh = soup.find("meta", attrs={"http-equiv": "refresh"})
                if meta_refresh and "url=" in meta_refresh.get("content", "").lower():
                    next_url = urljoin(current_url, meta_refresh["content"].lower().split("url=")[1].strip())
                    break

                for a_tag in soup.find_all(["a", "button", "div", "input"], href=True) or soup.find_all(["a", "button", "div", "input"]):
                    txt = a_tag.get_text().strip().lower()
                    if not txt:
                        txt = (a_tag.get("value") or a_tag.get("title") or "").strip().lower()
                    
                    if any(x in txt for x in button_markers):
                        href = a_tag.get("href")
                        if not href:
                            onclick = a_tag.get("onclick", "")
                            oc_match = re.search(r'location\.href\s*=\s*["\']([^"\']+)["\']', onclick)
                            if oc_match: href = oc_match.group(1)

                        if href:
                            next_url = urljoin(current_url, href)
                            break
                        elif a_tag.name in ["button", "input"] and (a_tag.get("type") == "submit" or a_tag.name == "button"):
                            form = a_tag.find_parent("form")
                            if form:
                                logger.info(f"📝 Submitting form found via button: {txt}")
                                post_url = urljoin(current_url, form.get("action", ""))
                                post_data = {inp.get("name"): inp.get("value", "") for inp in form.find_all("input") if inp.get("name")}
                                html, current_url = await self._light_fetch(headers, cookies, session_id, post_url, post_data=post_data, referer=current_url, force_flaresolverr=use_flaresolverr_only)
                                if html:
                                    soup = BeautifulSoup(html, "lxml")
                                    headers["Referer"] = current_url
                                    if current_url and any(d in current_url.lower() for d in ["safego.cc", "clicka.cc", "clicka", "uprot.net"]):
                                        use_flaresolverr_only = True
                                    next_url = current_url
                                    break
                
                if next_url and next_url != current_url and "uprot.net" not in next_url:
                    previous_url = current_url
                    current_url = next_url
                    html, current_url = await self._light_fetch(headers, cookies, session_id, current_url, referer=previous_url, force_flaresolverr=use_flaresolverr_only)
                    if html:
                        soup = BeautifulSoup(html, "lxml")
                        headers["Referer"] = previous_url
                        if current_url and any(d in current_url.lower() for d in ["safego.cc", "clicka.cc", "clicka", "uprot.net"]):
                            use_flaresolverr_only = True
                    break
                
                if attempt < 6:
                    await asyncio.sleep(4.0)
                    html, current_url = await self._light_fetch(headers, cookies, session_id, current_url, referer=current_url, force_flaresolverr=use_flaresolverr_only)
                    if html:
                        soup = BeautifulSoup(html, "lxml")
                        headers["Referer"] = current_url
                        if current_url and any(d in current_url.lower() for d in ["safego.cc", "clicka.cc", "clicka", "uprot.net"]):
                            use_flaresolverr_only = True
            
            if not next_url: break
        return current_url, ua, cookies

    async def _binary_fetch(self, target_url, session_id, ua, current_url, cookies):
        request_headers = self._step_headers(ua, current_url)
        try:
            pref_p = get_proxy_for_url(target_url, TRANSPORT_ROUTES, self.proxies, self.bypass_warp_active)
            async with await self._get_session(proxy=pref_p) as session:
                async with session.get(target_url, cookies=cookies, headers=request_headers, timeout=12) as r:
                    if r.status == 200: return await r.read()
        except: pass
        try:
            fs_res = await self._request_flaresolverr("request.get", target_url, session_id=session_id, headers=request_headers)
            response_text = fs_res.get("solution", {}).get("response", "")
            if "base64" in response_text or len(response_text) > 1000:
                try: return base64.b64decode(response_text)
                except: return response_text.encode('utf-8')
            return response_text.encode('utf-8')
        except: return None

    def _build_result(self, video_url: str, referer: str, ua: str, cookies: dict = None) -> dict:
        headers = {"Referer": referer, "User-Agent": ua, "Origin": f"https://{urlparse(referer).netloc}"}
        if cookies:
            headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        return {"destination_url": video_url, "request_headers": headers, "mediaflow_endpoint": self.mediaflow_endpoint, "bypass_warp": self.bypass_warp_active}

    async def close(self):
        if self.session and not self.session.closed: await self.session.close()
