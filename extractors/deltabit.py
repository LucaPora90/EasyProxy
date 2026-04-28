import asyncio
import logging
import re
import time
import base64
from urllib.parse import urlparse, urljoin, urlencode

import aiohttp
from aiohttp import ClientSession, TCPConnector
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

class DeltabitExtractor:
    _result_cache = {} # cache for final results: {url: (result, timestamp)}

    def __init__(self, request_headers: dict = None, proxies: list = None, bypass_warp: bool = False):
        self.request_headers = request_headers or {}
        self.base_headers = self.request_headers.copy()
        if "User-Agent" not in self.base_headers and "user-agent" not in self.base_headers:
             self.base_headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        self.proxies = proxies or GLOBAL_PROXIES
        self.cache = CookieCache("universal")
        self.mediaflow_endpoint = "proxy_stream_endpoint"
        self.bypass_warp_active = bypass_warp
        self.session = None
        self.proxy_manager = FreeProxyManager.get_instance(
            "deltabit",
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
        
        # If we have an existing session but need a different proxy, we must create a new one
        # To simplify, we'll return a one-off session if a proxy is requested
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

    async def extract(self, url: str, **kwargs) -> dict:
        # Normalize URL for cache
        normalized_url = url.strip()
        # Check cache (10 minutes validity)
        if normalized_url in DeltabitExtractor._result_cache:
            res, ts = DeltabitExtractor._result_cache[normalized_url]
            if time.time() - ts < 600:
                logger.info(f"🚀 [Cache Hit] Using cached extraction result for: {normalized_url}")
                return res
        
        logger.info(f"🔍 [Cache Miss] Extracting new link for: {normalized_url}")
        proxy = get_proxy_for_url(normalized_url, TRANSPORT_ROUTES, self.proxies, self.bypass_warp_active)
        is_redirector_url = any(d in normalized_url.lower() for d in ["safego.cc", "clicka.cc", "clicka", "uprot.net"])
        redirect_session_id = await solver_manager.get_persistent_session("redirector:clicka-safego", proxy) if is_redirector_url else None
        final_session_id = await solver_manager.get_persistent_session("deltabit", proxy)
        session_id = redirect_session_id or final_session_id
        is_persistent = True # Always persistent for this key
        try:
            ua, cookies = self.base_headers.get("User-Agent"), {}
            # 1. Hybrid Solver for Redirector (FAST)
            if is_redirector_url:
                url, ua, cookies = await self._solve_redirector_hybrid(url, session_id)

            session_id = final_session_id
            if "deltabit.co" in url.lower(): url = url.replace("deltabit.co/ ", "deltabit.co/")

            async def try_path(p, is_fs=False):
                try:
                    m_headers = self._step_headers(ua, url)
                    if is_fs:
                        res = await self._request_flaresolverr("request.get", url, session_id=session_id, wait=2000)
                        sol = res.get("solution", {})
                        return sol.get("response", ""), sol.get("url", url), sol.get("userAgent", ua), {c["name"]: c["value"] for c in sol.get("cookies", [])}
                    else:
                        connector = get_connector_for_proxy(p) if p else None
                        async with aiohttp.ClientSession(connector=connector, headers=self.base_headers) as local_session:
                            async with local_session.get(url, cookies=cookies, headers=m_headers, timeout=12) as r:
                                if r.status == 200:
                                    t = await r.text()
                                    if not any(m in t.lower() for m in ["cf-challenge", "robot", "checking your browser"]):
                                        return t, str(r.url), ua, {k: v.value for k, v in r.cookies.items()}
                except: pass
                return None

            pref_p = get_proxy_for_url(url, TRANSPORT_ROUTES, self.proxies, self.bypass_warp_active)
            tasks = [
                asyncio.create_task(try_path(pref_p)) if pref_p else None,
                asyncio.create_task(try_path(None)),
                asyncio.create_task(try_path(None, is_fs=True))
            ]
            tasks = [t for t in tasks if t]
            
            html = None
            for task in asyncio.as_completed(tasks):
                res = await task
                if res:
                    html, url, ua, new_cookies = res
                    cookies.update(new_cookies)
                    break
            
            if not html:
                raise ExtractorError("Deltabit: Page fetch failed")
            
            soup = BeautifulSoup(html, 'lxml')
            form_data = {inp.get('name'): inp.get('value', '') for inp in soup.find_all('input') if inp.get('name')}
            if not form_data.get("op"):
                link_match = re.search(r'sources:\s*\["([^"]+)"', html) or re.search(r'file:\s*["\']([^"\']+)["\']', html)
                if link_match: 
                    result = self._build_result(link_match.group(1), url, ua, proxy, cookies=cookies)
                    DeltabitExtractor._result_cache[normalized_url] = (result, time.time())
                    logger.info("✅ Extraction success (direct source found)")
                    return result
                raise ExtractorError("Deltabit: Form not found")

            # 3. Final POST via FlareSolverr (STABLE)
            form_data['imhuman'], form_data['referer'] = "", url
            await asyncio.sleep(2.5) 
            
            post_res = await self._request_flaresolverr("request.post", url, urlencode(form_data), session_id=session_id, wait=0)
            post_solution = post_res.get("solution", {})
            post_html = post_solution.get("response", "")
            # Update cookies after POST
            cookies.update({c["name"]: c["value"] for c in post_solution.get("cookies", [])})

            link_match = re.search(r'sources:\s*\["([^"]+)"', post_html) or re.search(r'file:\s*["\']([^"\']+)["\']', post_html)
            if not link_match: raise ExtractorError("Deltabit: Video source not found")
            result = self._build_result(link_match.group(1), url, ua, proxy, cookies=cookies)
            DeltabitExtractor._result_cache[normalized_url] = (result, time.time())
            return result
        finally:
            if redirect_session_id:
                await solver_manager.release_session(redirect_session_id, is_persistent)
            if final_session_id and final_session_id != redirect_session_id:
                await solver_manager.release_session(final_session_id, is_persistent)

    async def _solve_redirector_hybrid(self, url: str, session_id: str) -> tuple:
        res = await self._request_flaresolverr("request.get", url, session_id=session_id)
        solution = res.get("solution", {})
        ua, cookies = solution.get("userAgent"), {c["name"]: c["value"] for c in solution.get("cookies", [])}
        html, current_url = solution.get("response", ""), solution.get("url", url)
        
        # Determine initial preferred proxy (WARP/Route)
        preferred_proxy = get_proxy_for_url(url, TRANSPORT_ROUTES, self.proxies, self.bypass_warp_active)
        headers = self._step_headers(ua, url)
        fs_counter = 0
        max_fs_calls = 25
        use_flaresolverr_only = True

        async def light_fetch(target_url, post_data=None, referer=None, force_flaresolverr=False):
            nonlocal fs_counter
            async def try_path_light(p, is_fs=False):
                try:
                    request_headers = dict(headers)
                    if referer: request_headers["Referer"] = referer
                    
                    if is_fs:
                        fs_cmd = "request.post" if post_data else "request.get"
                        fs_res = await self._request_flaresolverr(fs_cmd, target_url, urlencode(post_data) if post_data else None, session_id=session_id)
                        sol = fs_res.get("solution", {})
                        return sol.get("response", ""), sol.get("url", target_url), {c["name"]: c["value"] for c in sol.get("cookies", [])}
                    else:
                        connector = get_connector_for_proxy(p) if p else TCPConnector(ssl=False)
                        async with ClientSession(connector=connector, headers=self.base_headers) as local_session:
                            if post_data:
                                async with local_session.post(target_url, data=post_data, cookies=cookies, headers=request_headers, timeout=12) as r:
                                    if r.status == 200:
                                        t = await r.text()
                                        if not any(m in t.lower() for m in ["cf-challenge", "ray id", "checking your browser"]):
                                            return t, str(r.url), {k: v.value for k, v in r.cookies.items()}
                            else:
                                async with local_session.get(target_url, cookies=cookies, headers=request_headers, timeout=12) as r:
                                    if r.status == 200:
                                        t = await r.text()
                                        if not any(m in t.lower() for m in ["cf-challenge", "ray id", "checking your browser"]):
                                            return t, str(r.url), {k: v.value for k, v in r.cookies.items()}
                except: pass
                return None

            tasks = [
                asyncio.create_task(try_path_light(preferred_proxy)) if preferred_proxy else None,
                asyncio.create_task(try_path_light(None)),
                asyncio.create_task(try_path_light(None, is_fs=True))
            ]
            tasks = [t for t in tasks if t]
            
            for task in asyncio.as_completed(tasks):
                res = await task
                if res:
                    text, final_url, new_cookies = res
                    cookies.update(new_cookies)
                    return text, final_url

            # Fallback to Free Proxies in parallel batches
            if any(d in target_url.lower() for d in ["safego.cc", "clicka.cc", "clicka", "uprot.net"]):
                try:
                    free_proxies = await self.proxy_manager.get_proxies()
                    for i in range(0, min(len(free_proxies), 15), 5):
                        batch = free_proxies[i:i+5]
                        batch_tasks = [asyncio.create_task(try_path_light(p)) for p in batch]
                        for bt in asyncio.as_completed(batch_tasks):
                            res = await bt
                            if res:
                                text, final_url, new_cookies = res
                                cookies.update(new_cookies)
                                return text, final_url
                except: pass
            
            return None, target_url

        async def binary_fetch(target_url):
            """Fetch binary data (like images) with direct/FlareSolverr hybrid fallback."""
            nonlocal fs_counter
            request_headers = dict(headers)
            request_headers["Referer"] = current_url
            try:
                # Try preferred proxy/direct first
                p = preferred_proxy or None
                async with await self._get_session(proxy=p) as session:
                    async with session.get(target_url, cookies=cookies, headers=request_headers, timeout=12) as r:
                        if r.status == 200:
                            return await r.read()
            except Exception as e:
                logger.debug(f"Direct binary fetch error: {e}")

            if fs_counter < max_fs_calls:
                fs_counter += 1
                try:
                    fs_res = await self._request_flaresolverr("request.get", target_url, session_id=session_id)
                    solution = fs_res.get("solution", {})
                    response_text = solution.get("response", "")
                    if "base64" in response_text or len(response_text) > 1000:
                         try: return base64.b64decode(response_text)
                         except: return response_text.encode('utf-8')
                    return response_text.encode('utf-8')
                except: pass
            return None

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
                    captcha_data = await binary_fetch(urljoin(current_url, img_tag["src"]))
                
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
                    html, current_url = await light_fetch(current_url, post_data=post_fields, referer=current_url, force_flaresolverr=use_flaresolverr_only)
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
                                html, current_url = await light_fetch(post_url, post_data=post_data, referer=current_url, force_flaresolverr=use_flaresolverr_only)
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
                    html, current_url = await light_fetch(current_url, referer=previous_url, force_flaresolverr=use_flaresolverr_only)
                    if html:
                        soup = BeautifulSoup(html, "lxml")
                        headers["Referer"] = previous_url
                        if current_url and any(d in current_url.lower() for d in ["safego.cc", "clicka.cc", "clicka", "uprot.net"]):
                            use_flaresolverr_only = True
                    break
                
                if attempt < 6:
                    await asyncio.sleep(4.0) 
                    html, current_url = await light_fetch(current_url, referer=current_url, force_flaresolverr=use_flaresolverr_only)
                    if html:
                        soup = BeautifulSoup(html, "lxml")
                        headers["Referer"] = current_url
                        if current_url and any(d in current_url.lower() for d in ["safego.cc", "clicka.cc", "clicka", "uprot.net"]):
                            use_flaresolverr_only = True
                else:
                    break
            
            if not next_url: break
        return current_url, ua, cookies

    def _build_result(self, video_url: str, referer: str, ua: str, proxy: str = None, cookies: dict = None) -> dict:
        headers = {"Referer": referer, "User-Agent": ua, "Origin": f"https://{urlparse(referer).netloc}"}
        if cookies:
            headers["Cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        return {"destination_url": video_url, "request_headers": headers, "mediaflow_endpoint": self.mediaflow_endpoint, "bypass_warp": self.bypass_warp_active, "selected_proxy": proxy}

    async def close(self):
        if self.session and not self.session.closed: await self.session.close()
