import asyncio
import logging
import time
import threading
import os
import cloudscraper
from typing import List, Dict, Optional, Callable, Any

logger = logging.getLogger(__name__)

class FreeProxyManager:
    """
    Manager for free proxy pools with parallel validation and caching.
    """
    _instances: Dict[str, 'FreeProxyManager'] = {}
    _lock = threading.Lock()

    def __init__(self, name: str, list_urls: List[str], cache_ttl: int = 7200, max_fetch: int = 0, max_good: int = 0):
        self.name = name
        self.list_urls = list_urls if isinstance(list_urls, list) else [list_urls]
        self.cache_ttl = cache_ttl
        self.max_fetch = max_fetch
        self.max_good = max_good
        self.proxies: List[str] = []
        self.expires_at: float = 0.0
        self.cursor: int = 0
        self._refresh_lock = asyncio.Lock()

    @classmethod
    def get_instance(cls, name: str, list_urls: List[str], **kwargs) -> 'FreeProxyManager':
        with cls._lock:
            if name not in cls._instances:
                kwargs.setdefault("cache_ttl", int(os.environ.get("VIXSRC_FREE_PROXY_CACHE_TTL", "7200")))
                cls._instances[name] = cls(name, list_urls, **kwargs)
            return cls._instances[name]

    def _normalize_proxy_url(self, proxy_value: str) -> str:
        proxy_value = proxy_value.strip()
        if not proxy_value:
            return ""
        if proxy_value.startswith("socks5://"):
            return proxy_value.replace("socks5://", "socks5h://", 1)
        if "://" not in proxy_value:
            return f"socks5h://{proxy_value}"
        return proxy_value

    async def _fetch_candidates(self) -> List[str]:
        all_candidates = []
        scraper = cloudscraper.create_scraper(delay=2)
        
        for url in self.list_urls:
            try:
                logger.debug(f"ProxyManager[{self.name}]: Fetching from {url}")
                resp = await asyncio.to_thread(scraper.get, url, timeout=25)
                resp.raise_for_status()
                
                count = 0
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    normalized = self._normalize_proxy_url(line)
                    if normalized and normalized not in all_candidates:
                        all_candidates.append(normalized)
                        count += 1
                        if self.max_fetch > 0 and len(all_candidates) >= self.max_fetch:
                            break
                logger.info(f"ProxyManager[{self.name}]: Fetched {count} candidates from {url}")
                if self.max_fetch > 0 and len(all_candidates) >= self.max_fetch:
                    break
            except Exception as e:
                logger.warning(f"ProxyManager[{self.name}]: Failed to fetch proxy list from {url}: {e}")
        
        return all_candidates

    async def _probe_proxy_worker(self, proxy_url: str, probe_func: Callable[[str], Any], semaphore: asyncio.Semaphore, good_list: List[str], ready_event: Optional[asyncio.Event] = None):
        if self.max_good > 0 and len(good_list) >= self.max_good:
            return

        async with semaphore:
            if self.max_good > 0 and len(good_list) >= self.max_good:
                return
                
            try:
                if asyncio.iscoroutinefunction(probe_func):
                    is_good = await probe_func(proxy_url)
                else:
                    is_good = await asyncio.to_thread(probe_func, proxy_url)
                
                if is_good:
                    if self.max_good <= 0 or len(good_list) < self.max_good:
                        if proxy_url not in good_list:
                            good_list.append(proxy_url)
                            logger.info(f"ProxyManager[{self.name}]: Validated working proxy: {proxy_url}")
                            if ready_event and len(good_list) >= 3:
                                ready_event.set()
            except Exception:
                pass

    async def get_proxies(self, probe_func: Optional[Callable[[str], Any]] = None, force_refresh: bool = False) -> List[str]:
        if probe_func is None:
            probe_func = lambda x: True
        now = time.time()
        
        # We need a minimum amount of working proxies.
        min_required = int(os.environ.get("PROXY_MANAGER_MIN_POOL", "5"))
        should_find_more = len(self.proxies) < min_required and not force_refresh
        
        if not force_refresh and self.proxies and self.expires_at > now and not should_find_more:
            return list(self.proxies)

        async with self._refresh_lock:
            # Double check after acquiring lock
            if not force_refresh and self.proxies and self.expires_at > time.time() and len(self.proxies) >= min_required:
                return list(self.proxies)

            # Reset cache if expired or forced
            if force_refresh or self.expires_at <= time.time():
                logger.info(f"ProxyManager[{self.name}]: Refreshing candidate list...")
                self.proxies = []
                self.expires_at = time.time() + self.cache_ttl
                self._candidates_cache = await self._fetch_candidates()
                self._tested_indices = set()
            
            if not hasattr(self, '_candidates_cache') or not self._candidates_cache:
                self._candidates_cache = await self._fetch_candidates()

            if not self._candidates_cache:
                return list(self.proxies)

            if not hasattr(self, '_tested_indices'):
                self._tested_indices = set()
            
            # Identify candidates not yet tested
            remaining_indices = [i for i in range(len(self._candidates_cache)) if i not in self._tested_indices]
            if not remaining_indices:
                logger.info(f"ProxyManager[{self.name}]: All candidates tested. Resetting test history.")
                self._tested_indices = set()
                remaining_indices = list(range(len(self._candidates_cache)))

            good_this_round = []
            # Use a more reasonable concurrency limit
            concurrency = int(os.environ.get("PROXY_MANAGER_CONCURRENCY", "30"))
            
            # Use a queue-based worker approach to avoid task explosion
            queue = asyncio.Queue()
            for idx in remaining_indices:
                queue.put_nowait(idx)

            found_enough_event = asyncio.Event()
            
            async def worker():
                while not queue.empty() and not found_enough_event.is_set():
                    try:
                        idx = queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                        
                    candidate = self._candidates_cache[idx]
                    self._tested_indices.add(idx)
                    
                    try:
                        if asyncio.iscoroutinefunction(probe_func):
                            is_good = await probe_func(candidate)
                        else:
                            is_good = await asyncio.to_thread(probe_func, candidate)
                        
                        if is_good:
                            good_this_round.append(candidate)
                            logger.info(f"ProxyManager[{self.name}]: Found working proxy: {candidate}")
                            # Stop if we found enough for this incremental round (e.g. 3 new ones)
                            if len(good_this_round) >= 3:
                                found_enough_event.set()
                    except Exception:
                        pass
                    finally:
                        queue.task_done()

            # Start workers
            workers = [asyncio.create_task(worker()) for _ in range(min(concurrency, len(remaining_indices)))]
            
            try:
                # Wait for workers to finish or for us to find enough
                done_task, pending = await asyncio.wait(
                    [asyncio.create_task(queue.join()), asyncio.create_task(found_enough_event.wait())],
                    return_when=asyncio.FIRST_COMPLETED,
                    timeout=60 # Max 60 seconds per refresh attempt
                )
            except Exception as e:
                logger.warning(f"ProxyManager[{self.name}]: Refresh timed out or failed: {e}")
            finally:
                # Cleanup workers
                found_enough_event.set() # Stop workers
                for w in workers:
                    if not w.done():
                        w.cancel()
                
                # Cleanup internal join/wait tasks if they were created
                try:
                    for t in pending: t.cancel()
                except: pass

            if good_this_round:
                for p in good_this_round:
                    if p not in self.proxies:
                        self.proxies.append(p)
                logger.info(f"ProxyManager[{self.name}]: Added {len(good_this_round)} new proxies. Pool size: {len(self.proxies)}")
            else:
                logger.warning(f"ProxyManager[{self.name}]: No new working proxies found in this round.")
            
            return list(self.proxies)

    async def get_next_sequence(self, probe_func: Optional[Callable[[str], Any]] = None) -> List[str]:
        proxies = await self.get_proxies(probe_func)
        if not proxies:
            return []
        
        idx = self.cursor % len(proxies)
        self.cursor = (idx + 1) % len(proxies)
        
        return proxies[idx:] + proxies[:idx]

    def report_failure(self, proxy_url: str):
        """Rimuove un proxy dalla cache se viene segnalato come non funzionante."""
        if proxy_url in self.proxies:
            try:
                self.proxies.remove(proxy_url)
                logger.warning(f"ProxyManager[{self.name}]: Proxy {proxy_url} removed from cache after reported failure.")
            except ValueError:
                pass
