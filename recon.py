import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from colors import Colors, status
from payloads import WORDLIST
from proxy import ProxyPool, safe_request
from speed import ProgressBar

class DirFuzzer:
    def __init__(self, base_url: str, pool: ProxyPool):
        self.base_url = base_url.rstrip("/")
        self.pool = pool
        self.lock = threading.Lock()

    def fuzz(self, wordlist: list[str]) -> None:
        status(f"Starting Dir Fuzzer ({len(wordlist)} words)...", "info")

        def check_word(word: str) -> None:
            time.sleep(random.uniform(0.25, 0.7))
            target = f"{self.base_url}/{word}/"
            resp, _ = safe_request("GET", target, self.pool, timeout=8)
            if resp and resp.status_code in (200, 301, 302, 403):
                with self.lock:
                    print(f"\n  {Colors.GREEN}[DIR HIT]{Colors.RESET} "
                          f"{Colors.WHITE}{target}{Colors.RESET} "
                          f"{Colors.DIM}({resp.status_code}){Colors.RESET}")

        with ThreadPoolExecutor(max_workers=3) as ex:
            list(ex.map(check_word, wordlist))


class Crawler:
    def __init__(self, start_url: str, pool: ProxyPool, max_depth: int = 2, max_pages: int = 80):
        self.start_url = start_url
        self.pool = pool
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited: set[str] = set()
        self.targets: set[tuple] = set()
        self.lock = threading.Lock()
        self.base_domain = urlparse(start_url).netloc

    def crawl(self) -> list:
        status(f"Starting Crawler (Depth: {self.max_depth})...", "info")
        queue: list[tuple[str, int]] = [(self.start_url, 1)]
        progress = ProgressBar(self.max_pages, "Crawling")

        with ThreadPoolExecutor(max_workers=10) as ex:
            while queue:
                with self.lock:
                    if len(self.visited) >= self.max_pages:
                        break
                    batch, queue = queue[:20], queue[20:]

                futures = {
                    ex.submit(self._fetch, url, depth): (url, depth)
                    for url, depth in batch if url not in self.visited
                }
                for fut in as_completed(futures):
                    links, tgts = fut.result()
                    depth = futures[fut][1]
                    with self.lock:
                        self.targets.update(tgts)
                        for link in links:
                            if link not in self.visited and len(self.visited) < self.max_pages:
                                queue.append((link, depth + 1))
                        progress.current = min(len(self.visited), self.max_pages)
                        progress.update(0, extra=f"{Colors.GREEN}Targets: {len(self.targets)}{Colors.RESET}")

        print()
        status(f"Crawler finished. Found {len(self.targets)} targets.", "ok")
        return list(self.targets)

    def _fetch(self, url: str, depth: int):
        if depth > self.max_depth:
            return [], []
        with self.lock:
            self.visited.add(url)
        time.sleep(random.uniform(0.2, 0.6))
        links, tgts = [], []
        resp, _ = safe_request("GET", url, self.pool, timeout=10)
        if not resp or resp.status_code != 200:
            return [], []
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.find_all("a", href=True):
                link = urljoin(url, str(a["href"]))
                if self.base_domain in link:
                    links.append(link)
                    if "?" in link and "=" in link:
                        tgts.append(("GET", link))
            for form in soup.find_all("form"):
                action = str(form.get("action", ""))
                method = str(form.get("method") or "get").upper()
                form_url = urljoin(url, action)
                inputs = [str(i.get("name")) for i in form.find_all(["input", "textarea"]) if i.get("name")]
                if inputs and self.base_domain in form_url:
                    for inp in inputs:
                        tgts.append((method, form_url, inp))
        except Exception:
            pass
        return links, tgts
