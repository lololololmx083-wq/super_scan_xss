import os
import random
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests
import urllib3

from colors import Colors, status
from headers import get_headers
from speed import ProgressBar

try:
    import socks
    HAS_SOCKS = True
except ImportError:
    HAS_SOCKS = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parse_proxy_line(line: str, default_scheme: str = "http") -> str | None:
    line = (line or "").strip()
    if not line or line.startswith("#"):
        return None
    if not re.match(r"^(socks4|socks5|socks5h|http|https)://", line):
        line = default_scheme + "://" + line
    if line.startswith("socks") and not HAS_SOCKS:
        return None
    return line


def split_and_parse(raw_data, default_scheme: str = "http") -> list[str]:
    lines = re.split(r"[\n\r,;]+", raw_data) if isinstance(raw_data, str) else raw_data
    out, seen = [], set()
    for line in lines:
        proxy = parse_proxy_line(line, default_scheme)
        if proxy and proxy not in seen:
            seen.add(proxy)
            out.append(proxy)
    return out


PROXY_SOURCES = [
    ("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", "http"),
    ("https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", "http"),
]

TEST_URLS = ["https://api.ipify.org?format=json"]


def fetch_public_proxies() -> list[str]:
    status("Fetching proxies from sources...", "info")
    found: set[str] = set()

    def pull(item):
        url, scheme = item
        if scheme.startswith("socks") and not HAS_SOCKS:
            return []
        try:
            r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code == 200:
                return split_and_parse(r.text, scheme)
        except requests.RequestException:
            pass
        return []

    with ThreadPoolExecutor(max_workers=6) as ex:
        for res in ex.map(pull, PROXY_SOURCES):
            found.update(res or [])
    status(f"Parsed {len(found)} unique proxies", "ok" if found else "warn")
    return list(found)


def test_and_filter_proxies(proxies: list[str]) -> list[str]:
    if not proxies:
        return []
    sample = proxies[:300]
    status(f"Testing {len(sample)} proxies...", "info")

    alive = []
    lock = threading.Lock()
    progress = ProgressBar(len(sample), "Testing Proxies")

    def test_one(proxy_url):
        proxies_dict = {"http": proxy_url, "https": proxy_url}
        is_alive = False
        for test_url in TEST_URLS:
            try:
                r = requests.get(test_url, proxies=proxies_dict, timeout=6,
                                 headers={"User-Agent": "Mozilla/5.0"})
                if r.status_code == 200 and (r.text or "").strip():
                    is_alive = True
                    break
            except requests.RequestException:
                continue
        with lock:
            if is_alive:
                alive.append(proxy_url)
            progress.update(extra=f"{Colors.GREEN}Alive: {len(alive)}{Colors.RESET}")

    with ThreadPoolExecutor(max_workers=30) as ex:
        list(ex.map(test_one, sample))

    if alive:
        with open("alive_proxies.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(alive))
        status(f"Saved {len(alive)} alive proxies → alive_proxies.txt", "ok")
    else:
        status("No alive proxies found. Falling back to Direct.", "err")
    return alive


class ProxyPool:
    def __init__(self, proxies=None, rotate: bool = True):
        self.proxies = [p for p in (proxies or []) if p]
        self.rotate = rotate
        self.i = 0
        self.lock = threading.Lock()
        self.dead: set[str] = set()

    def get(self) -> str | None:
        if not self.proxies:
            return None
        with self.lock:
            alive = [p for p in self.proxies if p not in self.dead]
            if not alive:
                return None
            if not self.rotate:
                return alive[0]
            proxy = alive[self.i % len(alive)]
            self.i += 1
            return proxy

    def mark_dead(self, proxy: str | None) -> None:
        if not proxy:
            return
        with self.lock:
            self.dead.add(proxy)

    @staticmethod
    def to_dict(proxy: str | None):
        return {"http": proxy, "https": proxy} if proxy else None


def safe_request(method: str, url: str, pool: ProxyPool, data=None, timeout=12, max_retries=3,
                 extra_headers=None):
    last_error = None

    def _hdrs():
        h = get_headers()
        if extra_headers:
            h.update(extra_headers)
        return h

    # ── Direct mode (no proxy in pool) ─────────────────────────
    if not pool.proxies:
        try:
            if method.upper() == "POST":
                r = requests.post(url, data=data, headers=_hdrs(),
                                  timeout=timeout, verify=False)
            else:
                r = requests.get(url, headers=_hdrs(),
                                 timeout=timeout, verify=False)
            return r, None
        except requests.RequestException as e:
            return None, str(e)

    # ── Proxy mode: retry across pool ──────────────────────────
    for attempt in range(max_retries):
        proxy = pool.get()
        if not proxy:
            break
        proxies = ProxyPool.to_dict(proxy)
        try:
            if method.upper() == "POST":
                r = requests.post(url, data=data, headers=_hdrs(),
                                  proxies=proxies, timeout=timeout, verify=False)
            else:
                r = requests.get(url, headers=_hdrs(),
                                 proxies=proxies, timeout=timeout, verify=False)
            return r, None
        except requests.RequestException as e:
            last_error = str(e)
            pool.mark_dead(proxy)
            if attempt < max_retries - 1:
                time.sleep(0.15)

    # ── Final fallback: direct (all proxies dead) ──────────────
    try:
        if method.upper() == "POST":
            r = requests.post(url, data=data, headers=_hdrs(),
                              timeout=timeout, verify=False)
        else:
            r = requests.get(url, headers=_hdrs(),
                             timeout=timeout, verify=False)
        return r, None
    except requests.RequestException as e:
        return None, last_error or str(e)


def build_pool(conn: str, config: dict | None = None) -> ProxyPool:
    if conn == "2":
        if not HAS_SOCKS:
            status("Tor needs PySocks → pip install pysocks. Falling back to Direct.", "err")
            return ProxyPool()
        status("Tor mode enabled (socks5h://127.0.0.1:9050)", "ok")
        return ProxyPool(["socks5h://127.0.0.1:9050"], rotate=False)

    raw: list[str] = []
    if conn == "3":
        raw = fetch_public_proxies()
    elif conn == "4":
        path = input(f"{Colors.YELLOW}File path: {Colors.RESET}").strip().strip('"').strip("'")
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                raw = split_and_parse(f.read())
        else:
            status("File not found.", "err")
    elif conn == "5":
        print(f"{Colors.YELLOW}Paste proxies (empty line to finish):{Colors.RESET}")
        lines = []
        while True:
            try:
                line = input()
                if not line.strip():
                    break
                lines.append(line)
            except EOFError:
                break
        raw = split_and_parse("\n".join(lines))

    if not raw:
        return ProxyPool()

    alive = test_and_filter_proxies(raw)
    if not alive:
        return ProxyPool()
    return ProxyPool(alive, rotate=True)


