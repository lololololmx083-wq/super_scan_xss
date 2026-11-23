import html
import json
import os
import random
import re
import string
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse

import state
from callback import callback_seen
from colors import Colors, status
from detect import _uniq_marker, _uniq_token, detect_context, reflected
from mutator import advanced_hpp_split
from proxy import ProxyPool, safe_request
from speed import ProgressBar, SpeedController
from payloads import CONTEXT_PAYLOADS, PAYLOADS_DB



class XSSScanner:
    def __init__(self, pool: ProxyPool, use_hpp: bool = False, rps: float = 8.0,
                 callback_url: str | None = None, target_url: str = "",
                 use_double_encode: bool = False, use_comment_junk: bool = False,
                 use_mixed_case: bool = False, use_ctype_confusion: bool = False,
                 force_method: str | None = None, advanced_hpp: bool = False):
        self.pool = pool
        self.use_hpp = use_hpp
        self.use_double_encode = use_double_encode
        self.use_comment_junk = use_comment_junk
        self.use_mixed_case = use_mixed_case
        self.use_ctype_confusion = use_ctype_confusion
        self.force_method = (force_method or "").upper() or None  # "GET" | "POST" | None
        self.advanced_hpp = advanced_hpp
        self.speed = SpeedController(rps)
        self.callback_url = (callback_url or "").rstrip("/") or None
        self.target_url = target_url
        self.lock = threading.Lock()
        self.stats = {"sent": 0, "errors": 0, "reflected": 0, "callback_hits": 0}
        self.hits: list[dict] = []
        self.errors: list[dict] = []

    def _hpp_key(self, param: str) -> str:
        """Advanced HPP prefers array-style keys many backends still merge."""
        if self.advanced_hpp and not param.endswith("[]"):
            return f"{param}[]"
        return param

    def _build_get(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if self.use_hpp:
            key = self._hpp_key(param)
            if key != param and param in qs:
                del qs[param]
            if self.advanced_hpp:
                qs[key] = advanced_hpp_split(payload)
            else:
                qs[key] = [payload[i:i + 3] for i in range(0, len(payload), 3)] or [payload]
        else:
            qs[param] = [payload]
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params,
                           urlencode(qs, doseq=True), parsed.fragment))

    def _materialize_payload(self, template: str) -> tuple[str, str | None]:
        token = None
        out = template
        if self.callback_url and ("{CALLBACK}" in template or "{TOKEN}" in template):
            token = _uniq_token()
            out = out.replace("{CALLBACK}", self.callback_url).replace("{TOKEN}", token)
        return out, token

    def _apply_evasion(self, payload: str) -> str:
        """Apply selected method transforms (after materialize, before HPP wrap)."""
        if self.use_comment_junk:
            # break event/keyword signatures WAF likes to match
            payload = re.sub(r"(?i)(on[a-z]+)\s*=", r"\1/**/=", payload)
            payload = payload.replace("<script", "<scr/**/ipt").replace("<SCRIPT", "<SCR/**/IPT")
            payload = payload.replace("alert", "al/**/ert").replace("ALERT", "AL/**/ERT")
        if self.use_mixed_case:
            out = []
            up = True
            for ch in payload:
                if ch.isalpha():
                    out.append(ch.upper() if up else ch.lower())
                    up = not up
                else:
                    out.append(ch)
            payload = "".join(out)
        if self.use_double_encode:
            payload = quote(payload, safe="")
            
        return payload

    def scan(self, targets, payloads, context_aware: bool = False) -> None:
        surfaces = []
        for item in targets:
            if len(item) == 2:
                method, url = item
                params = list(parse_qs(urlparse(url).query).keys()) or ["q"]
                for param in params:
                    surfaces.append((method, url, param))
            elif len(item) == 3:
                method, url, param = item
                surfaces.append((method, url, param))

        seen = set()
        uniq_surfaces = []
        for s in surfaces:
            if s not in seen:
                seen.add(s)
                uniq_surfaces.append(s)

        ctx_map = {}
        if context_aware:
            status("Context-aware probe on each parameter...", "info")
            for method, url, param in uniq_surfaces:
                if self.force_method:
                    method = self.force_method
                self.speed.wait()
                marker = _uniq_marker()
                if method == "GET":
                    target = self._build_get(url, param, marker)
                    body = None
                else:
                    target = urlunparse(urlparse(url)._replace(query=""))
                    body = urlencode({param: marker}).encode()
                resp, _err = safe_request(method, target, self.pool, data=body, timeout=12)
                ctx = "unknown"
                if resp is not None:
                    try:
                        text = resp.text or ""
                    except Exception:
                        text = ""
                    ctx = detect_context(text, marker)
                ctx_map[(method, url, param)] = ctx
                status(f"  {param} -> {ctx}", "info")

        def payloads_for(ctx: str) -> list:
            if not context_aware:
                return list(payloads)
            base = []
            if ctx in CONTEXT_PAYLOADS:
                base.extend(CONTEXT_PAYLOADS[ctx])
            else:
                base.extend(CONTEXT_PAYLOADS.get("html", []))
                base.extend(CONTEXT_PAYLOADS.get("attribute", []))
            for p in PAYLOADS_DB.get("waf_bypass", [])[:8]:
                if p not in base:
                    base.append(p)
            if self.callback_url:
                for p in PAYLOADS_DB.get("callback", []):
                    if p not in base:
                        base.append(p)
            if ctx == "unknown":
                for p in payloads:
                    if p not in base:
                        base.append(p)
            return list(dict.fromkeys(base))

        jobs = []
        for method, url, param in uniq_surfaces:
            ctx = ctx_map.get((method, url, param), "unknown")
            for pl in payloads_for(ctx):
                jobs.append((method, url, param, pl))

        total = len(jobs)
        tag = "context-aware" if context_aware else "flat"
        status(f"Starting XSS Attack -> {total} requests | {self.speed.rps:.1f} rps | {tag}", "info")
        progress = ProgressBar(total, "Firing")

        def worker(job) -> None:
            j_method, j_url, j_param, j_template = job
            self.speed.wait()

            payload, token = self._materialize_payload(j_template)
            payload = self._apply_evasion(payload)
            marker = _uniq_marker()
            wrapped = marker + payload
            extra_headers = None

            # lock HTTP method — user pick wins over everything
            if self.force_method:
                j_method = self.force_method

            # Content-Type confusion only when sending POST (never flips GET→POST)
            if self.use_ctype_confusion and j_method == "POST":
                target = urlunparse(urlparse(j_url)._replace(query=""))
                style = random.choice(["json", "plain", "xml", "multipart", "urlencoded"])
                if style == "json":
                    body = json.dumps({j_param: wrapped}).encode()
                    extra_headers = {"Content-Type": "application/json"}
                elif style == "plain":
                    body = f"{j_param}={wrapped}".encode()
                    extra_headers = {"Content-Type": "text/plain"}
                elif style == "xml":
                    esc = (wrapped.replace("&", "&amp;").replace("<", "&lt;")
                                   .replace(">", "&gt;").replace('"', "&quot;"))
                    body = ('<?xml version="1.0"?><root><' + j_param + '>' + esc + '</' + j_param + '></root>').encode()
                    extra_headers = {"Content-Type": "application/xml"}
                elif style == "multipart":
                    boundary = "----x" + _uniq_marker()
                    crlf = "\r\n"
                    body = (
                        "--" + boundary + crlf
                        + 'Content-Disposition: form-data; name="' + j_param + '"' + crlf + crlf
                        + wrapped + crlf
                        + "--" + boundary + "--" + crlf
                    ).encode()
                    extra_headers = {"Content-Type": "multipart/form-data; boundary=" + boundary}
                else:
                    body = urlencode({j_param: wrapped}).encode()
                    extra_headers = {"Content-Type": "application/x-www-form-urlencoded"}
            elif j_method == "GET":
                target = self._build_get(j_url, j_param, wrapped)
                body = None
            else:
                target = urlunparse(urlparse(j_url)._replace(query=""))
                if self.use_hpp:
                    key = self._hpp_key(j_param)
                    if self.advanced_hpp:
                        chunks = advanced_hpp_split(wrapped)
                    else:
                        chunks = [wrapped[i:i + 3] for i in range(0, len(wrapped), 3)] or [wrapped]
                    body = urlencode([(key, c) for c in chunks]).encode()
                else:
                    body = urlencode({j_param: wrapped}).encode()

            resp, err = safe_request(j_method, target, self.pool, data=body, timeout=12,
                                     extra_headers=extra_headers)

            if resp is None:
                with self.lock:
                    self.stats["errors"] += 1
                    self.errors.append({
                        "url": target, "method": j_method, "param": j_param,
                        "error": err or "Unknown", "time": datetime.now().isoformat()
                    })
                progress.update(extra=f"{Colors.RED}Hits:{self.stats['reflected']} Err:{self.stats['errors']}{Colors.RESET}")
                return

            if token:
                time.sleep(0.3)

            ok, reason = reflected(resp.text or "", payload, marker)
            cb_ok = bool(token and callback_seen(token))

            with self.lock:
                self.stats["sent"] += 1
                if cb_ok:
                    self.stats["callback_hits"] += 1
                if ok or cb_ok:
                    self.stats["reflected"] += 1
                    hit_reason = "CALLBACK_CONFIRMED (100% XSS)" if cb_ok else reason
                    self.hits.append({
                        "url": target, "param": j_param, "payload": payload,
                        "status": getattr(resp, "status_code", None),
                        "reason": hit_reason, "token": token, "cb_confirmed": cb_ok
                    })
                    if not state.SILENT_MODE:
                        print()
                        border = Colors.GREEN if cb_ok else Colors.RED
                        title = (f"{Colors.GREEN}XSS VULNERABILITY CONFIRMED{Colors.RESET}"
                                 if cb_ok else f"{Colors.RED}XSS VULNERABILITY DETECTED{Colors.RESET}")
                        d_url = target if len(target) <= 44 else target[:41] + "..."
                        d_param = j_param if len(j_param) <= 44 else j_param[:41] + "..."
                        d_reason = hit_reason if len(hit_reason) <= 44 else hit_reason[:41] + "..."
                        print(f"\n{border}╔{'═' * 58}╗{Colors.RESET}")
                        print(f"{border}║{Colors.RESET} {title:<56} {border}║{Colors.RESET}")
                        print(f"{border}╠{'═' * 58}╣{Colors.RESET}")
                        print(f"{border}║{Colors.RESET} {Colors.WHITE}URL   {Colors.RESET}{Colors.DIM}│{Colors.RESET} {Colors.CYAN}{d_url:<46}{Colors.RESET} {border}║{Colors.RESET}")
                        print(f"{border}║{Colors.RESET} {Colors.WHITE}Param {Colors.RESET}{Colors.DIM}│{Colors.RESET} {Colors.YELLOW}{d_param:<46}{Colors.RESET} {border}║{Colors.RESET}")
                        print(f"{border}║{Colors.RESET} {Colors.WHITE}Signal{Colors.RESET}{Colors.DIM}│{Colors.RESET} {Colors.GREEN if cb_ok else Colors.YELLOW}{d_reason:<46}{Colors.RESET} {border}║{Colors.RESET}")
                        print(f"{border}╚{'═' * 58}╝{Colors.RESET}\n")

                progress.update(extra=f"{Colors.RED}Hits:{self.stats['reflected']} Err:{self.stats['errors']}{Colors.RESET}")

        with ThreadPoolExecutor(max_workers=5) as pool:
            list(pool.map(worker, jobs))

        if self.callback_url:
            time.sleep(1.0)
            with self.lock:
                for hit in self.hits:
                    tok = hit.get("token")
                    if tok and not hit.get("cb_confirmed") and callback_seen(tok):
                        hit["reason"] = "CALLBACK_CONFIRMED (100% XSS)"
                        hit["cb_confirmed"] = True
                        self.stats["callback_hits"] += 1

    def save_report(self, fmt: str = "both") -> None:
        if fmt == "n":
            status("Reports skipped.", "warn")
            return

        os.makedirs("reports", exist_ok=True)
        ts = int(time.time())

        report = {
            "target": self.target_url,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "stats": dict(self.stats),
            "hits": self.hits,
            "errors": self.errors,
        }

        json_path = os.path.join("reports", f"xss_{ts}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        status(f"JSON → {json_path}", "ok")

        if fmt in ("txt", "both"):
            txt_path = os.path.join("reports", f"xss_{ts}.txt")
            lines = [
                "XSS Hunter Report",
                "=" * 60,
                f"Target   : {self.target_url}",
                f"Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Sent     : {self.stats['sent']}",
                f"Hits     : {self.stats['reflected']}",
                f"Callback : {self.stats['callback_hits']}",
                f"Errors   : {self.stats['errors']}",
                "=" * 60, "", "--- HITS ---", ""
            ]
            if not self.hits:
                lines.append("(no hits)")
            else:
                for i, h in enumerate(self.hits, 1):
                    lines += [
                        f"[{i}] {h.get('reason', '?')}",
                        f"    URL    : {h.get('url', '')}",
                        f"    Param  : {h.get('param', '')}",
                        f"    Payload: {h.get('payload', '')}",
                    ]
                    if h.get("token"):
                        lines.append(f"    Token  : {h.get('token')}")
                    lines += [f"    Status : {h.get('status', '')}", ""]
            lines += ["", "--- ERRORS ---", ""]
            if not self.errors:
                lines.append("(no errors)")
            else:
                for i, e in enumerate(self.errors, 1):
                    lines += [
                        f"[{i}] {e.get('error', '?')}",
                        f"    URL    : {e.get('url', '')}",
                        f"    Method : {e.get('method', '')}",
                        f"    Param  : {e.get('param', '')}", ""
                    ]
            with open(txt_path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))
            status(f"TXT  → {txt_path}", "ok")

        if fmt in ("html", "both"):
            html_path = os.path.join("reports", f"xss_{ts}.html")
            hit_rows = []
            for i, h in enumerate(self.hits, 1):
                reason = h.get("reason", "")
                color = "#00ff88" if "CALLBACK" in reason else "#ffaa00"
                hit_rows.append(f"""
                <tr>
                    <td>{i}</td>
                    <td style="color:{color};font-weight:bold">{html.escape(reason)}</td>
                    <td><code>{html.escape(h.get('param', ''))}</code></td>
                    <td><code>{html.escape(h.get('payload', '')[:120])}</code></td>
                    <td><a href="{html.escape(h.get('url', ''))}" target="_blank">open</a></td>
                    <td>{h.get('status', '')}</td>
                </tr>""")
            err_rows = []
            for i, e in enumerate(self.errors, 1):
                err_rows.append(f"""
                <tr>
                    <td>{i}</td>
                    <td><code>{html.escape(e.get('method', ''))}</code></td>
                    <td><code>{html.escape(e.get('param', ''))}</code></td>
                    <td style="color:#ff5555">{html.escape(e.get('error', '')[:100])}</td>
                    <td><a href="{html.escape(e.get('url', ''))}" target="_blank">open</a></td>
                </tr>""")
            hits_section = "".join(hit_rows) if hit_rows else '<tr><td colspan="6" style="text-align:center;color:#8b949e">No hits</td></tr>'
            errs_section = "".join(err_rows) if err_rows else '<tr><td colspan="5" style="text-align:center;color:#8b949e">No errors</td></tr>'

            html_body = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>XSS Hunter Report</title>
<style>
body{{font-family:system-ui,sans-serif;background:#0d1117;color:#e6edf3;margin:40px}}
h1{{color:#ff7bff}} h2{{color:#58a6ff;margin-top:40px}}
table{{border-collapse:collapse;width:100%;margin-top:12px}}
th,td{{border:1px solid #30363d;padding:10px 12px;text-align:left}}
th{{background:#161b22;color:#58a6ff}} tr:nth-child(even){{background:#161b22}}
code{{background:#21262d;padding:2px 6px;border-radius:4px}} a{{color:#58a6ff}}
.meta{{color:#8b949e;margin-bottom:20px;line-height:1.8}}
</style></head><body>
<h1>XSS Hunter Report</h1>
<div class="meta">
<b>Target:</b> {html.escape(self.target_url)}<br>
<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
<b>Sent:</b> {self.stats['sent']} | <b>Hits:</b> {self.stats['reflected']} |
<b>Callback:</b> {self.stats['callback_hits']} | <b>Errors:</b> {self.stats['errors']}
</div>
<h2>Hits ({len(self.hits)})</h2>
<table><thead><tr><th>#</th><th>Reason</th><th>Param</th><th>Payload</th><th>URL</th><th>Status</th></tr></thead>
<tbody>{hits_section}</tbody></table>
<h2>Errors ({len(self.errors)})</h2>
<table><thead><tr><th>#</th><th>Method</th><th>Param</th><th>Error</th><th>URL</th></tr></thead>
<tbody>{errs_section}</tbody></table>
</body></html>"""
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_body)
            status(f"HTML → {html_path}", "ok")

    def save_callback_hits_only(self) -> str:
        cb_hits = [h for h in self.hits if h.get("cb_confirmed")]
        if not cb_hits:
            return ""
        os.makedirs("reports", exist_ok=True)
        ts = int(time.time())
        path = os.path.join("reports", f"callback_hits_{ts}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write("CALLBACK-CONFIRMED XSS HITS\n" + "=" * 60 + "\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total : {len(cb_hits)}\n" + "=" * 60 + "\n\n")
            for i, h in enumerate(cb_hits, 1):
                f.write(f"[{i}] {h.get('url', '')}\n")
                f.write(f"    Param  : {h.get('param', '')}\n")
                f.write(f"    Payload: {h.get('payload', '')}\n")
                f.write(f"    Token  : {h.get('token', '')}\n")
                f.write(f"    Status : {h.get('status', '')}\n\n")
        return path

    def print_summary(self) -> None:
        if self.hits:
            print(f"\n{Colors.MAGENTA}╔{'═' * 48}╗{Colors.RESET}")
            print(f"{Colors.MAGENTA}║{Colors.RESET} {Colors.BOLD}HIT LIST{Colors.RESET}{' ' * 39}{Colors.MAGENTA}║{Colors.RESET}")
            print(f"{Colors.MAGENTA}╚{'═' * 48}╝{Colors.RESET}")
            for i, h in enumerate(self.hits, 1):
                reason = h.get("reason", "")
                color = Colors.GREEN if "CALLBACK" in reason else Colors.YELLOW
                print(f"  {color}#{i:<3}{Colors.RESET} {Colors.WHITE}{h.get('param', '')}{Colors.RESET} "
                      f"{Colors.DIM}→{Colors.RESET} {Colors.CYAN}{h.get('payload', '')[:64]}{Colors.RESET}")
        if self.errors and not state.SILENT_MODE:
            print(f"\n{Colors.RED}╔{'═' * 48}╗{Colors.RESET}")
            print(f"{Colors.RED}║{Colors.RESET} {Colors.BOLD}ERRORS (first 10){Colors.RESET}{' ' * 30}{Colors.RED}║{Colors.RESET}")
            print(f"{Colors.RED}╚{'═' * 48}╝{Colors.RESET}")
            for i, e in enumerate(self.errors[:10], 1):
                print(f"  {Colors.RED}#{i:<3}{Colors.RESET} {Colors.DIM}{e.get('error', '')[:72]}{Colors.RESET}")


