from urllib.parse import urlparse

import state
from callback import start_callback_server
from colors import Colors, banner, status
from config import Config
from menus import (
    ask_attack_methods,
    ask_custom_headers,
    ask_load_config,
    ask_save_format,
    ask_speed,
)
from mutator import Mutator, get_context_payloads
from payloads import CONTEXT_PAYLOADS, PAYLOADS_DB, WORDLIST
from proxy import build_pool
from recon import Crawler, DirFuzzer
from scanner import XSSScanner
from state import CONFIG_FILE
from ui import ask_yes_no, show_panel


def main() -> None:
    
    config = ask_load_config()

    default_silent = config.get("silent", False)
    if ask_yes_no("Enable SILENT (stealth auto) mode?", default_silent):
        state.SILENT_MODE = True
    SILENT_MODE = state.SILENT_MODE

    banner()
    if SILENT_MODE:
        print(f"{Colors.RED}{Colors.BOLD}  ┌ SILENT ─────────────────────────────────────────┐\n  │ proxy forced · bypass only · 2 rps · HPP on     │\n  └─────────────────────────────────────────────────┘{Colors.RESET}\n")
    else:
        print(f"{Colors.GREEN}  ┌ NORMAL ─────────────────────────────────────────┐\n  │ full control · all payloads · configurable      │\n  └─────────────────────────────────────────────────┘{Colors.RESET}\n")

    # ---------- Callback (both modes) ----------
    default_cb = config.get("callback_url", "")
    if not SILENT_MODE:
        print(f"{Colors.MAGENTA}╔ CALLBACK ════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.DIM}1. Cloudflare Tunnel: cloudflared tunnel --url http://localhost:9000{Colors.RESET}")
        print(f"{Colors.DIM}2. Ngrok: ngrok http 9000{Colors.RESET}")
        print(f"{Colors.DIM}3. Local network: http://YOUR_LAN_IP:9000{Colors.RESET}\n")

    use_cb = ask_yes_no("Use Callback for verification?", bool(default_cb))
    callback_url = None
    if use_cb:
        cb_prompt = f"{Colors.YELLOW}Callback public URL"
        if default_cb:
            cb_prompt += f" [{default_cb}]"
        cb_prompt += f": {Colors.RESET}"
        cb_input = input(cb_prompt).strip() or default_cb
        if not cb_input:
            status("No callback URL given. Continuing without OOB.", "warn")
        else:
            if not cb_input.startswith(("http://", "https://")):
                cb_input = "http://" + cb_input
            parsed = urlparse(cb_input)
            local_port = parsed.port or 9000
            if start_callback_server(local_port):
                callback_url = cb_input.rstrip("/")
                status(f"Callback base URL: {callback_url}", "ok")
            else:
                status("Local server failed. Reflection-only mode.", "warn")

    # ---------- Custom headers (both modes) ----------
    state.CUSTOM_HEADERS = ask_custom_headers()

    # ---------- Proxy ----------
    # SILENT  → proxy required (no Direct)
    # NORMAL  → Direct by default, proxy optional
    default_conn = config.get("proxy_conn", "1")
    conn = "1"

    if SILENT_MODE:
        if default_conn == "1":
            default_conn = "3"
        show_panel("PROXY (required)", [
            ("[2]", "Tor"),
            ("[3]", "Fetch Proxies"),
            ("[4]", "File"),
            ("[5]", "Paste"),
        ], border_color=Colors.RED)
        conn = input(f"{Colors.YELLOW}  ? proxy [{default_conn}]: {Colors.RESET}").strip() or default_conn
        if conn == "1":
            status("Direct blocked in silent mode → Fetch Proxies", "warn")
            conn = "3"
    else:
        # Normal: keep it light
        if ask_yes_no("Use proxy?", False):
            show_panel("PROXY", [
                ("[2]", "Tor"),
                ("[3]", "Fetch Proxies"),
                ("[4]", "File"),
                ("[5]", "Paste"),
            ], border_color=Colors.YELLOW)
            conn = input(f"{Colors.YELLOW}  ? proxy [3]: {Colors.RESET}").strip() or "3"
            if conn == "1":
                conn = "3"
        else:
            conn = "1"
            status("Direct connection", "info")

    pool = build_pool(conn, config)

    # ---------- Target ----------
    default_target = config.get("target", "")
    print(f"\n{Colors.MAGENTA}╔ TARGET ══════════════════════════════════╗{Colors.RESET}")
    t_prompt = f"{Colors.YELLOW}Target URL"
    if default_target:
        t_prompt += f" [{default_target}]"
    t_prompt += f": {Colors.RESET}"
    url = input(t_prompt).strip() or default_target
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # ---------- Recon ----------
    print(f"\n{Colors.MAGENTA}╔ RECON ═══════════════════════════════════╗{Colors.RESET}")

    if SILENT_MODE:
        status("Silent mode: dir fuzzer skipped (stealth)", "info")
        depth = int(config.get("crawl_depth", 2))
    else:
        if ask_yes_no("Run Dir Fuzzer?", True):
            DirFuzzer(url, pool).fuzz(WORDLIST)
        default_depth = str(config.get("crawl_depth", 2))
        depth_raw = input(f"{Colors.YELLOW}Crawl depth (1-3, default {default_depth}): {Colors.RESET}").strip() or default_depth
        try:
            depth = max(1, min(3, int(depth_raw)))
        except ValueError:
            depth = 2

    targets = Crawler(url, pool, max_depth=depth).crawl()
    if not targets:
        status("No params/forms found. Adding base URL as fallback.", "warn")
        sep = "&" if "?" in url else "?"
        targets = [("GET", url + sep + "q=test")]

    # ---------- Payloads & Speed ----------
    print(f"\n{Colors.MAGENTA}╔ EXPLOIT ═════════════════════════════════╗{Colors.RESET}")

    context = "all"
    use_double_encode = False
    use_comment_junk = False
    use_mixed_case = False
    use_ctype_confusion = False
    force_method = None
    advanced_hpp = False

    if SILENT_MODE:
        # SILENT: proxy forced, context-aware, bypass set, slow
        # HPP / mutators → user picks from expandable menu
        rps = 2.0
        payloads = list(PAYLOADS_DB.get("waf_bypass", []))
        if callback_url:
            payloads.extend(PAYLOADS_DB.get("callback", []))

        atk = ask_attack_methods({
            "use_hpp": config.get("use_hpp", True),
            "use_mutators": config.get("use_mutators", True),
        })
        use_hpp = atk["use_hpp"]
        use_mutators = atk["use_mutators"]
        use_double_encode = atk.get("use_double_encode", False)
        use_comment_junk = atk.get("use_comment_junk", False)
        use_mixed_case = atk.get("use_mixed_case", False)
        use_ctype_confusion = atk.get("use_ctype_confusion", False)
        advanced_hpp = atk.get("advanced_hpp", False)
        if use_mutators:
            payloads = Mutator.expand_list(payloads, max_variants=2)

        show_panel("HTTP METHOD", [
            ("[1]", "GET"),
            ("[2]", "POST"),
        ], border_color=Colors.CYAN)
        m_choice = input(f"{Colors.YELLOW}  ? send as [1]: {Colors.RESET}").strip() or "1"
        force_method = "POST" if m_choice == "2" else "GET"

        fixed = []
        for item in targets:
            if len(item) == 2:
                _m, u = item
                fixed.append((force_method, u))
            elif len(item) == 3:
                _m, u, p = item
                fixed.append((force_method, u, p))
            else:
                fixed.append(item)
        targets = fixed

        status("SILENT MODE active", "ok")
        status(
            f"-> proxy | context-aware | bypass | {force_method} | "
            f"method={atk.get('pick','?')} | 2 rps",
            "info",
        )
    else:
        # NORMAL: speed + payload profile + expandable options
        default_rps = float(config.get("rps", 8.0))
        rps = ask_speed(default_rps)

        show_panel("PAYLOADS", [
            ("[1]", "Standard   · classic + context"),
            ("[2]", "Strong     · + WAF bypass"),
            ("[3]", "Bypass only"),
            ("[4]", "Classic only"),
        ], border_color=Colors.CYAN)
        p_choice = input(f"{Colors.YELLOW}  ? payloads [1]: {Colors.RESET}").strip() or "1"

        context = "all"
        if p_choice == "3":
            payloads = list(PAYLOADS_DB.get("waf_bypass", []))
            if callback_url:
                payloads.extend(PAYLOADS_DB.get("callback", []))
        elif p_choice == "4":
            payloads = list(PAYLOADS_DB.get("classic", []))
        elif p_choice == "2":
            payloads = get_context_payloads("all", mutate=False)
            for p in PAYLOADS_DB.get("waf_bypass", []):
                if p not in payloads:
                    payloads.append(p)
        else:
            payloads = list(PAYLOADS_DB.get("classic", []))
            for p in CONTEXT_PAYLOADS.get("html", []):
                if p not in payloads:
                    payloads.append(p)
            for p in CONTEXT_PAYLOADS.get("attribute", []):
                if p not in payloads and "{CALLBACK}" not in p:
                    payloads.append(p)

        atk = ask_attack_methods({
            "use_hpp": config.get("use_hpp", False),
            "use_mutators": config.get("use_mutators", False),
        })
        use_hpp = atk["use_hpp"]
        use_mutators = atk["use_mutators"]
        use_double_encode = atk.get("use_double_encode", False)
        use_comment_junk = atk.get("use_comment_junk", False)
        use_mixed_case = atk.get("use_mixed_case", False)
        use_ctype_confusion = atk.get("use_ctype_confusion", False)
        advanced_hpp = atk.get("advanced_hpp", False)
        if use_mutators:
            payloads = Mutator.expand_list(payloads, max_variants=2)

    if not callback_url:
        payloads = [p for p in payloads if "{CALLBACK}" not in p]

    # dedupe preserve order
    seen = set()
    clean = []
    for p in payloads:
        if p not in seen:
            seen.add(p)
            clean.append(p)
    payloads = clean

    if not payloads:
        status("No payloads available!", "err")
        return

    mode_tag = "SILENT" if SILENT_MODE else "NORMAL"
    status(f"[{mode_tag}] {len(payloads)} payloads | {rps:.1f} req/s | HPP={use_hpp} | mutators={'ON' if use_mutators or SILENT_MODE else 'OFF'}", "ok")

    if not SILENT_MODE:
        print(f"\n{Colors.MAGENTA}Starting XSS Scan... (Press Ctrl+C to stop){Colors.RESET}")

    scanner = XSSScanner(pool, use_hpp=use_hpp, rps=rps, callback_url=callback_url, target_url=url,
                         use_double_encode=use_double_encode, use_comment_junk=use_comment_junk,
                         use_mixed_case=use_mixed_case, use_ctype_confusion=use_ctype_confusion,
                         force_method=force_method, advanced_hpp=advanced_hpp)

    try:
        scanner.scan(targets, payloads, context_aware=SILENT_MODE)
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}Scan stopped by user.{Colors.RESET}")

    fmt = ask_save_format()
    scanner.save_report(fmt=fmt)

    cb_path = scanner.save_callback_hits_only()
    if cb_path:
        status(f"Callback hits saved: {cb_path}", "ok")

    scanner.print_summary()

    print(f"\n{Colors.MAGENTA}╔{'═' * 42}╗{Colors.RESET}")
    print(f"{Colors.MAGENTA}║{Colors.RESET} {Colors.BOLD}SCAN COMPLETE{Colors.RESET}{' ' * 28}{Colors.MAGENTA}║{Colors.RESET}")
    print(f"{Colors.MAGENTA}╠{'═' * 42}╣{Colors.RESET}")
    print(f"{Colors.MAGENTA}║{Colors.RESET} {Colors.CYAN}Sent{Colors.RESET}       {Colors.WHITE}{scanner.stats['sent']:<28}{Colors.RESET}{Colors.MAGENTA}║{Colors.RESET}")
    print(f"{Colors.MAGENTA}║{Colors.RESET} {Colors.GREEN}Hits{Colors.RESET}       {Colors.WHITE}{scanner.stats['reflected']:<28}{Colors.RESET}{Colors.MAGENTA}║{Colors.RESET}")
    print(f"{Colors.MAGENTA}║{Colors.RESET} {Colors.YELLOW}Callback{Colors.RESET}   {Colors.WHITE}{scanner.stats['callback_hits']:<28}{Colors.RESET}{Colors.MAGENTA}║{Colors.RESET}")
    print(f"{Colors.MAGENTA}║{Colors.RESET} {Colors.RED}Errors{Colors.RESET}     {Colors.WHITE}{scanner.stats['errors']:<28}{Colors.RESET}{Colors.MAGENTA}║{Colors.RESET}")
    print(f"{Colors.MAGENTA}╚{'═' * 42}╝{Colors.RESET}")

    if ask_yes_no("Save this config for next time?", False):
        save_data = {
            "target": url,
            "proxy_conn": conn,
            "rps": rps,
            "use_hpp": use_hpp,
            "context": context,
            "crawl_depth": depth,
            "callback_url": callback_url or "",
            "silent": SILENT_MODE,
        }
        if Config.save(save_data):
            status(f"Config saved to {CONFIG_FILE}", "ok")

    input(f"\n{Colors.DIM}Press Enter to exit...{Colors.RESET}")
