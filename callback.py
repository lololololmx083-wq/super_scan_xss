import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

from colors import Colors, status


CALLBACK_HITS: dict[str, list[dict]] = {}
CALLBACK_LOCK = threading.Lock()


class CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        ip = self.client_address[0]
        ua = (self.headers.get("User-Agent") or "?")[:80]
        path = self.path or "/"

        token = ""
        parts = path.split("?")[0].strip("/").split("/")
        if len(parts) >= 2 and parts[0] == "x":
            token = parts[1]
        elif len(parts) >= 1 and parts[0].startswith("t"):
            token = parts[0]

        hit = {"time": ts, "ip": ip, "path": path, "ua": ua, "token": token}

        with CALLBACK_LOCK:
            if token:
                CALLBACK_HITS.setdefault(token, []).append(hit)

        print(f"\n{Colors.GREEN}╔{'═' * 58}╗{Colors.RESET}")
        print(f"{Colors.GREEN}║{Colors.RESET} {Colors.BOLD}{Colors.GREEN}★ CALLBACK — XSS EXECUTION CONFIRMED{Colors.RESET}{' ' * 18}{Colors.GREEN}║{Colors.RESET}")
        print(f"{Colors.GREEN}╠{'═' * 58}╣{Colors.RESET}")
        print(f"{Colors.GREEN}║{Colors.RESET} {Colors.WHITE}Token {Colors.RESET}{Colors.DIM}│{Colors.RESET} {Colors.YELLOW}{token or '(none)':<46}{Colors.RESET} {Colors.GREEN}║{Colors.RESET}")
        print(f"{Colors.GREEN}║{Colors.RESET} {Colors.WHITE}Path  {Colors.RESET}{Colors.DIM}│{Colors.RESET} {Colors.CYAN}{path[:46]:<46}{Colors.RESET} {Colors.GREEN}║{Colors.RESET}")
        print(f"{Colors.GREEN}║{Colors.RESET} {Colors.WHITE}From  {Colors.RESET}{Colors.DIM}│{Colors.RESET} {Colors.DIM}{ip} · {ua[:30]:<30}{Colors.RESET} {Colors.GREEN}║{Colors.RESET}")
        print(f"{Colors.GREEN}╚{'═' * 58}╝{Colors.RESET}")

        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_args) -> None:
        return


def start_callback_server(port: int) -> bool:
    try:
        server = HTTPServer(("0.0.0.0", port), CallbackHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        status(f"Callback server listening on 0.0.0.0:{port}", "ok")
        return True
    except OSError as exc:
        status(f"Failed to start callback server: {exc}", "err")
        return False


def callback_seen(token: str) -> bool:
    if not token:
        return False
    with CALLBACK_LOCK:
        return bool(CALLBACK_HITS.get(token))
