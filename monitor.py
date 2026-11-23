import re
import threading
from datetime import datetime

from colors import Colors


MONITOR_MODE = False
MONITOR_LOG_PATH = None
MONITOR_LOCK = threading.Lock()
PRINT_LOCK = threading.Lock()
MONITOR_COUNTER = {"send": 0, "recv": 0, "err": 0, "hit": 0}


def monitor_enable(log_path: str | None = None) -> None:
    global MONITOR_MODE, MONITOR_LOG_PATH
    MONITOR_MODE = True
    MONITOR_LOG_PATH = log_path


def _safe_print(*args, **kwargs) -> None:
    """Thread-safe print — prevents interleaved output from workers."""
    with PRINT_LOCK:
        print(*args, **kwargs)


def monitor_log(stage: str, data: dict) -> None:
    if not MONITOR_MODE:
        return

    # ── Update counters (hit counted ONLY on RECV) ────────────
    with MONITOR_LOCK:
        if stage == "SEND":
            MONITOR_COUNTER["send"] += 1
        elif stage == "RECV":
            MONITOR_COUNTER["recv"] += 1
            if data.get("hit"):
                MONITOR_COUNTER["hit"] += 1
        elif stage == "ERR":
            MONITOR_COUNTER["err"] += 1

    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    if stage == "SEND":
        idx = int(data.get("idx", 0) or 0)
        total = int(data.get("total", 0) or 0)
        method = data.get("method", "?")
        url = (data.get("url", "") or "")
        payload = (data.get("payload", "") or "")
        headers = data.get("headers")

        url_show = url if len(url) <= 85 else url[:82] + "..."
        pl_show = payload if len(payload) <= 70 else payload[:67] + "..."

        _safe_print(
            f"{Colors.DIM}{ts}{Colors.RESET} "
            f"{Colors.CYAN}[{idx:>4}/{total}]{Colors.RESET} "
            f"{Colors.BOLD}{method:<4}{Colors.RESET} "
            f"{Colors.WHITE}{url_show}{Colors.RESET}"
        )
        _safe_print(
            f"     {Colors.DIM}└─ payload:{Colors.RESET} "
            f"{Colors.YELLOW}{pl_show}{Colors.RESET}"
        )

        hdr_text = ""
        if isinstance(headers, dict) and headers:
            hdr_text = ", ".join(f"{k}: {v}" for k, v in headers.items())
            hdr_show = hdr_text if len(hdr_text) <= 85 else hdr_text[:82] + "..."
            _safe_print(
                f"     {Colors.DIM}└─ headers:{Colors.RESET} "
                f"{Colors.BLUE}{hdr_show}{Colors.RESET}"
            )

        line = f"{ts} SEND {method} {url} | {payload}" + (f" | headers={hdr_text}" if hdr_text else "")

    elif stage == "RECV":
        status = data.get("status")
        length = data.get("length", 0)
        time_ms = data.get("time_ms", 0)
        ok = data.get("reflected", False)
        hit = data.get("hit", False)
        signal = data.get("signal", "")

        if status == 200:
            s_color = Colors.GREEN
        elif status and status < 400:
            s_color = Colors.YELLOW
        else:
            s_color = Colors.RED

        if status is not None:
            status_disp = f"{s_color}{status}{Colors.RESET}"
        else:
            status_disp = f"{Colors.RED}None{Colors.RESET}"

        if hit:
            tag = f"{Colors.BOLD}{Colors.GREEN}★ HIT · {signal}{Colors.RESET}"
        elif ok:
            tag = f"{Colors.YELLOW}~ reflected{Colors.RESET}"
        else:
            tag = f"{Colors.DIM}clean{Colors.RESET}"

        _safe_print(
            f"     {Colors.DIM}└─{Colors.RESET} "
            f"status={status_disp} "
            f"len={length} "
            f"time={time_ms}ms "
            f"→ {tag}"
        )
        line = f"{ts} RECV status={status} len={length} time={time_ms}ms signal={signal} hit={hit}"

    elif stage == "ERR":
        err = (data.get("error", "") or "")
        err_show = err if len(err) <= 90 else err[:87] + "..."
        _safe_print(
            f"     {Colors.DIM}└─{Colors.RESET} "
            f"{Colors.RED}ERR{Colors.RESET} {Colors.DIM}{err_show}{Colors.RESET}"
        )
        line = f"{ts} ERR {err}"

    else:
        return

    if MONITOR_LOG_PATH:
        try:
            clean = re.sub(r"\033\[[0-9;]*m", "", line)
            with MONITOR_LOCK:
                with open(MONITOR_LOG_PATH, "a", encoding="utf-8") as f:
                    f.write(clean + "\n")
        except Exception:
            pass


def monitor_stats_line() -> str:
    with MONITOR_LOCK:
        c = dict(MONITOR_COUNTER)
    return (
        f"{Colors.DIM}monitor{Colors.RESET} "
        f"send={Colors.CYAN}{c['send']}{Colors.RESET} "
        f"recv={Colors.CYAN}{c['recv']}{Colors.RESET} "
        f"err={Colors.RED}{c['err']}{Colors.RESET} "
        f"hit={Colors.GREEN}{c['hit']}{Colors.RESET}"
    )