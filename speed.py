import sys
import threading
import time

from colors import Colors
import state


class SpeedController:
    def __init__(self, rps: float):
        self.rps = max(0.2, float(rps))
        self.delay = 1.0 / self.rps
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            slot = self._next if self._next > now else now
            self._next = slot + self.delay
        gap = slot - time.monotonic()
        if gap > 0:
            time.sleep(gap)


class ProgressBar:
    def __init__(self, total: int, prefix: str = "Progress", color: str = Colors.CYAN):
        self.total = max(1, total)
        self.prefix = prefix
        self.color = color
        self.current = 0
        self.lock = threading.Lock()
        self.bar_length = 28
        self.finished = False

    def update(self, step: int = 1, extra: str = "") -> None:
        with self.lock:
            if self.finished:
                return
            self.current = min(self.current + step, self.total)
            if not state.SILENT_MODE:
                percent = self.current / self.total
                filled = int(self.bar_length * percent)
                bar = "▓" * filled + "░" * (self.bar_length - filled)
                sys.stdout.write(
                    f"\r{Colors.DIM}{self.prefix}{Colors.RESET} "
                    f"{self.color}│{bar}│{Colors.RESET} "
                    f"{Colors.WHITE}{percent*100:5.1f}%{Colors.RESET} "
                    f"{Colors.DIM}({self.current}/{self.total}){Colors.RESET} {extra}   "
                )
                sys.stdout.flush()
            if self.current >= self.total:
                self.finished = True
                if not state.SILENT_MODE:
                    sys.stdout.write("\n")

