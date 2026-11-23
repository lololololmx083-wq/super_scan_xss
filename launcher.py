#!/usr/bin/env python3
"""XSS Hunter launcher — path setup, deps check, then main."""
from __future__ import annotations

import os
import sys


def _bootstrap() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)

    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except Exception:
            pass


def _check_deps() -> None:
    missing = []
    try:
        import requests  # noqa: F401
    except ImportError:
        missing.append("requests")
    try:
        import bs4  # noqa: F401
    except ImportError:
        missing.append("beautifulsoup4")
    try:
        import urllib3  # noqa: F401
    except ImportError:
        missing.append("urllib3")
    # optional
    try:
        import socks  # noqa: F401
    except ImportError:
        pass

    if missing:
        print("\n[!] Missing dependencies:")
        print("    pip install " + " ".join(missing))
        print("    or: pip install -r requirements.txt\n")
        sys.exit(1)


def main() -> None:
    _bootstrap()
    _check_deps()

    # warm-import package modules (same graph main uses)
    import state  # noqa: F401
    import colors  # noqa: F401
    import ui  # noqa: F401
    import config  # noqa: F401
    import callback  # noqa: F401
    import headers  # noqa: F401
    import payloads  # noqa: F401
    import mutator  # noqa: F401
    import speed  # noqa: F401
    import proxy  # noqa: F401
    import recon  # noqa: F401
    import detect  # noqa: F401
    import scanner  # noqa: F401
    import menus  # noqa: F401
    import threading

    from main import main as app_main

    try:
        app_main()
    except KeyboardInterrupt:
        from colors import Colors
        print(f"\n{Colors.RED}Exited.{Colors.RESET}")


if __name__ == "__main__":
    main()
