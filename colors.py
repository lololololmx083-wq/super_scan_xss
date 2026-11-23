import os

import state


class Colors:
    GREEN   = "\033[92m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def status(msg: str, kind: str = "info") -> None:
    if state.SILENT_MODE and kind not in ("err", "hit"):
        return
    if kind == "info":
        print(f"{Colors.CYAN}  › {msg}{Colors.RESET}")
    elif kind == "ok":
        print(f"{Colors.GREEN}  ✓ {msg}{Colors.RESET}")
    elif kind == "warn":
        print(f"{Colors.YELLOW}  ! {msg}{Colors.RESET}")
    elif kind == "err":
        print(f"{Colors.RED}  ✗ {msg}{Colors.RESET}")
    elif kind == "hit":
        print(f"{Colors.BOLD}{Colors.GREEN}  ★ HIT {msg}{Colors.RESET}")


def banner() -> None:
    clear()
    if state.SILENT_MODE:
        print(f"""
{Colors.DIM}{Colors.CYAN}                                                                                                          
 @@@@@@ @@@ @@@      @@@@@@@@ @@@  @@@ @@@@@@@    
!@@     @@! @@!      @@!      @@!@!@@@   @!!      
 !@@!!  !!@ @!!      @!!!:!   @!@@!!@!   @!!      
    !:! !!: !!:      !!:      !!:  !!!   !!:      
::.: :  :   : ::.: : : :: ::  ::    :     :                                         
{Colors.RESET}         
""")
        return
    print(f"""
{Colors.MAGENTA}{Colors.BOLD} ▒██   ██▒  ██████   ██████ {Colors.RESET}
{Colors.MAGENTA}{Colors.BOLD} ▒▒ █ █ ▒░▒██    ▒ ▒██    ▒ {Colors.RESET}
{Colors.CYAN}{Colors.BOLD}  ░░  █   ░░ ▓██▄   ░ ▓██▄   {Colors.RESET}
{Colors.CYAN}{Colors.BOLD}   ░ █ █ ▒   ▒   ██▒  ▒   ██▒{Colors.RESET}
{Colors.GREEN}{Colors.BOLD}  ▒██▒ ▒██▒▒██████▒▒▒██████▒▒{Colors.RESET}
{Colors.GREEN}{Colors.BOLD}  ▒▒ ░ ░▓ ░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░{Colors.RESET}
{Colors.YELLOW}{Colors.BOLD}  ░░   ░▒ ░░ ░▒  ░ ░░ ░▒  ░ ░{Colors.RESET}
{Colors.YELLOW}{Colors.BOLD}   ░    ░  ░  ░  ░  ░  ░  ░  {Colors.RESET}
{Colors.WHITE}{Colors.BOLD}   ░    ░        ░        ░  {Colors.RESET}

{Colors.CYAN}  XSS Hunter · Callback Edition (2026){Colors.RESET}
{Colors.DIM}  authorized testing only{Colors.RESET}
""")
