from colors import Colors


def show_panel(title: str, rows: list, border_color: str = Colors.MAGENTA) -> None:
    w = 44
    print(f"\n{border_color}╔{'═' * w}╗{Colors.RESET}")
    print(f"{border_color}║{Colors.RESET} {Colors.BOLD}{title:<{w-2}}{Colors.RESET} {border_color}║{Colors.RESET}")
    print(f"{border_color}╠{'═' * w}╣{Colors.RESET}")
    for key, label in rows:
        line = f" {key:<5} {label}"
        print(f"{border_color}║{Colors.RESET}{Colors.CYAN}{line:<{w}}{Colors.RESET}{border_color}║{Colors.RESET}")
    print(f"{border_color}╚{'═' * w}╝{Colors.RESET}\n")


def ask_yes_no(prompt: str, default: bool = False) -> bool:
    d = "Y/n" if default else "y/N"
    try:
        ans = input(f"{Colors.YELLOW}  ? {prompt} [{d}]: {Colors.RESET}").strip().lower()
        if not ans:
            return default
        return ans in ("y", "yes", "1", "true")
    except (EOFError, KeyboardInterrupt):
        print()
        return default
