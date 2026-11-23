from colors import Colors, status
from config import Config
from state import CONFIG_FILE
from ui import ask_yes_no, show_panel


def ask_save_format() -> str:
    print()
    print(f"{Colors.MAGENTA}╔{'═' * 48}╗{Colors.RESET}")
    print(f"{Colors.MAGENTA}║{Colors.RESET} {Colors.BOLD}SAVE RESULTS{Colors.RESET}{' ' * 35}{Colors.MAGENTA}║{Colors.RESET}")
    print(f"{Colors.MAGENTA}╠{'═' * 48}╣{Colors.RESET}")
    print(f"{Colors.MAGENTA}║{Colors.RESET}  {Colors.CYAN}[1]{Colors.RESET}  TXT     {Colors.DIM}text summary{Colors.RESET}{' ' * 18}{Colors.MAGENTA}║{Colors.RESET}")
    print(f"{Colors.MAGENTA}║{Colors.RESET}  {Colors.CYAN}[2]{Colors.RESET}  HTML    {Colors.DIM}web report{Colors.RESET}{' ' * 20}{Colors.MAGENTA}║{Colors.RESET}")
    print(f"{Colors.MAGENTA}║{Colors.RESET}  {Colors.GREEN}[3]{Colors.RESET}  BOTH    {Colors.DIM}txt + html  ★{Colors.RESET}{' ' * 15}{Colors.MAGENTA}║{Colors.RESET}")
    print(f"{Colors.MAGENTA}║{Colors.RESET}  {Colors.RED}[4]{Colors.RESET}  NONE    {Colors.DIM}skip{Colors.RESET}{' ' * 26}{Colors.MAGENTA}║{Colors.RESET}")
    print(f"{Colors.MAGENTA}╚{'═' * 48}╝{Colors.RESET}")
    try:
        choice = input(f"{Colors.YELLOW}  ? choice [3]: {Colors.RESET}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return "both"
    if choice in ("1", "txt"):
        return "txt"
    if choice in ("2", "html"):
        return "html"
    if choice in ("3", "both", ""):
        return "both"
    if choice in ("4", "n", "no", "none"):
        return "n"
    return "both"


def ask_attack_methods(defaults=None) -> dict:
    """Single-choice attack method — base techniques + golden combos."""
    defaults = defaults or {}
    default_pick = str(defaults.get("pick", "1"))

    show_panel("ATTACK METHOD", [
        ("[1]", "Raw payloads only"),
        ("[2]", "HPP (param pollution)"),
        ("[3]", "Mutators (17 transforms)"),
        ("[4]", "HPP + Mutators"),
        ("[5]", "Double URL-encode"),
        ("[6]", "Comment junk  (/**/)"),
        ("[7]", "Mixed case tags"),
        ("[8]", "Double-encode + HPP"),
        ("[9]", "Content-Type Confusion"),
    ], border_color=Colors.CYAN)

    show_panel("GOLD COMBOS", [
        ("[10]", "HPP + Mutators + Double-encode"),
        ("[11]", "Stack · AdvHPP+Mut+Double+Junk+Case"),
        ("[12]", "FULL · AdvHPP + all + ctype"),
        ("[13]", "HPP Advanced · var chunk + 17-sep + []"),
    ], border_color=Colors.YELLOW)

    choice = input(f"{Colors.YELLOW}  ? method [{default_pick}]: {Colors.RESET}").strip() or default_pick

    use_hpp = choice in ("2", "4", "8", "10", "11", "12", "13")
    use_mutators = choice in ("3", "4", "10", "11", "12")
    use_double_encode = choice in ("5", "8", "10", "11", "12")
    use_comment_junk = choice in ("6", "11", "12")
    use_mixed_case = choice in ("7", "11", "12")
    use_ctype_confusion = choice in ("9", "12")
    advanced_hpp = choice in ("11", "12", "13")

    return {
        "use_hpp": use_hpp,
        "use_mutators": use_mutators,
        "use_double_encode": use_double_encode,
        "use_comment_junk": use_comment_junk,
        "use_mixed_case": use_mixed_case,
        "use_ctype_confusion": use_ctype_confusion,
        "advanced_hpp": advanced_hpp,
        "pick": choice,
    }


def ask_speed(default: float = 8.0) -> float:
    show_panel("SPEED", [
        ("[1]", "Slow     ·  2 req/s"),
        ("[2]", "Normal   ·  8 req/s"),
        ("[3]", "Fast     · 20 req/s"),
        ("[4]", "Custom   · type value"),
    ], border_color=Colors.CYAN)
    hint = f"current {default:.0f}" if default != 8.0 else "default 8"
    choice = input(f"{Colors.YELLOW}  ? speed [{hint}]: {Colors.RESET}").strip() or "2"
    if choice == "1":
        return 2.0
    if choice == "3":
        return 20.0
    if choice == "4":
        try:
            return max(0.2, min(100.0, float(input(f"{Colors.YELLOW}  ? req/s [5]: {Colors.RESET}").strip() or "5")))
        except ValueError:
            return 5.0
    return default if default != 8.0 else 8.0


def ask_context(default: str = "all") -> str:
    show_panel("CONTEXT", [
        ("[1]", "ALL         · max coverage"),
        ("[2]", "attribute   · inside attrs"),
        ("[3]", "html        · HTML body"),
        ("[4]", "js          · JS strings"),
    ], border_color=Colors.BLUE)
    choice = input(f"{Colors.YELLOW}  ? context [{default}]: {Colors.RESET}").strip().lower() or default
    mapping = {"1": "all", "2": "attribute", "3": "html", "4": "js"}
    return mapping.get(choice, default if default in mapping.values() else "all")


def ask_custom_headers() -> dict:
    headers = {}
    if not ask_yes_no("Custom headers/cookies?", False):
        return headers
    print(f"{Colors.DIM}  paste Key: Value  (empty line = done){Colors.RESET}")
    while True:
        try:
            line = input().strip()
        except EOFError:
            break
        if not line:
            break
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
    if headers:
        status(f"Loaded {len(headers)} custom header(s)", "ok")
    return headers


def ask_load_config() -> dict:
    if not Config.exists():
        return {}
    if not ask_yes_no("Load previous config?", True):
        return {}
    cfg = Config.load()
    if cfg:
        status(f"Config loaded from {CONFIG_FILE}", "ok")
    return cfg

