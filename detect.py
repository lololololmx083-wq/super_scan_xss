import random
import re
import string


def _uniq_marker() -> str:
    return "x" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def _uniq_token() -> str:
    return "t" + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))


def reflected(body: str, payload: str, marker: str) -> tuple[bool, str]:
    if not body:
        return False, ""
    if marker and marker in body:
        dangerous = ("onerror=", "onload=", "ontoggle=", "<svg", "<img", "<script", "<details")
        if any(d in payload and d in body for d in dangerous):
            return True, "reflected_raw"
        return True, "marker_raw"
    if payload and payload in body:
        return True, "full_payload"
    return False, ""


def detect_context(body: str, marker: str) -> str:
    """Return html | attribute | js | unknown from marker position in body."""
    if not body or not marker or marker not in body:
        return "unknown"
    idx = body.find(marker)
    before = body[max(0, idx - 120):idx]
    after = body[idx: idx + len(marker) + 40]
    window = before + after

    # inside script block
    script_open = body.rfind("<script", 0, idx)
    script_close = body.find("</script>", idx)
    if script_open != -1 and (script_close == -1 or script_close > idx):
        return "js"

    # attribute: tag open behind + equals / quote
    if re.search(r"<\w+[^>]*$", before):
        tag_chunk = before[before.rfind("<"):]
        if "=" in tag_chunk:
            return "attribute"

    if re.search(r"""[\w:-]+=\s*["'][^"']*$""", before):
        return "attribute"

    # JS-ish assignment outside script tag
    if re.search(r"""(?i)(var|let|const|return)\s+\w+\s*=\s*['"`][^'"`]*$""", before):
        return "js"

    return "html"

