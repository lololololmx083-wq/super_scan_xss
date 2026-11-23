# XSS Hunter · Callback Edition (2026)

Split from monolithic `xss-18.py`. **Logic unchanged** — only modularized for GitHub.

Authorized testing only.

## Structure

| File | Role |
|------|------|
| `launcher.py` | entry point |
| `main.py` | CLI / flow |
| `state.py` | `SILENT_MODE`, `CUSTOM_HEADERS` |
| `colors.py` | Colors, status, banner |
| `monitor.py` | request monitor |
| `ui.py` | panels / yes-no |
| `config.py` | json config |
| `callback.py` | OOB callback server |
| `headers.py` | UA profiles |
| `payloads.py` | payload DB |
| `mutator.py` | 17 transforms + AdvHPP |
| `speed.py` | RPS / progress |
| `proxy.py` | pool, Tor, fetch |
| `recon.py` | dir fuzz + crawler |
| `detect.py` | reflection helpers |
| `scanner.py` | XSSScanner |
| `menus.py` | interactive menus |

## Install & run

```bash
cd xss_hunter
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python launcher.py
```
