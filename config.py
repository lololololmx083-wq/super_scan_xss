import json
import os

from colors import status
from state import CONFIG_FILE


class Config:
    @staticmethod
    def save(data, path=CONFIG_FILE):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            status(f"Failed to save config: {e}", "err")
            return False

    @staticmethod
    def load(path=CONFIG_FILE):
        if not os.path.isfile(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            status(f"Failed to load config: {e}", "err")
            return {}

    @staticmethod
    def exists(path=CONFIG_FILE):
        return os.path.isfile(path)
