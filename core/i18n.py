"""
i18n.py - Internationalization provider.
Allows decoupling all user-facing hardcoded text into dictionary maps.
"""

import json
import os
from typing import Dict, Optional


class I18n:
    def __init__(self, locale: str = "en"):
        self.locale = locale
        self._translations: Dict[str, str] = {}
        self._load_locale()

    def _load_locale(self) -> None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        locale_path = os.path.join(base_dir, "locales", f"{self.locale}.json")
        try:
            with open(locale_path, "r", encoding="utf-8") as f:
                self._translations = json.load(f)
        except Exception:
            self._translations = {}

    def get_text(self, key: str, default: Optional[str] = None) -> str:
        """Fetch localized text by key."""
        if key in self._translations:
            return self._translations[key]
        return default if default is not None else key


# Singleton instance
_i18n_instance = I18n()


def set_locale(lang: str) -> None:
    _i18n_instance.locale = lang
    _i18n_instance._load_locale()


def get_text(key: str, default: Optional[str] = None) -> str:
    """Helper method to access singleton instance translations."""
    return _i18n_instance.get_text(key, default)
