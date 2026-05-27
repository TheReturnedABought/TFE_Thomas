"""
core/i18n.py - Internationalization provider.

Allows decoupling all user-facing hardcoded text into dictionary maps.
"""

import json
import os
from typing import Dict, Optional


class I18n:
    """
    Internationalization manager that loads translation files from the locales directory
    and provides key-based translation retrieval.
    """

    def __init__(self, locale: str = "en") -> None:
        """
        Initialize the translation manager with a specific locale.

        Args:
            locale (str): The locale language code (e.g., 'en', 'fr', 'es'). Defaults to 'en'.
        """
        self.locale = locale
        self._translations: Dict[str, str] = {}
        self._load_locale()

    def _load_locale(self) -> None:
        """
        Load translation keys and values from the corresponding JSON locale file.
        Resets translations to an empty dictionary if file loading fails.
        """
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        locale_path = os.path.join(base_dir, "locales", f"{self.locale}.json")
        try:
            with open(locale_path, "r", encoding="utf-8") as f:
                self._translations = json.load(f)
        except Exception:
            self._translations = {}

    def get_text(self, key: str, default: Optional[str] = None) -> str:
        """
        Retrieve a localized translation string by its key.

        Args:
            key (str): The unique translation lookup key.
            default (str, optional): A fallback string if the key is not found. Defaults to None.

        Returns:
            str: The translated text, the specified default fallback, or the key itself.
        """
        if key in self._translations:
            return self._translations[key]
        return default if default is not None else key


# Singleton instance
_i18n_instance = I18n()


def set_locale(lang: str) -> None:
    """
    Set the active translation language for the global I18n instance.

    Args:
        lang (str): The locale language code (e.g., 'en', 'fr', 'es').
    """
    _i18n_instance.locale = lang
    _i18n_instance._load_locale()


def get_text(key: str, default: Optional[str] = None) -> str:
    """
    Helper function to query the global I18n translation registry.

    Args:
        key (str): The translation lookup key.
        default (str, optional): Fallback string if key is missing. Defaults to None.

    Returns:
        str: The retrieved translated string or fallback value.
    """
    return _i18n_instance.get_text(key, default)
