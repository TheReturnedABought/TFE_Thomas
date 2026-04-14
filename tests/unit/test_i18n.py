"""
Unit tests for Internationalization provider assuring fallback keys and custom loading logic.
"""

from core.i18n import I18n, get_text


class TestI18n:
    def test_default_singleton(self):
        """Test default singleton."""
        # By default english loads the custom keys
        assert get_text("cli.interrupt") == "Analysis interrupted by user."
        assert get_text("cli.starting") == "Starting analysis..."

    def test_missing_translation_returns_key(self):
        """Test missing translation returns key."""
        # Ensure fallback on missing keys returns the key itself
        assert get_text("super.random.invalid.key") == "super.random.invalid.key"

    def test_missing_translation_returns_default(self):
        """Test missing translation returns default."""
        # Ensure default values are prioritized when specified
        assert get_text("invalid", "My Fallback") == "My Fallback"

    def test_locale_not_found(self):
        """Test locale not found."""
        # Construct explicit missing locale
        custom = I18n(locale="zzzz")
        # Ensure it falls back to raw keys smoothly without crashing
        assert custom.get_text("cli.interrupt") == "cli.interrupt"
