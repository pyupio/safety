from safety.emoji import (
    load_emoji,
    process_custom_emojis,
    process_rich_emojis_fallback,
)


class TestProcessCustomEmojis:
    def test_non_string_input_is_unchanged(self):
        assert process_custom_emojis(None) is None
        assert process_custom_emojis(123) == 123

    def test_text_without_custom_icons_is_unchanged(self):
        text = "Just a plain message with no icons"
        assert process_custom_emojis(text) == text

    def test_known_icons_use_unicode_by_default(self):
        assert process_custom_emojis(":icon_check:") == "✓"
        assert process_custom_emojis(":icon_warning:") == "⚠️"
        assert process_custom_emojis(":icon_info:") == "ℹ️"

    def test_known_icons_use_ascii_fallback(self):
        assert process_custom_emojis(":icon_check:", use_ascii=True) == "+"
        assert process_custom_emojis(":icon_warning:", use_ascii=True) == "!"
        assert process_custom_emojis(":icon_info:", use_ascii=True) == "i"

    def test_unknown_icons_are_left_unchanged(self):
        text = ":icon_does_not_exist:"
        assert process_custom_emojis(text) == text

    def test_multiple_icons_are_replaced(self):
        text = "Status: :icon_check: Warning: :icon_warning:"
        assert process_custom_emojis(text) == "Status: ✓ Warning: ⚠️"


class TestProcessRichEmojisFallback:
    def test_text_without_emoji_codes_is_unchanged(self):
        text = "Just a plain message"
        assert process_rich_emojis_fallback(text) == text

    def test_known_emojis_use_ascii_fallback(self):
        assert process_rich_emojis_fallback(":rocket:") == ">>"
        assert process_rich_emojis_fallback(":white_check_mark:") == "+"
        assert process_rich_emojis_fallback(":lock:") == "[LOCK]"

    def test_unknown_emojis_are_left_unchanged(self):
        text = ":unknown_emoji:"
        assert process_rich_emojis_fallback(text) == text

    def test_multiple_emojis_are_replaced(self):
        text = "Launching :rocket: with :lock: enabled"
        assert process_rich_emojis_fallback(text) == "Launching >> with [LOCK] enabled"


class TestLoadEmoji:
    def test_empty_string_is_unchanged(self):
        assert load_emoji("") == ""

    def test_custom_icons_are_processed_by_default(self):
        assert load_emoji(":icon_check:") == "✓"

    def test_rich_emojis_are_left_for_rich_by_default(self):
        assert load_emoji(":rocket:") == ":rocket:"

    def test_ascii_mode_processes_both_emoji_types(self):
        text = ":icon_check: Launching :rocket:"
        assert load_emoji(text, use_ascii=True) == "+ Launching >>"