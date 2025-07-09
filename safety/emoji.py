# Custom emoji namespace mapping
import re
from typing import Match


CUSTOM_EMOJI_MAP = {
    "icon_check": "✓",
    "icon_warning": "⚠️",
    "icon_info": "ℹ️",
}

# ASCII fallback mapping for problematic environments
ASCII_FALLBACK_MAP = {
    "icon_check": "+",
    "icon_warning": "!",
    "icon_info": "i",
    "white_heavy_check_mark": "++",
    "white_check_mark": "+",
    "check_mark": "+",
    "heavy_check_mark": "+",
    "shield": "[SHIELD]",
    "x": "X",
    "lock": "[LOCK]",
    "key": "[KEY]",
    "pencil": "[EDIT]",
    "arrow_up": "^",
    "stop_sign": "[STOP]",
    "warning": "!",
    "locked": "[LOCK]",
    "pushpin": "[PIN]",
    "magnifying_glass_tilted_left": "[SCAN]",
    "fire": "[CRIT]",
    "yellow_circle": "[HIGH]",
    "sparkles": "*",
    "mag_right": "[VIEW]",
    "link": "->",
    "light_bulb": "[TIP]",
    "trophy": "[DONE]",
    "rocket": ">>",
    "busts_in_silhouette": "[TEAM]",
    "floppy_disk": "[SAVE]",
    "heavy_plus_sign": "[ADD]",
    "books": "[DOCS]",
    "speech_balloon": "[HELP]",
}

# Pre-compiled regex for emoji processing (Rich-style)
CUSTOM_EMOJI_PATTERN = re.compile(r"(:icon_\w+:)")


def process_custom_emojis(text: str, use_ascii: bool = False) -> str:
    """
    Pre-process our custom emoji namespace before Rich handles the text.
    This only handles our custom :icon_*: emojis.
    """
    if not isinstance(text, str) or ":icon_" not in text:
        return text

    def replace_custom_emoji(match: Match[str]) -> str:
        emoji_code = match.group(1)  # :icon_check:
        emoji_name = emoji_code[1:-1]  # icon_check

        # If we should use ASCII, use the fallback
        if use_ascii:
            return ASCII_FALLBACK_MAP.get(emoji_name, emoji_code)

        return CUSTOM_EMOJI_MAP.get(emoji_name, emoji_code)

    return CUSTOM_EMOJI_PATTERN.sub(replace_custom_emoji, text)


def process_rich_emojis_fallback(text: str) -> str:
    """
    Replace Rich emoji codes with ASCII alternatives when in problematic environments.
    """
    # Simple pattern to match Rich emoji codes like :emoji_name:
    emoji_pattern = re.compile(r":([a-zA-Z0-9_]+):")

    def replace_with_ascii(match: Match[str]) -> str:
        emoji_name = match.group(1)
        # Check if we have an ASCII fallback
        ascii_replacement = ASCII_FALLBACK_MAP.get(emoji_name, None)
        if ascii_replacement:
            return ascii_replacement

        # Otherwise keep the original
        return match.group(0)

    return emoji_pattern.sub(replace_with_ascii, text)


def load_emoji(text: str, use_ascii: bool = False) -> str:
    """
    Load emoji from text if emoji is present.
    """

    # Pre-process our custom emojis
    text = process_custom_emojis(text, use_ascii)

    # If we need ASCII fallbacks, also process Rich emoji codes
    if use_ascii:
        text = process_rich_emojis_fallback(text)

    return text
