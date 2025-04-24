import re
from typing import Any, List, Optional

from click.core import ParameterSource as ClickParameterSource

from safety_schemas.models.events.types import ParamSource


def is_sensitive_parameter(param_name: str) -> bool:
    """
    Determine if a parameter name likely contains sensitive information.
    """
    sensitive_patterns = [
        r"(?i)pass(word)?",  # password, pass
        r"(?i)token",  # token, auth_token
        r"(?i)key",  # key, apikey
        r"(?i)auth",  # auth, authorization
    ]

    return any(re.search(pattern, param_name) for pattern in sensitive_patterns)


def scrub_sensitive_value(value: str) -> str:
    """
    Detect if a value appears to be sensitive information based on
    specific patterns.
    """
    if not isinstance(value, str):
        return value

    result = value

    if re.match(r"^-{1,2}[\w-]+$", value) and "=" not in value:
        return value

    # Patterns to detect and replace
    patterns = [
        # This will replace ports too, but that's fine
        (r"\b\w+:\w+\b", "-:-"),
        (r"Basic\s+[A-Za-z0-9+/=]+", "Basic -"),
        (r"Bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer -"),
        (r"\b[A-Za-z0-9_-]{20,}\b", "-"),
        (
            r"((?:token|api|apikey|key|auth|secret|password|access|jwt|bearer|credential|pwd)=)([^&\s]+)",
            r"\1-",
        ),
    ]

    # Apply each pattern and replace matches
    for pattern, repl in patterns:
        result = re.sub(pattern, repl, result)

    return result


def clean_parameter(param_name: str, param_value: Any) -> Any:
    """
    Scrub a parameter value if it's sensitive.
    """
    if not isinstance(param_value, str):
        return param_value

    if is_sensitive_parameter(param_name):
        return "-"

    return scrub_sensitive_value(param_value)


def get_command_path(ctx) -> List[str]:
    hierarchy = []
    current = ctx

    while current is not None:
        if current.command:
            name = current.command.name
            if name == "cli":
                name = "safety"
            hierarchy.append(name)
        current = current.parent

    # Reverse to get top-level first
    hierarchy.reverse()

    return hierarchy


def get_root_context(ctx):
    """
    Get the top-level parent context.
    """
    current = ctx
    while current.parent is not None:
        current = current.parent
    return current


def translate_param_source(source: Optional[ClickParameterSource]) -> ParamSource:
    """
    Translate Click's ParameterSource enum to our ParameterSource enum
    """
    mapping = {
        ClickParameterSource.COMMANDLINE: ParamSource.COMMANDLINE,
        ClickParameterSource.ENVIRONMENT: ParamSource.ENVIRONMENT,
        ClickParameterSource.DEFAULT: ParamSource.DEFAULT,
        # In newer Click versions
        getattr(ClickParameterSource, "PROMPT", None): ParamSource.PROMPT,
        getattr(ClickParameterSource, "CONFIG_FILE", None): ParamSource.CONFIG,
    }

    return mapping.get(source, ParamSource.UNKNOWN)
