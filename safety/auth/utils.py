# type: ignore
import importlib.util
import logging
from functools import lru_cache
from typing import Any, Dict, Optional


from safety.constants import (
    FeatureType,
    get_config_setting,
)
from safety.models import SafetyCLI

LOG = logging.getLogger(__name__)


def is_email_verified(info: Dict[str, Any]) -> Optional[bool]:
    """
    Check if the email is verified.

    Args:
        info (Dict[str, Any]): The user information.

    Returns:
        bool: True
    """
    # return info.get(CLAIM_EMAIL_VERIFIED_API) or info.get(
    #     CLAIM_EMAIL_VERIFIED_AUTH_SERVER
    # )

    # Always return True to avoid email verification
    return True


@lru_cache(maxsize=1)
def is_jupyter_notebook() -> bool:
    """
    Detects if the code is running in a Jupyter notebook environment, including
    various cloud-hosted Jupyter notebooks.

    Returns:
        bool: True if the environment is identified as a Jupyter notebook (or
              equivalent cloud-based environment), False otherwise.

    Supported environments:
    - Google Colab
    - Amazon SageMaker
    - Azure Notebooks
    - Kaggle Notebooks
    - Databricks Notebooks
    - Datalore by JetBrains
    - Paperspace Gradient Notebooks
    - Classic Jupyter Notebook and JupyterLab
    """
    if (
        (
            importlib.util.find_spec("google")
            and importlib.util.find_spec("google.colab")
        )
        is not None
        or importlib.util.find_spec("sagemaker") is not None
        or importlib.util.find_spec("azureml") is not None
        or importlib.util.find_spec("kaggle") is not None
        or importlib.util.find_spec("dbutils") is not None
        or importlib.util.find_spec("datalore") is not None
        or importlib.util.find_spec("gradient") is not None
    ):
        return True

    # Detect classic Jupyter Notebook, JupyterLab, and other IPython kernel-based environments
    try:
        from IPython import get_ipython  # type: ignore

        ipython = get_ipython()
        if ipython is not None and "IPKernelApp" in ipython.config:
            return True
    except (ImportError, AttributeError, NameError):
        pass

    return False


def save_flags_config(flags: Dict[FeatureType, bool]) -> None:
    """
    Save feature flags configuration to file.

    This function attempts to save feature flags to the configuration file
    but will fail silently if unable to do so (e.g., due to permission issues
    or disk problems). Silent failure is chosen to prevent configuration issues
    from disrupting core application functionality.

    Note that if saving fails, the application will continue using existing
    or default flag values until the next restart.

    Args:
        flags: Dictionary mapping feature types to their enabled/disabled state

    The operation will be logged (with stack trace) if it fails.
    """
    import configparser

    from safety.constants import CONFIG_FILE_USER

    config = configparser.ConfigParser()
    config.read(CONFIG_FILE_USER)

    flag_settings = {key.name.upper(): str(value) for key, value in flags.items()}

    if not config.has_section("settings"):
        config.add_section("settings")

    settings = dict(config.items("settings"))
    settings.update(flag_settings)

    for key, value in settings.items():
        config.set("settings", key, value)

    try:
        with open(CONFIG_FILE_USER, "w") as config_file:
            config.write(config_file)
    except Exception:
        LOG.exception("Unable to save flags configuration.")


def get_feature_name(feature: FeatureType, as_attr: bool = False) -> str:
    """Returns a formatted feature name with enabled suffix.

    Args:
        feature: The feature to format the name for
        as_attr: If True, formats for attribute usage (underscore),
                otherwise uses hyphen

    Returns:
        Formatted feature name string with enabled suffix
    """
    name = feature.name.lower()
    separator = "_" if as_attr else "-"
    return f"{name}{separator}enabled"


def str_to_bool(value) -> Optional[bool]:
    """Convert basic string representations to boolean."""
    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        value = value.lower().strip()
        if value in ("true"):
            return True
        if value in ("false"):
            return False

    return None


def initialize(ctx: Any, refresh: bool = True) -> None:
    """
    Initializes the run by loading settings.

    Args:
        ctx (Any): The context object.
        refresh (bool): Whether to refresh settings from the server. Defaults to True.
    """
    settings = None
    current_values = {}

    if not ctx.obj:
        ctx.obj = SafetyCLI()

    for feature in FeatureType:
        value = get_config_setting(feature.name)
        if value is not None:
            current_values[feature] = str_to_bool(value)

    if refresh:
        try:
            settings = ctx.obj.auth.platform.initialize()  # type: ignore
        except Exception:
            LOG.info("Unable to initialize, continue with default values.")

    if settings:
        for feature in FeatureType:
            server_value = str_to_bool(settings.get(feature.config_key))
            if server_value is not None:
                if (
                    feature not in current_values
                    or current_values[feature] != server_value
                ):
                    current_values[feature] = server_value

        save_flags_config(current_values)

    for feature, value in current_values.items():
        if value is not None:
            setattr(ctx.obj, feature.attr_name, value)
