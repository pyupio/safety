
import os
from pathlib import Path
from typing import Optional, Tuple
import typer
from safety.scan.models import ScanExport, ScanOutput

from safety_schemas.models import AuthenticationType


MISSING_SPDX_EXTENSION_MSG = "spdx extra is not installed, please install it with: pip install safety[spdx]"


def raise_if_not_spdx_extension_installed() -> None:
    """
    Raises an error if the spdx extension is not installed.
    """
    try:
        import spdx_tools.spdx
    except Exception as e:
        raise typer.BadParameter(MISSING_SPDX_EXTENSION_MSG)


def save_as_callback(save_as: Optional[Tuple[ScanExport, Path]]) -> Tuple[Optional[str], Optional[Path]]:
    """
    Callback function to handle save_as parameter and validate if spdx extension is installed.

    Args:
        save_as (Optional[Tuple[ScanExport, Path]]): The export type and path.

    Returns:
        Tuple[Optional[str], Optional[Path]]: The validated export type and path.
    """
    export_type, export_path = save_as if save_as else (None, None)

    if ScanExport.is_format(export_type, ScanExport.SPDX):
        raise_if_not_spdx_extension_installed()

    return (export_type.value, export_path) if export_type and export_path else (export_type, export_path)

def output_callback(output: ScanOutput) -> str:
    """
    Callback function to handle output parameter and validate if spdx extension is installed.

    Args:
        output (ScanOutput): The output format.

    Returns:
        str: The validated output format.
    """
    if ScanOutput.is_format(output, ScanExport.SPDX):
        raise_if_not_spdx_extension_installed()

    return output.value


def fail_if_not_allowed_stage(ctx: typer.Context):
    """
    Fail the command if the authentication type is not allowed in the current stage.

    Args:
        ctx (typer.Context): The context of the Typer command.
    """
    if ctx.resilient_parsing:
        return

    stage = ctx.obj.auth.stage
    auth_type: AuthenticationType = ctx.obj.auth.client.get_authentication_type()

    if os.getenv("SAFETY_DB_DIR"):
        return

    if not auth_type.is_allowed_in(stage):
        raise typer.BadParameter(f"'{auth_type.value}' auth type isn't allowed with " \
                                 f"the '{stage}' stage.")
