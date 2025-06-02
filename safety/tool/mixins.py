from typing import Any, List, Protocol, Tuple, Dict, Optional, runtime_checkable
import typer
from rich.padding import Padding

from .base import EnvironmentDiffTracker

from safety.console import main_console as console
from safety.init.render import render_header, progressive_print
from safety.models import ToolResult
import logging

logger = logging.getLogger(__name__)


@runtime_checkable
class AuditableCommand(Protocol):
    """
    Protocol defining the contract for classes that can be audited for packages.
    """

    @property
    def _diff_tracker(self) -> "EnvironmentDiffTracker":
        """
        Provides package tracking functionality.
        """
        ...

    @property
    def _packages(self) -> List[Tuple[str, Optional[str]]]:
        """
        Provides the target package list.
        """
        ...


class InstallationAuditMixin:
    """
    Mixin providing installation audit functionality for command classes.

    This mixin can be used by any command class that needs to audit
    installation and show warnings.

    Classes using this mixin should conform to the AuditableCommand protocol.
    """

    def render_installation_warnings(
        self, ctx: typer.Context, packages_audit: Dict[str, Any]
    ):
        """
        Render installation warnings based on package audit results.

        Args:
            ctx: The typer context
            packages_audit: pre-fetched audit data
        """

        warning_messages = []
        for audited_package in packages_audit.get("audit", {}).get("packages", []):
            vulnerabilities = audited_package.get("vulnerabilities", {})
            critical_vulnerabilities = vulnerabilities.get("critical", 0)
            total_vulnerabilities = 0
            for count in vulnerabilities.values():
                total_vulnerabilities += count

            if total_vulnerabilities == 0:
                continue

            warning_message = f"[[yellow]Warning[/yellow]] {audited_package.get('package_specifier')} contains {total_vulnerabilities} vulnerabilities"
            if critical_vulnerabilities > 0:
                warning_message += f", including {critical_vulnerabilities} critical severity vulnerabilities"

            warning_message += "."
            warning_messages.append(warning_message)

        if len(warning_messages) > 0:
            console.print()
            render_header(" Safety Report")
            progressive_print(warning_messages)
            console.line()

    def render_package_details(self: "AuditableCommand"):
        """
        Render details for installed packages.
        """
        for package_name, _ in self._packages:
            console.print(
                Padding(
                    f"Learn more: [link]https://data.safetycli.com/packages/pypi/{package_name}/[/link]",
                    (0, 0, 0, 1),
                ),
                emoji=True,
            )

    def audit_packages(self, ctx: typer.Context) -> Dict[str, Any]:
        """
        Audit packages based on environment diff tracking.
        Override this method in your command class if needed.

        Args:
            ctx: The typer context

        Returns:
            Dict containing audit results
        """
        try:
            # Check if the instance has a diff tracker and can get a diff
            # Using getattr to avoid lint errors
            diff_tracker = getattr(self, "_diff_tracker", None)
            if diff_tracker and hasattr(diff_tracker, "get_diff"):
                added, _, updated = diff_tracker.get_diff()
                packages = {**added, **updated}

                if hasattr(ctx.obj, "auth") and hasattr(ctx.obj.auth, "client"):
                    return ctx.obj.auth.client.audit_packages(
                        [
                            f"{package_name}=={version[-1] if isinstance(version, tuple) else version}"
                            for (package_name, version) in packages.items()
                        ]
                    )
        except Exception:
            logger.debug("Audit API failed with error", exc_info=True)

        # Always return a dict to satisfy the return type
        return dict()

    def handle_installation_audit(self, ctx: typer.Context, result: ToolResult):
        """
        Handle installation audit and rendering warnings/details.
        This is an explicit method that can be called from a command's after method.

        Usage example:
            def after(self, ctx, result):
                super().after(ctx, result)
                self.handle_installation_audit(ctx, result)

        Args:
            ctx: The typer context
            result: The tool result
        """

        if not isinstance(self, AuditableCommand):
            raise TypeError(
                "handle_installation_audit can only be called on instances of AuditableCommand"
            )

        packages_audit = self.audit_packages(ctx)
        self.render_installation_warnings(ctx, packages_audit)

        # If command failed, show package details
        if not result.process or result.process.returncode != 0:
            self.render_package_details()
