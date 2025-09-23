from typing import Any, List, Protocol, Tuple, Dict, runtime_checkable
import typer
from rich.padding import Padding

from .base import EnvironmentDiffTracker

from safety.console import main_console as console
from safety.init.render import render_header, progressive_print
from safety.models import ToolResult
import logging
from .intents import ToolIntentionType, CommandToolIntention
from .environment_diff import PackageLocation

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

    def render_package_details(self: "AuditableCommand", packages: List[str]):
        """
        Render details for installed packages.
        """
        for package_name in packages:
            console.print(
                Padding(
                    f"Learn more: [link]https://data.safetycli.com/packages/pypi/{package_name}/[/link]",
                    (0, 0, 0, 1),
                ),
                emoji=True,
            )

    def audit_packages(
        self, ctx: typer.Context
    ) -> Tuple[Dict[str, Any], Dict[PackageLocation, str]]:
        """
        Audit packages based on environment diff tracking.
        Override this method in your command class if needed.

        Args:
            ctx: The typer context

        Returns:
            Dict containing audit results
        """
        try:
            diff_tracker = getattr(self, "_diff_tracker", None)
            if diff_tracker and hasattr(diff_tracker, "get_diff"):
                added, _, updated = diff_tracker.get_diff()
                packages: Dict[PackageLocation, str] = {**added, **updated}

                if hasattr(ctx.obj, "auth") and hasattr(ctx.obj.auth, "client"):
                    return (
                        ctx.obj.auth.client.audit_packages(
                            [
                                f"{package.name}=={version[-1] if isinstance(version, tuple) else version}"
                                for (package, version) in packages.items()
                            ]
                        ),
                        packages,
                    )
        except Exception:
            logger.debug("Audit API failed with error", exc_info=True)

        # Always return a dict to satisfy the return type
        return dict(), dict()

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

        audit_result, packages = self.audit_packages(ctx)
        self.render_installation_warnings(ctx, audit_result)

        if not result.process or result.process.returncode != 0:
            package_names = {pl.name for pl in packages}

            # Access _intention safely to keep the protocol minimal and satisfy type checkers
            intent = getattr(self, "_intention", None)
            if isinstance(intent, CommandToolIntention):
                command_intent: CommandToolIntention = intent

                if (
                    command_intent.intention_type
                    is not ToolIntentionType.REMOVE_PACKAGE
                    and command_intent.packages
                ):
                    for dep in command_intent.packages:
                        if dep.name:
                            package_names.add(dep.name)

            if package_names:
                self.render_package_details(sorted(package_names))
