import logging
from pathlib import Path
import re
import shutil
import tempfile
from typing import List
from .base import CommandInterceptor, Tool
from .types import InterceptorType

from safety.constants import USER_CONFIG_DIR


LOG = logging.getLogger(__name__)


class UnixAliasInterceptor(CommandInterceptor):
    def __init__(self):
        super().__init__(InterceptorType.UNIX_ALIAS)
        self.user_rc_path = self._get_user_rc_path()
        self.custom_rc_path = self._get_custom_rc_path()

        # Update these markers could be a breaking change; be careful to handle
        # backward compatibility
        self.marker_start = "# >>> Safety >>>"
        self.marker_end = "# <<< Safety <<<"

    # .profile is not a rc file, but is what we support for now.
    def _get_user_rc_path(self) -> Path:
        """
        We support .profile for now.
        """
        home = Path.home()
        return home / ".profile"

    def _get_custom_rc_path(self) -> Path:
        return USER_CONFIG_DIR / ".safety_profile"

    def _backup_file(self, path: Path) -> None:
        """
        Create backup of file if it exists
        """
        if path.exists():
            backup_path = path.with_suffix(".backup")
            shutil.copy2(path, backup_path)

    def _generate_user_rc_content(self) -> str:
        """
        Generate the content to be added to user's rc.

        Example:
        ```
        # >>> Safety >>>
        [ -f "$HOME/.safety/.safety_profile" ] && . "$HOME/.safety/.safety_profile"
        # <<< Safety <<<
        ```
        """
        lines = (
            self.marker_start,
            f'[ -f "{self.custom_rc_path}" ] && . "{self.custom_rc_path}"',
            self.marker_end,
        )
        return "\n".join(lines) + "\n"

    def _is_configured(self) -> bool:
        """
        Check if the configuration block exists in user's rc file
        """
        try:
            if not self.user_rc_path.exists():
                return False

            content = self.user_rc_path.read_text()
            return self.marker_start in content and self.marker_end in content

        except OSError:
            LOG.info("Failed to read user's rc file")
            return False

    def _generate_custom_rc_content(self, aliases: List[str]) -> str:
        """
        Generate the content for the custom profile with metadata
        """
        metadata_lines = self._generate_metadata_content(prepend="#")
        aliases_lines = tuple(aliases)

        lines = (
            (self.marker_start,) + metadata_lines + aliases_lines + (self.marker_end,)
        )

        return "\n".join(lines) + "\n"

    def _ensure_source_line_in_user_rc(self) -> None:
        """
        Ensure source line exists in user's .profile

        If the source line is not present in the user's .profile, append it.
        If the user's .profile does not exist, create it.
        """
        source_line = self._generate_user_rc_content()

        if not self.user_rc_path.exists():
            self.user_rc_path.write_text(source_line)
            return

        if not self._is_configured():
            with open(self.user_rc_path, "a") as f:
                f.write(source_line)

    def _batch_install_tools(self, tools: List[Tool]) -> bool:
        """
        Install aliases for multiple tools
        """
        try:
            # Generate aliases
            aliases = []
            for tool in tools:
                for binary in tool.binary_names:
                    alias_def = f'alias {binary}="safety {tool.name}"'
                    aliases.append(alias_def)

            if not aliases:
                return False

            # Create safety profile directory if it doesn't exist
            self.custom_rc_path.parent.mkdir(parents=True, exist_ok=True)

            # Generate new profile content
            profile_content = self._generate_custom_rc_content(aliases)

            # Backup target files
            for f_path in [self.user_rc_path, self.custom_rc_path]:
                self._backup_file(path=f_path)

            # Override our custom profile
            # TODO: handle exceptions
            self.custom_rc_path.write_text(profile_content)

            # Ensure source line in user's .profile
            self._ensure_source_line_in_user_rc()

            return True

        except Exception:
            LOG.exception("Failed to batch install aliases")
            return False

    def _batch_remove_tools(self, tools: List[Tool]) -> bool:
        """
        This will remove all the tools.

        NOTE: for now this does not support to remove individual tools.
        """
        try:
            # Backup target files
            for f_path in [self.user_rc_path, self.custom_rc_path]:
                self._backup_file(path=f_path)

            if self._is_configured():
                temp_dir = tempfile.gettempdir()
                temp_file = Path(temp_dir) / f"{self.user_rc_path.name}.tmp"

                pattern = rf"{self.marker_start}\n.*?\{self.marker_end}\n?"

                with open(self.user_rc_path, "r") as src, open(temp_file, "w") as dst:
                    content = src.read()
                    cleaned_content = re.sub(pattern, "", content, flags=re.DOTALL)
                    dst.write(cleaned_content)

                if not temp_file.exists():
                    LOG.info("Temp file is empty or invalid")
                    return False

                shutil.move(str(temp_file), str(self.user_rc_path))

            self.custom_rc_path.unlink(missing_ok=True)

            return True
        except Exception as e:
            print(f"Failed to batch remove aliases: {e}")
            return False

    def _install_tool(self, tool: Tool) -> bool:
        return self._batch_install_tools([tool])

    def _remove_tool(self, tool: Tool) -> bool:
        return self._batch_remove_tools([tool])
