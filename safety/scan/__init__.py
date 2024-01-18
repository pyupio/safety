from rich.console import Console

from safety_schemas.models import Vulnerability, RemediationModel
from safety.scan.render import get_render_console
console = Console()

Vulnerability.__render__ = get_render_console(Vulnerability)
