# type: ignore
import http.server
import json
import logging
import random
import socket
import sys
import time
from typing import Any, Optional, Dict, Tuple
import urllib.parse
import threading
import click

from safety.auth.utils import is_jupyter_notebook
from safety.console import main_console as console

from safety.auth.constants import (
    AUTH_SERVER_URL,
    CLI_AUTH_SUCCESS,
    CLI_LOGOUT_SUCCESS,
    HOST,
)
from safety.auth.main import save_auth_config
from rich.prompt import Prompt

LOG = logging.getLogger(__name__)


def find_available_port() -> Optional[int]:
    """
    Find an available port on localhost within the dynamic port range (49152-65536).

    Returns:
        Optional[int]: An available port number, or None if no ports are available.
    """
    # Dynamic ports IANA
    port_range = list(range(49152, 65536))
    random.shuffle(port_range)

    for port in port_range:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect(("localhost", port))
                # If the connect succeeds, the port is already in use
            except socket.error:
                # If the connect fails, the port is available
                return port

    return None


def auth_process(
    code: str, state: str, initial_state: str, code_verifier: str, client: Any
) -> Any:
    """
    Process the authentication callback and exchange the authorization code for tokens.

    Args:
        code (str): The authorization code.
        state (str): The state parameter from the callback.
        initial_state (str): The initial state parameter.
        code_verifier (str): The code verifier for PKCE.
        client (Any): The OAuth client.

    Returns:
        Any: The user information.

    Raises:
        SystemExit: If there is an error during authentication.
    """
    err = None

    if initial_state is None or initial_state != state:
        err = (
            "The state parameter value provided does not match the expected "
            "value. The state parameter is used to protect against Cross-Site "
            "Request Forgery (CSRF) attacks. For security reasons, the "
            "authorization process cannot proceed with an invalid state "
            "parameter value. Please try again, ensuring that the state "
            "parameter value provided in the authorization request matches "
            "the value returned in the callback."
        )

    if err:
        click.secho(f"Error: {err}", fg="red")
        sys.exit(1)

    try:
        tokens = client.fetch_token(
            url=f"{AUTH_SERVER_URL}/oauth/token",
            code_verifier=code_verifier,
            client_id=client.client_id,
            grant_type="authorization_code",
            code=code,
        )

        save_auth_config(
            access_token=tokens["access_token"],
            id_token=tokens["id_token"],
            refresh_token=tokens["refresh_token"],
        )
        return client.fetch_user_info()

    except Exception as e:
        LOG.exception(e)
        sys.exit(1)


class CallbackHandler(http.server.BaseHTTPRequestHandler):
    def auth(self, code: str, state: str, err: str, error_description: str) -> None:
        """
        Handle the authentication callback.

        Args:
            code (str): The authorization code.
            state (str): The state parameter.
            err (str): The error message, if any.
            error_description (str): The error description, if any.
        """
        initial_state = self.server.initial_state
        ctx = self.server.ctx

        result = auth_process(
            code=code,
            state=state,
            initial_state=initial_state,
            code_verifier=ctx.obj.auth.code_verifier,
            client=ctx.obj.auth.client,
        )

        self.server.callback = result
        self.do_redirect(location=CLI_AUTH_SUCCESS, params={})

    def logout(self) -> None:
        """
        Handle the logout callback.
        """
        ctx = self.server.ctx
        uri = CLI_LOGOUT_SUCCESS

        if ctx.obj.auth.org:
            uri = f"{uri}&org_id={ctx.obj.auth.org.id}"

        self.do_redirect(location=CLI_LOGOUT_SUCCESS, params={})

    def do_GET(self) -> None:
        """
        Handle GET requests.
        """
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        callback_type: Optional[str] = None

        try:
            c_type = params.get("type", [])
            if (
                isinstance(c_type, list)
                and len(c_type) == 1
                and isinstance(c_type[0], str)
            ):
                callback_type = c_type[0]
        except Exception:
            msg = "Unable to process the callback, try again."
            self.send_error(400, msg)
            click.secho("Unable to process the callback, try again.")
            return

        if callback_type == "logout":
            self.logout()
            return

        code = params.get("code", [""])[0]
        state = params.get("state", [""])[0]
        err = params.get("error", [""])[0]
        error_description = params.get("error_description", [""])[0]

        self.auth(code=code, state=state, err=err, error_description=error_description)

    def do_redirect(self, location: str, params: Dict) -> None:
        """
        Redirect the client to the specified location.

        Args:
            location (str): The URL to redirect to.
            params (dict): Additional parameters for the redirection.
        """
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        """
        Log an arbitrary message.

        Args:
            format (str): The format string.
            args (Any): Arguments for the format string.
        """
        LOG.info(format % args)


def process_browser_callback(uri: str, **kwargs: Any) -> Any:
    """
    Process the browser callback for authentication.

    Args:
        uri (str): The authorization URL.
        **kwargs (Any): Additional keyword arguments.

    Returns:
        Any: The user information.

    Raises:
        SystemExit: If there is an error during the process.
    """

    class ThreadedHTTPServer(http.server.HTTPServer):
        def __init__(self, server_address: Tuple, RequestHandlerClass: Any) -> None:
            """
            Initialize the ThreadedHTTPServer.
            Args:
                server_address (Tuple): The server address as a tuple (host, port).
                RequestHandlerClass (Any): The request handler class.
            """
            super().__init__(server_address, RequestHandlerClass)
            self.initial_state = None
            self.ctx = None
            self.callback = None
            self.timeout_reached = False

        def handle_timeout(self) -> None:
            """
            Handle server timeout.
            """
            self.timeout_reached = True
            return super().handle_timeout()

    PORT = find_available_port()

    if not PORT:
        click.secho("No available ports.")
        sys.exit(1)

    try:
        headless = kwargs.get("headless", False)
        initial_state = kwargs.get("initial_state", None)
        ctx = kwargs.get("ctx", None)
        message = "Copy and paste this URL into your browser:\n:icon_warning: Ensure there are no extra spaces, especially at line breaks, as they may break the link."

        if not headless:
            # Start a threaded HTTP server to handle the callback
            server = ThreadedHTTPServer((HOST, PORT), CallbackHandler)
            server.initial_state = initial_state
            server.timeout = kwargs.get("timeout", 600)
            server.ctx = ctx
            server_thread = threading.Thread(target=server.handle_request)
            server_thread.start()
            message = "If the browser does not automatically open in 5 seconds, copy and paste this url into your browser:"

        target = uri if headless else f"{uri}&port={PORT}"

        if is_jupyter_notebook():
            console.print(f"{message} {target}")
        else:
            console.print(f"{message} [link={target}]{target}[/link]")

        if headless:
            # Handle the headless mode where user manually provides the response
            exchange_data = None
            while not exchange_data:
                auth_code_text = Prompt.ask(
                    "Paste the response here", default=None, console=console
                )
                try:
                    exchange_data = json.loads(auth_code_text)
                    state = exchange_data["state"]
                    code = exchange_data["code"]
                except Exception:
                    code = state = None

            return auth_process(
                code=code,
                state=state,
                initial_state=initial_state,
                code_verifier=ctx.obj.auth.code_verifier,
                client=ctx.obj.auth.client,
            )
        else:
            # Wait for the browser authentication in non-headless mode
            console.print()
            wait_msg = "waiting for browser authentication"
            with console.status(wait_msg, spinner="bouncingBar"):
                time.sleep(2)
                click.launch(target)
                server_thread.join()

    except OSError as e:
        if e.errno == socket.errno.EADDRINUSE:
            reason = f"The port {HOST}:{PORT} is currently being used by another application or process. Please choose a different port or terminate the conflicting application/process to free up the port."
        else:
            reason = "An error occurred while performing this operation."

        click.secho(reason)
        sys.exit(1)

    return server.callback
