import http.server
import logging
import socket
import sys
import time
from typing import Any, Optional
import urllib.parse
import threading
import click
from safety.auth.cli_utils import load_auth_session

from safety.console import main_console as console

from safety.auth.constants import AUTH_SERVER_URL, CLI_AUTH_SUCCESS, CLI_LOGOUT_SUCCESS, HOST
from safety.auth.main import save_auth_config

LOG = logging.getLogger(__name__)


def find_available_port():
    """Find an available port on localhost"""
    # Dynamic ports IANA
    port_range = range(49152, 65536)

    for port in port_range:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                result = s.connect(('localhost', port))
                # If the connect succeeds, the port is already in use
            except socket.error as e:
                # If the connect fails, the port is available
                return port

    return None


class CallbackHandler(http.server.BaseHTTPRequestHandler):
    def auth(self, code: str, state: str, err, error_description):
        initial_state = self.server.initial_state
        ctx = self.server.ctx

        if initial_state is None or initial_state != state:
            err = "The state parameter value provided does not match the expected" \
                    "value. The state parameter is used to protect against Cross-Site " \
                    "Request Forgery (CSRF) attacks. For security reasons, the " \
                    "authorization process cannot proceed with an invalid state " \
                    "parameter value. Please try again, ensuring that the state " \
                    "parameter value provided in the authorization request matches " \
                    "the value returned in the callback."

        if err:
            click.secho(f'Error: {err}', fg='red')
            sys.exit(1)
        
        try:
            tokens = ctx.obj.auth.client.fetch_token(url=f'{AUTH_SERVER_URL}/oauth/token',
                                            code_verifier=ctx.obj.auth.code_verifier,
                                            client_id=ctx.obj.auth.client.client_id,
                                            grant_type='authorization_code', code=code)

            save_auth_config(access_token=tokens['access_token'], 
                             id_token=tokens['id_token'], 
                             refresh_token=tokens['refresh_token'])
            self.server.callback = ctx.obj.auth.client.fetch_user_info()

        except Exception as e:
            LOG.exception(e)
            sys.exit(1)

        self.do_redirect(location=CLI_AUTH_SUCCESS, params={})

    def logout(self):
        ctx = self.server.ctx
        uri = CLI_LOGOUT_SUCCESS

        if ctx.obj.auth.org:
            uri = f"{uri}&org_id={ctx.obj.auth.org.id}"

        self.do_redirect(location=CLI_LOGOUT_SUCCESS, params={})

    def do_GET(self):
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        callback_type: Optional[str] = None

        try:
            c_type = params.get('type', [])
            if isinstance(c_type, list) and len(c_type) == 1 and isinstance(c_type[0], str):
                callback_type = c_type[0]
        except Exception:
            click.secho("Unable to process the callback, try again.")
            return

        if callback_type == 'logout':
            self.logout()
            return

        code = params.get('code', [''])[0]
        state = params.get('state', [''])[0]
        err = params.get('error', [''])[0]
        error_description = params.get('error_description', [''])[0]
        
        self.auth(code=code, state=state, err=err, error_description=error_description)

    def do_redirect(self, location, params):
        self.send_response(301)
        self.send_header('Location', location)
        self.end_headers()

    def log_message(self, format, *args):
        LOG.info(format % args)


def process_browser_callback(uri, **kwargs) -> Any:

    class ThreadedHTTPServer(http.server.HTTPServer):
        def __init__(self, server_address, RequestHandlerClass):
            super().__init__(server_address, RequestHandlerClass)
            self.initial_state = None
            self.ctx = None
            self.callback = None
            self.timeout_reached = False

        def handle_timeout(self) -> None:
            self.timeout_reached = True
            return super().handle_timeout()

    PORT = find_available_port()

    if not PORT:
        click.secho("No available ports.")
        sys.exit(1)
    
    try:
        server = ThreadedHTTPServer((HOST, PORT), CallbackHandler)
        server.initial_state = kwargs.get("initial_state", None)
        server.timeout = kwargs.get("timeout", 600)
        # timeout = kwargs.get("timeout", None)
        # timeout = float(timeout) if timeout else None
        server.ctx = kwargs.get("ctx", None)
        server_thread = threading.Thread(target=server.handle_request)
        server_thread.start()

        target = f"{uri}&port={PORT}"
        console.print(f"If the browser does not automatically open in 5 seconds, " \
                      "copy and paste this url into your browser: " \
                      f"[link={target}]{target}[/link]")
        click.echo()

        wait_msg = "waiting for browser authentication"
        
        with console.status(wait_msg, spinner="bouncingBar"):
            time.sleep(2)
            click.launch(target)
            server_thread.join()

    except OSError as e:
        if e.errno == socket.errno.EADDRINUSE:
            reason = f"The port {HOST}:{PORT} is currently being used by another" \
                       "application or process. Please choose a different port or " \
                       "terminate the conflicting application/process to free up " \
                        "the port."
        else:
            reason = "An error occurred while performing this operation."

        click.secho(reason)
        sys.exit(1)

    return server.callback
