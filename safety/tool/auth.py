import base64
import json

import typer
from urllib.parse import urlsplit, urlunsplit

from safety.tool.constants import PUBLIC_REPOSITORY_URL
from typing import Optional


def index_credentials(ctx: typer.Context) -> str:
    """
    Returns the index credentials for the current context.
    This should be used together with user:index_credential for index
    basic auth.

    Args:
        ctx (typer.Context): The context.

    Returns:
        str: The index credentials.
    """
    api_key = None
    token = None

    if auth := getattr(ctx.obj, "auth", None):
        client = auth.client
        token = client.token.get("access_token") if client.token else None
        api_key = client.api_key

    auth_envelop = json.dumps(
        {
            "version": "1.0",
            "access_token": token,
            "api_key": api_key,
            "project_id": ctx.obj.project.id if ctx.obj.project else None,
        }
    )
    return base64.urlsafe_b64encode(auth_envelop.encode("utf-8")).decode("utf-8")


def build_pypi_index_url(ctx: typer.Context, index_url: Optional[str]) -> str:
    """
    Builds the index URL for the current context.
    """
    if index_url is None:
        index_url = PUBLIC_REPOSITORY_URL

    url = urlsplit(index_url)

    encoded_auth = index_credentials(ctx)
    netloc = f"user:{encoded_auth}@{url.netloc}"

    if type(url.netloc) is bytes:
        url = url._replace(netloc=netloc.encode("utf-8"))
    elif type(url.netloc) is str:
        url = url._replace(netloc=netloc)

    return urlunsplit(url)
