from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Union
from authlib.integrations.httpx_client import OAuth2Client
import httpx


@dataclass(frozen=True)
class SafetyPlatformSinkConfig:
    http_client: Union[OAuth2Client, httpx.Client]
    kind: Literal["safety_platform"] = "safety_platform"
    base_url: str = "http://localhost:8000"
    timeout: float = 30.0


@dataclass(frozen=True)
class JsonlSinkConfig:
    kind: Literal["jsonl"] = "jsonl"
    path: str = "scan.jsonl"


@dataclass(frozen=True)
class NullSinkConfig:
    kind: Literal["null"] = "null"


SinkConfig = Union[SafetyPlatformSinkConfig, JsonlSinkConfig, NullSinkConfig]
