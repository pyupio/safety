from pathlib import Path
from .platform import SafetyPlatformSink
from .jsonl import JsonlSink
from .null import NullSink
from .config import (
    SinkConfig,
    SafetyPlatformSinkConfig,
    JsonlSinkConfig,
    NullSinkConfig,
)
from .streaming.callbacks import StreamingCallbacks


def build_sink(cfg: SinkConfig, sink_callbacks: StreamingCallbacks):
    if isinstance(cfg, SafetyPlatformSinkConfig):
        from .streaming import SenderConfig, BatchConfig

        sender_config = SenderConfig(
            base_url=cfg.base_url,
            timeout=cfg.timeout,
            workers=3,
            batch=BatchConfig(
                max_events=500,
                max_bytes=500_000,
                flush_interval=0.8,
                max_pending_events=3000,
            ),
        )

        return SafetyPlatformSink(
            sender_config=sender_config,
            http_client=cfg.http_client,
            callbacks=sink_callbacks,
        )

    if isinstance(cfg, JsonlSinkConfig):
        dest = Path(cfg.path)
        return JsonlSink(path=dest)

    if isinstance(cfg, NullSinkConfig):
        return NullSink()

    raise TypeError(f"Unsupported sink config: {type(cfg)}")
