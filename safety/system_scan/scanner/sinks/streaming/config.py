from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class BatchConfig:
    max_events: int = 100  # Batch size: send every 100 events
    max_bytes: int = 500_000
    flush_interval: float = 2.0
    max_pending_events: int = 500  # Backpressure: block if queue exceeds 500 events


@dataclass
class SenderConfig:
    base_url: str
    timeout: float = 30.0
    workers: int = 2
    batch: BatchConfig = field(default_factory=BatchConfig)
