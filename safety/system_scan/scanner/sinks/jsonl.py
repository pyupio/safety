from __future__ import annotations

import json
from typing import TextIO
from ..models import Detection
from .base import Sink
from pathlib import Path
from datetime import datetime


class JsonlSink(Sink[Detection]):
    name = "jsonl"

    def __init__(self, path: Path):
        self.path = path
        self._fp: TextIO | None = None

    def open(self, machine_id: str, hostname: str) -> str:
        scan_id = f"offline-scan-{int(datetime.now().timestamp())}"

        if self.path.is_dir():
            file_path = self.path / f"{scan_id}.jsonl"
        else:
            file_path = self.path

        self._fp = open(file_path, "a", encoding="utf-8")
        return scan_id

    def write(self, item: Detection) -> None:
        assert self._fp is not None

        payload = item.get_payload()
        self._fp.write(json.dumps(payload, separators=(",", ":")) + "\n")

    def close(self, ok: bool) -> None:
        if self._fp:
            self._fp.close()
            self._fp = None
