from __future__ import annotations

from typing import Iterable

from .context import Config, DetectContext
from .stages import CandidatesStage, DetectStageSerial
from .sinks import SinkConfig
from .sinks import build_sink
from .sources import PathSource, HomeSource, KnownPathsSource
from .registry import ScanRefRegistry
from .events.payloads.links import ExecutionContextRelation, HostRef
from .events.payloads import ExecutionContextInfo


from .sinks.streaming.callbacks import StreamingCallbacks, NullStreamingCallbacks

from .callbacks import Callbacks, NullCallbacks, ScanSummary
from .sinks import NullSinkConfig
from .filesystem import FsRuntime

from .detectors import (
    ExecutionContextDetector,
    PythonRuntimeDetector,
    PythonEnvironmentDetector,
    PythonDependencyDetector,
    ToolDetector,
)

from .pipeline import run_pipeline


class SystemScanner:
    def __init__(
        self,
        config: Config,
        callbacks: Callbacks | None = None,
        sink_cfg: SinkConfig | None = None,
        sink_callbacks: StreamingCallbacks | None = None,
        detectors: list | None = None,
        stages: list | None = None,
    ):
        self.config = config
        self.callbacks = callbacks or NullCallbacks()
        self.sink_callbacks = sink_callbacks or NullStreamingCallbacks()
        self.sink_cfg = sink_cfg or NullSinkConfig()
        self.detectors = detectors
        self.stages = stages

    def build(self):
        exec_ctx_det = ExecutionContextDetector()
        exec_ctx_detections = list(exec_ctx_det.detect())

        if not exec_ctx_detections:
            error_msg = "Failed to detect execution context - cannot proceed with detection phase"
            self.callbacks.error(error_msg, RuntimeError(error_msg))
            raise RuntimeError(error_msg)

        exec_ctx_detection = exec_ctx_detections[0]

        registry = ScanRefRegistry()
        exec_ctx_inf: ExecutionContextInfo = exec_ctx_detection.meta
        exec_ctx_rel = ExecutionContextRelation(
            ref=HostRef(
                machine_id=exec_ctx_inf.machine_id, hostname=exec_ctx_inf.hostname
            )
        )

        self.ctx = DetectContext(
            exec_ctx_rel=exec_ctx_rel,
            registry=registry,
            callbacks=self.callbacks,
            config=self.config,
            fs=FsRuntime(),
        )

        dependency_detector = PythonDependencyDetector()
        tool_detector = ToolDetector()

        runtime_detector = PythonRuntimeDetector()
        env_detector = PythonEnvironmentDetector(
            dependency_detector=dependency_detector,
            tool_detector=tool_detector,
            runtime_detector=runtime_detector,
        )
        detectors = self.detectors or [
            runtime_detector,
            env_detector,
            tool_detector,
        ]

        sources = [
            PathSource(),
            KnownPathsSource(),
            HomeSource(
                max_depth=self.config.max_depth, prune_dirs=set(self.config.prune_dirs)
            ),
        ]

        stages = self.stages or [
            CandidatesStage(sources=sources),
            DetectStageSerial(detectors=detectors),
        ]

        sink = build_sink(self.sink_cfg, self.sink_callbacks)
        return stages, sink, exec_ctx_detection

    def run(self) -> None:
        self.callbacks.phase("init")

        stages, sink, exec_ctx_detection = self.build()

        seed: Iterable[None] = [None]
        detections = run_pipeline(seed, stages, self.ctx)

        self.callbacks.phase("sink_open")
        exc_ctx_ref = self.ctx.exec_ctx_rel.ref

        scan_id = sink.open(
            machine_id=exc_ctx_ref.machine_id,
            hostname=exc_ctx_ref.hostname,
        )

        self.ctx.callbacks.scan_id(scan_id=scan_id)

        self.callbacks.detection(exec_ctx_detection)
        sink.write(exec_ctx_detection)

        ok = False
        count = 0
        try:
            self.callbacks.phase("working")
            for detection in detections:
                self.callbacks.detection(detection)
                sink.write(detection)
                count += 1
            ok = True
        finally:
            self.callbacks.complete(
                ScanSummary(
                    total_detections=count,
                )
            )
            sink.close(ok=ok)
