from __future__ import annotations

from .events.payloads.links import RuntimeRef, EnvironmentRef, HostRef


class ScanRefRegistry:
    """
    Simple registry that stores lightweight Ref objects to avoid duplicate detection work.
    Uses existing RuntimeRef, EnvironmentRef objects.
    Note: This implementation is not thread-safe.
    """

    def __init__(self):
        self._seen_stable_ids: set[str] = set()

        # Store lightweight Ref objects by stable ID
        self._runtime_refs: dict[str, RuntimeRef] = {}
        self._environment_refs: dict[str, EnvironmentRef] = {}
        self._execution_context_ref: HostRef | None = None

    def is_seen(self, stable_id: str) -> bool:
        return stable_id in self._seen_stable_ids

    def register_runtime(self, stable_id: str, ref: RuntimeRef):
        self._seen_stable_ids.add(stable_id)
        self._runtime_refs[stable_id] = ref

    def register_environment(self, stable_id: str, ref: EnvironmentRef):
        self._seen_stable_ids.add(stable_id)
        self._environment_refs[stable_id] = ref

    def register_execution_context(self, stable_id: str, ref: HostRef):
        self._seen_stable_ids.add(stable_id)
        self._execution_context_ref = ref

    def register_other(self, stable_id: str):
        self._seen_stable_ids.add(stable_id)

    def get_runtime_ref(self, stable_id: str) -> RuntimeRef | None:
        return self._runtime_refs.get(stable_id)

    def get_environment_ref(self, stable_id: str) -> EnvironmentRef | None:
        return self._environment_refs.get(stable_id)

    def get_execution_context_ref(self) -> HostRef | None:
        return self._execution_context_ref

    def clear(self):
        self._seen_stable_ids.clear()
        self._runtime_refs.clear()
        self._environment_refs.clear()
        self._execution_context_ref = None
