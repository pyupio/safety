from __future__ import annotations

import pytest
from typing import Iterator, Iterable, Any
from unittest.mock import Mock

from safety.system_scan.scanner.pipeline.runner import run_pipeline


class MockStage:
    """
    Mock stage implementation for testing pipeline.
    """

    def __init__(self, name: str, transform_func=None):
        self.name = name
        self.transform_func = transform_func or (lambda x, ctx: x)

    def run(self, items: Iterable[Any], ctx: Any) -> Iterator[Any]:
        """
        Transform items using the transform function.
        """
        for item in items:
            yield self.transform_func(item, ctx)


@pytest.mark.unit
class TestRunPipeline:
    """
    Test run_pipeline function.
    """

    def test_run_pipeline_empty_stages(self) -> None:
        """
        Test pipeline with no stages returns input unchanged.
        """
        initial = [1, 2, 3]
        stages = []
        ctx = Mock()

        result = list(run_pipeline(initial, stages, ctx))

        assert result == [1, 2, 3]

    def test_run_pipeline_single_stage(self) -> None:
        """
        Test pipeline with single stage processes items.
        """
        initial = [1, 2, 3]
        stage = MockStage("double", lambda x, ctx: x * 2)
        stages = [stage]
        ctx = Mock()

        result = list(run_pipeline(initial, stages, ctx))

        assert result == [2, 4, 6]

    def test_run_pipeline_multiple_stages(self) -> None:
        """
        Test pipeline with multiple stages chains processing.
        """
        initial = [1, 2, 3]
        stage1 = MockStage("double", lambda x, ctx: x * 2)
        stage2 = MockStage("add_one", lambda x, ctx: x + 1)
        stages = [stage1, stage2]
        ctx = Mock()

        result = list(run_pipeline(initial, stages, ctx))

        # (1*2)+1=3, (2*2)+1=5, (3*2)+1=7
        assert result == [3, 5, 7]

    def test_run_pipeline_with_context(self) -> None:
        """
        Test pipeline passes context to stages correctly.
        """
        initial = [1, 2, 3]

        def transform_with_ctx(x, ctx):
            return x + ctx.multiplier

        stage = MockStage("add_ctx", transform_with_ctx)
        stages = [stage]
        ctx = Mock()
        ctx.multiplier = 10

        result = list(run_pipeline(initial, stages, ctx))

        assert result == [11, 12, 13]

    def test_run_pipeline_empty_initial(self) -> None:
        """
        Test pipeline with empty input returns empty result.
        """
        initial = []
        stage = MockStage("double", lambda x, ctx: x * 2)
        stages = [stage]
        ctx = Mock()

        result = list(run_pipeline(initial, stages, ctx))

        assert result == []

    def test_run_pipeline_filtering_stage(self) -> None:
        """
        Test pipeline with stage that filters items.
        """
        initial = [1, 2, 3, 4, 5]

        def filter_even(items, ctx):
            for item in items:
                if item % 2 == 0:
                    yield item

        stage = MockStage("filter_even")
        stage.run = filter_even
        stages = [stage]
        ctx = Mock()

        result = list(run_pipeline(initial, stages, ctx))

        assert result == [2, 4]

    def test_run_pipeline_expanding_stage(self) -> None:
        """
        Test pipeline with stage that expands items.
        """
        initial = [1, 2, 3]

        def duplicate_items(items, ctx):
            for item in items:
                yield item
                yield item

        stage = MockStage("duplicate")
        stage.run = duplicate_items
        stages = [stage]
        ctx = Mock()

        result = list(run_pipeline(initial, stages, ctx))

        assert result == [1, 1, 2, 2, 3, 3]

    def test_run_pipeline_stage_with_protocol(self) -> None:
        """
        Test pipeline works with proper Stage protocol implementation.
        """

        class ProperStage:
            name = "proper_stage"

            def run(self, items: Iterable[Any], ctx: Any) -> Iterator[Any]:
                for item in items:
                    yield item * 3

        initial = [1, 2]
        stage = ProperStage()
        stages = [stage]
        ctx = Mock()

        result = list(run_pipeline(initial, stages, ctx))

        assert result == [3, 6]
