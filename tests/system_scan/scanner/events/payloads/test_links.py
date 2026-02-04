import pytest
from safety.system_scan.scanner.events.payloads.links import (
    BaseRelations,
    ExecutionContextRelation,
    RuntimeRelation,
    EnvironmentRelation,
    ParentEnvironmentRelation,
    ExecutionContextRef,
    RuntimeRef,
    EnvironmentRef,
    DependencyRelations,
    EnvironmentRelations,
    RuntimeRelations,
)


@pytest.fixture
def execution_context_ref():
    return ExecutionContextRef(machine_id="test-machine-123", hostname="test-host")


@pytest.fixture
def runtime_ref():
    return RuntimeRef(canonical_path="/usr/bin/python3")


@pytest.fixture
def environment_ref():
    return EnvironmentRef(canonical_path="/home/user/venv")


@pytest.fixture
def execution_context_relation(execution_context_ref):
    return ExecutionContextRelation(ref=execution_context_ref)


@pytest.fixture
def runtime_relation(runtime_ref):
    return RuntimeRelation(ref=runtime_ref)


@pytest.fixture
def environment_relation(environment_ref):
    return EnvironmentRelation(ref=environment_ref)


@pytest.fixture
def parent_environment_relation(environment_ref):
    return ParentEnvironmentRelation(ref=environment_ref)


def test_base_relations_to_list_empty():
    relations = BaseRelations()
    result = relations.to_list()
    assert result == []


def test_dependency_relations_to_list_with_execution_context_only(
    execution_context_relation,
):
    relations = DependencyRelations(execution_context=execution_context_relation)
    result = relations.to_list()

    expected = [
        {
            "ref": {
                "machine_id": "test-machine-123",
                "hostname": "test-host",
                "subtype": "host",
            },
            "type": "execution_context",
        }
    ]
    assert result == expected


def test_dependency_relations_to_list_with_both_relations(
    execution_context_relation, environment_relation
):
    relations = DependencyRelations(
        execution_context=execution_context_relation, environment=environment_relation
    )
    result = relations.to_list()

    expected = [
        {
            "ref": {
                "machine_id": "test-machine-123",
                "hostname": "test-host",
                "subtype": "host",
            },
            "type": "execution_context",
        },
        {"ref": {"canonical_path": "/home/user/venv"}, "type": "environment"},
    ]
    assert result == expected


def test_environment_relations_to_list_full(
    execution_context_relation, runtime_relation, parent_environment_relation
):
    relations = EnvironmentRelations(
        execution_context=execution_context_relation,
        runtime=runtime_relation,
        parent=parent_environment_relation,
    )
    result = relations.to_list()

    expected = [
        {
            "ref": {
                "machine_id": "test-machine-123",
                "hostname": "test-host",
                "subtype": "host",
            },
            "type": "execution_context",
        },
        {"ref": {"canonical_path": "/usr/bin/python3"}, "type": "runtime"},
        {"ref": {"canonical_path": "/home/user/venv"}, "type": "parent"},
    ]
    assert result == expected


def test_environment_relations_to_list_with_none_values(execution_context_relation):
    relations = EnvironmentRelations(
        execution_context=execution_context_relation, runtime=None, parent=None
    )
    result = relations.to_list()

    expected = [
        {
            "ref": {
                "machine_id": "test-machine-123",
                "hostname": "test-host",
                "subtype": "host",
            },
            "type": "execution_context",
        }
    ]
    assert result == expected


def test_runtime_relations_to_list(execution_context_relation):
    relations = RuntimeRelations(execution_context=execution_context_relation)
    result = relations.to_list()

    expected = [
        {
            "ref": {
                "machine_id": "test-machine-123",
                "hostname": "test-host",
                "subtype": "host",
            },
            "type": "execution_context",
        }
    ]
    assert result == expected


def test_execution_context_ref_has_default_subtype():
    exec_ref = ExecutionContextRef(machine_id="machine-123", hostname="")
    assert exec_ref.machine_id == "machine-123"
    assert exec_ref.hostname == ""
    assert exec_ref.subtype == "host"


def test_relation_type_defaults():
    assert (
        ExecutionContextRelation(
            ref=ExecutionContextRef(machine_id="test", hostname="")
        ).type
        == "execution_context"
    )
    assert RuntimeRelation(ref=RuntimeRef(canonical_path="/test")).type == "runtime"
    assert (
        EnvironmentRelation(ref=EnvironmentRef(canonical_path="/test")).type
        == "environment"
    )
    assert (
        ParentEnvironmentRelation(ref=EnvironmentRef(canonical_path="/test")).type
        == "parent"
    )
