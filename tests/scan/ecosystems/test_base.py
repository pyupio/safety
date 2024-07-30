import unittest
from unittest.mock import MagicMock
from typer import FileTextWrite
from safety_schemas.models import ConfigModel, DependencyResultModel, Ecosystem, FileType
from safety.scan.ecosystems.base import Inspectable, Remediable, InspectableFile

class TestInspectable(unittest.TestCase):
    def test_inspect_abstract_method(self):
        class TestClass(Inspectable):
            pass

        with self.assertRaises(TypeError):
            TestClass()

    def test_inspect_implemented_method(self):
        class TestClass(Inspectable):
            def inspect(self, config: ConfigModel) -> DependencyResultModel:
                return DependencyResultModel(dependencies=[])

        instance = TestClass()
        result = instance.inspect(MagicMock(spec=ConfigModel))
        self.assertIsInstance(result, DependencyResultModel)


class TestRemediable(unittest.TestCase):
    def test_remediate_abstract_method(self):
        class TestClass(Remediable):
            pass

        with self.assertRaises(TypeError):
            TestClass()

    def test_remediate_implemented_method(self):
        class TestClass(Remediable):
            def remediate(self):
                return "Remediation done"

        instance = TestClass()
        result = instance.remediate()
        self.assertEqual(result, "Remediation done")


class TestInspectableFile(unittest.TestCase):
    def test_initialization(self):
        class ConcreteInspectableFile(InspectableFile):
            def inspect(self, config: ConfigModel) -> DependencyResultModel:
                return DependencyResultModel(dependencies=[])

        file_mock = MagicMock(spec=FileTextWrite)
        inspectable_file = ConcreteInspectableFile(file=file_mock)
        self.assertEqual(inspectable_file.file, file_mock)
        self.assertIsInstance(inspectable_file.dependency_results, DependencyResultModel)
        self.assertEqual(inspectable_file.dependency_results.dependencies, [])

if __name__ == '__main__':
    unittest.main()
