import unittest

import packaging

from safety.errors import InvalidRequirementError
from safety.models import SafetyRequirement


class TestSafetyRequirement(unittest.TestCase):

    @unittest.skipIf(tuple(map(int, packaging.__version__.split("."))) < (22, 0),
                     "not validated in these versions")
    def test_with_invalid_input(self):
        invalid_inputs = [
            'django*',
            'django>=python>=3.6',
            'numpy>=3.3python>=3.6',
            '',
            '\n'
        ]

        for i_input in invalid_inputs:
            with self.assertRaises(InvalidRequirementError):
                SafetyRequirement(i_input)
