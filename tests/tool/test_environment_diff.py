"""
Tests for environment diff tracking logic.
"""

import pytest
from safety.tool.environment_diff import PackageLocation, PipEnvironmentDiffTracker


@pytest.mark.unit
class TestPackageLocation:
    """
    Test suite for PackageLocation NamedTuple.
    """

    def test_package_location_positional_order(self):
        """
        Ensure positional tuple order is (name, location).
        """
        # Arrange
        name = "requests"
        location = "/usr/local/lib/python3.9/site-packages"
        package_loc = PackageLocation(name=name, location=location)

        # Act
        first, second = package_loc  # unpacking relies on field order

        # Assert
        assert first == name
        assert second == location
        assert package_loc[0] == name
        assert package_loc[1] == location
        assert tuple(package_loc) == (name, location)

    def test_package_location_equality(self):
        """
        Test PackageLocation equality comparison.
        """
        # Arrange
        loc1 = PackageLocation(
            name="requests", location="/usr/local/lib/python3.9/site-packages"
        )
        loc2 = PackageLocation(
            name="requests", location="/usr/local/lib/python3.9/site-packages"
        )
        loc3 = PackageLocation(
            name="requests", location="/home/user/.local/lib/python3.9/site-packages"
        )
        loc4 = PackageLocation(
            name="urllib3", location="/usr/local/lib/python3.9/site-packages"
        )

        # Act & Assert
        assert loc1 == loc2
        assert loc1 != loc3  # Different location
        assert loc1 != loc4  # Different name
        assert hash(loc1) == hash(loc2)  # Should be hashable
        assert hash(loc1) != hash(loc3)


@pytest.mark.unit
class TestPipEnvironmentDiffTracker:
    """
    Test suite for PipEnvironmentDiffTracker
    """

    def setup_method(self):
        """
        Set up test fixtures.
        """
        self.tracker = PipEnvironmentDiffTracker()

    def test_diff_canonicalizes_name_and_version(self):
        """
        Name and version should be canonicalized when computing diffs.
        """
        # Arrange: same package/location, case-different name and semver-equivalent version update
        location = "/usr/local/lib/python3.9/site-packages"
        before = [{"name": "Django", "version": "4.0.0", "location": location}]
        after = [{"name": "django", "version": "4.1.0", "location": location}]

        # Act
        self.tracker.set_before_state(before)
        self.tracker.set_after_state(after)
        added, removed, updated = self.tracker.get_diff()

        # Assert: key uses canonicalized name, value uses canonicalized versions
        key = PackageLocation(name="django", location=location)
        assert added == {}
        assert removed == {}
        assert key in updated
        assert updated[key] == ("4.0.0", "4.1.0")

    def test_diff_treats_case_only_name_changes_as_noop(self):
        """
        Changing only the case of the package name should not create a diff.
        """
        # Arrange: identical version and location, only name case differs
        location = "/opt/site-packages"
        before = [{"name": "NumPy", "version": "1.23.5", "location": location}]
        after = [{"name": "numpy", "version": "1.23.5", "location": location}]

        # Act
        self.tracker.set_before_state(before)
        self.tracker.set_after_state(after)
        added, removed, updated = self.tracker.get_diff()

        # Assert: no changes
        assert added == {}
        assert removed == {}
        assert updated == {}

    @pytest.mark.parametrize(
        "before, after, expected_added, expected_removed, expected_updated",
        [
            # Unix paths scenario
            (
                [
                    {
                        "name": "requests",
                        "version": "2.27.1",
                        "location": "/usr/local/lib/python3.9/site-packages",
                    },
                    {
                        "name": "urllib3",
                        "version": "1.26.11",
                        "location": "/usr/local/lib/python3.9/site-packages",
                    },
                ],
                [
                    {
                        "name": "requests",
                        "version": "2.28.1",
                        "location": "/usr/local/lib/python3.9/site-packages",
                    },
                    {
                        "name": "numpy",
                        "version": "1.23.5",
                        "location": "/home/user/.local/lib/python3.9/site-packages",
                    },
                ],
                {
                    PackageLocation(
                        name="numpy",
                        location="/home/user/.local/lib/python3.9/site-packages",
                    ): "1.23.5"
                },
                {
                    PackageLocation(
                        name="urllib3",
                        location="/usr/local/lib/python3.9/site-packages",
                    ): "1.26.11"
                },
                {
                    PackageLocation(
                        name="requests",
                        location="/usr/local/lib/python3.9/site-packages",
                    ): ("2.27.1", "2.28.1")
                },
            ),
            # Windows paths scenario
            (
                [
                    {
                        "name": "Django",
                        "version": "4.0.0",
                        "location": "C:\\Python39\\Lib\\site-packages",
                    },
                ],
                [
                    {
                        "name": "Django",
                        "version": "4.1.0",
                        "location": "C:\\Python39\\Lib\\site-packages",
                    },
                    {
                        "name": "Pillow",
                        "version": "9.2.0",
                        "location": "C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python39\\Lib\\site-packages",
                    },
                ],
                {
                    PackageLocation(
                        name="pillow",
                        location="C:\\Users\\User\\AppData\\Local\\Programs\\Python\\Python39\\Lib\\site-packages",
                    ): "9.2.0"
                },
                {},
                {
                    PackageLocation(
                        name="django", location="C:\\Python39\\Lib\\site-packages"
                    ): ("4.0.0", "4.1.0")
                },
            ),
        ],
    )
    def test_diff_tracking_with_package_locations(
        self, before, after, expected_added, expected_removed, expected_updated
    ):
        """
        Track diffs with PackageLocation keys across different OS path formats.
        """
        # Act
        self.tracker.set_before_state(before)
        self.tracker.set_after_state(after)
        added, removed, updated = self.tracker.get_diff()

        # Assert
        assert added == expected_added
        assert removed == expected_removed
        assert updated == expected_updated

    def test_diff_tracking_same_package_different_locations(self):
        """Test diff tracking when same package exists in different locations."""
        # Arrange - Same package in system and user locations
        before_packages = [
            {
                "name": "requests",
                "version": "2.27.1",
                "location": "/usr/lib/python3.9/site-packages",
            },
            {
                "name": "requests",
                "version": "2.28.0",
                "location": "/home/user/.local/lib/python3.9/site-packages",
            },
        ]

        after_packages = [
            {
                "name": "requests",
                "version": "2.28.1",
                "location": "/usr/lib/python3.9/site-packages",
            },  # Updated
            {
                "name": "requests",
                "version": "2.28.1",
                "location": "/home/user/.local/lib/python3.9/site-packages",
            },  # Updated
        ]

        # Act
        self.tracker.set_before_state(before_packages)
        self.tracker.set_after_state(after_packages)
        added, removed, updated = self.tracker.get_diff()

        # Assert - Both locations should be tracked separately
        assert len(added) == 0
        assert len(removed) == 0
        assert len(updated) == 2

        system_loc = PackageLocation(
            name="requests", location="/usr/lib/python3.9/site-packages"
        )
        user_loc = PackageLocation(
            name="requests", location="/home/user/.local/lib/python3.9/site-packages"
        )

        assert system_loc in updated
        assert user_loc in updated
        assert updated[system_loc] == ("2.27.1", "2.28.1")
        assert updated[user_loc] == ("2.28.0", "2.28.1")

    def test_diff_tracking_with_empty_states(self):
        """
        Test diff tracking with empty before/after states.
        """
        # Test case 1: Empty before state
        after_packages = [
            {
                "name": "requests",
                "version": "2.28.1",
                "location": "/usr/local/lib/python3.9/site-packages",
            }
        ]

        self.tracker.set_before_state([])
        self.tracker.set_after_state(after_packages)
        added, removed, updated = self.tracker.get_diff()

        assert added == {
            PackageLocation(
                name="requests", location="/usr/local/lib/python3.9/site-packages"
            ): "2.28.1"
        }
        assert removed == {}
        assert updated == {}

        # Test case 2: Empty after state
        before_packages = [
            {
                "name": "requests",
                "version": "2.27.1",
                "location": "/usr/local/lib/python3.9/site-packages",
            }
        ]

        self.tracker.set_before_state(before_packages)
        self.tracker.set_after_state([])
        added, removed, updated = self.tracker.get_diff()

        assert added == {}
        assert removed == {
            PackageLocation(
                name="requests", location="/usr/local/lib/python3.9/site-packages"
            ): "2.27.1"
        }
        assert updated == {}

    def test_diff_tracking_handles_malformed_package_data(self):
        """
        Test diff tracking gracefully handles malformed package data.
        """
        # Arrange - Mix of good and bad package data
        before_packages = [
            {
                "name": "requests",
                "version": "2.27.1",
                "location": "/usr/local/lib/python3.9/site-packages",
            },
            {
                "version": "1.0.0",
                "location": "/usr/local/lib/python3.9/site-packages",
            },  # Missing name
            {"name": "urllib3"},  # Missing version and location
            None,  # Completely invalid
            "invalid_data",  # Wrong type
        ]

        after_packages = [
            {
                "name": "requests",
                "version": "2.28.1",
                "location": "/usr/local/lib/python3.9/site-packages",
            }
        ]

        # Act - Should not raise exceptions
        self.tracker.set_before_state(before_packages)
        self.tracker.set_after_state(after_packages)
        added, removed, updated = self.tracker.get_diff()

        # Assert - Only valid package should be processed
        assert len(updated) == 1
        requests_loc = PackageLocation(
            name="requests", location="/usr/local/lib/python3.9/site-packages"
        )
        assert requests_loc in updated
        assert updated[requests_loc] == ("2.27.1", "2.28.1")
