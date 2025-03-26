from typing import Dict, List, Tuple, Any, Callable, TypeVar, Generic
from packaging.utils import canonicalize_name, canonicalize_version

T = TypeVar("T")  # For the package data type
K = TypeVar("K")  # For the key type
V = TypeVar("V")  # For the value type


class EnvironmentDiffTracker(Generic[T, K, V]):
    """
    Generic utility class to track changes in environment states before and
    after operations. Can be used with any environment management system
    (pip, npm, apt, docker, etc.).
    """

    def __init__(
        self,
        key_extractor: Callable[[T], K],
        value_extractor: Callable[[T], V],
    ) -> None:
        """
        Initialize a new environment diff tracker.

        Args:
            key_extractor: Function to extract the item identifier from an entry
            value_extractor: Function to extract the version or other value to
                             compare
            normalize_key: Optional function to normalize keys
                           (e.g., make lowercase)
        """
        self._key_extractor = key_extractor
        self._value_extractor = value_extractor
        self._before_items: Dict[K, V] = {}
        self._after_items: Dict[K, V] = {}

    def set_before_state(self, items_data: List[T]) -> None:
        """
        Set the before-operation environment state.

        Args:
            items_data: List of items in the format specific to the environment
        """
        self._before_items = self._normalize_items_data(items_data)

    def set_after_state(self, items_data: List[T]) -> None:
        """
        Set the after-operation environment state.

        Args:
            items_data: List of items in the format specific to the environment
        """
        self._after_items = self._normalize_items_data(items_data)

    def get_diff(self) -> Tuple[Dict[K, V], Dict[K, V], Dict[K, Tuple[V, V]]]:
        """
        Compute the difference between before and after environment states.

        Returns:
            Tuple containing:
            - Dictionary of added items {key: value}
            - Dictionary of removed items {key: value}
            - Dictionary of updated items {key: (old_value, new_value)}
        """
        if not self._before_items or not self._after_items:
            return {}, {}, {}

        before_keys = set(self._before_items.keys())
        after_keys = set(self._after_items.keys())

        # Find added and removed items
        added_keys = after_keys - before_keys
        removed_keys = before_keys - after_keys

        # Find updated items (same key, different value)
        common_keys = before_keys & after_keys
        updated_keys = {
            key: (self._before_items[key], self._after_items[key])
            for key in common_keys
            if self._before_items[key] != self._after_items[key]
        }

        # Create result dictionaries
        added = {key: self._after_items[key] for key in added_keys}
        removed = {key: self._before_items[key] for key in removed_keys}
        updated = {key: updated_keys[key] for key in updated_keys}

        return added, removed, updated

    def _normalize_items_data(self, items_data: List[T]) -> Dict[K, V]:
        """
        Normalize items data into a standardized dictionary format.

        Args:
            items_data: List of item data entries

        Returns:
            Dict mapping normalized item keys to their values
        """
        result = {}

        for item_info in items_data:
            try:
                key = self._key_extractor(item_info)
                value = self._value_extractor(item_info)
                result[key] = value
            except (KeyError, TypeError, AttributeError):
                # Skip entries that don't have the expected structure
                continue
        return result


class PipEnvironmentDiffTracker(EnvironmentDiffTracker[Dict[str, Any], str, str]):
    """
    Specialized diff tracker for pip package environments.
    """

    def __init__(self):
        super().__init__(
            key_extractor=self._pip_key_extractor,
            value_extractor=self._pip_value_extractor,
        )

    # TODO: handle errors in value extraction

    def _pip_key_extractor(self, pkg: Dict[str, Any]) -> str:
        return canonicalize_name(pkg.get("name", ""))

    def _pip_value_extractor(self, pkg: Dict[str, Any]) -> str:
        return canonicalize_version(pkg.get("version", ""))
