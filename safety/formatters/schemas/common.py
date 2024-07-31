from typing import Dict, Generic, TypeVar, Generator

from pydantic import BaseModel as PydanticBaseModel
from pydantic import Extra
from pydantic.validators import dict_validator

from common.const import SCHEMA_DICT_ITEMS_COUNT_LIMIT
from common.exceptions import DictMaxLengthError


class BaseModel(PydanticBaseModel):
    """
    Base model that extends Pydantic's BaseModel with additional configurations.
    """
    class Config:
        arbitrary_types_allowed: bool = True
        max_anystr_length: int = 50
        validate_assignment: bool = True
        extra = Extra.forbid


KeyType = TypeVar("KeyType")
ValueType = TypeVar("ValueType")


class ConstrainedDict(Generic[KeyType, ValueType]):
    """
    A constrained dictionary that validates its length based on a specified limit.
    """
    def __init__(self, v: Dict[KeyType, ValueType]) -> None:
        """
        Initialize the ConstrainedDict.

        Args:
            v (Dict[KeyType, ValueType]): The dictionary to constrain.
        """
        super().__init__()

    @classmethod
    def __get_validators__(cls) -> Generator:
        yield cls.dict_length_validator

    @classmethod
    def dict_length_validator(cls, v: Dict[KeyType, ValueType]) -> Dict[KeyType, ValueType]:
        """
        Validate the length of the dictionary.

        Args:
            v (Dict[KeyType, ValueType]): The dictionary to validate.

        Returns:
            Dict[KeyType, ValueType]: The validated dictionary.

        Raises:
            DictMaxLengthError: If the dictionary exceeds the allowed length.
        """
        v = dict_validator(v)
        if len(v) > SCHEMA_DICT_ITEMS_COUNT_LIMIT:
            raise DictMaxLengthError(limit_value=SCHEMA_DICT_ITEMS_COUNT_LIMIT)
        return v
