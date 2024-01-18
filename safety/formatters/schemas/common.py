from typing import Dict, Generic, TypeVar

from pydantic import BaseModel as PydanticBaseModel
from pydantic import Extra
from pydantic.validators import dict_validator

from common.const import SCHEMA_DICT_ITEMS_COUNT_LIMIT
from common.exceptions import DictMaxLengthError


class BaseModel(PydanticBaseModel):
    class Config:
        arbitrary_types_allowed = True
        max_anystr_length = 50
        validate_assignment = True
        extra = Extra.forbid


KeyType = TypeVar("KeyType")
ValueType = TypeVar("ValueType")


class ConstrainedDict(Generic[KeyType, ValueType]):
    def __init__(self, v: Dict[KeyType, ValueType]):
        super().__init__()

    @classmethod
    def __get_validators__(cls):
        yield cls.dict_length_validator

    @classmethod
    def dict_length_validator(cls, v):
        v = dict_validator(v)
        if len(v) > SCHEMA_DICT_ITEMS_COUNT_LIMIT:
            raise DictMaxLengthError(limit_value=SCHEMA_DICT_ITEMS_COUNT_LIMIT)
        return v
