from typing import TYPE_CHECKING, Dict, Optional, Union

if TYPE_CHECKING:
    from safety_schemas.models.events.types import ToolType
    from safety_schemas.models.events.payloads import (
        AliasConfig,
        IndexConfig,
    )


FirewallConfigStatus = Dict[
    ToolType, Dict[str, Optional[Union[AliasConfig, IndexConfig]]]
]
