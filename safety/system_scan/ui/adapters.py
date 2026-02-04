from ..scanner import Detection
from .models import Asset, AssetKind


def convert_detection_to_asset(detection: Detection) -> Asset:
    """
    Convert scanner Detection to UI Asset.
    """
    # Map detection kinds to UI asset kinds
    kind_mapping = {
        "execution_context": AssetKind.CONTEXT,
        "runtime": AssetKind.RUNTIME,
        "environment": AssetKind.ENVIRONMENT,
        "dependency": AssetKind.DEPENDENCY,
        "tool": AssetKind.TOOL,
    }

    asset_kind = kind_mapping.get(detection.kind.value, AssetKind.TOOL)

    # Extract linked runtime from metadata if available

    path = ""
    linked_runtime = ""
    subtype = detection.subtype.split(".")[-1]

    if asset_kind == AssetKind.CONTEXT:
        path = detection.meta.machine_id

    elif asset_kind == AssetKind.RUNTIME:
        path = detection.meta.canonical_path

    elif asset_kind == AssetKind.ENVIRONMENT:
        path = detection.meta.canonical_path
        if runtime := detection.meta.links.runtime:
            linked_runtime = runtime.ref.canonical_path
            linked_runtime = linked_runtime.split("/")[-1]

    elif asset_kind == AssetKind.DEPENDENCY:
        path = detection.meta.canonical_path
        subtype = detection.meta.name

    elif asset_kind == AssetKind.TOOL:
        path = detection.meta.canonical_path

    return Asset(
        kind=asset_kind, subtype=subtype, path=path, linked_runtime=linked_runtime
    )
