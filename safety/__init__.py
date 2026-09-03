# -*- coding: utf-8 -*-

__author__ = """safetycli.com"""
__email__ = "cli@safetycli.com"

# Patch safety_schemas to make expires attribute optional
try:
    from safety_schemas.config.schemas.v3_0.main import IgnoredVulnerability
    from typing import Optional
    from datetime import date
    from pydantic.fields import FieldInfo
    
    IgnoredVulnerability.model_fields['expires'] = FieldInfo(annotation=Optional[date], default=None)
    IgnoredVulnerability.model_rebuild(force=True)
except ImportError:
    pass
