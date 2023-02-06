from typing import Optional

from marshmallow import Schema, fields as fields_, post_dump


class CVSSv2(Schema):
    base_score = fields_.Int()
    impact_score = fields_.Int()
    vector_string = fields_.Str()

    class Meta:
        ordered = True


class CVSSv3(Schema):
    base_score = fields_.Int()
    base_severity = fields_.Str()
    impact_score = fields_.Int()
    vector_string = fields_.Str()

    class Meta:
        ordered = True


class VulnerabilitySchemaV05(Schema):
    """
    Legacy JSON report used in Safety 1.10.3
    """

    package_name = fields_.Str()
    vulnerable_spec = fields_.Str()
    version = fields_.Str(attribute='pkg.version')
    advisory = fields_.Str()
    vulnerability_id = fields_.Str()
    cvssv2: Optional[CVSSv2] = fields_.Nested(CVSSv2, attribute='severity.cvssv2')
    cvssv3: Optional[CVSSv3] = fields_.Nested(CVSSv3, attribute='severity.cvssv3')

    class Meta:
        ordered = True

    @post_dump(pass_many=True)
    def wrap_with_envelope(self, data, many, **kwargs):
        return [tuple(d.values()) for d in data]

