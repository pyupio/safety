from typing import Optional, List, Any, Dict, Tuple

from marshmallow import Schema, fields as fields_, post_dump


class CVSSv2(Schema):
    """
    Schema for CVSSv2 data.

    Attributes:
        base_score (fields_.Int): Base score of the CVSSv2.
        impact_score (fields_.Int): Impact score of the CVSSv2.
        vector_string (fields_.Str): Vector string of the CVSSv2.
    """
    base_score = fields_.Int()
    impact_score = fields_.Int()
    vector_string = fields_.Str()

    class Meta:
        ordered = True


class CVSSv3(Schema):
    """
    Schema for CVSSv3 data.

    Attributes:
        base_score (fields_.Int): Base score of the CVSSv3.
        base_severity (fields_.Str): Base severity of the CVSSv3.
        impact_score (fields_.Int): Impact score of the CVSSv3.
        vector_string (fields_.Str): Vector string of the CVSSv3.
    """
    base_score = fields_.Int()
    base_severity = fields_.Str()
    impact_score = fields_.Int()
    vector_string = fields_.Str()

    class Meta:
        ordered = True


class VulnerabilitySchemaV05(Schema):
    """
    Legacy JSON report schema used in Safety 1.10.3.

    Attributes:
        package_name (fields_.Str): Name of the vulnerable package.
        vulnerable_spec (fields_.Str): Vulnerable specification of the package.
        version (fields_.Str): Version of the package.
        advisory (fields_.Str): Advisory details for the vulnerability.
        vulnerability_id (fields_.Str): ID of the vulnerability.
        cvssv2 (Optional[CVSSv2]): CVSSv2 details of the vulnerability.
        cvssv3 (Optional[CVSSv3]): CVSSv3 details of the vulnerability.
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
    def wrap_with_envelope(self, data: List[Dict[str, Any]], many: bool, **kwargs: Any) -> List[Tuple]:
        """
        Wraps the dumped data with an envelope.

        Args:
            data (List[Dict[str, Any]]): The data to be wrapped.
            many (bool): Indicates if multiple objects are being dumped.
            **kwargs (Any): Additional keyword arguments.

        Returns:
            List[Tuple]: The wrapped data.
        """
        return [tuple(d.values()) for d in data]

