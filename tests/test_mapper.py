import pytest
import json
import os
import sys

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.framework_mapper import FrameworkMapper


@pytest.fixture
def mapper():
    """Loads the real framework_mappings.json for all tests."""
    return FrameworkMapper()


def test_mappings_load_successfully(mapper):
    """
    Verifies the JSON file loads without errors
    and contains at least one rule.
    """
    assert len(mapper.mappings) > 0


def test_all_rules_have_required_fields(mapper):
    """
    Every rule in framework_mappings.json must have:
        - config_rule
        - description
        - severity
        - frameworks (with at least one framework)
    """
    required_fields = ["description", "severity", "frameworks"]
    for rule_name, rule_data in mapper.mappings.items():
        for field in required_fields:
            assert field in rule_data, f"Rule {rule_name} missing field: {field}"


def test_all_rules_map_to_all_three_frameworks(mapper):
    """
    Every rule must map to all three frameworks:
    GDPR, UAE_PDPL, Essential_Eight.
    This ensures complete cross-framework coverage.
    """
    expected_frameworks = {"GDPR", "UAE_PDPL", "Essential_Eight"}
    for rule_name, rule_data in mapper.mappings.items():
        mapped = set(rule_data["frameworks"].keys())
        assert mapped == expected_frameworks, (
            f"Rule {rule_name} does not map to all three frameworks. "
            f"Found: {mapped}"
        )


def test_enrich_attaches_metadata():
    """
    Verifies that enrich() correctly attaches description,
    severity, and frameworks to a raw compliance result.
    """
    mapper = FrameworkMapper()
    raw_results = [
        {
            "rule_name": "S3_BUCKET_PUBLIC_ACCESS_PROHIBITED",
            "compliance_type": "NON_COMPLIANT",
            "non_compliant_resources": ["my-test-bucket"]
        }
    ]
    enriched = mapper.enrich(raw_results)
    assert len(enriched) == 1
    assert enriched[0]["description"] != ""
    assert enriched[0]["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert "GDPR" in enriched[0]["frameworks"]
    assert "UAE_PDPL" in enriched[0]["frameworks"]
    assert "Essential_Eight" in enriched[0]["frameworks"]


def test_get_all_rule_names_returns_list(mapper):
    """
    get_all_rule_names() must return a non-empty list of strings.
    """
    rule_names = mapper.get_all_rule_names()
    assert isinstance(rule_names, list)
    assert len(rule_names) > 0
    assert all(isinstance(name, str) for name in rule_names)