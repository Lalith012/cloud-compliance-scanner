import json
from pathlib import Path


class FrameworkMapper:
    """
    Loads framework_mappings.json and enriches raw AWS Config
    compliance results with framework context.

    What it does:
        - Reads the static mapping file once at init
        - For each compliance result, attaches description, severity,
          and which framework articles the rule maps to
        - Output feeds into both report_generator and gap_analysis
    """

    def __init__(self, mappings_path: str = "rules/framework_mappings.json"):
        """
        Args:
            mappings_path: path to framework_mappings.json
        """
        path = Path(mappings_path)
        if not path.exists():
            raise FileNotFoundError(f"Mappings file not found: {mappings_path}")

        with open(path, "r") as f:
            data = json.load(f)

        # Build a lookup dict keyed by config_rule name for O(1) access
        # e.g. self.mappings["S3_BUCKET_PUBLIC_ACCESS_PROHIBITED"] = {...}
        self.mappings = {
            rule["config_rule"]: rule
            for rule in data["rules"]
        }

        self.frameworks = ["GDPR", "UAE_PDPL", "Essential_Eight"]

    def enrich(self, compliance_results: list) -> list:
        """
        Takes raw compliance results from ConfigClient.get_all_compliance()
        and attaches framework mapping metadata to each result.

        Args:
            compliance_results: list of dicts from ConfigClient

        Returns:
            list of enriched dicts, each containing:
                - rule_name, compliance_type, non_compliant_resources (from Config)
                - description, severity, frameworks (from mappings.json)
        """
        enriched = []

        for result in compliance_results:
            rule_name = result["rule_name"]
            mapping = self.mappings.get(rule_name, {})

            enriched_result = {
                **result,  # spread original compliance data
                "description": mapping.get("description", "No description available"),
                "severity": mapping.get("severity", "UNKNOWN"),
                "frameworks": mapping.get("frameworks", {})
            }
            enriched.append(enriched_result)

        return enriched

    def get_all_rule_names(self) -> list:
        """
        Returns list of all Config rule names from the mappings file.
        Used by main.py to know which rules to scan.
        """
        return list(self.mappings.keys())

    def get_frameworks(self) -> list:
        """Returns the list of supported framework names."""
        return self.frameworks