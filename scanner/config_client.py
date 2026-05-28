import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError
from rich.console import Console

console = Console()


class ConfigClient:
    """
    Handles all interactions with AWS Config.
    Fetches compliance status for each rule defined in framework_mappings.json.
    """

    def __init__(self, profile_name: str = None, region: str = "ap-south-1"):
        """
        Initializes a boto3 session using a named AWS CLI profile.
        Falls back to default credential chain if no profile specified.

        Args:
            profile_name: AWS CLI profile name (e.g. "member")
            region: AWS region to scan (default: ap-south-1 = Mumbai)
        """
        try:
            session = boto3.Session(
                profile_name=profile_name,
                region_name=region
            )
            self.client = session.client("config")
            self.region = region
            self.profile = profile_name
            console.print(f"[green]Connected to AWS Config[/green] | Profile: {profile_name} | Region: {region}")
        except NoCredentialsError:
            console.print("[red]ERROR: No AWS credentials found.[/red]")
            raise

    def get_compliance_by_rule(self, rule_name: str) -> dict:
        """
        Fetches compliance status for a single AWS Config rule.

        Returns a dict with:
            - rule_name: str
            - compliance_type: COMPLIANT | NON_COMPLIANT | INSUFFICIENT_DATA | NOT_APPLICABLE
            - non_compliant_resources: list of resource IDs that are violating the rule
        """
        result = {
            "rule_name": rule_name,
            "compliance_type": "INSUFFICIENT_DATA",
            "non_compliant_resources": []
        }

        try:
            # Get overall rule compliance
            response = self.client.describe_compliance_by_config_rule(
                ConfigRuleNames=[rule_name]
            )

            if response["ComplianceByConfigRules"]:
                compliance = response["ComplianceByConfigRules"][0]["Compliance"]
                result["compliance_type"] = compliance.get("ComplianceType", "INSUFFICIENT_DATA")

            # If non-compliant, fetch which specific resources are violating
            if result["compliance_type"] == "NON_COMPLIANT":
                resources = self.client.get_compliance_details_by_config_rule(
                    ConfigRuleName=rule_name,
                    ComplianceTypes=["NON_COMPLIANT"]
                )
                result["non_compliant_resources"] = [
                    r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"]
                    for r in resources.get("EvaluationResults", [])
                ]

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "NoSuchConfigRuleException":
                result["compliance_type"] = "RULE_NOT_FOUND"
            else:
                console.print(f"[yellow]WARNING: {rule_name} — {error_code}[/yellow]")
                result["compliance_type"] = "ERROR"

        return result

    def get_all_compliance(self, rule_names: list) -> list:
        """
        Iterates over all rule names from framework_mappings.json
        and returns a list of compliance results.
        """
        console.print(f"\n[bold]Scanning {len(rule_names)} rules...[/bold]\n")
        results = []
        for rule in rule_names:
            result = self.get_compliance_by_rule(rule)
            status_color = "green" if result["compliance_type"] == "COMPLIANT" else "red"
            console.print(f"  [{status_color}]{result['compliance_type']:<20}[/{status_color}] {rule}")
            results.append(result)
        return results