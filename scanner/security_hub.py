import boto3
from datetime import datetime, timezone
from botocore.exceptions import ClientError
from rich.console import Console

console = Console()


class SecurityHubClient:
    """
    Pushes non-compliant findings from the gap analysis
    into AWS Security Hub as custom findings.

    Why this matters:
        - Security Hub is the central aggregation point for security findings
        - Pushing custom findings means your compliance scanner integrates
          with the same dashboard that GuardDuty and Config already feed into
        - This ties Project 4 to Project 3's Security Hub setup
        - In real environments, this is how compliance teams get a single pane of glass

    Finding format follows ASFF — Amazon Security Finding Format.
    This is the standard AWS uses across all security services.
    """

    def __init__(self, profile_name: str = None, region: str = "ap-south-1", account_id: str = None):
        """
        Args:
            profile_name: AWS CLI profile name
            region: AWS region
            account_id: AWS account ID (used in ASFF finding ARNs)
        """
        session = boto3.Session(
            profile_name=profile_name,
            region_name=region
        )
        self.client = session.client("securityhub")
        self.region = region
        self.account_id = account_id
        self.product_arn = f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default"

    def _build_finding(self, control: dict, scan_timestamp: str) -> dict:
        """
        Builds a single ASFF-compliant finding dict from a failing control.

        ASFF required fields:
            - SchemaVersion: always "2018-10-08"
            - Id: unique identifier for this finding
            - ProductArn: identifies the product generating the finding
            - GeneratorId: identifies the rule/check that generated it
            - AwsAccountId: account being scanned
            - Types: finding classification
            - CreatedAt / UpdatedAt: ISO8601 timestamps
            - Severity: normalized severity object
            - Title / Description: human-readable
            - Resources: what AWS resource is affected

        Args:
            control: a single failing control from GapAnalyzer.get_failing_controls()
            scan_timestamp: ISO8601 timestamp of the scan

        Returns:
            ASFF-compliant finding dict
        """
        severity_map = {
            "CRITICAL": {"Label": "CRITICAL", "Normalized": 90},
            "HIGH":     {"Label": "HIGH",     "Normalized": 70},
            "MEDIUM":   {"Label": "MEDIUM",   "Normalized": 40},
            "LOW":      {"Label": "LOW",      "Normalized": 10},
            "UNKNOWN":  {"Label": "INFORMATIONAL", "Normalized": 0}
        }

        # Build framework references for finding notes
        framework_refs = []
        for fw, articles in control.get("frameworks", {}).items():
            framework_refs.append(f"{fw.replace('_', ' ')}: {', '.join(articles)}")
        framework_note = " | ".join(framework_refs)

        # One finding per non-compliant resource, or one generic if no resources listed
        resources = control.get("non_compliant_resources", []) or ["ACCOUNT_LEVEL"]

        finding_id = (
            f"arn:aws:securityhub:{self.region}:{self.account_id}:"
            f"finding/compliance-scanner/{control['rule_name']}"
        )

        return {
            "SchemaVersion": "2018-10-08",
            "Id": finding_id,
            "ProductArn": self.product_arn,
            "GeneratorId": f"compliance-scanner/{control['rule_name']}",
            "AwsAccountId": self.account_id,
            "Types": ["Software and Configuration Checks/Industry and Regulatory Standards"],
            "CreatedAt": scan_timestamp,
            "UpdatedAt": scan_timestamp,
            "Severity": severity_map.get(control["severity"], severity_map["UNKNOWN"]),
            "Title": f"[Compliance Scanner] {control['rule_name']}",
            "Description": f"{control['description']} | Framework mappings: {framework_note}",
            "Resources": [
                {
                    "Type": "AwsAccount",
                    "Id": f"arn:aws:iam::{self.account_id}:root",
                    "Partition": "aws",
                    "Region": self.region
                }
            ],
            "Compliance": {
                "Status": "FAILED",
                "RelatedRequirements": [
                    article
                    for articles in control.get("frameworks", {}).values()
                    for article in articles
                ]
            },
            "RecordState": "ACTIVE"
        }

    def push_findings(self, failing_controls: list) -> dict:
        """
        Pushes all failing controls to Security Hub as ASFF findings.

        Security Hub BatchImportFindings accepts max 100 findings per call.
        We chunk if needed (unlikely at our scale but correct practice).

        Args:
            failing_controls: list from GapAnalyzer.get_failing_controls()

        Returns:
            dict with SuccessCount and FailedCount
        """
        if not failing_controls:
            console.print("[green]No failing controls — nothing to push to Security Hub.[/green]")
            return {"SuccessCount": 0, "FailedCount": 0}

        scan_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        findings = [self._build_finding(ctrl, scan_timestamp) for ctrl in failing_controls]

        # Chunk into batches of 100
        chunk_size = 100
        total_success = 0
        total_failed = 0

        for i in range(0, len(findings), chunk_size):
            chunk = findings[i:i + chunk_size]
            try:
                response = self.client.batch_import_findings(Findings=chunk)
                total_success += response.get("SuccessCount", 0)
                total_failed += response.get("FailedCount", 0)

                if response.get("FailedFindings"):
                    for ff in response["FailedFindings"]:
                        console.print(f"[yellow]Failed finding: {ff['Id']} — {ff['ErrorMessage']}[/yellow]")

            except ClientError as e:
                console.print(f"[red]Security Hub error: {e.response['Error']['Message']}[/red]")
                total_failed += len(chunk)

        console.print(
            f"[bold]Security Hub:[/bold] "
            f"[green]{total_success} findings pushed[/green] | "
            f"[red]{total_failed} failed[/red]"
        )

        return {"SuccessCount": total_success, "FailedCount": total_failed}