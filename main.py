import os
import sys
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

from scanner.config_client import ConfigClient
from scanner.framework_mapper import FrameworkMapper
from scanner.gap_analysis import GapAnalyzer
from scanner.report_generator import ReportGenerator
from scanner.security_hub import SecurityHubClient

# Load .env file if present (local dev only)
# In GitHub Actions, these are set as environment variables/secrets
load_dotenv()

console = Console()


def main():
    """
    Orchestrates the full compliance scan pipeline:

    1. Load framework mappings — get list of rules to scan
    2. Connect to AWS Config — fetch compliance status for each rule
    3. Enrich results — attach framework metadata to each result
    4. Run gap analysis — calculate scores, find priority gaps
    5. Generate reports — JSON + HTML
    6. Push to Security Hub — custom ASFF findings
    7. Exit with code 1 if non-compliant findings exist (fails CI pipeline)

    Environment variables (set in .env locally or GitHub Actions secrets):
        AWS_PROFILE:    AWS CLI profile name (e.g. "member")
        AWS_REGION:     AWS region to scan (e.g. "ap-south-1")
        AWS_ACCOUNT_ID: AWS account ID being scanned
        PUSH_TO_HUB:    "true" to push findings to Security Hub (default: false)
    """

    console.print(Panel.fit(
        "[bold cyan]Cloud Compliance Scanner[/bold cyan]\n"
        "[dim]GDPR · UAE PDPL · Essential Eight[/dim]",
        border_style="cyan"
    ))

    # --- Configuration ---
    profile     = os.getenv("AWS_PROFILE") or None
    region      = os.getenv("AWS_REGION", "ap-south-1")
    account_id  = os.getenv("AWS_ACCOUNT_ID", "664858858896")
    push_to_hub = os.getenv("PUSH_TO_HUB", "false").lower() == "true"

    console.print(f"\n[bold]Configuration[/bold]")
    console.print(f"  Profile:    {profile}")
    console.print(f"  Region:     {region}")
    console.print(f"  Account:    {account_id}")
    console.print(f"  Push to Hub: {push_to_hub}\n")

    # --- Step 1: Load framework mappings ---
    console.print("[bold]Step 1:[/bold] Loading framework mappings...")
    mapper = FrameworkMapper()
    rule_names = mapper.get_all_rule_names()
    console.print(f"  Loaded {len(rule_names)} rules from framework_mappings.json\n")

    # --- Step 2: Fetch compliance from AWS Config ---
    console.print("[bold]Step 2:[/bold] Connecting to AWS Config...")
    config_client = ConfigClient(profile_name=profile, region=region)
    raw_results = config_client.get_all_compliance(rule_names)

    # --- Step 3: Enrich with framework metadata ---
    console.print("\n[bold]Step 3:[/bold] Enriching results with framework mappings...")
    enriched_results = mapper.enrich(raw_results)
    console.print(f"  Enriched {len(enriched_results)} results\n")

    # --- Step 4: Gap analysis ---
    console.print("[bold]Step 4:[/bold] Running gap analysis...")
    analyzer = GapAnalyzer(enriched_results)
    summary = analyzer.get_summary()

    # Print framework scores to terminal
    console.print("\n  [bold]Framework Scores:[/bold]")
    for fw, data in summary["framework_scores"].items():
        score = data["score_pct"]
        color = "green" if score >= 80 else "yellow" if score >= 60 else "red"
        console.print(f"    {fw:<20} [{color}]{score}%[/{color}] ({data['compliant']}/{data['total_rules']} compliant)")

    console.print(f"\n  [bold]Overall Score:[/bold] {summary['overall']['overall_score_pct']}%")
    console.print(f"  Non-compliant controls: {summary['overall']['non_compliant']}\n")

    # Print priority gaps
    if summary["priority_gaps"]:
        console.print("  [bold]Priority Gaps (fix these first):[/bold]")
        for i, gap in enumerate(summary["priority_gaps"], 1):
            console.print(
                f"    #{i} [red]{gap['severity']}[/red] {gap['rule_name']} "
                f"(impacts {gap['frameworks_affected_count']} frameworks)"
            )

    # --- Step 5: Generate reports ---
    console.print("\n[bold]Step 5:[/bold] Generating reports...")
    reporter = ReportGenerator()
    json_path = reporter.generate_json(summary, account_id, region)
    html_path = reporter.generate_html(summary, account_id, region)
    console.print(f"  JSON: {json_path}")
    console.print(f"  HTML: {html_path}\n")

    # --- Step 6: Push to Security Hub ---
    if push_to_hub:
        console.print("[bold]Step 6:[/bold] Pushing findings to Security Hub...")
        hub_client = SecurityHubClient(
            profile_name=profile,
            region=region,
            account_id=account_id
        )
        hub_client.push_findings(summary["failing_controls"])
    else:
        console.print("[bold]Step 6:[/bold] [dim]Security Hub push skipped (PUSH_TO_HUB=false)[/dim]")

    # --- Step 7: Exit code for CI ---
    # Non-zero exit fails the GitHub Actions pipeline — intentional.
    # A passing pipeline means zero non-compliant findings.
    non_compliant_count = summary["overall"]["non_compliant"]
    if non_compliant_count > 0:
        console.print(
            f"\n[bold red]SCAN COMPLETE — {non_compliant_count} non-compliant controls found.[/bold red]"
        )
        console.print("[dim]Pipeline will fail — this is expected behavior for a compliance scanner.[/dim]")
        sys.exit(1)
    else:
        console.print("\n[bold green]SCAN COMPLETE — All controls compliant.[/bold green]")
        sys.exit(0)


if __name__ == "__main__":
    main()