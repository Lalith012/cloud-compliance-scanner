import boto3
from botocore.exceptions import ClientError
from rich.console import Console

console = Console()

"""
remediate_misconfig.py

Remediates all misconfigurations introduced by introduce_misconfig.py.

Demonstrates the full compliance loop:
    introduce → scan (NON_COMPLIANT) → remediate → scan again (COMPLIANT)

This is what a real compliance engineer does:
    - Detect violation
    - Understand framework impact
    - Remediate
    - Verify remediation via re-scan
"""

MEMBER_PROFILE = "member"
REGION = "ap-south-1"
DEMO_BUCKET_NAME = "compliance-scanner-demo-misconfig-664858858896"


def get_s3_client():
    session = boto3.Session(profile_name=MEMBER_PROFILE, region_name=REGION)
    return session.client("s3")


def fix_1_block_public_access(s3):
    """
    Fix #1: Re-enable S3 public access block on all four settings.
    Remediates: S3_BUCKET_PUBLIC_ACCESS_PROHIBITED
    """
    s3.put_public_access_block(
        Bucket=DEMO_BUCKET_NAME,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True
        }
    )
    console.print("[green]Fix #1 applied:[/green] S3 public access block ENABLED")


def fix_2_enable_encryption(s3):
    """
    Fix #2: Enable AES-256 server-side encryption by default.
    Remediates: S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED
    """
    s3.put_bucket_encryption(
        Bucket=DEMO_BUCKET_NAME,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    },
                    "BucketKeyEnabled": True
                }
            ]
        }
    )
    console.print("[green]Fix #2 applied:[/green] S3 server-side encryption ENABLED (AES-256)")


def fix_3_enable_versioning(s3):
    """
    Fix #3: Enable S3 versioning.
    Remediates: S3_BUCKET_VERSIONING_ENABLED
    """
    s3.put_bucket_versioning(
        Bucket=DEMO_BUCKET_NAME,
        VersioningConfiguration={"Status": "Enabled"}
    )
    console.print("[green]Fix #3 applied:[/green] S3 versioning ENABLED")


def main():
    console.print("\n[bold green]Remediating misconfigurations...[/bold green]")
    console.print(f"[dim]Bucket: {DEMO_BUCKET_NAME} | Region: {REGION}[/dim]\n")

    s3 = get_s3_client()

    try:
        fix_1_block_public_access(s3)
        fix_2_enable_encryption(s3)
        fix_3_enable_versioning(s3)

        console.print("\n[bold green]All misconfigurations remediated.[/bold green]")
        console.print("[dim]Re-run the compliance scanner to verify COMPLIANT status.[/dim]")

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NoSuchBucket":
            console.print(f"[red]ERROR: Bucket {DEMO_BUCKET_NAME} not found.[/red]")
            console.print("[dim]Run introduce_misconfig.py first.[/dim]")
        else:
            console.print(f"[red]ERROR: {error_code} — {e.response['Error']['Message']}[/red]")
            raise


if __name__ == "__main__":
    main()