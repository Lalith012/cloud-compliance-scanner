import boto3
import json
from botocore.exceptions import ClientError
from rich.console import Console

console = Console()

"""
introduce_misconfig.py

Intentionally introduces real misconfigurations into the member account
so the compliance scanner has actual NON_COMPLIANT findings to detect.

Why this exists:
    A scanner that always returns green proves nothing.
    This script creates controlled, documented violations so we can
    demonstrate the full detection loop:
    introduce → scan → report → remediate → scan again → clean

Misconfigurations introduced:
    1. S3 bucket with public access enabled
    2. S3 bucket without server-side encryption
    3. S3 bucket without versioning

IMPORTANT:
    - Only run against the member account (664858858896)
    - These are intentional — document them as such
    - Always run remediate_misconfig.py after demonstrating the scan
    - Never run against production accounts
"""

MEMBER_PROFILE = "member"
REGION = "ap-south-1"
DEMO_BUCKET_NAME = "compliance-scanner-demo-misconfig-664858858896"


def get_s3_client():
    session = boto3.Session(profile_name=MEMBER_PROFILE, region_name=REGION)
    return session.client("s3")


def create_demo_bucket(s3):
    """
    Creates a demo S3 bucket for misconfig demonstration.
    Uses LocationConstraint because ap-south-1 is not us-east-1.
    """
    try:
        s3.create_bucket(
            Bucket=DEMO_BUCKET_NAME,
            CreateBucketConfiguration={"LocationConstraint": REGION}
        )
        console.print(f"[green]Created bucket:[/green] {DEMO_BUCKET_NAME}")
    except ClientError as e:
        if e.response["Error"]["Code"] == "BucketAlreadyOwnedByYou":
            console.print(f"[yellow]Bucket already exists:[/yellow] {DEMO_BUCKET_NAME}")
        else:
            raise


def misconfig_1_enable_public_access(s3):
    """
    Misconfig #1: Disable the S3 public access block.
    Violates: S3_BUCKET_PUBLIC_ACCESS_PROHIBITED
    Framework impact: GDPR Article 5(1)(f), Article 32 | UAE PDPL Article 16, 20 | Essential Eight
    """
    s3.put_public_access_block(
        Bucket=DEMO_BUCKET_NAME,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False
        }
    )
    console.print("[red]Misconfig #1 introduced:[/red] S3 public access block DISABLED")


def misconfig_2_remove_encryption(s3):
    """
    Misconfig #2: Delete bucket encryption configuration.
    Violates: S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED
    Framework impact: GDPR Article 32 | UAE PDPL Article 16 | Essential Eight
    """
    try:
        s3.delete_bucket_encryption(Bucket=DEMO_BUCKET_NAME)
        console.print("[red]Misconfig #2 introduced:[/red] S3 server-side encryption REMOVED")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            console.print("[yellow]Encryption was not set — misconfig #2 already in effect[/yellow]")
        else:
            raise


def misconfig_3_disable_versioning(s3):
    """
    Misconfig #3: Suspend S3 versioning.
    Violates: S3_BUCKET_VERSIONING_ENABLED
    Framework impact: GDPR Article 32 | UAE PDPL Article 16 | Essential Eight
    """
    s3.put_bucket_versioning(
        Bucket=DEMO_BUCKET_NAME,
        VersioningConfiguration={"Status": "Suspended"}
    )
    console.print("[red]Misconfig #3 introduced:[/red] S3 versioning SUSPENDED")


def main():
    console.print("\n[bold red]WARNING: Introducing intentional misconfigurations[/bold red]")
    console.print("[dim]Member account: 664858858896 | Region: ap-south-1[/dim]\n")

    s3 = get_s3_client()

    create_demo_bucket(s3)
    misconfig_1_enable_public_access(s3)
    misconfig_2_remove_encryption(s3)
    misconfig_3_disable_versioning(s3)

    console.print("\n[bold]Misconfigurations introduced:[/bold]")
    console.print("  1. S3 public access block disabled")
    console.print("  2. S3 server-side encryption removed")
    console.print("  3. S3 versioning suspended")
    console.print("\n[dim]Run the compliance scanner to detect these findings.[/dim]")
    console.print("[dim]Run remediate_misconfig.py to fix them after demonstration.[/dim]")


if __name__ == "__main__":
    main()