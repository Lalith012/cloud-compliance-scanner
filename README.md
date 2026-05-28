# Cloud Compliance Scanner

Automated cloud compliance posture scanner mapped to **GDPR**, **UAE PDPL**, and **Australia Essential Eight** frameworks. Built with Python, AWS Config, and GitHub Actions.

---

## What It Does

Most compliance tools tell you *what* is non-compliant. This scanner tells you *what to fix first* — by calculating cross-framework impact scores and ranking remediation priorities across all three frameworks simultaneously.

**Example output:**
- Overall compliance score: 63.6%
- GDPR: 63.6% | UAE PDPL: 63.6% | Essential Eight: 63.6%
- Priority gap #1: `IAM_PASSWORD_POLICY` — impacts all 3 frameworks, fix this first

---

## Architecture

AWS Config Rules (12)
│
▼
config_client.py       ← Fetches compliance status via boto3
│
▼
framework_mapper.py    ← Maps each rule to GDPR / UAE PDPL / Essential Eight articles
│
▼
gap_analysis.py        ← Calculates per-framework scores + cross-framework priority gaps
│
▼
report_generator.py    ← Outputs JSON + HTML audit-ready reports
│
▼
security_hub.py        ← Pushes ASFF-format findings to AWS Security Hub
│
▼
GitHub Actions CI/CD   ← Runs on every push + daily cron, uploads reports as artifacts

---

## Tech Stack

| Layer | Technology |
|---|---|
| Cloud | AWS (Config, Security Hub, S3, IAM, VPC) |
| Language | Python 3.11 |
| AWS SDK | boto3 |
| CI/CD | GitHub Actions with OIDC authentication |
| Auth | OIDC — no long-lived credentials stored |
| Reporting | JSON + HTML |
| Testing | pytest (10/10 passing) |

---

## Compliance Frameworks

| Framework | Region | Controls Mapped |
|---|---|---|
| GDPR | European Union | 12 |
| UAE Personal Data Protection Law (PDPL) | United Arab Emirates | 12 |
| Australia Essential Eight | Australia | 12 |

---

## AWS Config Rules

| Rule | Severity | GDPR | UAE PDPL | Essential Eight |
|---|---|---|---|---|
| S3_BUCKET_PUBLIC_ACCESS_PROHIBITED | CRITICAL | Art. 5(1)(f), 32 | Art. 16, 20 | User Application Hardening |
| S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED | HIGH | Art. 32 | Art. 16 | Encrypt Data at Rest |
| S3_BUCKET_VERSIONING_ENABLED | MEDIUM | Art. 32 | Art. 16 | Regular Backups |
| ROOT_ACCOUNT_MFA_ENABLED | CRITICAL | Art. 32 | Art. 16, 20 | Multi-Factor Authentication |
| IAM_ROOT_ACCESS_KEY_CHECK | CRITICAL | Art. 32 | Art. 20 | Restrict Administrative Privileges |
| IAM_PASSWORD_POLICY | HIGH | Art. 32 | Art. 16 | Multi-Factor Authentication |
| CLOUD_TRAIL_ENABLED | CRITICAL | Art. 30, 32 | Art. 16, 22 | Audit Logging |
| CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED | HIGH | Art. 32 | Art. 22 | Audit Logging |
| CMK_BACKING_KEY_ROTATION_ENABLED | HIGH | Art. 32 | Art. 16 | Encrypt Data at Rest |
| EC2_EBS_ENCRYPTION_BY_DEFAULT | HIGH | Art. 32 | Art. 16 | Encrypt Data at Rest |
| RESTRICTED_INCOMING_TRAFFIC | CRITICAL | Art. 32 | Art. 16, 20 | Limit Network Access |
| VPC_FLOW_LOGS_ENABLED | HIGH | Art. 30, 32 | Art. 22 | Audit Logging |

---

## Gap Analysis — Cross-Framework Priority Scoring

The scanner calculates a **cross-framework impact score** for each non-compliant control:

impact_score = frameworks_affected × severity_weight
severity_weight: CRITICAL=3, HIGH=2, MEDIUM=1

This answers: *"If I can only fix 4 things, which 4 fixes close the most gaps across GDPR, UAE PDPL, and Essential Eight simultaneously?"*

---

## Project Structure

cloud-compliance-scanner/
├── .github/
│   └── workflows/
│       └── compliance-scan.yml    # CI/CD pipeline
├── scanner/
│   ├── config_client.py           # AWS Config API integration
│   ├── framework_mapper.py        # Rule → framework mapping
│   ├── gap_analysis.py            # Cross-framework scoring
│   ├── report_generator.py        # JSON + HTML report generation
│   └── security_hub.py            # ASFF findings push to Security Hub
├── rules/
│   └── framework_mappings.json    # Control → framework mapping data
├── misconfig_demo/
│   ├── introduce_misconfig.py     # Introduces intentional violations
│   └── remediate_misconfig.py     # Remediates violations
├── tests/
│   ├── test_mapper.py             # Framework mapper tests
│   └── test_gap_analysis.py       # Gap analysis tests
├── main.py                        # Pipeline orchestrator
├── requirements.txt
└── .env.example                   # Environment variable template

---

## CI/CD Pipeline

The GitHub Actions pipeline runs on every push to `main` and on a daily schedule (06:00 UTC):

1. Checkout repository
2. Install Python dependencies
3. Run unit tests — pipeline fails if tests fail
4. Authenticate to AWS via OIDC (no stored credentials)
5. Run compliance scan
6. Upload JSON + HTML reports as artifacts (90-day retention)

**Pipeline exits with code 1 when non-compliant findings exist** — this is intentional. A compliance scanner should fail CI when violations are detected.

---

## Running Locally

```bash
# Clone
git clone https://github.com/Lalith012/cloud-compliance-scanner.git
cd cloud-compliance-scanner

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your AWS profile and account ID

# Run scanner
python main.py

# Run tests
pytest tests/ -v
```

---

## Misconfig Demo — Full Detection Loop

```bash
# Step 1 — Introduce intentional misconfigurations
python misconfig_demo/introduce_misconfig.py

# Step 2 — Run scanner (score drops, new violations appear)
python main.py

# Step 3 — Remediate
python misconfig_demo/remediate_misconfig.py

# Step 4 — Rescan (score recovers, violations resolved)
python main.py
```

**Before remediation:** 54.5% overall | 5 non-compliant controls
**After remediation:** 63.6% overall | 4 non-compliant controls

---

## Security Hub Integration

Non-compliant findings are pushed to AWS Security Hub as ASFF-format custom findings via `batch_import_findings`. Each finding includes:
- Severity mapping (CRITICAL / HIGH / MEDIUM)
- Framework article references (GDPR / UAE PDPL / Essential Eight)
- Affected resource IDs
- Compliance status and related requirements

Security Hub custom finding display requires partner product registration in enterprise AWS environments.

---

## Sample Report

**Terminal output:**

Framework Scores:
GDPR                 63.6% (7/11 compliant)
UAE_PDPL             63.6% (7/11 compliant)
Essential_Eight      63.6% (7/11 compliant)
Priority Gaps (fix these first):
#1 HIGH IAM_PASSWORD_POLICY (impacts 3 frameworks)
#2 HIGH EC2_EBS_ENCRYPTION_BY_DEFAULT (impacts 3 frameworks)
#3 HIGH VPC_FLOW_LOGS_ENABLED (impacts 3 frameworks)
#4 MEDIUM S3_BUCKET_VERSIONING_ENABLED (impacts 3 frameworks)

HTML and JSON reports are generated in `reports/` and uploaded as GitHub Actions artifacts on every pipeline run.

---

## Authorization

This scanner is configured to run exclusively against AWS account `664858858896` (personal lab environment). All scanning is authorized and performed on infrastructure owned and operated by the repository author.

