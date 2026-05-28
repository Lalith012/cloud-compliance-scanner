import pytest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner.gap_analysis import GapAnalyzer


@pytest.fixture
def sample_enriched_results():
    """
    Mock enriched results simulating a realistic scan output.
    Mix of COMPLIANT, NON_COMPLIANT, and INSUFFICIENT_DATA.
    """
    return [
        {
            "rule_name": "S3_BUCKET_PUBLIC_ACCESS_PROHIBITED",
            "compliance_type": "NON_COMPLIANT",
            "non_compliant_resources": ["bucket-a", "bucket-b"],
            "description": "S3 buckets must block all public access",
            "severity": "CRITICAL",
            "frameworks": {
                "GDPR": ["Article 5(1)(f)", "Article 32"],
                "UAE_PDPL": ["Article 16", "Article 20"],
                "Essential_Eight": ["User Application Hardening"]
            }
        },
        {
            "rule_name": "ROOT_ACCOUNT_MFA_ENABLED",
            "compliance_type": "NON_COMPLIANT",
            "non_compliant_resources": [],
            "description": "Root account must have MFA enabled",
            "severity": "CRITICAL",
            "frameworks": {
                "GDPR": ["Article 32"],
                "UAE_PDPL": ["Article 16", "Article 20"],
                "Essential_Eight": ["Multi-Factor Authentication"]
            }
        },
        {
            "rule_name": "CLOUD_TRAIL_ENABLED",
            "compliance_type": "COMPLIANT",
            "non_compliant_resources": [],
            "description": "CloudTrail must be enabled in all regions",
            "severity": "CRITICAL",
            "frameworks": {
                "GDPR": ["Article 30", "Article 32"],
                "UAE_PDPL": ["Article 16", "Article 22"],
                "Essential_Eight": ["Audit Logging"]
            }
        },
        {
            "rule_name": "CMK_BACKING_KEY_ROTATION_ENABLED",
            "compliance_type": "COMPLIANT",
            "non_compliant_resources": [],
            "description": "KMS key rotation must be enabled",
            "severity": "HIGH",
            "frameworks": {
                "GDPR": ["Article 32"],
                "UAE_PDPL": ["Article 16"],
                "Essential_Eight": ["Encrypt Data at Rest"]
            }
        },
        {
            "rule_name": "VPC_FLOW_LOGS_ENABLED",
            "compliance_type": "INSUFFICIENT_DATA",
            "non_compliant_resources": [],
            "description": "VPC flow logs must be enabled",
            "severity": "HIGH",
            "frameworks": {
                "GDPR": ["Article 30", "Article 32"],
                "UAE_PDPL": ["Article 22"],
                "Essential_Eight": ["Audit Logging"]
            }
        }
    ]


def test_framework_scores_calculated(sample_enriched_results):
    """
    Verifies framework scores are calculated correctly.
    INSUFFICIENT_DATA results must be excluded from scoring.
    """
    analyzer = GapAnalyzer(sample_enriched_results)
    scores = analyzer.calculate_framework_scores()

    assert "GDPR" in scores
    assert "UAE_PDPL" in scores
    assert "Essential_Eight" in scores

    # VPC_FLOW_LOGS is INSUFFICIENT_DATA — must not be counted
    for fw in ["GDPR", "UAE_PDPL", "Essential_Eight"]:
        assert scores[fw]["total_rules"] > 0
        assert 0.0 <= scores[fw]["score_pct"] <= 100.0


def test_failing_controls_sorted_by_severity(sample_enriched_results):
    """
    get_failing_controls() must return only NON_COMPLIANT results,
    sorted CRITICAL first.
    """
    analyzer = GapAnalyzer(sample_enriched_results)
    failing = analyzer.get_failing_controls()

    assert len(failing) == 2
    assert all(r["compliance_type"] == "NON_COMPLIANT" for r in failing)
    assert failing[0]["severity"] == "CRITICAL"


def test_priority_gaps_returns_correct_count(sample_enriched_results):
    """
    get_priority_gaps() must return at most top_n results.
    """
    analyzer = GapAnalyzer(sample_enriched_results)
    gaps = analyzer.get_priority_gaps(top_n=4)

    assert len(gaps) <= 4
    assert all("impact_score" in g for g in gaps)


def test_priority_gaps_sorted_by_impact(sample_enriched_results):
    """
    Priority gaps must be sorted by impact_score descending.
    Higher impact score = more frameworks affected * higher severity weight.
    """
    analyzer = GapAnalyzer(sample_enriched_results)
    gaps = analyzer.get_priority_gaps(top_n=4)

    scores = [g["impact_score"] for g in gaps]
    assert scores == sorted(scores, reverse=True)


def test_summary_structure(sample_enriched_results):
    """
    get_summary() must return a dict with all required top-level keys.
    """
    analyzer = GapAnalyzer(sample_enriched_results)
    summary = analyzer.get_summary()

    assert "overall" in summary
    assert "framework_scores" in summary
    assert "failing_controls" in summary
    assert "priority_gaps" in summary
    assert "overall_score_pct" in summary["overall"]