from collections import defaultdict


class GapAnalyzer:
    """
    Takes enriched compliance results and calculates:
        1. Compliance % per framework
        2. Which controls are failing per framework
        3. Priority gaps — controls whose remediation closes the most
           gaps across all three frameworks simultaneously

    This is the Option C differentiator. Most scanners stop at
    "rule X is non-compliant." This goes further and answers:
    "which 3 fixes give you the highest cross-framework compliance lift?"
    """

    def __init__(self, enriched_results: list):
        """
        Args:
            enriched_results: output of FrameworkMapper.enrich()
        """
        self.results = enriched_results
        self.frameworks = ["GDPR", "UAE_PDPL", "Essential_Eight"]

    def calculate_framework_scores(self) -> dict:
        """
        For each framework, calculates:
            - total_rules: how many rules map to this framework
            - compliant: how many are currently compliant
            - non_compliant: how many are failing
            - score_pct: compliance percentage (compliant / total * 100)

        Skips rules with RULE_NOT_FOUND or INSUFFICIENT_DATA —
        only counts rules with a definitive COMPLIANT or NON_COMPLIANT status.
        """
        framework_scores = {
            fw: {"total_rules": 0, "compliant": 0, "non_compliant": 0, "score_pct": 0.0}
            for fw in self.frameworks
        }

        for result in self.results:
            compliance = result["compliance_type"]

            # Only count definitive results
            if compliance not in ["COMPLIANT", "NON_COMPLIANT"]:
                continue

            for framework in self.frameworks:
                if framework in result.get("frameworks", {}):
                    framework_scores[framework]["total_rules"] += 1
                    if compliance == "COMPLIANT":
                        framework_scores[framework]["compliant"] += 1
                    else:
                        framework_scores[framework]["non_compliant"] += 1

        # Calculate percentage
        for fw in self.frameworks:
            total = framework_scores[fw]["total_rules"]
            if total > 0:
                framework_scores[fw]["score_pct"] = round(
                    (framework_scores[fw]["compliant"] / total) * 100, 1
                )

        return framework_scores

    def get_failing_controls(self) -> list:
        """
        Returns list of all non-compliant rules with their
        framework mappings and affected resources.
        Sorted by severity: CRITICAL > HIGH > MEDIUM > LOW
        """
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

        failing = [
            r for r in self.results
            if r["compliance_type"] == "NON_COMPLIANT"
        ]

        return sorted(failing, key=lambda x: severity_order.get(x["severity"], 4))

    def get_priority_gaps(self, top_n: int = 4) -> list:
        """
        Identifies the top N controls that, if remediated, would close
        the most gaps across all frameworks simultaneously.

        Logic:
            - For each non-compliant rule, count how many frameworks it maps to
            - Weight by severity (CRITICAL=3, HIGH=2, MEDIUM=1)
            - Sort by weighted cross-framework impact score descending
            - Return top N

        This answers: "if I can only fix 4 things, which 4 have the most impact
        across GDPR, UAE PDPL, and Essential Eight combined?"

        Args:
            top_n: number of priority gaps to return (default 4)
        """
        severity_weight = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 1, "UNKNOWN": 0}

        failing = self.get_failing_controls()
        scored = []

        for rule in failing:
            framework_count = len(rule.get("frameworks", {}))
            severity_score = severity_weight.get(rule["severity"], 0)

            # Impact score = frameworks affected * severity weight
            impact_score = framework_count * severity_score

            scored.append({
                **rule,
                "frameworks_affected_count": framework_count,
                "impact_score": impact_score
            })

        # Sort by impact score descending, severity as tiebreaker
        scored.sort(key=lambda x: x["impact_score"], reverse=True)

        return scored[:top_n]

    def get_summary(self) -> dict:
        """
        Returns a complete gap analysis summary dict.
        This is what gets passed to report_generator and Security Hub.
        """
        framework_scores = self.calculate_framework_scores()
        failing_controls = self.get_failing_controls()
        priority_gaps = self.get_priority_gaps()

        overall_compliant = sum(
            1 for r in self.results if r["compliance_type"] == "COMPLIANT"
        )
        overall_total = sum(
            1 for r in self.results
            if r["compliance_type"] in ["COMPLIANT", "NON_COMPLIANT"]
        )
        overall_pct = round((overall_compliant / overall_total * 100), 1) if overall_total > 0 else 0.0

        return {
            "overall": {
                "total_rules_evaluated": overall_total,
                "compliant": overall_compliant,
                "non_compliant": len(failing_controls),
                "overall_score_pct": overall_pct
            },
            "framework_scores": framework_scores,
            "failing_controls": failing_controls,
            "priority_gaps": priority_gaps
        }