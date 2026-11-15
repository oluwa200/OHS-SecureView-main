"""
Security Posture Agent — Cross-correlates data from all security tools.

Reads JSON data files, identifies coverage gaps, and writes ai_insights.json.
"""
import json
import os
from datetime import datetime, timezone, timedelta

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


class SecurityPostureAgent:
    """Analyzes security data across tools and produces actionable insights."""

    def __init__(self):
        self.ec2_instances = {}
        self.crowdstrike_hosts = {}
        self.qualys_report = {}
        self.iom_data = {}
        self.cspm_data = {}
        self.ec2_counts = {}
        self.insights = {
            "generated_at": "",
            "overall_risk_score": 0,
            "coverage_gaps": [],
            "high_risk_findings": [],
            "priority_actions": [],
            "summary": "",
            "stats": {},
        }

    def load_data(self):
        """Load all available JSON data files."""
        self.ec2_instances = self._load("aws_ec2_instances.json", {})
        self.crowdstrike_hosts = self._load("crowdstrike_hosts.json", {})
        self.qualys_report = self._load("vulnerability_report.json", {})
        self.iom_data = self._load("crowdstrike_iom_analysis.json", {})
        self.cspm_data = self._load("crowdstrike_cspm_report.json", {})
        self.ec2_counts = self._load("aws_ec2_counts.json", {})

    def _load(self, filename, default):
        """Load a single JSON file."""
        path = os.path.join(DATA_DIR, filename)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return default

    def analyze(self):
        """Run full cross-correlation analysis."""
        self.load_data()

        # Extract IP sets from each tool
        ec2_ips = self._get_ec2_ips()
        cs_ips = self._get_crowdstrike_ips()
        qualys_ips = self._get_qualys_ips()

        # Cross-correlate
        all_ips = ec2_ips | cs_ips | qualys_ips

        no_edr = ec2_ips - cs_ips  # EC2 instances without CrowdStrike
        no_vuln_scan = ec2_ips - qualys_ips  # EC2 instances without Qualys
        completely_blind = ec2_ips - cs_ips - qualys_ips  # No coverage at all
        full_coverage = ec2_ips & cs_ips & qualys_ips  # Both tools

        # Build coverage gaps
        coverage_gaps = []
        for ip in sorted(no_edr)[:20]:
            coverage_gaps.append({
                "ip": ip,
                "gap_type": "no_edr",
                "description": f"EC2 instance {ip} has no CrowdStrike Falcon sensor",
                "risk": "HIGH" if ip in qualys_ips else "CRITICAL",
            })
        for ip in sorted(no_vuln_scan - no_edr)[:20]:
            coverage_gaps.append({
                "ip": ip,
                "gap_type": "no_vuln_scan",
                "description": f"EC2 instance {ip} has no Qualys vulnerability scanning",
                "risk": "MEDIUM",
            })
        for ip in sorted(completely_blind)[:10]:
            coverage_gaps.append({
                "ip": ip,
                "gap_type": "completely_blind",
                "description": f"EC2 instance {ip} has NO security tool coverage (blind spot)",
                "risk": "CRITICAL",
            })

        # Calculate overall risk score (0-100, higher = worse)
        risk_score = self._calculate_risk_score(
            ec2_ips, cs_ips, qualys_ips, completely_blind
        )

        # High-risk findings
        high_risk = self._find_high_risk_assets(ec2_ips, cs_ips, qualys_ips)

        # Priority actions
        priority_actions = self._generate_priority_actions(
            no_edr, no_vuln_scan, completely_blind
        )

        # Summary
        summary = self._generate_summary(
            ec2_ips, cs_ips, qualys_ips, completely_blind, risk_score
        )

        # Assemble insights
        self.insights = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overall_risk_score": risk_score,
            "coverage_gaps": coverage_gaps,
            "high_risk_findings": high_risk,
            "priority_actions": priority_actions,
            "summary": summary,
            "stats": {
                "total_ec2_ips": len(ec2_ips),
                "crowdstrike_coverage": len(cs_ips & ec2_ips),
                "qualys_coverage": len(qualys_ips & ec2_ips),
                "full_coverage": len(full_coverage),
                "no_edr": len(no_edr),
                "no_vuln_scan": len(no_vuln_scan),
                "completely_blind": len(completely_blind),
                "edr_coverage_pct": round(len(cs_ips & ec2_ips) / max(len(ec2_ips), 1) * 100, 1),
                "vuln_scan_coverage_pct": round(len(qualys_ips & ec2_ips) / max(len(ec2_ips), 1) * 100, 1),
                "full_coverage_pct": round(len(full_coverage) / max(len(ec2_ips), 1) * 100, 1),
            },
        }

        return self.insights

    def save_insights(self):
        """Write insights to data/ai_insights.json."""
        output_path = os.path.join(DATA_DIR, "ai_insights.json")
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.insights, f, indent=2, default=str)
        return output_path

    # ─── Internal Helpers ─────────────────────────────────────────────────────
    def _get_ec2_ips(self):
        """Extract all private IPs from EC2 data."""
        ips = set()
        accounts = self.ec2_instances.get("accounts", {})
        for acct_instances in accounts.values():
            for inst in acct_instances:
                ip = inst.get("PrivateIp") or inst.get("private_ip", "")
                if ip:
                    ips.add(ip)
        return ips

    def _get_crowdstrike_ips(self):
        """Extract all IPs from CrowdStrike hosts."""
        ips = set()
        accounts = self.crowdstrike_hosts.get("accounts", {})
        for acct_hosts in accounts.values():
            for host in acct_hosts:
                ip = host.get("local_ip", "") or host.get("LocalIP", "")
                if ip:
                    ips.add(ip)
        return ips

    def _get_qualys_ips(self):
        """Extract all IPs from Qualys vulnerability report."""
        ips = set()
        for acct_data in self.qualys_report.values():
            if not isinstance(acct_data, dict):
                continue
            for asset in acct_data.get("internet_facing_assets", []):
                ip = asset.get("ip", "")
                if ip:
                    ips.add(ip)
            for asset in acct_data.get("internal_assets", []):
                ip = asset.get("ip", "")
                if ip:
                    ips.add(ip)
            # Also extract from vulns
            for vuln in acct_data.get("internet_facing_vulns", []):
                ip = vuln.get("ip", "")
                if ip:
                    ips.add(ip)
            for vuln in acct_data.get("internal_vulns", []):
                ip = vuln.get("ip", "")
                if ip:
                    ips.add(ip)
        return ips

    def _calculate_risk_score(self, ec2_ips, cs_ips, qualys_ips, blind):
        """Calculate 0-100 risk score. Higher = worse."""
        if not ec2_ips:
            return 0

        total = len(ec2_ips)
        blind_pct = len(blind) / total * 100
        no_edr_pct = len(ec2_ips - cs_ips) / total * 100
        no_scan_pct = len(ec2_ips - qualys_ips) / total * 100

        # Weighted risk: blind spots are worst, then no EDR, then no scan
        score = (blind_pct * 0.5) + (no_edr_pct * 0.3) + (no_scan_pct * 0.2)
        return min(100, round(score, 1))

    def _find_high_risk_assets(self, ec2_ips, cs_ips, qualys_ips):
        """Find assets with critical vulns that lack EDR."""
        findings = []
        for acct_name, acct_data in self.qualys_report.items():
            if not isinstance(acct_data, dict):
                continue
            for vuln in acct_data.get("internet_facing_vulns", []):
                sev = str(vuln.get("severity", "3"))
                ip = vuln.get("ip", "")
                if sev in ("5", "4") and ip and ip not in cs_ips:
                    findings.append({
                        "ip": ip,
                        "account": acct_name,
                        "severity": sev,
                        "qid": vuln.get("qid", "N/A"),
                        "reason": "Critical/High vuln on internet-facing host WITHOUT EDR protection",
                        "risk": "CRITICAL",
                    })
        return findings[:20]

    def _generate_priority_actions(self, no_edr, no_vuln_scan, blind):
        """Generate top 5 priority actions."""
        actions = []
        if blind:
            actions.append({
                "priority": 1,
                "action": f"Deploy BOTH CrowdStrike and Qualys to {len(blind)} completely unmonitored hosts",
                "impact": "CRITICAL — These hosts have zero visibility",
                "hosts_affected": len(blind),
            })
        if no_edr:
            actions.append({
                "priority": 2,
                "action": f"Install CrowdStrike Falcon on {len(no_edr)} EC2 instances missing EDR",
                "impact": "HIGH — No threat detection or response capability",
                "hosts_affected": len(no_edr),
            })
        if no_vuln_scan:
            actions.append({
                "priority": 3,
                "action": f"Add {len(no_vuln_scan)} hosts to Qualys vulnerability scanning",
                "impact": "MEDIUM — Unknown vulnerability exposure",
                "hosts_affected": len(no_vuln_scan),
            })
        actions.append({
            "priority": 4,
            "action": "Review and remediate CSPM misconfigurations",
            "impact": "MEDIUM — Cloud infrastructure hardening",
            "hosts_affected": 0,
        })
        actions.append({
            "priority": 5,
            "action": "Update Defender secure score by implementing pending recommendations",
            "impact": "LOW — Incremental posture improvement",
            "hosts_affected": 0,
        })
        return actions[:5]

    def _generate_summary(self, ec2_ips, cs_ips, qualys_ips, blind, risk_score):
        """Generate executive summary text."""
        total = len(ec2_ips)
        edr_pct = round(len(cs_ips & ec2_ips) / max(total, 1) * 100, 1)
        scan_pct = round(len(qualys_ips & ec2_ips) / max(total, 1) * 100, 1)

        risk_label = "LOW" if risk_score < 25 else "MEDIUM" if risk_score < 50 else "HIGH" if risk_score < 75 else "CRITICAL"

        return (
            f"Security Posture Assessment: {risk_label} risk (score: {risk_score}/100). "
            f"Across {total} EC2 instances: EDR coverage is {edr_pct}%, "
            f"vulnerability scanning covers {scan_pct}%, "
            f"and {len(blind)} hosts have NO security tool coverage. "
            f"Immediate action required for blind spots."
        )


def run_agent():
    """Entry point to run the agent and produce insights."""
    agent = SecurityPostureAgent()
    insights = agent.analyze()
    output_path = agent.save_insights()
    print(f"[SecurityAgent] Insights written to: {output_path}")
    print(f"[SecurityAgent] Risk Score: {insights['overall_risk_score']}/100")
    print(f"[SecurityAgent] Coverage Gaps: {len(insights['coverage_gaps'])}")
    print(f"[SecurityAgent] Priority Actions: {len(insights['priority_actions'])}")
    return insights


if __name__ == "__main__":
    run_agent()
