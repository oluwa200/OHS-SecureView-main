"""
Weekly Security Brief Generator
================================
Produces a natural-language executive summary based on:
- AI insights (risk score, coverage gaps)
- Trend data (history.json)
- IOM analysis
- Anomaly detection (coverage drops, new unprotected instances)
"""
import os
import json
from datetime import datetime, timezone, timedelta

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def load_json(filename, default=None):
    path = os.path.join(DATA_DIR, filename)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return default if default is not None else {}


def detect_anomalies(history, current_insights):
    """Detect significant changes from recent history."""
    anomalies = []
    if not history or len(history) < 2:
        return anomalies

    # Compare last 7 days avg to previous 7 days
    recent = history[-7:]
    prior = history[-14:-7] if len(history) >= 14 else history[:len(history)//2]

    if not prior:
        return anomalies

    def avg(data, key):
        vals = [d.get(key, 0) for d in data if d.get(key) is not None]
        return sum(vals) / len(vals) if vals else 0

    # EDR coverage drop
    recent_edr = avg(recent, "edr_coverage_pct")
    prior_edr = avg(prior, "edr_coverage_pct")
    if prior_edr > 0 and (prior_edr - recent_edr) > 3:
        anomalies.append({
            "type": "coverage_drop",
            "severity": "HIGH",
            "metric": "EDR Coverage",
            "prior_avg": round(prior_edr, 1),
            "current_avg": round(recent_edr, 1),
            "delta": round(recent_edr - prior_edr, 1),
            "message": f"EDR coverage dropped {round(prior_edr - recent_edr, 1)}pp "
                       f"(from {round(prior_edr, 1)}% to {round(recent_edr, 1)}%)"
        })

    # Risk score spike
    recent_risk = avg(recent, "risk_score")
    prior_risk = avg(prior, "risk_score")
    if (recent_risk - prior_risk) > 5:
        anomalies.append({
            "type": "risk_spike",
            "severity": "HIGH",
            "metric": "Risk Score",
            "prior_avg": round(prior_risk, 1),
            "current_avg": round(recent_risk, 1),
            "delta": round(recent_risk - prior_risk, 1),
            "message": f"Risk score increased by {round(recent_risk - prior_risk, 1)} points "
                       f"(from {round(prior_risk, 1)} to {round(recent_risk, 1)})"
        })

    # New blind spots
    recent_blind = avg(recent, "completely_blind")
    prior_blind = avg(prior, "completely_blind")
    if recent_blind > prior_blind and (recent_blind - prior_blind) >= 2:
        anomalies.append({
            "type": "new_blind_spots",
            "severity": "CRITICAL",
            "metric": "Blind Spots",
            "prior_avg": round(prior_blind),
            "current_avg": round(recent_blind),
            "delta": round(recent_blind - prior_blind),
            "message": f"{round(recent_blind - prior_blind)} new blind spot(s) detected "
                       f"(hosts with NO EDR and NO vuln scanning)"
        })

    # Vuln scan coverage drop
    recent_vuln = avg(recent, "vuln_scan_coverage_pct")
    prior_vuln = avg(prior, "vuln_scan_coverage_pct")
    if prior_vuln > 0 and (prior_vuln - recent_vuln) > 3:
        anomalies.append({
            "type": "coverage_drop",
            "severity": "MEDIUM",
            "metric": "Vulnerability Scan Coverage",
            "prior_avg": round(prior_vuln, 1),
            "current_avg": round(recent_vuln, 1),
            "delta": round(recent_vuln - prior_vuln, 1),
            "message": f"Vuln scan coverage dropped {round(prior_vuln - recent_vuln, 1)}pp "
                       f"(from {round(prior_vuln, 1)}% to {round(recent_vuln, 1)}%)"
        })

    return anomalies


def prioritize_remediation(insights, iom_data):
    """Generate prioritized remediation plan combining coverage gaps + IOMs.
    Internet-facing + critical vulns get highest priority.
    """
    priorities = []

    # Priority 1: Blind spots (no EDR + no vuln scan) — immediate risk
    blind_count = insights.get("stats", {}).get("completely_blind", 0)
    if blind_count > 0:
        priorities.append({
            "rank": 1,
            "category": "Coverage Gap",
            "action": f"Deploy CrowdStrike Falcon + Qualys agent to {blind_count} completely blind hosts",
            "impact": "CRITICAL",
            "effort": "Medium",
            "rationale": "Hosts with zero security tooling are invisible to incident response"
        })

    # Priority 2: Critical IOMs on internet-facing services
    p1_findings = iom_data.get("prioritized_findings", {}).get("P1", [])
    internet_facing_p1 = [f for f in p1_findings if f.get("impact_category") in
                          ("critical_exposure", "network_exposure")]
    if internet_facing_p1:
        top_rule = internet_facing_p1[0].get("rule_name", "Unknown")
        total_misconfigs = sum(f.get("misconfigurations", 0) for f in internet_facing_p1)
        priorities.append({
            "rank": 2,
            "category": "Internet Exposure",
            "action": f"Remediate {len(internet_facing_p1)} internet-facing misconfigurations "
                      f"({total_misconfigs} total resources). Top: '{top_rule}'",
            "impact": "CRITICAL",
            "effort": "High",
            "rationale": "Public exposure combined with misconfigurations = active attack surface"
        })

    # Priority 3: Privilege escalation IOMs
    priv_esc_p1 = [f for f in p1_findings if f.get("impact_category") == "privilege_escalation"]
    if priv_esc_p1:
        total_roles = sum(f.get("misconfigurations", 0) for f in priv_esc_p1)
        priorities.append({
            "rank": 3,
            "category": "IAM Risk",
            "action": f"Fix {len(priv_esc_p1)} privilege escalation paths "
                      f"({total_roles} overpermissive roles/policies)",
            "impact": "HIGH",
            "effort": "Medium",
            "rationale": "Compromised credentials can escalate to admin-level access"
        })

    # Priority 4: No EDR hosts
    no_edr = insights.get("stats", {}).get("no_edr", 0)
    if no_edr > blind_count:
        priorities.append({
            "rank": 4,
            "category": "EDR Gap",
            "action": f"Install Falcon sensor on {no_edr - blind_count} additional hosts "
                      f"(already scanned but no EDR)",
            "impact": "HIGH",
            "effort": "Low",
            "rationale": "Vuln scanning without EDR = detection gap for active threats"
        })

    # Priority 5: Data exposure IOMs
    data_exposure = [f for f in p1_findings + iom_data.get("prioritized_findings", {}).get("P2", [])
                     if f.get("impact_category") == "data_exposure"]
    if data_exposure:
        total_unencrypted = sum(f.get("misconfigurations", 0) for f in data_exposure)
        priorities.append({
            "rank": 5,
            "category": "Data Exposure",
            "action": f"Enable encryption on {total_unencrypted} unencrypted resources "
                      f"(EBS, S3, Lambda, RDS)",
            "impact": "MEDIUM",
            "effort": "Medium",
            "rationale": "Unencrypted data at rest violates compliance and exposes sensitive data"
        })

    return priorities


def predict_sla_breaches(history):
    """Forecast potential SLA breaches based on risk trend."""
    if not history or len(history) < 7:
        return None

    recent = history[-7:]
    risk_values = [h.get("risk_score", 0) for h in recent]

    # Simple linear trend
    n = len(risk_values)
    if n < 2:
        return None

    x_mean = (n - 1) / 2
    y_mean = sum(risk_values) / n
    numerator = sum((i - x_mean) * (risk_values[i] - y_mean) for i in range(n))
    denominator = sum((i - x_mean) ** 2 for i in range(n))
    slope = numerator / denominator if denominator != 0 else 0

    # Forecast 7 days ahead
    forecast_7d = risk_values[-1] + slope * 7
    forecast_14d = risk_values[-1] + slope * 14

    return {
        "current_risk": risk_values[-1],
        "trend_direction": "increasing" if slope > 0.5 else "decreasing" if slope < -0.5 else "stable",
        "daily_change": round(slope, 2),
        "forecast_7d": round(min(100, max(0, forecast_7d)), 1),
        "forecast_14d": round(min(100, max(0, forecast_14d)), 1),
        "breach_risk": "HIGH" if forecast_7d > 60 else "MEDIUM" if forecast_7d > 40 else "LOW",
    }


def generate_weekly_brief():
    """Generate the complete weekly security brief."""
    insights = load_json("ai_insights.json", {})
    history = load_json("history.json", [])
    iom_data = load_json("crowdstrike_iom_analysis.json", {})

    now = datetime.now(timezone.utc)
    risk_score = insights.get("overall_risk_score", 0)
    stats = insights.get("stats", {})

    # Determine risk level
    if risk_score < 25:
        risk_level = "LOW"
        risk_emoji = "🟢"
    elif risk_score < 50:
        risk_level = "MEDIUM"
        risk_emoji = "🟡"
    elif risk_score < 75:
        risk_level = "HIGH"
        risk_emoji = "🟠"
    else:
        risk_level = "CRITICAL"
        risk_emoji = "🔴"

    # Detect anomalies
    anomalies = detect_anomalies(history, insights)

    # Prioritize remediation
    priorities = prioritize_remediation(insights, iom_data)

    # Predict trend
    forecast = predict_sla_breaches(history)

    # IOM summary
    iom_summary = iom_data.get("summary", {})

    # Build narrative
    narrative_parts = []

    # Opening
    narrative_parts.append(
        f"## {risk_emoji} Weekly Security Posture Brief — {now.strftime('%B %d, %Y')}\n\n"
        f"**Overall Risk: {risk_level} ({risk_score}/100)**\n\n"
    )

    # Coverage summary
    narrative_parts.append(
        f"### 📊 Coverage Summary\n"
        f"- **EC2 Fleet:** {stats.get('total_ec2_ips', 0)} instances monitored\n"
        f"- **EDR Coverage:** {stats.get('edr_coverage_pct', 0)}% "
        f"({stats.get('crowdstrike_coverage', 0)} of {stats.get('total_ec2_ips', 0)})\n"
        f"- **Vuln Scanning:** {stats.get('vuln_scan_coverage_pct', 0)}%\n"
        f"- **Full Coverage:** {stats.get('full_coverage_pct', 0)}% (both EDR + scanning)\n"
        f"- **Blind Spots:** {stats.get('completely_blind', 0)} hosts with ZERO security tooling\n\n"
    )

    # Anomalies
    if anomalies:
        narrative_parts.append("### ⚠️ Anomalies Detected\n")
        for a in anomalies:
            sev_icon = "🔴" if a["severity"] == "CRITICAL" else "🟠" if a["severity"] == "HIGH" else "🟡"
            narrative_parts.append(f"- {sev_icon} **{a['severity']}:** {a['message']}\n")
        narrative_parts.append("\n")
    else:
        narrative_parts.append("### ✅ No Anomalies Detected\nAll metrics within normal ranges.\n\n")

    # CSPM/IOM summary
    if iom_summary:
        narrative_parts.append(
            f"### 🔐 Cloud Misconfigurations (CrowdStrike CSPM)\n"
            f"- **P1 Critical:** {iom_summary.get('p1_critical', 0)} findings\n"
            f"- **P2 High:** {iom_summary.get('p2_high', 0)} findings\n"
            f"- **Total IOMs:** {iom_summary.get('total_ioms_analyzed', 0)}\n"
            f"- **Top Categories:** {', '.join(f'{k} ({v})' for k, v in list(iom_summary.get('top_categories', {}).items())[:5])}\n\n"
        )

    # Forecast
    if forecast:
        trend_icon = "📈" if forecast["trend_direction"] == "increasing" else "📉" if forecast["trend_direction"] == "decreasing" else "➡️"
        narrative_parts.append(
            f"### {trend_icon} Risk Trend Forecast\n"
            f"- **Trend:** {forecast['trend_direction'].title()} ({forecast['daily_change']:+.1f}/day)\n"
            f"- **7-day forecast:** Risk score → {forecast['forecast_7d']}\n"
            f"- **14-day forecast:** Risk score → {forecast['forecast_14d']}\n"
            f"- **SLA Breach Risk:** {forecast['breach_risk']}\n\n"
        )

    # Remediation priorities
    if priorities:
        narrative_parts.append("### 🎯 Top Remediation Priorities\n")
        for p in priorities[:5]:
            impact_icon = "🔴" if p["impact"] == "CRITICAL" else "🟠" if p["impact"] == "HIGH" else "🟡"
            narrative_parts.append(
                f"{p['rank']}. {impact_icon} **[{p['category']}]** {p['action']}\n"
                f"   - Impact: {p['impact']} | Effort: {p['effort']}\n"
                f"   - _Rationale: {p['rationale']}_\n"
            )
        narrative_parts.append("\n")

    # Closing
    narrative_parts.append(
        f"---\n_Generated: {now.strftime('%Y-%m-%d %H:%M UTC')} | "
        f"Next brief: {(now + timedelta(days=7)).strftime('%B %d, %Y')}_\n"
    )

    brief = {
        "generated_at": now.isoformat(),
        "risk_level": risk_level,
        "risk_score": risk_score,
        "narrative": "".join(narrative_parts),
        "anomalies": anomalies,
        "remediation_priorities": priorities,
        "forecast": forecast,
        "stats": stats,
    }

    # Write to data dir
    write_path = os.path.join(DATA_DIR, "weekly_brief.json")
    with open(write_path, "w", encoding="utf-8") as f:
        json.dump(brief, f, indent=2, default=str)

    return brief


if __name__ == "__main__":
    brief = generate_weekly_brief()
    print(brief["narrative"])
