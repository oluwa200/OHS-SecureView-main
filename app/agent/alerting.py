"""
Alerting Module — Sends daily digest to Teams/Slack webhook.

Set environment variable:
  TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/...
  or
  SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

The digest is sent once per day (tracks last send date).
"""
import os
import json
import httpx
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
LAST_SENT_FILE = os.path.join(DATA_DIR, ".last_digest_sent")


def should_send_digest() -> bool:
    """Check if digest was already sent today."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if os.path.exists(LAST_SENT_FILE):
        with open(LAST_SENT_FILE, "r") as f:
            last_date = f.read().strip()
        if last_date == today:
            return False
    return True


def mark_sent():
    """Mark today's digest as sent."""
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    with open(LAST_SENT_FILE, "w") as f:
        f.write(today)


def send_daily_digest(insights: dict):
    """Send daily security digest to Teams or Slack."""
    if not should_send_digest():
        log.info("  Digest already sent today. Skipping.")
        return

    teams_url = os.getenv("TEAMS_WEBHOOK_URL", "").strip()
    slack_url = os.getenv("SLACK_WEBHOOK_URL", "").strip()

    if not teams_url and not slack_url:
        log.info("  No webhook URL configured. Set TEAMS_WEBHOOK_URL or SLACK_WEBHOOK_URL.")
        return

    # Build message
    stats = insights.get("stats", {})
    risk_score = insights.get("overall_risk_score", 0)
    summary = insights.get("summary", "No summary available.")
    actions = insights.get("priority_actions", [])
    blind = stats.get("completely_blind", 0)
    edr_pct = stats.get("edr_coverage_pct", 0)
    vuln_pct = stats.get("vuln_scan_coverage_pct", 0)

    risk_emoji = "🟢" if risk_score < 25 else "🟡" if risk_score < 50 else "🟠" if risk_score < 75 else "🔴"
    today_str = datetime.now(timezone.utc).strftime("%B %d, %Y")

    if teams_url:
        _send_teams(teams_url, risk_emoji, risk_score, today_str, summary, stats, actions)
    if slack_url:
        _send_slack(slack_url, risk_emoji, risk_score, today_str, summary, stats, actions)

    mark_sent()
    log.info("  Daily digest sent successfully.")


def _send_teams(webhook_url, risk_emoji, risk_score, date_str, summary, stats, actions):
    """Send to Microsoft Teams via Incoming Webhook."""
    actions_text = "\n".join([f"- **P{a['priority']}**: {a['action']}" for a in actions[:5]])

    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "ff4444" if risk_score >= 50 else "ff8800" if risk_score >= 25 else "44bb44",
        "summary": f"Security Posture Digest - {date_str}",
        "sections": [{
            "activityTitle": f"{risk_emoji} Security Posture Digest — {date_str}",
            "activitySubtitle": f"Risk Score: {risk_score}/100",
            "facts": [
                {"name": "EDR Coverage", "value": f"{stats.get('edr_coverage_pct', 0)}%"},
                {"name": "Vuln Scan Coverage", "value": f"{stats.get('vuln_scan_coverage_pct', 0)}%"},
                {"name": "Total EC2", "value": str(stats.get("total_ec2_ips", 0))},
                {"name": "Blind Spots", "value": str(stats.get("completely_blind", 0))},
                {"name": "No EDR", "value": str(stats.get("no_edr", 0))},
            ],
            "markdown": True,
            "text": f"**Summary:** {summary}\n\n**Priority Actions:**\n{actions_text}",
        }],
    }

    try:
        r = httpx.post(webhook_url, json=card, timeout=10)
        if r.status_code == 200:
            log.info("  Teams digest sent.")
        else:
            log.error(f"  Teams webhook failed: {r.status_code} {r.text[:100]}")
    except Exception as e:
        log.error(f"  Teams send error: {e}")


def _send_slack(webhook_url, risk_emoji, risk_score, date_str, summary, stats, actions):
    """Send to Slack via Incoming Webhook."""
    actions_text = "\n".join([f"• *P{a['priority']}*: {a['action']}" for a in actions[:5]])

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{risk_emoji} Security Digest — {date_str}"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Risk Score:* {risk_score}/100\n*EDR:* {stats.get('edr_coverage_pct', 0)}% | *Vuln Scan:* {stats.get('vuln_scan_coverage_pct', 0)}% | *Blind:* {stats.get('completely_blind', 0)}"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Summary:* {summary}"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Priority Actions:*\n{actions_text}"}
            },
        ]
    }

    try:
        r = httpx.post(webhook_url, json=payload, timeout=10)
        if r.status_code == 200:
            log.info("  Slack digest sent.")
        else:
            log.error(f"  Slack webhook failed: {r.status_code} {r.text[:100]}")
    except Exception as e:
        log.error(f"  Slack send error: {e}")


def send_threshold_alert(insights: dict, threshold: int):
    """Send immediate alert when risk score exceeds threshold."""
    teams_url = os.getenv("TEAMS_WEBHOOK_URL", "").strip()
    slack_url = os.getenv("SLACK_WEBHOOK_URL", "").strip()

    if not teams_url and not slack_url:
        return

    risk_score = insights.get("overall_risk_score", 0)
    blind = insights.get("stats", {}).get("completely_blind", 0)
    summary = insights.get("summary", "")

    message = (
        f"🚨 RISK THRESHOLD EXCEEDED\n"
        f"Score: {risk_score}/100 (threshold: {threshold})\n"
        f"Blind spots: {blind}\n"
        f"{summary}"
    )

    if teams_url:
        card = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "ff0000",
            "summary": "Risk Threshold Alert",
            "sections": [{"activityTitle": "🚨 Risk Threshold Exceeded", "text": message, "markdown": True}],
        }
        try:
            httpx.post(teams_url, json=card, timeout=10)
            log.info("  Threshold alert sent to Teams.")
        except Exception as e:
            log.error(f"  Threshold alert (Teams) failed: {e}")

    if slack_url:
        payload = {"text": message}
        try:
            httpx.post(slack_url, json=payload, timeout=10)
            log.info("  Threshold alert sent to Slack.")
        except Exception as e:
            log.error(f"  Threshold alert (Slack) failed: {e}")
