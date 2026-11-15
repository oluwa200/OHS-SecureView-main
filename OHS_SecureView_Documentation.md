# OHS SecureView — Security Posture & Compliance Dashboard

## Executive Summary

OHS SecureView is a fully autonomous security posture dashboard that consolidates data from 5 security platforms into a single, real-time view. It eliminates manual data gathering, auto-corrects data accuracy issues, and surfaces coverage gaps that would otherwise go undetected.

**Key Outcomes:**
- Reduced manual security reporting from 4+ hours/week to zero
- Identified 464 Windows laptops without log telemetry (previously hidden by inflated counts)
- Consolidated 5 security tools into one unified view with cross-correlation
- Automated data refresh every 15 minutes with self-healing capabilities

---

## Problem Statement

Before SecureView, the security team faced:
- **Inflated device counts** — Defender showed 3,982 devices when only 1,406 were Active
- **Duplicate agent entries** — BindPlane reported 828 laptops when the real number was 281 connected
- **No cross-correlation** — gaps between CrowdStrike, Qualys, BindPlane, and AWS were invisible
- **Manual data pulls** — engineers had to log into 5 consoles to build a security picture
- **Silent failures** — when API calls failed, the dashboard showed stale data with no warning

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         DATA SOURCES                                  │
│  CrowdStrike │ Microsoft Defender │ Qualys │ BindPlane │ AWS EC2     │
└──────┬───────────────┬──────────────┬──────────┬──────────┬─────────┘
       │               │              │          │          │
       ▼               ▼              ▼          ▼          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    UNIFIED AGENT (Docker)                             │
│  • Fetches from all APIs every 15 minutes                            │
│  • Deduplicates BindPlane agents by hostname                         │
│  • Processes Defender into structured report                         │
│  • Cross-correlates EC2 IPs vs CrowdStrike/Qualys/BindPlane         │
│  • Watchdog auto-corrects data integrity issues                      │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ writes JSON files
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    SMART-LOAD LAYER                                   │
│  • load_defender_active_devices() — Active only, handles V1/V2       │
│  • load_bindplane_deduped() — Dedup by hostname, connected priority  │
│  • load_crowdstrike_hosts() — Active sensors only                    │
│  • load_qualys_summary() — Recomputes from raw vulnerability data    │
│  • Never trusts pre-computed counts — always recomputes              │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    STREAMLIT DASHBOARD (Port 8502)                    │
│  • 8 sub-dashboards: Vulnerability, Endpoint, Defender, AWS,         │
│    BindPlane, AI Insights, GreyMatter SOC, Executive                 │
│  • Auto-refresh every 60 seconds                                     │
│  • Stale data warnings surface fetch failures automatically          │
│  • Live code mounting — changes reflect without rebuild              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Data Sources & Integration

| Source | What It Provides | Refresh Rate | Auth Method |
|--------|-----------------|--------------|-------------|
| **CrowdStrike Falcon** | EDR hosts, CSPM IOMs, sensor status | 15 min | OAuth2 client credentials |
| **Microsoft Defender XDR** | Managed devices, alerts, secure score, vulnerabilities | 15 min | Azure AD app registration |
| **Qualys VMDR** | Vulnerability detections, asset inventory, SLA tracking | 15 min | Basic auth (API credentials) |
| **BindPlane OpAMP** | Log collection agents, telemetry coverage | 15 min | API key |
| **AWS EC2** (4 accounts) | Instance inventory, running/stopped state | 15 min | SSO (ReadOnlyAccess) |

---

## Key Features

### 1. Autonomous Data Pipeline
- Agent container runs 24/7 with 15-minute refresh cycle
- No human intervention required for data accuracy
- Self-healing: watchdog auto-corrects corrupted/stale files

### 2. Smart Data Normalization
Every number displayed is recomputed from raw data at render time:
- **Defender**: Filters to `health == "Active"` only (eliminates 1,967 inactive devices)
- **BindPlane**: Deduplicates by hostname, shows connected-only for coverage metrics
- **CrowdStrike**: Filters to active sensor status
- **Qualys**: Recomputes asset/vuln totals from detection lists (ignores pre-baked counts)

### 3. Cross-Dashboard Correlation
The AI Insights engine correlates all sources by IP address:
- EC2 instances without CrowdStrike = **No EDR** (HIGH risk)
- EC2 instances without Qualys = **No vuln scan** (MEDIUM risk)
- EC2 instances without BindPlane = **No telemetry** (MEDIUM risk)
- EC2 instances with none = **Completely blind** (CRITICAL risk)

### 4. BindPlane Coverage Gap Analysis
Uses Defender/Intune as source of truth for device fleet:
- 592 Active Windows laptops identified
- 128 with connected BindPlane agents (21.6% coverage)
- 464 Windows laptops without log collection — actionable deployment list
- Breakdown by category: Windows Laptops, Servers, macOS, Mobile, Linux

### 5. Stale Data Warnings
If any API fails, the home page shows a visible yellow banner:
> ⚠️ Stale data detected — CrowdStrike (180min old), AWS EC2 (missing)

No silent degradation — users always know when data is outdated.

### 6. Zero-Rebuild Deployments
Source code is volume-mounted into the container:
- Edit any `.py` file → Streamlit detects change in 2 seconds → page reloads
- No `docker compose build` needed for code changes
- Only infrastructure changes (Dockerfile, requirements.txt) need a rebuild

---

## Infrastructure

### Docker Containers

| Container | Purpose | Port |
|-----------|---------|------|
| `dashboard-v2` | Streamlit web app | 8502 (direct) |
| `nginx` | mTLS reverse proxy | 8443 (HTTPS) |
| `agent` | Unified data refresher | internal |

### Resilience Features
- **`restart: unless-stopped`** — containers auto-recover from crashes
- **Health checks** — nginx only starts after dashboard is confirmed healthy
- **Dynamic DNS** — nginx re-resolves container IPs every 5 seconds (no stale routing)
- **SSO auto-refresh** — Windows scheduled task prompts every 8 hours (Chrome Incognito)

### Security
- mTLS on port 8443 (client certificate required)
- AWS SSO with explicit human approval (Incognito mode)
- ReadOnlyAccess across all AWS accounts
- No secrets stored in code — `.env` file + AWS Secrets Manager fallback
- SSL verification configurable per environment

---

## Dashboards

### Home Page
6 tiles with real-time KPIs: Qualys, CrowdStrike, Defender, AWS, BindPlane, AI Insights
- Coverage rings show percentage at a glance
- Sparkline trends from 14-day history
- Role-based visibility (Engineer, CISO, Compliance)
- Global asset search (IP or hostname) with cross-tool detail

### Vulnerability (Qualys)
4 tabs: Executive Overview, Monthly SLA Tracking, KRI Prioritization, Asset Inventory
- SLA breach tracking with Internet-Facing vs Internal thresholds
- Severity breakdown: Critical/High/Medium
- Decommissioned server filtering (8 IPs excluded automatically)

### Endpoint (CrowdStrike)
4 tabs: Coverage, CSPM IOMs, Unmanaged Assets
- EDR coverage by AWS account
- IOM impact scoring with P1/P2/P3/P4 prioritization
- Service-level breakdown (EC2, IAM, S3, etc.)

### Defender (Microsoft)
4 tabs: Overview, Assets Coverage, Posture & Recommendations, Email Security
- Active-only device counts
- Secure Score breakdown by control category
- Onboarding gap analysis (CanBeOnboarded devices)

### BindPlane
5 tabs: Overview, Laptops, EC2, WorkSpaces, Coverage Gaps
- Real coverage gap by device category
- 464 Windows laptops identified for BindPlane deployment
- WorkSpace correlation with AWS inventory
- Stale agent detection

### AI Insights
Risk score (0-100) with trending, priority actions, blind spot identification

### Executive
PDF-exportable summary for leadership reporting

---

## Operational Procedures

### Daily (Automated)
- Agent pulls all data every 15 minutes
- Watchdog auto-corrects data integrity issues
- Snapshot saves daily metrics for trending
- Threshold alerts fire if risk score exceeds limit

### Every 8 Hours (Semi-Automated)
- Chrome Incognito opens with AWS SSO page
- Sign in as `a-oluwacheid@homeownersvcs.onmicrosoft.com`
- Click "Allow" — token cached for next 12 hours

### On Code Change (Automated)
- Edit file on host → Streamlit detects via poll watcher → page reloads
- No rebuild, no restart, no human action

### On Container Crash (Automated)
- Docker restarts container automatically
- Nginx waits for health check before routing traffic
- No 502 errors during recovery

---

## Metrics & Impact

| Metric | Before | After |
|--------|--------|-------|
| Defender device count accuracy | 3,982 (inflated) | 1,406 (Active only) |
| BindPlane laptop count | 828 (duplicated) | 281 connected / 575 unique |
| Time to identify coverage gaps | Hours (manual) | Instant (automated) |
| Data refresh frequency | Manual (weekly) | Every 15 minutes |
| Human intervention for data | Daily | SSO approval every 8h |
| Dashboard rebuild time | 35+ seconds | 0 (live volume mounts) |
| 502 errors after restart | Frequent | Eliminated (health checks) |
| Silent data staleness | Undetected | Visible warning banner |

---

## Technology Stack

- **Frontend**: Streamlit 1.58, Plotly, Pandas
- **Backend**: Python 3.11, asyncio, httpx
- **Infrastructure**: Docker Compose, nginx (mTLS), volume mounts
- **Data Sources**: CrowdStrike API, Microsoft Graph/MDE API, Qualys API, BindPlane OpAMP, AWS SDK (boto3)
- **Authentication**: AWS SSO (PKCE flow), Azure AD client credentials, API keys
- **Monitoring**: Data integrity watchdog, stale data alerts, audit logging

---

## Future Roadmap

1. **EC2 Deployment** — Move from localhost to AWS EC2 with IAM instance role (eliminates SSO requirement entirely)
2. **Entra ID Authentication** — Add user login to the dashboard itself
3. **Teams/Slack Alerting** — Push notifications on critical findings
4. **Performance** — Lazy-load charts with `@st.fragment`, pre-compute trend caches
5. **Historical Reporting** — PDF exports with month-over-month comparisons

---

*Document generated: June 26, 2026*
*System: OHS SecureView v2.0*
*Author: Security Engineering Team*
