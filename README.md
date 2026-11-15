# OHS SecureView v2 — Security Posture & Compliance Dashboard

A fully autonomous security posture dashboard that consolidates data from 5 security platforms (CrowdStrike, Microsoft Defender, Qualys, BindPlane, AWS EC2) into a single real-time view. The agent pulls from all APIs every 15 minutes, normalizes the data, cross-correlates coverage gaps, and serves the results through a Streamlit dashboard behind an mTLS reverse proxy.

---

## Table of Contents

- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Local Development (Docker Compose)](#local-development-docker-compose)
- [Configuration](#configuration)
- [EKS Production Deployment](#eks-production-deployment)
  - [Network Requirements](#network-requirements)
  - [IAM & Secrets](#iam--secrets)
  - [Kubernetes Manifests](#kubernetes-manifests)
  - [Ingress & TLS](#ingress--tls)
  - [Persistent Storage](#persistent-storage)
  - [Health Checks & Scaling](#health-checks--scaling)
- [Internal Network Configuration](#internal-network-configuration)
- [Data Sources & API Connectivity](#data-sources--api-connectivity)
- [Agent Behavior](#agent-behavior)
- [Dashboard Features](#dashboard-features)
- [Operational Procedures](#operational-procedures)
- [Troubleshooting](#troubleshooting)

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           DATA SOURCES                                   │
│  CrowdStrike │ Microsoft Defender │ Qualys │ BindPlane │ AWS │ Aikido   │
└──────┬────────────────┬──────────────┬──────────┬──────────┬─────┬─────┘
       │                │              │          │          │     │
       ▼                ▼              ▼          ▼          ▼     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      UNIFIED AGENT (Pod)                                 │
│  • Fetches all 6 APIs every 15 min (AGENT_INTERVAL_SECONDS=900)         │
│  • Deduplicates, normalizes, cross-correlates                           │
│  • Writes JSON to shared volume (/app/data)                             │
│  • Watchdog auto-corrects data integrity issues                         │
│  • Email security logger tracks threat history                          │
│  • Aikido: SAST/SCA/DAST prioritized by environment + exploit           │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │ shared volume (EFS/PVC)
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      SMART-LOAD LAYER                                    │
│  • Recomputes all counts from raw data at render time                   │
│  • Never trusts pre-computed numbers                                    │
│  • Handles data format migrations (V1 → V2)                            │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      STREAMLIT DASHBOARD (Pod)                           │
│  • 9 sub-dashboards: Vuln, Endpoint, Defender, AWS, BindPlane,          │
│    AI Insights, GreyMatter, Executive, Aikido (AppSec)                  │
│  • Port 8501 (internal) → exposed via Ingress/ALB                       │
│  • Auto-refresh every 60s                                               │
└─────────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      NGINX / ALB INGRESS                                 │
│  • TLS termination (mTLS optional via client certs)                     │
│  • WebSocket support for Streamlit                                      │
│  • Health check: /_stcore/health                                        │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
security-dashboard-v2/
├── agent/                      # Autonomous data pipeline
│   ├── unified_agent.py        # Main agent loop (fetches all 5 sources)
│   ├── alerting.py             # Threshold alerts (Teams/Slack webhooks)
│   ├── data_watchdog.py        # Auto-corrects data integrity issues
│   ├── email_security_logger.py # Historical email threat logging
│   ├── snapshot.py             # Daily metric snapshots for trending
│   ├── weekly_brief.py         # Weekly report generation
│   └── security_agent.py       # Legacy (deprecated)
├── dashboards/                 # Streamlit sub-dashboards
│   ├── home.py                 # Home page with KPI tiles
│   ├── ai_insights/            # Cross-correlation & risk scoring
│   ├── aws_assets/             # EC2 inventory
│   ├── bindplane/              # Log collection coverage
│   ├── defender/               # Microsoft Defender (4 tabs)
│   ├── endpoint/               # CrowdStrike EDR
│   ├── executive/              # PDF-exportable executive summary
│   ├── greymatter/             # SOC integration
│   └── vulnerability/          # Qualys VMDR
├── config/                     # Dashboard configuration
│   └── dashboard_config.py     # DATA_DIR, load_json, KRI scoring
├── assets/                     # Logo images
├── nginx/                      # Reverse proxy config
│   ├── nginx.conf              # mTLS + WebSocket proxy
│   └── certs/                  # TLS certificates (not committed)
├── data/                       # Runtime data (not committed, volume-mounted)
├── app.py                      # Streamlit entry point
├── auth.py                     # Entra ID authentication (optional)
├── secrets_loader.py           # AWS Secrets Manager integration
├── Dockerfile                  # Container image (Python 3.11-slim)
├── docker-compose.yml          # Local dev: dashboard + nginx + agent
├── requirements.txt            # Python dependencies
├── .env.example                # Template for environment variables
├── .dockerignore               # Excludes secrets & data from image
└── .gitignore                  # Excludes secrets, data, caches from git
```

---

## Prerequisites

- **Docker** 20.10+ and Docker Compose v2
- **Python 3.11+** (for local development without Docker)
- **AWS CLI v2** with SSO configured (for EC2 data)
- **API credentials** for: CrowdStrike, Microsoft Defender, Qualys, BindPlane

---

## Local Development (Docker Compose)

```bash
# 1. Clone and configure
cp .env.example .env
# Edit .env with your actual credentials

# 2. Build and run
docker compose up -d --build

# 3. Access
# Dashboard: http://localhost:8502
# mTLS:     https://localhost:8443 (requires client cert)
```

The agent starts pulling data immediately. First cycle takes ~5 minutes, after which the dashboard will populate.

### Live Development

Code changes are reflected without rebuild (volume mounts):
- Edit any `.py` file → Streamlit detects in ~2s → page reloads
- Only `Dockerfile` / `requirements.txt` changes need `docker compose build`

---

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `CS_CLIENT_ID` | Yes | CrowdStrike API client ID |
| `CS_CLIENT_SECRET` | Yes | CrowdStrike API client secret |
| `CS_BASE_URL` | Yes | CrowdStrike API base URL (e.g., `https://api.us-2.crowdstrike.com`) |
| `DEFENDER_TENANT_ID` | Yes | Azure AD tenant ID |
| `DEFENDER_CLIENT_ID` | Yes | Azure AD app registration client ID |
| `DEFENDER_CLIENT_SECRET` | Yes | Azure AD app registration client secret |
| `QUALYS_USERNAME` | Yes | Qualys API username |
| `QUALYS_PASSWORD` | Yes | Qualys API password |
| `QUALYS_BASE_URL` | Yes | Qualys API URL (e.g., `https://qualysapi.qg3.apps.qualys.com`) |
| `BINDPLANE_URL` | Yes | BindPlane server URL |
| `BINDPLANE_API_KEY` | Yes | BindPlane API key |
| `AGENT_INTERVAL_SECONDS` | No | Fetch interval (default: 900 = 15 min) |
| `SSL_VERIFY` | No | Validate TLS certs (default: `true`, set `false` for corp proxy) |
| `SECRET_NAME` | No | AWS Secrets Manager secret name (default: `security-dashboard/credentials`) |
| `SECRET_REGION` | No | AWS region for Secrets Manager (default: `us-east-1`) |
| `TEAMS_WEBHOOK_URL` | No | Microsoft Teams webhook for alerts |
| `SLACK_WEBHOOK_URL` | No | Slack webhook for alerts |
| `AUTH_ENABLED` | No | Enable Entra ID authentication (default: `false`) |
| `RISK_ALERT_THRESHOLD` | No | Risk score threshold for immediate alerts (default: `50`) |

### Secrets Management

The app uses a tiered secrets strategy:
1. **AWS Secrets Manager** (preferred in production) — `secrets_loader.py` fetches from secret named `security-dashboard/credentials`
2. **Environment variables** — Set via Kubernetes Secrets or `.env` file
3. **`.env` file** — Fallback for local development

In EKS, use **AWS Secrets Manager** with an IRSA (IAM Role for Service Account) — no static credentials needed.

---

## EKS Production Deployment

### Network Requirements

The agent makes **outbound HTTPS (443)** calls to 5 external APIs. Your EKS cluster's security groups and NACLs must allow egress to:

| Destination | Protocol | Port | Purpose |
|-------------|----------|------|---------|
| `api.us-2.crowdstrike.com` | HTTPS | 443 | CrowdStrike Falcon API |
| `login.microsoftonline.com` | HTTPS | 443 | Azure AD token endpoint |
| `api.securitycenter.microsoft.com` | HTTPS | 443 | Microsoft Defender for Endpoint |
| `graph.microsoft.com` | HTTPS | 443 | Microsoft Graph (Intune, Secure Score) |
| `qualysapi.qg3.apps.qualys.com` | HTTPS | 443 | Qualys VMDR API |
| Your BindPlane server IP/DNS | HTTPS | 3001 | BindPlane OpAMP API |
| `sts.amazonaws.com` | HTTPS | 443 | AWS STS (for Secrets Manager) |
| `secretsmanager.us-east-1.amazonaws.com` | HTTPS | 443 | AWS Secrets Manager |
| `ec2.us-east-1.amazonaws.com` | HTTPS | 443 | AWS EC2 API (DescribeInstances) |

#### If Behind a Corporate Proxy

Set these environment variables on the agent pod:

```yaml
env:
  - name: HTTPS_PROXY
    value: "http://proxy.internal.corp:8080"
  - name: HTTP_PROXY
    value: "http://proxy.internal.corp:8080"
  - name: NO_PROXY
    value: "169.254.169.254,10.0.0.0/8,172.16.0.0/12,.internal.corp,.eks.amazonaws.com"
  - name: SSL_VERIFY
    value: "false"  # Or mount your corporate CA bundle
```

If your org uses a corporate CA for TLS inspection, mount the CA bundle:

```yaml
volumeMounts:
  - name: corporate-ca
    mountPath: /usr/local/share/ca-certificates/corporate-ca.crt
    subPath: corporate-ca.crt
volumes:
  - name: corporate-ca
    configMap:
      name: corporate-ca-bundle
```

Then set `REQUESTS_CA_BUNDLE=/usr/local/share/ca-certificates/corporate-ca.crt` or keep `SSL_VERIFY=false` if the proxy handles verification.

---

### IAM & Secrets

#### IAM Role for Service Account (IRSA)

Create an IAM role with these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:ACCOUNT_ID:secret:security-dashboard/credentials-*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeRegions"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:RequestedRegion": "us-east-1"
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": [
        "arn:aws:iam::446329232350:role/SecurityDashboardReadOnly",
        "arn:aws:iam::937786629491:role/SecurityDashboardReadOnly",
        "arn:aws:iam::895945783203:role/SecurityDashboardReadOnly",
        "arn:aws:iam::754120856488:role/SecurityDashboardReadOnly"
      ]
    }
  ]
}
```

Annotate the Kubernetes ServiceAccount:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: secureview-agent
  namespace: security
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/SecureViewAgentRole
```

#### AWS Secrets Manager Secret

Store all API credentials in one secret:

```bash
aws secretsmanager create-secret \
  --name security-dashboard/credentials \
  --secret-string '{
    "CS_CLIENT_ID": "...",
    "CS_CLIENT_SECRET": "...",
    "CS_BASE_URL": "https://api.us-2.crowdstrike.com",
    "DEFENDER_TENANT_ID": "...",
    "DEFENDER_CLIENT_ID": "...",
    "DEFENDER_CLIENT_SECRET": "...",
    "QUALYS_USERNAME": "...",
    "QUALYS_PASSWORD": "...",
    "QUALYS_BASE_URL": "https://qualysapi.qg3.apps.qualys.com",
    "BINDPLANE_URL": "https://...",
    "BINDPLANE_API_KEY": "..."
  }'
```

No static credentials in pods — the agent's `secrets_loader.py` will automatically fetch from Secrets Manager using the IRSA role.

---

### Kubernetes Manifests

#### Namespace

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: security
  labels:
    app: secureview
```

#### Shared PersistentVolumeClaim (for data/)

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: secureview-data
  namespace: security
spec:
  accessModes:
    - ReadWriteMany  # Required: both agent and dashboard read/write
  storageClassName: efs-sc  # Use EFS StorageClass for RWX
  resources:
    requests:
      storage: 5Gi
```

> **Important:** Use Amazon EFS (via EFS CSI Driver) for the shared volume. EBS does not support `ReadWriteMany` access mode needed by both pods.

#### Agent Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secureview-agent
  namespace: security
spec:
  replicas: 1  # Only 1 replica — agent is a singleton
  strategy:
    type: Recreate  # Prevent duplicate cycles
  selector:
    matchLabels:
      app: secureview-agent
  template:
    metadata:
      labels:
        app: secureview-agent
    spec:
      serviceAccountName: secureview-agent
      containers:
        - name: agent
          image: YOUR_ECR_REPO/secureview:latest
          command: ["python", "-u", "agent/unified_agent.py"]
          env:
            - name: AGENT_INTERVAL_SECONDS
              value: "900"
            - name: SSL_VERIFY
              value: "false"  # Set "true" if not behind TLS-inspecting proxy
            - name: SECRET_NAME
              value: "security-dashboard/credentials"
            - name: SECRET_REGION
              value: "us-east-1"
            - name: TZ
              value: "America/New_York"
          volumeMounts:
            - name: data
              mountPath: /app/data
          resources:
            requests:
              cpu: 500m
              memory: 512Mi
            limits:
              cpu: "2"
              memory: 1Gi
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: secureview-data
```

#### Dashboard Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secureview-dashboard
  namespace: security
spec:
  replicas: 2  # Can scale horizontally (read-only)
  selector:
    matchLabels:
      app: secureview-dashboard
  template:
    metadata:
      labels:
        app: secureview-dashboard
    spec:
      containers:
        - name: dashboard
          image: YOUR_ECR_REPO/secureview:latest
          ports:
            - containerPort: 8501
          env:
            - name: STREAMLIT_SERVER_RUN_ON_SAVE
              value: "false"
            - name: STREAMLIT_SERVER_FILE_WATCHER_TYPE
              value: "none"
            - name: STREAMLIT_BROWSER_GATHER_USAGE_STATS
              value: "false"
            - name: TZ
              value: "America/New_York"
          volumeMounts:
            - name: data
              mountPath: /app/data
              readOnly: true
          readinessProbe:
            httpGet:
              path: /_stcore/health
              port: 8501
            initialDelaySeconds: 10
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /_stcore/health
              port: 8501
            initialDelaySeconds: 30
            periodSeconds: 30
          resources:
            requests:
              cpu: "1"
              memory: 1Gi
            limits:
              cpu: "4"
              memory: 2Gi
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: secureview-data
---
apiVersion: v1
kind: Service
metadata:
  name: secureview-dashboard
  namespace: security
spec:
  selector:
    app: secureview-dashboard
  ports:
    - port: 80
      targetPort: 8501
  type: ClusterIP
```

---

### Ingress & TLS

#### Option A: AWS ALB Ingress (recommended)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secureview-ingress
  namespace: security
  annotations:
    kubernetes.io/ingress.class: alb
    alb.ingress.kubernetes.io/scheme: internal  # Internal-only access
    alb.ingress.kubernetes.io/target-type: ip
    alb.ingress.kubernetes.io/listen-ports: '[{"HTTPS": 443}]'
    alb.ingress.kubernetes.io/certificate-arn: arn:aws:acm:us-east-1:ACCOUNT:cert/CERT_ID
    alb.ingress.kubernetes.io/healthcheck-path: /_stcore/health
    alb.ingress.kubernetes.io/security-groups: sg-XXXXXXXXX
    alb.ingress.kubernetes.io/subnets: subnet-aaa,subnet-bbb
    # WebSocket support (required for Streamlit)
    alb.ingress.kubernetes.io/target-group-attributes: stickiness.enabled=true,stickiness.lb_cookie.duration_seconds=86400
spec:
  rules:
    - host: secureview.internal.yourcompany.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: secureview-dashboard
                port:
                  number: 80
```

#### Option B: nginx Ingress (if ALB not available)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secureview-ingress
  namespace: security
  annotations:
    nginx.ingress.kubernetes.io/proxy-read-timeout: "86400"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "86400"
    nginx.ingress.kubernetes.io/websocket-services: secureview-dashboard
    nginx.ingress.kubernetes.io/upstream-hash-by: "$remote_addr"
spec:
  tls:
    - hosts:
        - secureview.internal.yourcompany.com
      secretName: secureview-tls
  rules:
    - host: secureview.internal.yourcompany.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: secureview-dashboard
                port:
                  number: 80
```

> **Critical:** Streamlit uses WebSockets. Any ingress/proxy must support WebSocket upgrade (`Connection: Upgrade`) and long timeouts (86400s).

---

### Persistent Storage

#### EFS Setup (required for ReadWriteMany)

1. Create an EFS filesystem in your VPC
2. Install the EFS CSI Driver:
   ```bash
   helm repo add aws-efs-csi-driver https://kubernetes-sigs.github.io/aws-efs-csi-driver/
   helm install aws-efs-csi-driver aws-efs-csi-driver/aws-efs-csi-driver -n kube-system
   ```
3. Create the StorageClass:
   ```yaml
   apiVersion: storage.k8s.io/v1
   kind: StorageClass
   metadata:
     name: efs-sc
   provisioner: efs.csi.aws.com
   parameters:
     provisioningMode: efs-ap
     fileSystemId: fs-XXXXXXXXX
     directoryPerms: "700"
   ```

#### What's Stored in data/ (PVC)

| File | Size | Updated By | Read By |
|------|------|------------|---------|
| `defender_report.json` | ~2 MB | Agent | Dashboard |
| `vulnerability_report.json` | ~1 MB | Agent | Dashboard |
| `crowdstrike_hosts.json` | ~500 KB | Agent | Dashboard |
| `crowdstrike_iom_analysis.json` | ~200 KB | Agent | Dashboard |
| `aws_ec2_instances.json` | ~100 KB | Agent | Dashboard |
| `aws_ec2_counts.json` | ~2 KB | Agent | Dashboard |
| `ai_insights.json` | ~50 KB | Agent | Dashboard |
| `bindplane_agents.json` | ~100 KB | Agent | Dashboard |
| `history.json` | ~50 KB | Agent | Dashboard |
| `email_security_log.jsonl` | Grows ~1 KB/day | Agent | Dashboard |
| `email_security_daily.json` | ~20 KB | Agent | Dashboard |
| `weekly_brief.json` | ~10 KB | Agent | Dashboard |
| `watchdog_audit.json` | ~5 KB | Agent | Dashboard |

Total steady-state: ~5 MB. The 5Gi PVC provides years of headroom.

---

### Health Checks & Scaling

| Component | Scaling | Notes |
|-----------|---------|-------|
| **Agent** | 1 replica (singleton) | Uses `Recreate` strategy to avoid duplicate API calls |
| **Dashboard** | 2+ replicas | Stateless reader, can scale with HPA |

HPA for dashboard (optional):

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: secureview-dashboard-hpa
  namespace: security
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: secureview-dashboard
  minReplicas: 2
  maxReplicas: 5
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

---

## Internal Network Configuration

### DNS Resolution

Register an internal DNS record for the ALB:
```
secureview.internal.yourcompany.com → ALB DNS name
```

If using Route 53 Private Hosted Zone:
```bash
aws route53 change-resource-record-sets \
  --hosted-zone-id ZONE_ID \
  --change-batch '{
    "Changes": [{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "secureview.internal.yourcompany.com",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [{"Value": "ALB_DNS_NAME"}]
      }
    }]
  }'
```

### Security Group Rules

**ALB Security Group (inbound):**

| Source | Port | Protocol | Description |
|--------|------|----------|-------------|
| `10.0.0.0/8` (or your corp CIDR) | 443 | TCP | Dashboard access from internal network |
| VPC CIDR | 80 | TCP | Health checks (redirect to HTTPS) |

**EKS Node Security Group (outbound — for agent pod):**

| Destination | Port | Protocol | Description |
|-------------|------|----------|-------------|
| `0.0.0.0/0` | 443 | TCP | API calls to external security platforms |
| Or specific IPs if firewall restricted | 443 | TCP | Allowlist per source (see Network Requirements) |

### Firewall Allowlist (if egress restricted)

If your network has egress filtering, add these to the firewall allowlist:

```
# CrowdStrike
api.us-2.crowdstrike.com:443

# Microsoft (Azure AD + APIs)
login.microsoftonline.com:443
api.securitycenter.microsoft.com:443
graph.microsoft.com:443

# Qualys
qualysapi.qg3.apps.qualys.com:443

# BindPlane (your internal server)
<your-bindplane-host>:3001

# AWS (for Secrets Manager + EC2 API)
sts.us-east-1.amazonaws.com:443
secretsmanager.us-east-1.amazonaws.com:443
ec2.us-east-1.amazonaws.com:443
```

---

## Data Sources & API Connectivity

| Source | Auth Method | EKS Auth Strategy | Required Permissions |
|--------|-------------|-------------------|---------------------|
| **CrowdStrike** | OAuth2 client credentials | Stored in Secrets Manager | Hosts Read, CSPM Read |
| **Defender/Graph** | Azure AD app registration | Stored in Secrets Manager | Machine.Read.All, SecurityAlert.Read.All, SecurityEvents.Read.All, DeviceManagementManagedDevices.Read.All |
| **Qualys** | Basic auth | Stored in Secrets Manager | VM Detection API access |
| **BindPlane** | API key | Stored in Secrets Manager | Agent list read |
| **Aikido** | OAuth2 client credentials | Stored in Secrets Manager | issues:read, repositories:read, clouds:read |
| **AWS EC2** | IRSA (IAM Role) | Service Account annotation | ec2:DescribeInstances + cross-account AssumeRole |

### Cross-Account EC2 Access (in EKS)

Instead of AWS SSO profiles, use cross-account IAM role assumption:

1. In each target account (446329232350, 937786629491, 895945783203, 754120856488), create a role:
   ```json
   {
     "Effect": "Allow",
     "Principal": {
       "AWS": "arn:aws:iam::YOUR_EKS_ACCOUNT:role/SecureViewAgentRole"
     },
     "Action": "sts:AssumeRole"
   }
   ```

2. The agent's `fetch_aws_ec2()` uses boto3 profiles locally. In EKS, modify to use `sts:AssumeRole` (or configure the profiles via a ConfigMap-mounted `~/.aws/config`):

   ```ini
   # ConfigMap: aws-config
   [profile infra]
   role_arn = arn:aws:iam::446329232350:role/SecurityDashboardReadOnly
   source_profile = default

   [profile prod]
   role_arn = arn:aws:iam::937786629491:role/SecurityDashboardReadOnly
   source_profile = default

   [profile network]
   role_arn = arn:aws:iam::895945783203:role/SecurityDashboardReadOnly
   source_profile = default

   [profile test-qa]
   role_arn = arn:aws:iam::754120856488:role/SecurityDashboardReadOnly
   source_profile = default

   [default]
   region = us-east-1
   ```

   Mount as:
   ```yaml
   volumeMounts:
     - name: aws-config
       mountPath: /root/.aws/config
       subPath: config
   volumes:
     - name: aws-config
       configMap:
         name: secureview-aws-config
   ```

---

## Agent Behavior

The unified agent (`agent/unified_agent.py`) runs a continuous loop:

1. **Fetch** — Pulls from all 5 APIs concurrently (CrowdStrike, Defender, Qualys, BindPlane, AWS EC2)
2. **Process** — Normalizes data, deduplicates, computes summaries
3. **Log Email Security** — Appends threat metrics to historical log (JSONL + daily rollup)
4. **Cross-Correlate** — Matches EC2 IPs against CrowdStrike/Qualys/BindPlane to find blind spots
5. **Snapshot** — Saves daily metrics for trending (90-day retention)
6. **Alert** — Fires webhooks if risk score exceeds threshold
7. **Weekly Brief** — Generates weekly summary with anomaly detection
8. **Watchdog** — Auto-corrects data integrity issues (stale counts, format drift)
9. **Sleep** — Waits `AGENT_INTERVAL_SECONDS` (default 900s = 15 min)

Cycle time: ~300-330 seconds (5-5.5 min) per cycle.

---

## Dashboard Features

| Dashboard | Key Metrics |
|-----------|-------------|
| **Home** | 6 KPI tiles with coverage rings, sparklines, global search |
| **Vulnerability** | Qualys SLA tracking, KRI prioritization, severity breakdown |
| **Endpoint** | CrowdStrike EDR coverage by account, IOM scoring (P1-P4) |
| **Defender** | Active devices, Secure Score, Intune compliance, email threat history |
| **AWS Assets** | EC2 inventory by account, running/stopped state |
| **BindPlane** | Coverage gap analysis (464 Windows laptops without telemetry) |
| **AI Insights** | Risk score 0-100, blind spots, no-EDR/no-vuln-scan correlation |
| **Executive** | PDF-exportable summary for leadership |

---

## Operational Procedures

### Container Image Build (CI/CD)

```bash
# Build
docker build -t secureview:v2 .

# Tag for ECR
docker tag secureview:v2 YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/secureview:v2
docker tag secureview:v2 YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/secureview:latest

# Push
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com
docker push YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/secureview:v2
docker push YOUR_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/secureview:latest
```

### Rolling Update

```bash
kubectl rollout restart deployment/secureview-dashboard -n security
kubectl rollout restart deployment/secureview-agent -n security
```

### Viewing Agent Logs

```bash
kubectl logs -f deployment/secureview-agent -n security
```

### Manual Cycle Trigger (for testing)

```bash
kubectl exec deployment/secureview-agent -n security -- python -c "
import asyncio
from agent.unified_agent import run_cycle
asyncio.run(run_cycle())
"
```

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| All tiles show 0 | Agent hasn't completed first cycle | Wait 5 min, check agent logs |
| EC2 coverage shows 0 | AWS credentials not working | Verify IRSA role + cross-account trust |
| Defender 400 errors | Token expired or wrong permissions | Check Azure AD app registration |
| Qualys 400 on some pages | Pagination edge case (benign) | Agent retries — no action needed |
| Dashboard 502 | Pod not ready | Check readiness probe, Streamlit health |
| Stale data warning | API fetch failing | Check egress network, proxy config |
| WebSocket disconnects | Ingress timeout too low | Set proxy-read-timeout to 86400 |
| "No module named agent" | PYTHONPATH issue | Verify Dockerfile COPY paths |

---

## Security Considerations

- **No secrets in code** — All credentials in AWS Secrets Manager or Kubernetes Secrets
- **Read-only access** — All API credentials are read-only (no write/delete permissions)
- **Internal ALB** — Dashboard only accessible from corporate network
- **mTLS optional** — Can require client certificates via nginx sidecar
- **Audit trail** — Agent logs every API call, watchdog logs corrections, email logger tracks all threat data
- **No PII** — Dashboard shows device hostnames/IPs but no user personal data

---

## Changelog

### v2.1 — Feature1 (June 27, 2026)

**Data Accuracy & Anti-Inflation**
- Cross-correlation only counts EC2 instances with IPs (eliminates ghost/terminated entries)
- CrowdStrike stale host detection: flags orphaned entries that don't match any current AWS instance
- EKS Coverage reconciliation: compares only EKS-type CS hosts vs actual AWS EKS nodes (not all Linux hosts)
- Assets Coverage: shows exact unmanaged server list (IP, name, account, state) for actionable remediation
- Data Reconciliation Summary on both EC2 and EKS tabs with correct math

**Agent Resilience**
- SSO token expiry no longer crashes the entire cycle — EC2 fetch fails gracefully, other 4 sources continue
- EKS nodes auto-fetched every 15 min (eliminates 9-day stale `aws_eks_nodes.json` problem)
- `TokenRetrievalError` and `BotoCoreError` caught per-account (no more full-cycle crashes)
- Email security historical logger: per-cycle JSONL log + daily rollup for reporting

**Environment Isolation (Critical for EKS Deployment)**
- Prod container: code baked into image, NO code volume mounts — file edits cannot affect production
- Dev container: separate stack on port 8503 with isolated `data-dev/` directory
- Both require explicit `docker compose up -d --build` to update code
- Streamlit file watcher disabled in prod (`fileWatcherType=none`)
- Dashboard only accessible via nginx mTLS (port 8443), no direct Streamlit port exposed

**Infrastructure**
- Container naming: `secureview-prod-*` and `secureview-dev-*` for clarity
- `docker-compose.dev.yml` for isolated development/testing
- `fix_wslrelay.ps1` + scheduled task: auto-kills stuck WSL port relays (Windows dev only)
- MFA report fetcher ready (`agent/fetch_mfa_report.py`) — pending `AuditLog.Read.All` permission

**EKS Deployment Readiness**
- No SSO dependency: agent handles token failures gracefully, IRSA replaces SSO in EKS
- No volume mount dependency for code: image is self-contained
- Cross-account EC2 access via IAM role assumption (ConfigMap-mounted `~/.aws/config`)
- EFS PVC for shared data between agent and dashboard pods
- Health checks, readiness probes, and HPA configs documented

---

## License

Internal use only — OHS Security Engineering Team.
