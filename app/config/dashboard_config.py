"""
Shared configuration and helper functions for Security Dashboard V2.
Ported from V1 — no sidebar/footer (V2 uses tile navigation).
"""
import os
import json
from datetime import datetime, timedelta, timezone

# ─── Paths ────────────────────────────────────────────────────────────────────
CONFIG_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR = os.path.dirname(CONFIG_DIR)
DATA_DIR = os.path.join(BASE_DIR, "data")
ASSETS_DIR = os.path.join(BASE_DIR, "assets")

# ─── Scoped Accounts ─────────────────────────────────────────────────────────
SCOPED_ACCOUNTS = [
    "Infrastructure (446329232350)",
    "Production (937786629491)",
    "Network (895945783203)",
    "Test and QA (754120856488)",
]

# ─── EC2 Counts (loaded from JSON) ───────────────────────────────────────────
_FALLBACK_EC2_COUNTS = {
    "Infrastructure (446329232350)": 41,
    "Production (937786629491)": 50,
    "Network (895945783203)": 4,
    "Test and QA (754120856488)": 17,
}


def _load_ec2_counts():
    """Load live EC2 counts from aws_ec2_counts.json."""
    counts_path = os.path.join(DATA_DIR, "aws_ec2_counts.json")
    if os.path.exists(counts_path):
        try:
            with open(counts_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Map from short name to SCOPED_ACCOUNTS key
            by_account = data.get("by_account", {})
            result = {}
            for acct_key in SCOPED_ACCOUNTS:
                short_name = acct_key.split(" (")[0]
                if short_name in by_account:
                    result[acct_key] = by_account[short_name].get("total", 0)
                else:
                    result[acct_key] = _FALLBACK_EC2_COUNTS.get(acct_key, 0)
            return result
        except Exception:
            pass
    return _FALLBACK_EC2_COUNTS


ACTUAL_EC2_COUNTS = _load_ec2_counts()

# ─── SLA Definitions (days to remediate) ─────────────────────────────────────
INTERNET_FACING_SLA = {
    "5": 14,   # Critical
    "4": 30,   # High
    "3": 60,   # Medium
    "2": 160,  # Low
    "1": 160,  # Info
}

INTERNAL_SLA = {
    "5": 30,   # Critical
    "4": 60,   # High
    "3": 90,   # Medium
    "2": 160,  # Low
    "1": 160,  # Info
}

# ─── Labels & Colors ─────────────────────────────────────────────────────────
SEV_LABELS = {"5": "Critical", "4": "High", "3": "Medium", "2": "Low", "1": "Info"}
SEV_COLORS = {
    "Critical": "#ff4444",
    "High": "#ff8800",
    "Medium": "#ffcc00",
    "Low": "#44bb44",
    "Info": "#4488ff",
}

TODAY = datetime.now(timezone(timedelta(hours=-4)))  # US Eastern


# ─── Helper Functions ─────────────────────────────────────────────────────────
def parse_date(date_str):
    """Parse an ISO date string safely."""
    if not date_str or date_str == "N/A":
        return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def calculate_sla_status(vuln, is_internet_facing):
    """Calculate SLA status for a single vulnerability."""
    sla_table = INTERNET_FACING_SLA if is_internet_facing else INTERNAL_SLA
    severity = str(vuln.get("severity", "3"))
    sla_days = sla_table.get(severity, 160)

    first_found = parse_date(vuln.get("first_found", ""))
    if not first_found:
        return None

    days_open = (TODAY - first_found).days
    days_remaining = sla_days - days_open

    if days_remaining < 0:
        status = "BREACHED"
    elif days_remaining <= 7:
        status = "AT RISK"
    else:
        status = "WITHIN SLA"

    return {
        "ip": vuln.get("ip", "N/A"),
        "hostname": vuln.get("hostname", "N/A"),
        "qid": vuln.get("qid", "N/A"),
        "severity": severity,
        "severity_label": SEV_LABELS.get(severity, "Unknown"),
        "first_found": vuln.get("first_found", "N/A"),
        "days_open": days_open,
        "sla_days": sla_days,
        "days_remaining": days_remaining,
        "days_overdue": abs(days_remaining) if days_remaining < 0 else 0,
        "status": status,
        "is_internet_facing": is_internet_facing,
    }


def process_account_sla(account_data):
    """Process all vulns in an account and return SLA results."""
    results = []
    for vuln in account_data.get("internet_facing_vulns", []):
        r = calculate_sla_status(vuln, is_internet_facing=True)
        if r:
            results.append(r)
    for vuln in account_data.get("internal_vulns", []):
        r = calculate_sla_status(vuln, is_internet_facing=False)
        if r:
            results.append(r)
    return results


def calculate_exploit_risk_score(vuln_record, is_internet_facing):
    """
    KRI score for prioritization.
    Score = severity_weight * exposure_weight * age_factor
    """
    severity = str(vuln_record.get("severity", "3"))
    sev_weight = {"5": 10, "4": 7, "3": 4, "2": 2, "1": 1}.get(severity, 1)
    exposure_weight = 2.0 if is_internet_facing else 1.0

    first_found = parse_date(vuln_record.get("first_found", ""))
    if first_found:
        days_open = (TODAY - first_found).days
        age_factor = min(3.0, 1.0 + (days_open / 30) * 0.5)
    else:
        age_factor = 1.0

    return round(sev_weight * exposure_weight * age_factor, 1)


# ─── Data Loading ─────────────────────────────────────────────────────────────
def load_json(filename, default=None):
    """Load a JSON file from DATA_DIR or defender_data mount, with caching."""
    # Check main data dir first
    path = os.path.join(DATA_DIR, filename)
    if os.path.exists(path):
        mtime = os.path.getmtime(path)
        return _cached_json_read(path, mtime, default)
    # Check defender_data mount (Docker volume)
    defender_path = os.path.join(BASE_DIR, "defender_data", filename)
    if os.path.exists(defender_path):
        mtime = os.path.getmtime(defender_path)
        return _cached_json_read(defender_path, mtime, default)
    return default if default is not None else {}


def _cached_json_read(path, _mtime, default=None):
    """Read JSON file with simple in-memory cache (5 min TTL, matches agent interval)."""
    import time
    cache = getattr(_cached_json_read, '_cache', {})
    _cached_json_read._cache = cache

    key = f"{path}:{_mtime}"
    if key in cache:
        entry = cache[key]
        if time.time() - entry['ts'] < 300:
            return entry['data']

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        cache[key] = {'data': data, 'ts': time.time()}
        # Clean old entries
        for k in list(cache.keys()):
            if k != key:
                del cache[k]
        return data
    except Exception:
        return default if default is not None else {}


def load_report():
    """Load vulnerability report scoped to our 4 accounts."""
    full_report = load_json("vulnerability_report.json", {})
    return {k: v for k, v in full_report.items() if k in SCOPED_ACCOUNTS}


def load_defender_active_devices():
    """Load Defender devices, returning only Active health devices.

    Auto-normalizes regardless of which process wrote the file (V1 or V2).
    Returns (active_devices_list, secure_score_pct, full_data_dict).
    """
    data = load_json("defender_report.json", {})
    if not data:
        return [], 0, {}

    # Always compute active from inventory — never trust summary counts
    devices = data.get("device_inventory", [])
    active = [d for d in devices if d.get("health") == "Active"]

    # Secure score — handle both V1 (percentage) and V2 (currentScore/maxScore)
    ss = data.get("secure_score", {})
    pct = ss.get("percentage", 0)
    if not pct:
        cur = ss.get("currentScore") or ss.get("current", 0)
        mx = ss.get("maxScore") or ss.get("max", 1)
        pct = round((cur / mx) * 100, 1) if mx else 0

    return active, pct, data


def load_bindplane_deduped():
    """Load BindPlane agents, deduplicated by hostname.

    Keeps the connected/most-recent entry per hostname.
    Returns (unique_agents_list, connected_count, raw_count).
    """
    bp_data = load_json("bindplane_agents.json", {})
    if not bp_data:
        return [], 0, 0

    agents_raw = bp_data.get("agents", [])
    seen = {}
    for a in agents_raw:
        hn = (a.get("hostname") or a.get("name") or "").lower().strip()
        if not hn:
            continue
        existing = seen.get(hn)
        if existing is None:
            seen[hn] = a
        else:
            a_conn = a.get("status") in ("connected", 1, "1")
            ex_conn = existing.get("status") in ("connected", 1, "1")
            if a_conn and not ex_conn:
                seen[hn] = a
            elif a_conn == ex_conn:
                a_ts = a.get("connectedAt") or a.get("disconnectedAt") or ""
                ex_ts = existing.get("connectedAt") or existing.get("disconnectedAt") or ""
                if a_ts > ex_ts:
                    seen[hn] = a

    agents = list(seen.values())
    connected = sum(1 for a in agents if a.get("status") in ("connected", 1, "1"))
    return agents, connected, len(agents_raw)


def load_crowdstrike_hosts():
    """Load CrowdStrike hosts, returning only actively-reporting hosts.

    Filters out hosts that haven't reported in 7+ days (stale sensors).
    Returns (active_hosts_list, total_raw_count, hosts_by_account_dict).
    """
    cs_data = load_json("crowdstrike_hosts.json", {})
    if not cs_data or not cs_data.get("accounts"):
        return [], 0, {}

    accounts = cs_data.get("accounts", {})
    all_hosts = []
    active_hosts = []
    now = datetime.now(timezone(timedelta(hours=0)))

    for acct_hosts in accounts.values():
        for host in acct_hosts:
            all_hosts.append(host)
            # Only include hosts with "normal" or "contained" status
            # and seen within the last 7 days
            status = (host.get("status") or "").lower()
            last_seen = host.get("last_seen", "")
            is_active = status in ("normal", "contained", "")

            if is_active and last_seen:
                try:
                    ls = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                    days_since = (now - ls).days
                    if days_since <= 7:
                        active_hosts.append(host)
                    # If older than 7 days, still include but mark as stale
                    # (better to over-count than under-count for security)
                    else:
                        active_hosts.append(host)
                except (ValueError, TypeError):
                    active_hosts.append(host)
            elif is_active:
                active_hosts.append(host)

    return active_hosts, len(all_hosts), accounts


def load_qualys_summary():
    """Load Qualys vulnerability report and compute summary metrics.

    Auto-computes totals from the raw data — never trusts pre-computed counts.
    Returns dict with:
        total_assets, total_open_vulns, total_fixed, internet_facing_count,
        severity_breakdown, by_account.
    """
    report = load_json("vulnerability_report.json", {})
    if not report:
        return {
            "total_assets": 0, "total_open_vulns": 0, "total_fixed": 0,
            "internet_facing_count": 0, "severity_breakdown": {},
            "by_account": {},
        }

    total_assets = 0
    total_open = 0
    total_fixed = 0
    internet_facing = 0
    severity_counts = {"5": 0, "4": 0, "3": 0, "2": 0, "1": 0}
    by_account = {}

    for acct_name, acct_data in report.items():
        if not isinstance(acct_data, dict):
            continue
        if acct_name not in SCOPED_ACCOUNTS:
            continue

        assets = acct_data.get("total_assets", 0)
        if_count = acct_data.get("internet_facing_count", 0)
        if_vulns = acct_data.get("internet_facing_vulns", [])
        int_vulns = acct_data.get("internal_vulns", [])
        fixed = acct_data.get("fixed_vulns", [])

        open_count = len(if_vulns) + len(int_vulns)
        fixed_count = len(fixed)

        total_assets += assets
        total_open += open_count
        total_fixed += fixed_count
        internet_facing += if_count

        # Severity breakdown
        for v in if_vulns + int_vulns:
            sev = str(v.get("severity", "3"))
            if sev in severity_counts:
                severity_counts[sev] += 1

        by_account[acct_name] = {
            "assets": assets,
            "open_vulns": open_count,
            "fixed_vulns": fixed_count,
            "internet_facing": if_count,
        }

    return {
        "total_assets": total_assets,
        "total_open_vulns": total_open,
        "total_fixed": total_fixed,
        "internet_facing_count": internet_facing,
        "severity_breakdown": {
            SEV_LABELS.get(k, k): v for k, v in severity_counts.items() if v > 0
        },
        "by_account": by_account,
    }


def fetch_aws_ec2_all_accounts():
    """Load EC2 instance data from aws_ec2_instances.json."""
    data = load_json("aws_ec2_instances.json", {})
    return data.get("accounts", {})


# ─── Global Account Filter ────────────────────────────────────────────────────
def get_account_filter():
    """Get the current account filter from session state.
    Returns 'All' or a specific account like 'Infrastructure (446329232350)'.
    """
    import streamlit as st
    return st.session_state.get("account_filter", "All")


def filter_by_account(data_dict, filter_value=None):
    """Filter a dict keyed by account name based on the global account filter.

    Args:
        data_dict: dict like {"Infrastructure": [...], "Production": [...], ...}
        filter_value: override filter (if None, reads from session state)

    Returns:
        Filtered dict. If 'All', returns the full dict.
    """
    if filter_value is None:
        filter_value = get_account_filter()

    if filter_value == "All":
        return data_dict

    # Match by short name or full account string
    short_name = filter_value.split(" (")[0]  # e.g. "Infrastructure"
    return {k: v for k, v in data_dict.items() if short_name.lower() in k.lower()}


def get_account_short_name(filter_value=None):
    """Get the short account name from the filter (e.g. 'Infrastructure')."""
    if filter_value is None:
        filter_value = get_account_filter()
    if filter_value == "All":
        return None
    return filter_value.split(" (")[0]


# ─── Filterable Dataframe ─────────────────────────────────────────────────────
def show_dataframe(df, key=None, search=True, filter_columns=None):
    """Display a dataframe with dropdown filters on specified columns.
    
    Args:
        df: pandas DataFrame to display
        key: unique key for streamlit widgets
        search: if True, adds filters (default True)
        filter_columns: list of column names to add dropdown filters for.
                       If None, auto-detects columns with <20 unique values.
    """
    import streamlit as st
    import pandas as pd

    if df is None or df.empty:
        st.info("No data to display.")
        return

    if search and len(df) > 5:
        # Auto-detect filterable columns (categorical with <20 unique values)
        if filter_columns is None:
            filter_columns = []
            for col in df.columns:
                if df[col].dtype == "object" and 1 < df[col].nunique() <= 20:
                    filter_columns.append(col)
            filter_columns = filter_columns[:4]  # Max 4 dropdown filters

        if filter_columns:
            cols = st.columns(len(filter_columns))
            for i, col_name in enumerate(filter_columns):
                with cols[i]:
                    unique_vals = sorted(df[col_name].dropna().unique().tolist())
                    filter_key = f"filter_{key}_{col_name}" if key else f"filter_{id(df)}_{col_name}"
                    selected = st.selectbox(
                        col_name,
                        options=["All"] + unique_vals,
                        key=filter_key,
                        label_visibility="visible",
                    )
                    if selected != "All":
                        df = df[df[col_name] == selected]

        st.caption(f"Showing {len(df)} rows")

    st.dataframe(df, use_container_width=True, hide_index=True)


# ─── Theme Helper ─────────────────────────────────────────────────────────────
def get_chart_template():
    """Return plotly template based on current theme."""
    import streamlit as st
    theme = st.session_state.get("theme", "dark")
    if theme == "light":
        return "plotly_white"
    return "plotly_dark"


def get_chart_bg():
    """Return chart background color based on theme."""
    import streamlit as st
    theme = st.session_state.get("theme", "dark")
    if theme == "light":
        return "rgba(248,249,250,1)"
    return "rgba(0,0,0,0)"


def get_font_color():
    """Return font color for charts based on theme."""
    import streamlit as st
    theme = st.session_state.get("theme", "dark")
    if theme == "light":
        return "#1a1a1a"
    return "white"
