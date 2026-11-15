"""Home — Dynamic Tile Landing Page with auto-refresh, sparklines, and live health."""
import json
import os
import streamlit as st
from datetime import datetime, timedelta

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def load_json(filename, default=None):
    """Load a JSON data file safely with caching."""
    path = os.path.join(DATA_DIR, filename)
    if os.path.exists(path):
        mtime = os.path.getmtime(path)
        return _load_json_cached(path, mtime, default)
    return default or {}


@st.cache_data(ttl=300)
def _load_json_cached(path, _mtime, default=None):
    """Cached file reader — re-reads only when file modification time changes."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default or {}


def render(navigate_to):
    """Render the dynamic tile landing page."""
    import plotly.graph_objects as go

    ASSETS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "assets")

    # ─── Auto-refresh every 60 seconds ───────────────────────────────────────
    try:
        from streamlit_autorefresh import st_autorefresh
        st_autorefresh(interval=60000, limit=None, key="home_autorefresh")
    except ImportError:
        pass  # Graceful fallback if not installed

    # ─── Custom CSS using Streamlit CSS variables (theme-aware) ─────────────
    st.markdown("""
    <style>
    /* Tiles adapt to theme automatically */
    div[data-testid="stContainer"] {
        transition: all 0.3s ease;
        border-radius: 12px !important;
        min-height: 320px;
        background-color: var(--secondary-background-color) !important;
        border: 1px solid rgba(128,128,128,0.15) !important;
    }
    div[data-testid="stContainer"]:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 30px rgba(0,120,212,0.15);
        border-color: rgba(0,120,212,0.3) !important;
    }
    /* Pulse animation for critical badges */
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.5; }
        100% { opacity: 1; }
    }
    .pulse { animation: pulse 2s infinite; }
    /* Status bar - uses theme variables */
    .status-bar {
        display: flex; gap: 12px; padding: 8px 16px;
        background-color: var(--secondary-background-color);
        color: var(--text-color);
        border-radius: 8px;
        font-size: 13px; align-items: center;
        border: 1px solid rgba(128,128,128,0.1);
    }
    .status-bar * { color: var(--text-color); }
    .status-item { display: flex; align-items: center; gap: 4px; }
    .dot-green { width: 8px; height: 8px; border-radius: 50%; background: #44bb44; display: inline-block; }
    .dot-yellow { width: 8px; height: 8px; border-radius: 50%; background: #ff8800; display: inline-block; }
    .dot-red { width: 8px; height: 8px; border-radius: 50%; background: #ff4444; display: inline-block; }
    /* Brand header - uses theme variables */
    .brand-header { display: flex; align-items: center; justify-content: space-between; padding: 4px 0; margin-bottom: 8px; }
    .brand-title { font-size: 32px; font-weight: 900; letter-spacing: -0.5px; color: var(--text-color); }
    .brand-subtitle { font-size: 12px; color: var(--text-color); opacity: 0.6; }
    /* Data freshness - uses theme variables */
    .freshness { display: flex; gap: 16px; font-size: 11px; color: var(--text-color); opacity: 0.6; flex-wrap: wrap; }
    .freshness * { color: var(--text-color); opacity: 0.8; }
    .freshness span { display: flex; align-items: center; gap: 3px; }
    /* Logo always on white background */
    .logo-container {
        background-color: white;
        padding: 10px 20px;
        border-radius: 10px;
        display: inline-block;
        margin-bottom: 10px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    }
    </style>
    """, unsafe_allow_html=True)

    # ─── Theme Toggle + Branded Header ────────────────────────────────────────
    hcol1, hcol2 = st.columns([5, 1])
    with hcol1:
        ohs_logo = os.path.join(ASSETS_DIR, "1100x400px_Oncourse_h_rgb_(R).png")
        if os.path.exists(ohs_logo):
            import base64
            with open(ohs_logo, "rb") as f:
                logo_b64 = base64.b64encode(f.read()).decode()
            st.markdown(f'<div class="logo-container"><img src="data:image/png;base64,{logo_b64}" width="220"></div>', unsafe_allow_html=True)

        st.markdown("""
        <div class="brand-header">
            <div>
                <div class="brand-title">OHS SecureView</div>
                <div class="brand-subtitle">Security Posture & Compliance Dashboard</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
    with hcol2:
        current_theme = st.session_state.get("theme", "dark")
        if st.button("☀️" if current_theme == "dark" else "🌙", key="theme_toggle", help="Toggle theme"):
            new_theme = "light" if current_theme == "dark" else "dark"
            st.session_state.theme = new_theme
            st.rerun()

    # Apply light theme via Streamlit's config override
    current_theme = st.session_state.get("theme", "dark")
    if current_theme == "light":
        st.markdown("""
        <style>
        .stApp { background-color: #f5f5f5 !important; }
        [data-testid="stAppViewContainer"] { background-color: #f5f5f5 !important; }
        .stApp h1, .stApp h2, .stApp h3, .stApp p, .stApp span, .stApp label,
        [data-testid="stMetricValue"], [data-testid="stMetricLabel"],
        [data-testid="stMarkdownContainer"] { color: #1a1a1a !important; }
        div[data-testid="stContainer"] { background-color: #ffffff !important; }
        .logo-container { box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        </style>
        """, unsafe_allow_html=True)

    # ─── Live Status Bar ──────────────────────────────────────────────────────
    ai_insights = load_json("ai_insights.json")
    risk_score = ai_insights.get("overall_risk_score", 0) if ai_insights else 0
    generated_at = ai_insights.get("generated_at", "") if ai_insights else ""
    last_refresh = generated_at[:16].replace("T", " ") if generated_at else "Never"

    # Determine overall health
    if risk_score < 25:
        health_dot, health_text = "dot-green", "HEALTHY"
    elif risk_score < 50:
        health_dot, health_text = "dot-yellow", "ELEVATED"
    else:
        health_dot, health_text = "dot-red", "AT RISK"

    st.markdown(f"""
    <div class="status-bar">
        <span class="status-item"><span class="{health_dot}"></span> <b>{health_text}</b></span>
        <span class="status-item">Risk: {risk_score}/100</span>
        <span class="status-item">🕐 Last refresh: {last_refresh}</span>
        <span class="status-item">⏱️ Auto-refresh: 60s</span>
        <span class="status-item">📅 {datetime.now().strftime('%b %d, %Y %H:%M')}</span>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("")

    # ─── Role & Account Filter (compact row) ─────────────────────────────────
    col_role, col_spacer = st.columns([2, 6])
    with col_role:
        role = st.selectbox("View as:", ["Engineer", "CISO", "Compliance"],
                           key="role_select", label_visibility="collapsed")
        st.session_state.role = role

    # ─── Load Data ────────────────────────────────────────────────────────────
    ec2_counts = load_json("aws_ec2_counts.json")
    cs_hosts = load_json("crowdstrike_hosts.json")
    vuln_report = load_json("vulnerability_report.json")
    defender_data = load_json("defender_report.json")
    bp_data = load_json("bindplane_agents.json")
    history = load_json("history.json", [])

    # ─── Data Freshness Bar ───────────────────────────────────────────────────
    def _relative_time(ts_str):
        """Convert timestamp string to relative time like '3 min ago'."""
        if not ts_str or ts_str == "N/A":
            return "N/A"
        try:
            from datetime import timezone
            # Handle various formats
            ts_str_clean = ts_str.replace(" UTC", "+00:00").replace("Z", "+00:00")
            if "T" not in ts_str_clean and len(ts_str_clean) > 10:
                ts_str_clean = ts_str_clean.replace(" ", "T", 1)
            if "+" not in ts_str_clean and "-" not in ts_str_clean[10:]:
                ts_str_clean += "+00:00"
            ts = datetime.fromisoformat(ts_str_clean)
            now = datetime.now(timezone.utc)
            delta = now - ts
            minutes = int(delta.total_seconds() / 60)
            if minutes < 1:
                return "just now"
            elif minutes < 60:
                return f"{minutes} min ago"
            elif minutes < 1440:
                return f"{minutes // 60}h ago"
            else:
                return f"{minutes // 1440}d ago"
        except Exception:
            return ts_str[:16] if len(ts_str) > 16 else ts_str

    cs_updated = _relative_time(cs_hosts.get("updated_at", "")) if cs_hosts else "N/A"
    ec2_updated = _relative_time(ec2_counts.get("last_updated", "")) if ec2_counts.get("last_updated") else "N/A"
    bp_updated = _relative_time(bp_data.get("updated_at", "")) if bp_data else "N/A"

    st.markdown(f"""
    <div class="freshness">
        <span>🦅 CrowdStrike: {cs_updated}</span>
        <span>🔍 Qualys: loaded</span>
        <span>☁️ AWS EC2: {ec2_updated}</span>
        <span>📡 BindPlane: {bp_updated}</span>
    </div>
    """, unsafe_allow_html=True)

    # Apply account filter
    acct_filter = st.session_state.get("account_filter", "All")

    def _filter_accts(d):
        if acct_filter == "All":
            return d
        short = acct_filter.split(" (")[0]
        return {k: v for k, v in d.items() if short.lower() in k.lower()}

    ec2_by_account = _filter_accts(ec2_counts.get("by_account", {}))

    total_ec2 = sum(d.get("total", 0) for d in ec2_by_account.values()) if ec2_by_account else ec2_counts.get("total_instances", 0)
    total_running = sum(d.get("running", 0) for d in ec2_by_account.values()) if ec2_by_account else ec2_counts.get("total_running", 0)

    # CrowdStrike KPIs — auto-computed from raw host data (active sensors only)
    from config.dashboard_config import (
        load_defender_active_devices, load_bindplane_deduped,
        load_crowdstrike_hosts, load_qualys_summary,
    )
    cs_active_hosts, _cs_raw, cs_accounts = load_crowdstrike_hosts()
    cs_filtered = _filter_accts(cs_accounts)
    cs_total = sum(len(h) for h in cs_filtered.values()) if cs_filtered else len(cs_active_hosts)

    # Qualys KPIs — auto-computed from raw vulnerability data
    qualys_summary = load_qualys_summary()
    vuln_assets = qualys_summary["total_assets"]

    # Defender KPIs — always compute from device_inventory (never trust summary counts)
    active_defender_devices, defender_pct, _ = load_defender_active_devices()
    defender_devices = len(active_defender_devices)

    # BindPlane KPIs — deduplicated, single source of truth
    bp_agents, bp_connected, _bp_raw = load_bindplane_deduped()
    bp_total = len(bp_agents)
    bp_health_pct = round(bp_connected / bp_total * 100, 1) if bp_total else 0

    # AI stats
    stats = ai_insights.get("stats", {}) if ai_insights else {}
    edr_pct = stats.get("edr_coverage_pct", 0)
    vuln_pct = stats.get("vuln_scan_coverage_pct", 0)

    # ─── Sparkline Helper ─────────────────────────────────────────────────────
    chart_bg = "rgba(0,0,0,0)"  # Transparent — inherits from page background
    chart_font_color = "#ffffff" if current_theme == "dark" else "#1a1a1a"

    def make_sparkline(values, color="#44bb44", height=50):
        """Create a tiny trend sparkline chart."""
        if not values or len(values) < 2:
            return None
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            y=values, mode="lines",
            line=dict(color=color, width=2),
            fill="tozeroy", fillcolor=f"rgba({int(color[1:3],16)},{int(color[3:5],16)},{int(color[5:7],16)},0.1)",
        ))
        fig.update_layout(
            height=height, margin=dict(l=0, r=0, t=0, b=0),
            paper_bgcolor=chart_bg, plot_bgcolor=chart_bg,
            xaxis=dict(visible=False), yaxis=dict(visible=False),
            showlegend=False,
        )
        return fig

    # Extract trend data from history
    risk_trend = [h.get("risk_score", 0) for h in history[-14:]] if history else []
    edr_trend = [h.get("edr_coverage_pct", 0) for h in history[-14:]] if history else []
    blind_trend = [h.get("completely_blind", 0) for h in history[-14:]] if history else []

    # ─── Risk badge helpers ───────────────────────────────────────────────────
    def risk_badge(value, thresholds=(80, 50)):
        if value >= thresholds[0]:
            return "🟢"
        elif value >= thresholds[1]:
            return "🟡"
        return "🔴"

    def inverse_risk_badge(value, thresholds=(25, 50)):
        if value <= thresholds[0]:
            return "🟢"
        elif value <= thresholds[1]:
            return "🟡"
        return "🔴"

    # ─── Role-based visibility ────────────────────────────────────────────────
    role = st.session_state.get("role", "Engineer")
    show_vuln = role in ["Engineer", "Compliance"]
    show_endpoint = role in ["Engineer"]
    show_defender = role in ["Engineer"]
    show_aws = role in ["Engineer"]
    show_ai = role in ["Engineer", "CISO"]
    show_exec = role in ["Engineer", "CISO", "Compliance"]

    st.markdown("---")

    # ═══════════════════════════════════════════════════════════════════════════
    # Row 1: Security Coverage Ring + KPI Cards
    # ═══════════════════════════════════════════════════════════════════════════

    if show_vuln or show_endpoint or show_defender:
        cols = st.columns(3 if all([show_vuln, show_endpoint, show_defender]) else 2)
        col_idx = 0

        if show_vuln:
            with cols[col_idx]:
                with st.container(border=True):
                    qualys_logo = os.path.join(ASSETS_DIR, "R.jpg")
                    if os.path.exists(qualys_logo):
                        st.image(qualys_logo, width=100)
                    badge = risk_badge(vuln_pct)
                    st.markdown(f"**{badge} Scan Coverage: {vuln_pct}%**")
                    st.metric("Assets Scanned", vuln_assets, delta=None)

                    # Mini coverage ring
                    fig_ring = go.Figure(go.Pie(
                        values=[vuln_pct, 100 - vuln_pct],
                        hole=0.7, marker_colors=["#44bb44" if vuln_pct >= 80 else "#ff8800", "#1a1a1a"],
                        textinfo="none", hoverinfo="skip",
                    ))
                    fig_ring.update_layout(
                        height=120, margin=dict(l=10, r=10, t=5, b=5),
                        paper_bgcolor="rgba(0,0,0,0)", showlegend=False,
                        annotations=[dict(text=f"{vuln_pct}%", x=0.5, y=0.5, font_size=18, showarrow=False, font_color="white")]
                    )
                    st.plotly_chart(fig_ring, use_container_width=True, key="ring_vuln")

                    bcol1, bcol2 = st.columns(2)
                    with bcol1:
                        if st.button("Dashboard →", key="btn_vuln", use_container_width=True):
                            navigate_to("vulnerability")
                            st.rerun()
                    with bcol2:
                        if st.button("SLA", key="btn_vuln_sla", use_container_width=True):
                            navigate_to("vulnerability", tab=1)
                            st.rerun()
            col_idx += 1

        if show_endpoint:
            with cols[col_idx]:
                with st.container(border=True):
                    cs_logo = os.path.join(ASSETS_DIR, "crowdstrike_1610034789874.webp")
                    if os.path.exists(cs_logo):
                        st.image(cs_logo, width=100)
                    else:
                        st.markdown("#### :red[CROWDSTRIKE]")
                    badge = risk_badge(edr_pct)
                    st.markdown(f"**{badge} EDR Coverage: {edr_pct}%**")
                    st.metric("Protected Hosts", cs_total)

                    # Coverage ring
                    fig_ring = go.Figure(go.Pie(
                        values=[edr_pct, 100 - edr_pct],
                        hole=0.7, marker_colors=["#44bb44" if edr_pct >= 80 else "#ff8800", "#1a1a1a"],
                        textinfo="none", hoverinfo="skip",
                    ))
                    fig_ring.update_layout(
                        height=120, margin=dict(l=10, r=10, t=5, b=5),
                        paper_bgcolor="rgba(0,0,0,0)", showlegend=False,
                        annotations=[dict(text=f"{edr_pct}%", x=0.5, y=0.5, font_size=18, showarrow=False, font_color="white")]
                    )
                    st.plotly_chart(fig_ring, use_container_width=True, key="ring_edr")

                    # Sparkline trend
                    if edr_trend:
                        spark = make_sparkline(edr_trend, "#44bb44" if edr_pct >= 80 else "#ff8800")
                        if spark:
                            st.plotly_chart(spark, use_container_width=True, key="spark_edr")

                    bcol1, bcol2 = st.columns(2)
                    with bcol1:
                        if st.button("Dashboard →", key="btn_endpoint", use_container_width=True):
                            navigate_to("endpoint")
                            st.rerun()
                    with bcol2:
                        if st.button("CSPM", key="btn_endpoint_cspm", use_container_width=True):
                            navigate_to("endpoint", tab=1)
                            st.rerun()
            col_idx += 1

        if show_defender:
            with cols[col_idx]:
                with st.container(border=True):
                    defender_logo = os.path.join(ASSETS_DIR, "Microsoft Defender XDR.png")
                    if os.path.exists(defender_logo):
                        st.image(defender_logo, width=45)
                    badge = risk_badge(defender_pct)
                    st.markdown(f"**{badge} Secure Score: {defender_pct}%**")
                    st.metric("Managed Devices", f"{defender_devices:,}")

                    # Score ring
                    fig_ring = go.Figure(go.Pie(
                        values=[defender_pct, 100 - defender_pct],
                        hole=0.7, marker_colors=["#44bb44" if defender_pct >= 80 else "#ff8800", "#1a1a1a"],
                        textinfo="none", hoverinfo="skip",
                    ))
                    fig_ring.update_layout(
                        height=120, margin=dict(l=10, r=10, t=5, b=5),
                        paper_bgcolor="rgba(0,0,0,0)", showlegend=False,
                        annotations=[dict(text=f"{defender_pct}%", x=0.5, y=0.5, font_size=18, showarrow=False, font_color="white")]
                    )
                    st.plotly_chart(fig_ring, use_container_width=True, key="ring_defender")

                    bcol1, bcol2 = st.columns(2)
                    with bcol1:
                        if st.button("Dashboard →", key="btn_defender", use_container_width=True):
                            navigate_to("defender")
                            st.rerun()
                    with bcol2:
                        if st.button("Alerts", key="btn_defender_alerts", use_container_width=True):
                            navigate_to("defender", tab=2)
                            st.rerun()

    st.markdown("")

    # ═══════════════════════════════════════════════════════════════════════════
    # Row 2: AWS + BindPlane + AI + Executive
    # ═══════════════════════════════════════════════════════════════════════════
    row2_tiles = [t for t in ["aws", "bindplane", "ai", "exec"] if
                  (t == "aws" and show_aws) or (t == "bindplane" and show_aws) or
                  (t == "ai" and show_ai) or (t == "exec" and show_exec)]

    if row2_tiles:
        cols2 = st.columns(len(row2_tiles))
        col_idx = 0

        if show_aws:
            with cols2[col_idx]:
                with st.container(border=True):
                    aws_logo = os.path.join(ASSETS_DIR, "AWS-Logo-svg.jpg")
                    if os.path.exists(aws_logo):
                        st.image(aws_logo, width=80)
                    st.markdown("### AWS Assets")
                    st.metric("EC2 Total", total_ec2)
                    st.metric("Running", total_running, delta=f"{total_running}/{total_ec2}")
                    ws_data = load_json("aws_workspaces.json")
                    ws_count = len(ws_data.get("workspaces", [])) if ws_data else 0
                    if ws_count:
                        st.metric("WorkSpaces", ws_count)
                    if st.button("Open →", key="btn_aws", use_container_width=True):
                        navigate_to("aws_assets")
                        st.rerun()
            col_idx += 1

        if show_aws:
            with cols2[col_idx]:
                with st.container(border=True):
                    bp_logo = os.path.join(ASSETS_DIR, "bindplane-logo-black.0f~cd4guqyl3k.svg")
                    if os.path.exists(bp_logo):
                        import base64
                        with open(bp_logo, "r", encoding="utf-8") as f:
                            svg_content = f.read()
                        b64 = base64.b64encode(svg_content.encode()).decode()
                        st.markdown(f'<img src="data:image/svg+xml;base64,{b64}" width="120" style="filter:invert(1);" />', unsafe_allow_html=True)
                    bp_badge = risk_badge(bp_health_pct, thresholds=(90, 70))
                    st.markdown(f"### {bp_badge} 📡 BindPlane")
                    st.metric("Agents", bp_total)
                    st.metric("Connected", bp_connected)
                    if bp_total:
                        st.progress(min(1.0, bp_connected / bp_total),
                                   text=f"{round(bp_connected/bp_total*100)}% healthy")
                    bcol1, bcol2 = st.columns(2)
                    with bcol1:
                        if st.button("Open →", key="btn_bp", use_container_width=True):
                            navigate_to("bindplane")
                            st.rerun()
                    with bcol2:
                        if st.button("Gaps", key="btn_bp_gaps", use_container_width=True):
                            navigate_to("bindplane", tab=4)
                            st.rerun()
            col_idx += 1

        if show_ai:
            with cols2[col_idx]:
                with st.container(border=True):
                    ai_badge = inverse_risk_badge(risk_score)
                    st.markdown(f"### {ai_badge} AI Insights")
                    st.metric("Risk Score", f"{risk_score}/100",
                             delta=f"{risk_score - risk_trend[-2] if len(risk_trend) >= 2 else 0:+.0f}" if risk_trend else None,
                             delta_color="inverse")
                    st.metric("Blind Spots", stats.get("completely_blind", 0))
                    # Risk trend sparkline
                    if risk_trend:
                        color = "#44bb44" if risk_score < 25 else "#ff8800" if risk_score < 50 else "#ff4444"
                        spark = make_sparkline(risk_trend, color, height=45)
                        if spark:
                            st.plotly_chart(spark, use_container_width=True, key="spark_risk")
                    if st.button("Open →", key="btn_ai", use_container_width=True):
                        navigate_to("ai_insights")
                        st.rerun()
            col_idx += 1

        if show_exec:
            with cols2[col_idx]:
                with st.container(border=True):
                    st.markdown("### 📊 Executive")
                    overall = "Low" if risk_score < 25 else "Medium" if risk_score < 50 else "High" if risk_score < 75 else "Critical"
                    st.metric("Overall Risk", overall)
                    st.metric("Coverage", f"{stats.get('full_coverage_pct', 0)}%")
                    if st.button("Open →", key="btn_exec", use_container_width=True):
                        navigate_to("executive")
                        st.rerun()

    # ═══════════════════════════════════════════════════════════════════════════
    # Row 3: Unified Search
    # ═══════════════════════════════════════════════════════════════════════════
    st.markdown("---")
    all_assets = _build_asset_list()
    search_input = st.text_input("🔍 Search asset (IP or hostname)",
                                key="global_search",
                                placeholder="Start typing... e.g. 10.128 or awsnv")

    if search_input and len(search_input) >= 2:
        q = search_input.lower()
        filtered = [a for a in all_assets if q in a.lower()][:20]
        if filtered:
            selected = st.radio("Select:", filtered, key="asset_select", label_visibility="collapsed")
            if selected:
                _render_asset_detail(selected)
        else:
            st.caption("No matches found.")

    # ─── Footer ───────────────────────────────────────────────────────────────
    st.markdown("---")
    st.caption(f"OHS SecureView | Auto-refreshes every 60s | {datetime.now().strftime('%H:%M:%S')}")


# ═══════════════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════════════
def _build_asset_list():
    """Build a sorted list of all known assets for search."""
    assets = set()
    ec2_data = load_json("aws_ec2_instances.json")
    for acct_name, instances in ec2_data.get("accounts", {}).items():
        for inst in instances:
            ip = inst.get("PrivateIp", "")
            name = inst.get("name", "unnamed")
            if ip:
                assets.add(f"{ip} — {name}")
    cs_hosts = load_json("crowdstrike_hosts.json")
    for acct_name, hosts in cs_hosts.get("accounts", {}).items():
        for host in hosts:
            ip = host.get("local_ip", "")
            name = host.get("hostname", "")
            if ip and name:
                assets.add(f"{ip} — {name}")
    return sorted(assets)


def _render_asset_detail(selected):
    """Show cross-tool detail for a selected asset."""
    import pandas as pd
    ip = selected.split(" — ")[0].strip()
    st.subheader(f"📋 {selected}")

    col1, col2, col3 = st.columns(3)

    ec2_data = load_json("aws_ec2_instances.json")
    ec2_match = None
    for acct_name, instances in ec2_data.get("accounts", {}).items():
        for inst in instances:
            if inst.get("PrivateIp") == ip:
                ec2_match = {**inst, "account": acct_name}
                break

    with col1:
        st.markdown("**☁️ AWS EC2**")
        if ec2_match:
            st.markdown(f"- Account: {ec2_match['account']}")
            st.markdown(f"- ID: `{ec2_match.get('instance_id', 'N/A')}`")
            st.markdown(f"- State: {ec2_match.get('state', 'N/A')}")
        else:
            st.caption("Not found")

    cs_hosts = load_json("crowdstrike_hosts.json")
    cs_match = None
    for acct_name, hosts in cs_hosts.get("accounts", {}).items():
        for host in hosts:
            if host.get("local_ip") == ip:
                cs_match = host
                break

    with col2:
        st.markdown("**🦅 CrowdStrike**")
        if cs_match:
            st.markdown(f"- Hostname: {cs_match.get('hostname', 'N/A')}")
            st.markdown(f"- Status: {cs_match.get('status', 'N/A')}")
            st.markdown(f"- Agent: {cs_match.get('agent_version', 'N/A')}")
        else:
            st.error("❌ No EDR")

    vuln_report = load_json("vulnerability_report.json")
    qualys_match = None
    for acct_name, acct_data in vuln_report.items():
        if not isinstance(acct_data, dict):
            continue
        for asset in acct_data.get("internet_facing_assets", []) + acct_data.get("internal_assets", []):
            if asset.get("ip") == ip:
                qualys_match = asset
                break

    with col3:
        st.markdown("**🔍 Qualys**")
        if qualys_match:
            st.markdown("- Scanned: ✅")
        else:
            st.warning("⚠️ Not scanned")

    # Coverage verdict
    has_edr = cs_match is not None
    has_scan = qualys_match is not None
    if has_edr and has_scan:
        st.success("✅ Full coverage")
    elif has_edr:
        st.warning("⚠️ EDR only — no vuln scan")
    elif has_scan:
        st.error("❌ Scan only — no EDR")
    else:
        st.error("🚨 BLIND SPOT")
