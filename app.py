"""
Security Posture Dashboard V2 — Main Entry Point
=================================================
Tile-based landing page with sub-dashboard routing.
"""
import streamlit as st

# Load secrets from AWS Secrets Manager (falls back to .env)
from secrets_loader import load_secrets
load_secrets()

st.set_page_config(
    page_title="OHS SecureView",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─── Anti-flash CSS (reduces white flash on page re-render) ───────────────────
st.markdown("""
<style>
    /* Prevent white flash during Streamlit re-renders */
    .stApp { transition: none !important; }
    [data-testid="stAppViewContainer"] { background-color: #0e1117; }
    [data-testid="stHeader"] { background-color: #0e1117; }
    .stSpinner { display: none !important; }
    /* Smoother tab transitions */
    .stTabs [data-baseweb="tab-panel"] { transition: opacity 0.1s ease-in; }
    /* Hide Streamlit branding */
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    header { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

# ─── Authentication (Entra ID / Azure AD) ─────────────────────────────────────
from auth import require_auth, show_user_badge

user = require_auth()
if user is None:
    st.stop()

# ─── Session State Router ─────────────────────────────────────────────────────
if "current_view" not in st.session_state:
    st.session_state.current_view = "home"
if "current_tab" not in st.session_state:
    st.session_state.current_tab = 0
if "theme" not in st.session_state:
    st.session_state.theme = "dark"
if "role" not in st.session_state:
    st.session_state.role = "Engineer"
if "account_filter" not in st.session_state:
    st.session_state.account_filter = "All"


def navigate_to(view: str, tab: int = 0):
    """Navigate to a sub-dashboard, optionally to a specific tab."""
    st.session_state.current_view = view
    st.session_state.current_tab = tab
    st.session_state.drill_down_tab = tab  # Pass tab index to sub-dashboards


def go_home():
    """Return to the tile landing page."""
    st.session_state.current_view = "home"
    st.session_state.current_tab = 0


# ─── Global Filter Bar ───────────────────────────────────────────────────────
ACCOUNT_OPTIONS = [
    "All",
    "Infrastructure (446329232350)",
    "Production (937786629491)",
    "Network (895945783203)",
    "Test and QA (754120856488)",
]

filter_col1, filter_col2, filter_col3 = st.columns([4, 3, 1])
with filter_col1:
    if st.session_state.current_view != "home":
        st.caption(f"📍 {st.session_state.current_view.replace('_', ' ').title()}")
    else:
        show_user_badge()
with filter_col2:
    account_filter = st.selectbox(
        "🔽 Filter by Account",
        ACCOUNT_OPTIONS,
        index=ACCOUNT_OPTIONS.index(st.session_state.account_filter),
        key="account_filter_select",
        label_visibility="collapsed",
    )
    if account_filter != st.session_state.account_filter:
        st.session_state.account_filter = account_filter
        st.rerun()
with filter_col3:
    if st.session_state.current_view != "home":
        if st.button("🏠", key="global_home_btn", help="Back to Home"):
            go_home()
            st.rerun()

# ─── Apply Global Styles ─────────────────────────────────────────────────────
st.markdown("""
<style>
    [data-testid="stSidebar"] { display: none; }
</style>
""", unsafe_allow_html=True)

# ─── Route to the Current View ────────────────────────────────────────────────
match st.session_state.current_view:
    case "home":
        from dashboards.home import render
        render(navigate_to)
    case "vulnerability":
        from dashboards.vulnerability import render
        render(go_home)
    case "endpoint":
        from dashboards.endpoint import render
        render(go_home)
    case "defender":
        from dashboards.defender import render
        render(go_home)
    case "aws_assets":
        from dashboards.aws_assets import render
        render(go_home)
    case "ai_insights":
        from dashboards.ai_insights import render
        render(go_home)
    case "executive":
        from dashboards.executive import render
        render(go_home)
    case "bindplane":
        from dashboards.bindplane import render
        render(go_home)
    case "greymatter":
        from dashboards.greymatter import render
        render(go_home)
    case "aikido":
        from dashboards.aikido import render
        render(go_home)
    case _:
        from dashboards.home import render
        render(navigate_to)
