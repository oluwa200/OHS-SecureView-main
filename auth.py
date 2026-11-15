"""
Entra ID (Azure AD) Authentication for OHS SecureView
=====================================================
Uses msal-streamlit-authentication for client-side OIDC login.

Required env vars (or secrets):
  AUTH_ENABLED=true
  AUTH_CLIENT_ID=<app registration client id>
  AUTH_TENANT_ID=<entra tenant id>
  AUTH_REDIRECT_URI=http://localhost:8502 (or https://...)

Install:
  pip install msal-streamlit-authentication

The app registration needs:
  - Platform: Single-page application (SPA)
  - Redirect URI: http://localhost:8502 (and https://localhost:8443)
  - Supported account types: Accounts in this organizational directory only
  - Token configuration: Add optional claims (email, preferred_username)
  - API permissions: User.Read (delegated)
"""
import os
import streamlit as st


def is_auth_enabled() -> bool:
    """Check if authentication is enabled via env var."""
    return os.getenv("AUTH_ENABLED", "false").lower() in ("true", "1", "yes")


def get_auth_config() -> dict:
    """Get auth configuration from environment."""
    return {
        "client_id": os.getenv("AUTH_CLIENT_ID", "").strip(),
        "tenant_id": os.getenv("AUTH_TENANT_ID", os.getenv("DEFENDER_TENANT_ID", "")).strip(),
        "redirect_uri": os.getenv("AUTH_REDIRECT_URI", "http://localhost:8502").strip(),
    }


def require_auth() -> dict | None:
    """Require authentication. Returns user info dict or None if not authenticated.
    
    If AUTH_ENABLED=false, returns a bypass dict so the app always works.
    
    Returns:
        dict with keys: name, email, preferred_username, oid, roles
        None if auth failed (should not render the app)
    """
    if not is_auth_enabled():
        # Auth disabled — bypass with default user
        return {
            "name": "Local User",
            "email": "local@dev",
            "preferred_username": "local",
            "oid": "local",
            "roles": ["Engineer"],
        }

    config = get_auth_config()
    if not config["client_id"] or not config["tenant_id"]:
        st.error(
            "Authentication is enabled but AUTH_CLIENT_ID and AUTH_TENANT_ID are not set.\n\n"
            "Set these in `.env` or disable auth with `AUTH_ENABLED=false`."
        )
        st.stop()
        return None

    try:
        from msal_streamlit_authentication import msal_authentication
    except ImportError:
        st.error(
            "Authentication requires the `msal-streamlit-authentication` package.\n\n"
            "Install it: `pip install msal-streamlit-authentication`\n\n"
            "Or disable auth: set `AUTH_ENABLED=false` in `.env`"
        )
        st.stop()
        return None

    # Configure MSAL
    authority = f"https://login.microsoftonline.com/{config['tenant_id']}"

    login_token = msal_authentication(
        auth={
            "clientId": config["client_id"],
            "authority": authority,
            "redirectUri": config["redirect_uri"],
            "postLogoutRedirectUri": config["redirect_uri"],
        },
        cache={
            "cacheLocation": "sessionStorage",
            "storeAuthStateInCookie": False,
        },
        login_request={
            "scopes": ["openid", "profile", "email", "User.Read"],
        },
        logout_request={},
        login_button_text="Sign in with Microsoft",
        logout_button_text="Sign out",
        key="msal_auth",
    )

    if login_token is None:
        st.warning("Please sign in to access OHS SecureView.")
        st.info("Click the 'Sign in with Microsoft' button above to authenticate with your OHS account.")
        st.stop()
        return None

    # Extract user info from token
    user_info = {
        "name": login_token.get("account", {}).get("name", "Unknown"),
        "email": login_token.get("account", {}).get("username", ""),
        "preferred_username": login_token.get("account", {}).get("username", ""),
        "oid": login_token.get("account", {}).get("localAccountId", ""),
        "roles": login_token.get("account", {}).get("idTokenClaims", {}).get("roles", []),
    }

    # Store in session
    st.session_state.user = user_info
    return user_info


def show_user_badge():
    """Show the logged-in user badge in the header."""
    if not is_auth_enabled():
        return

    user = st.session_state.get("user")
    if user:
        st.caption(f"👤 {user.get('name', 'Unknown')} ({user.get('email', '')})")
