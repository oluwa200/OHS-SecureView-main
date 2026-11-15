"""
MFA Registration Report Fetcher
================================
Pulls user authentication method registration details from Microsoft Graph API.
Identifies users without MFA registered — a critical security gap.

Endpoint: GET /reports/authenticationMethods/userRegistrationDetails
Permission required: AuditLog.Read.All (Application)

Output: data/mfa_report.json
"""
import os
import sys
import json
import asyncio
import logging
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [MFA] %(message)s")
log = logging.getLogger(__name__)

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def write_json(filename, data):
    """Write data to a JSON file in DATA_DIR."""
    path = os.path.join(DATA_DIR, filename)
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    log.info(f"Written: {filename}")


async def fetch_mfa_registration_details():
    """Fetch MFA registration status for all users from Microsoft Graph.

    Returns structured report with:
    - All users and their MFA status
    - Users without MFA (security gap)
    - Summary statistics
    """
    import httpx

    tenant_id = os.getenv("DEFENDER_TENANT_ID", "").strip()
    client_id = os.getenv("DEFENDER_CLIENT_ID", "").strip()
    client_secret = os.getenv("DEFENDER_CLIENT_SECRET", "").strip()

    if not tenant_id or not client_id or not client_secret:
        log.error("Defender/Graph credentials not set. Cannot fetch MFA report.")
        return None

    ssl_verify = os.getenv("SSL_VERIFY", "true").lower() != "false"
    log.info("Fetching MFA registration details from Microsoft Graph...")

    try:
        async with httpx.AsyncClient(verify=ssl_verify, timeout=60) as client:
            # Authenticate to Graph API
            token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            r = await client.post(token_url, data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://graph.microsoft.com/.default",
            })

            if r.status_code != 200:
                log.error(f"Graph auth failed: {r.status_code} - {r.text[:200]}")
                return None

            token = r.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}

            # Fetch all user registration details (paginated)
            all_users = []
            url = "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$top=999"

            while url:
                r = await client.get(url, headers=headers, timeout=60)
                if r.status_code != 200:
                    log.error(f"Graph API error: {r.status_code} - {r.text[:200]}")
                    break

                data = r.json()
                users = data.get("value", [])
                all_users.extend(users)
                log.info(f"  Fetched {len(all_users)} users so far...")

                # Handle pagination
                url = data.get("@odata.nextLink")

            if not all_users:
                log.warning("No user registration data returned.")
                return None

            log.info(f"  Total users fetched: {len(all_users)}")

            # Process and categorize
            report = _process_mfa_data(all_users)
            return report

    except Exception as e:
        log.error(f"MFA fetch failed: {e}")
        return None


def _process_mfa_data(users: list) -> dict:
    """Process raw Graph API response into structured MFA report."""
    now = datetime.now(timezone.utc)

    # Categorize users
    mfa_registered = []
    mfa_not_registered = []
    mfa_capable = []
    mfa_not_capable = []
    admins_no_mfa = []
    members_no_mfa = []
    guests_no_mfa = []

    method_distribution = {}
    user_type_counts = {"member": 0, "guest": 0, "other": 0}

    for user in users:
        is_mfa_registered = user.get("isMfaRegistered", False)
        is_mfa_capable = user.get("isMfaCapable", False)
        is_admin = user.get("isAdmin", False)
        user_type = (user.get("userType") or "other").lower()
        methods = user.get("methodsRegistered", [])

        # Count user types
        if user_type in user_type_counts:
            user_type_counts[user_type] += 1
        else:
            user_type_counts["other"] += 1

        # Track method distribution
        for method in methods:
            method_distribution[method] = method_distribution.get(method, 0) + 1

        # Categorize
        user_record = {
            "userPrincipalName": user.get("userPrincipalName", ""),
            "userDisplayName": user.get("userDisplayName", ""),
            "isAdmin": is_admin,
            "isMfaRegistered": is_mfa_registered,
            "isMfaCapable": is_mfa_capable,
            "isPasswordlessCapable": user.get("isPasswordlessCapable", False),
            "isSsprRegistered": user.get("isSsprRegistered", False),
            "methodsRegistered": methods,
            "userType": user_type,
            "lastUpdated": user.get("lastUpdatedDateTime", ""),
        }

        if is_mfa_registered:
            mfa_registered.append(user_record)
        else:
            mfa_not_registered.append(user_record)

        if is_mfa_capable:
            mfa_capable.append(user_record)
        else:
            mfa_not_capable.append(user_record)

        # High-risk: admins without MFA
        if is_admin and not is_mfa_registered:
            admins_no_mfa.append(user_record)

        # Categorize no-MFA by user type
        if not is_mfa_registered:
            if user_type == "member":
                members_no_mfa.append(user_record)
            elif user_type == "guest":
                guests_no_mfa.append(user_record)

    total = len(users)
    registered_count = len(mfa_registered)
    not_registered_count = len(mfa_not_registered)
    registration_rate = round(registered_count / total * 100, 1) if total > 0 else 0

    report = {
        "generated_at": now.isoformat(),
        "summary": {
            "total_users": total,
            "mfa_registered": registered_count,
            "mfa_not_registered": not_registered_count,
            "mfa_registration_rate": registration_rate,
            "mfa_capable": len(mfa_capable),
            "mfa_not_capable": len(mfa_not_capable),
            "admins_without_mfa": len(admins_no_mfa),
            "members_without_mfa": len(members_no_mfa),
            "guests_without_mfa": len(guests_no_mfa),
            "passwordless_capable": sum(1 for u in users if u.get("isPasswordlessCapable")),
        },
        "user_types": user_type_counts,
        "method_distribution": dict(sorted(method_distribution.items(), key=lambda x: x[1], reverse=True)),
        "high_risk": {
            "admins_without_mfa": admins_no_mfa,
        },
        "users_without_mfa": {
            "members": members_no_mfa,
            "guests": guests_no_mfa,
        },
        "all_users": sorted(users, key=lambda u: (u.get("isMfaRegistered", False), u.get("userDisplayName", ""))),
    }

    log.info(f"  MFA Report: {registered_count}/{total} registered ({registration_rate}%)")
    log.info(f"  Gap: {not_registered_count} users without MFA ({len(admins_no_mfa)} admins!)")

    return report


async def main():
    """Standalone run — fetch and write MFA report."""
    from dotenv import load_dotenv
    load_dotenv()

    report = await fetch_mfa_registration_details()
    if report:
        write_json("mfa_report.json", report)
        print(f"\n✅ MFA Report written to data/mfa_report.json")
        print(f"   Total users: {report['summary']['total_users']}")
        print(f"   MFA registered: {report['summary']['mfa_registered']} ({report['summary']['mfa_registration_rate']}%)")
        print(f"   WITHOUT MFA: {report['summary']['mfa_not_registered']}")
        print(f"   Admins without MFA: {report['summary']['admins_without_mfa']} ⚠️")
    else:
        print("❌ Failed to fetch MFA report")


if __name__ == "__main__":
    asyncio.run(main())
