"""
Refresh IAM Access Key Ages from all 4 scoped AWS accounts.
Requires: Active AWS SSO session (aws sso login --sso-session Oluwachei --no-browser)

Usage:
    python refresh_iam_keys.py
"""
import json
import os
import sys
from datetime import datetime, timezone

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
KEY_AGE_CRITICAL = 90


def main():
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError:
        print("ERROR: boto3 not installed. Run: pip install boto3")
        sys.exit(1)

    profiles = [
        {"name": "Infrastructure", "profile": "infra", "account_id": "446329232350"},
        {"name": "Production", "profile": "prod", "account_id": "937786629491"},
        {"name": "Network", "profile": "network", "account_id": "895945783203"},
        {"name": "Test and QA", "profile": "test-qa", "account_id": "754120856488"},
    ]

    result = {
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "accounts": {},
    }

    total_keys = 0
    total_non_compliant = 0

    for p in profiles:
        print(f"\n{'='*50}")
        print(f"Account: {p['name']} ({p['account_id']})")
        print(f"{'='*50}")
        try:
            session = boto3.Session(profile_name=p["profile"])
            iam = session.client("iam")
            keys = []

            # List all users
            paginator = iam.get_paginator("list_users")
            user_count = 0
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]
                    user_count += 1

                    # List access keys for user
                    key_resp = iam.list_access_keys(UserName=username)
                    for key_meta in key_resp.get("AccessKeyMetadata", []):
                        key_id = key_meta["AccessKeyId"]
                        create_date = key_meta["CreateDate"].isoformat()
                        status = key_meta["Status"]

                        # Calculate age
                        age_days = (datetime.now(timezone.utc) - key_meta["CreateDate"].replace(tzinfo=timezone.utc)).days

                        # Get last used info
                        try:
                            last_used_resp = iam.get_access_key_last_used(AccessKeyId=key_id)
                            last_used = last_used_resp.get("AccessKeyLastUsed", {})
                            last_used_date = last_used.get("LastUsedDate", "")
                            last_used_service = last_used.get("ServiceName", "N/A")
                            if last_used_date:
                                last_used_date = last_used_date.isoformat()
                            else:
                                last_used_date = "Never"
                        except Exception:
                            last_used_date = "N/A"
                            last_used_service = "N/A"

                        keys.append({
                            "username": username,
                            "access_key_id": key_id,
                            "status": status,
                            "create_date": create_date,
                            "age_days": age_days,
                            "last_used_date": last_used_date,
                            "last_used_service": last_used_service,
                        })

                        # Flag non-compliant
                        flag = "🔴" if age_days > KEY_AGE_CRITICAL else "  "
                        if age_days > 60:
                            print(f"  {flag} {username}: {key_id} ({status}) — {age_days} days old")

            non_compliant = sum(1 for k in keys if k["age_days"] > KEY_AGE_CRITICAL)
            total_keys += len(keys)
            total_non_compliant += non_compliant

            result["accounts"][p["name"]] = {
                "account_id": p["account_id"],
                "keys": keys,
                "total_keys": len(keys),
                "total_users": user_count,
                "non_compliant": non_compliant,
            }
            print(f"  Users: {user_count} | Keys: {len(keys)} | Non-compliant (>90d): {non_compliant}")

        except NoCredentialsError:
            print(f"  ❌ No credentials. Run: aws sso login --sso-session Oluwachei --no-browser")
            result["accounts"][p["name"]] = {"account_id": p["account_id"], "keys": [], "error": "NoCredentials"}
        except ClientError as e:
            print(f"  ❌ Error: {e}")
            result["accounts"][p["name"]] = {"account_id": p["account_id"], "keys": [], "error": str(e)}

    # Write output
    os.makedirs(DATA_DIR, exist_ok=True)
    output_path = os.path.join(DATA_DIR, "iam_access_keys.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

    print(f"\n{'='*50}")
    print(f"SUMMARY")
    print(f"{'='*50}")
    print(f"Total keys: {total_keys}")
    print(f"Non-compliant (>90 days): {total_non_compliant}")
    compliance_pct = round((total_keys - total_non_compliant) / total_keys * 100, 1) if total_keys > 0 else 100
    print(f"Compliance: {compliance_pct}%")
    print(f"Output: {output_path}")


if __name__ == "__main__":
    main()
