#!/usr/bin/env python3
"""
Fetch AWS WorkSpaces inventory from the Infrastructure account.
Writes aws_workspaces.json to the data/ directory.

Usage:
    python refresh_workspaces.py          # Uses 'infra' profile (SSO)
    python refresh_workspaces.py --loop   # Runs every 15 minutes

Requires: boto3, valid SSO session for 'infra' profile
"""
import json
import os
import sys
import time
import argparse
from datetime import datetime, timezone

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
OUTPUT_FILE = os.path.join(DATA_DIR, "aws_workspaces.json")

PROFILE = "infra"
REGION = os.getenv("WORKSPACES_REGION", "us-east-1")
INTERVAL = 900


def fetch_workspaces():
    """Pull all WorkSpaces from the Infrastructure account."""
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError

    print(f"[WorkSpaces] Fetching from profile '{PROFILE}', region '{REGION}'...")

    try:
        session = boto3.Session(profile_name=PROFILE, region_name=REGION)
        client = session.client("workspaces")
    except Exception as e:
        print(f"[WorkSpaces] Failed to create session: {e}")
        return None

    all_workspaces = []
    next_token = None

    try:
        while True:
            params = {}
            if next_token:
                params["NextToken"] = next_token
            response = client.describe_workspaces(**params)
            for ws in response.get("Workspaces", []):
                all_workspaces.append({
                    "WorkspaceId": ws.get("WorkspaceId", ""),
                    "DirectoryId": ws.get("DirectoryId", ""),
                    "UserName": ws.get("UserName", ""),
                    "IpAddress": ws.get("IpAddress", ""),
                    "State": ws.get("State", ""),
                    "BundleId": ws.get("BundleId", ""),
                    "SubnetId": ws.get("SubnetId", ""),
                    "ComputerName": ws.get("ComputerName", ""),
                    "WorkspaceProperties": {
                        "RunningMode": ws.get("WorkspaceProperties", {}).get("RunningMode", ""),
                        "ComputeTypeName": ws.get("WorkspaceProperties", {}).get("ComputeTypeName", ""),
                    },
                    "RootVolumeEncrypted": ws.get("RootVolumeEncryptionEnabled", False),
                    "UserVolumeEncrypted": ws.get("UserVolumeEncryptionEnabled", False),
                })
            next_token = response.get("NextToken")
            if not next_token:
                break
    except ClientError as e:
        print(f"[WorkSpaces] API error: {e}")
        return None
    except NoCredentialsError:
        print("[WorkSpaces] No credentials. Run: aws sso login --profile infra")
        return None

    return all_workspaces


def write_output(workspaces):
    """Write the WorkSpaces data to JSON."""
    os.makedirs(DATA_DIR, exist_ok=True)
    total = len(workspaces)
    available = sum(1 for ws in workspaces if ws["State"] == "AVAILABLE")
    stopped = sum(1 for ws in workspaces if ws["State"] == "STOPPED")

    output = {
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "account": "Infrastructure (446329232350)",
        "region": REGION,
        "summary": {"total": total, "available": available, "stopped": stopped, "other": total - available - stopped},
        "workspaces": workspaces,
    }
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"[WorkSpaces] Written {total} workspaces to {OUTPUT_FILE}")
    print(f"  Available: {available} | Stopped: {stopped} | Other: {total - available - stopped}")


def main():
    parser = argparse.ArgumentParser(description="Fetch AWS WorkSpaces inventory")
    parser.add_argument("--loop", action="store_true", help="Run continuously every 15 min")
    args = parser.parse_args()

    if args.loop:
        print(f"[WorkSpaces] Running in loop mode (interval: {INTERVAL}s)")
        while True:
            try:
                workspaces = fetch_workspaces()
                if workspaces is not None:
                    write_output(workspaces)
            except Exception as e:
                print(f"[WorkSpaces] Error: {e}")
            time.sleep(INTERVAL)
    else:
        workspaces = fetch_workspaces()
        if workspaces is not None:
            write_output(workspaces)
        else:
            print("[WorkSpaces] Failed to fetch. Check SSO session.")
            sys.exit(1)


if __name__ == "__main__":
    main()
