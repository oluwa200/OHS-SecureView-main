"""
Secrets Loader — Pulls credentials from AWS Secrets Manager.
Falls back to .env file if Secrets Manager is unavailable (local dev).

Usage:
    from secrets import load_secrets
    load_secrets()  # Call once at startup — sets os.environ

Secret name: security-dashboard/credentials
Region: us-east-1
Profile: sandbox-admin (or IAM role in ECS/EKS)
"""
import os
import json
import logging

log = logging.getLogger(__name__)

SECRET_NAME = os.getenv("SECRET_NAME", "security-dashboard/credentials")
SECRET_REGION = os.getenv("SECRET_REGION", "us-east-1")


def load_secrets():
    """Load secrets from AWS Secrets Manager into os.environ.
    
    Falls back to .env file via python-dotenv if SM is unavailable.
    Only sets env vars that are NOT already set (existing env takes precedence).
    """
    # Try Secrets Manager first
    sm_loaded = _load_from_secrets_manager()
    
    if not sm_loaded:
        # Fallback to .env
        try:
            from dotenv import load_dotenv
            load_dotenv()
            log.info("Secrets loaded from .env file (Secrets Manager unavailable)")
        except ImportError:
            log.warning("Neither Secrets Manager nor python-dotenv available")


def _load_from_secrets_manager() -> bool:
    """Attempt to load secrets from AWS Secrets Manager.
    
    Returns True if successful, False if unavailable.
    """
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError
    except ImportError:
        log.debug("boto3 not installed — skipping Secrets Manager")
        return False

    try:
        # Try with profile first (local dev), then default creds (container/IAM role)
        session = None
        for profile in [os.getenv("AWS_PROFILE"), "sandbox-admin", "sandbox", None]:
            try:
                if profile:
                    session = boto3.Session(profile_name=profile, region_name=SECRET_REGION)
                else:
                    session = boto3.Session(region_name=SECRET_REGION)
                # Test if session has valid creds
                sts = session.client("sts")
                sts.get_caller_identity()
                break
            except (ClientError, NoCredentialsError, BotoCoreError):
                session = None
                continue

        if not session:
            log.debug("No valid AWS credentials found for Secrets Manager")
            return False

        client = session.client("secretsmanager", region_name=SECRET_REGION)
        response = client.get_secret_value(SecretId=SECRET_NAME)
        secret_string = response.get("SecretString", "{}")
        secrets = json.loads(secret_string)

        if not secrets:
            log.warning(f"Secret '{SECRET_NAME}' is empty")
            return False

        # Set env vars (don't override existing ones)
        loaded_count = 0
        for key, value in secrets.items():
            if key and value and not os.getenv(key):
                os.environ[key] = str(value)
                loaded_count += 1

        log.info(f"Loaded {loaded_count} secrets from AWS Secrets Manager ({SECRET_NAME})")
        return True

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "ResourceNotFoundException":
            log.debug(f"Secret '{SECRET_NAME}' not found in Secrets Manager")
        elif error_code == "AccessDeniedException":
            log.debug("Access denied to Secrets Manager — check IAM permissions")
        else:
            log.debug(f"Secrets Manager error: {e}")
        return False
    except (NoCredentialsError, BotoCoreError) as e:
        log.debug(f"AWS credentials not available: {e}")
        return False
    except Exception as e:
        log.debug(f"Unexpected error loading secrets: {e}")
        return False
