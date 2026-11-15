# Paste your temporary credentials from the SSO Portal here
# Go to: https://d-9a67168ca6.awsapps.com/start/#/
# Click: Sandbox → AWSDeveloperAdminAccess → Access keys
# Copy all 3 values below:

$env:AWS_ACCESS_KEY_ID = ""
$env:AWS_SECRET_ACCESS_KEY = ""
$env:AWS_SESSION_TOKEN = ""

# Then run this to pull secrets:
# aws secretsmanager get-secret-value --secret-id "security-dashboard/credentials" --region us-east-1 --query "SecretString" --output text | Out-File -Encoding utf8 "C:\Users\DAAGNAOL\.aws\security-dashboard-v2\.env.secrets"
