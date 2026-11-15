"""AWS SSO Auto-Refresh - Forces Chrome Incognito for approval.
Runs aws sso login --no-browser, captures the URL, opens it in Chrome Incognito.
"""
import subprocess
import re
import os
import sys

CHROME = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
SSO_SESSION = "Oluwachei"

print("Starting AWS SSO login (no-browser mode)...")
print("Will open Chrome Incognito for approval.")
print("Sign in as: a-oluwacheid@homeownersvcs.onmicrosoft.com")
print()

# Start aws sso login --no-browser and capture output
proc = subprocess.Popen(
    ["aws", "sso", "login", "--sso-session", SSO_SESSION, "--no-browser"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
)

# Read output lines looking for the URL
url_found = False
for line in iter(proc.stdout.readline, ""):
    print(line.rstrip())
    # Look for the verification URL
    match = re.search(r"(https://\S+)", line)
    if match and not url_found:
        url = match.group(1)
        url_found = True
        print(f"\nOpening Chrome (clean profile): {url}\n")
        subprocess.Popen([CHROME, "--incognito", "--user-data-dir=C:\\Temp\\sso-chrome", "--no-first-run", "--no-default-browser-check", url])

# Wait for the login to complete
proc.wait()
print(f"\nSSO login completed with exit code: {proc.returncode}")
