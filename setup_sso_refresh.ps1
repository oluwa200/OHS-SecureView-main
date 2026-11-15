# Setup AWS SSO Auto-Refresh Scheduled Task
# Runs every 8 hours to refresh the SSO token before it expires

$TaskName = "AWS-SSO-AutoRefresh"
$Description = "Auto-refreshes AWS SSO token every 8 hours for SecureView dashboard"

# Remove existing task if present
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# Create the action
$Action = New-ScheduledTaskAction -Execute "aws" -Argument "sso login --sso-session Oluwachei"

# Trigger: every 8 hours
$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 8)

# Settings
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

# Register without elevated RunLevel
Register-ScheduledTask -TaskName $TaskName -Description $Description -Action $Action -Trigger $Trigger -Settings $Settings

Write-Host ""
Write-Host "Done! Task created: $TaskName" -ForegroundColor Green
Write-Host "Runs every 8 hours. Browser will open for approval."
Write-Host ""
