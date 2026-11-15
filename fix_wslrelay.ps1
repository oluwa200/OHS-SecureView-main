# fix_wslrelay.ps1 — Silently kills stuck wslrelay processes ONLY when blocking Docker ports
# Runs as a hidden scheduled task. No window, no output unless there's an actual fix needed.

$TargetPorts = @(8502, 8443, 8080)
$FixApplied = $false

foreach ($port in $TargetPorts) {
    # Only act if there's a stuck connection in CloseWait state
    $stuckConnections = Get-NetTCPConnection -LocalPort $port -State CloseWait -ErrorAction SilentlyContinue
    if (-not $stuckConnections) { continue }

    foreach ($conn in $stuckConnections) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        if ($proc -and $proc.ProcessName -eq "wslrelay") {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            $FixApplied = $true
        }
    }
}

# Only log if we actually fixed something (keeps things silent otherwise)
if ($FixApplied) {
    $logFile = "$env:USERPROFILE\.aws\security-dashboard-v2\wslrelay_fixes.log"
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Killed stuck wslrelay process(es)" | Out-File -Append -FilePath $logFile
}
