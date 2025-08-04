# ====================================================================================
# --- NEW SECTION: CREATE SCHEDULED TASK FOR BITLOCKER MONITORING (5-min interval for testing) ---
# ====================================================================================
Write-Host "Creating Scheduled Task for BitLocker monitoring..."
try {
    # Define the action: run the PowerShell script
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-File `"$destinationScriptPath`""

    # Define the trigger: run every 5 minutes for testing, starting now
    $trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -Once -At (Get-Date)

    # Define the principal: run as the SYSTEM account for highest reliability
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount

    # Register the task with the system
    Register-ScheduledTask -TaskName "Wazuh-BitLocker-Check" -Action $action -Trigger $trigger -Principal $principal -Description "Periodically checks BitLocker status for Wazuh monitoring." -Force
    
    Write-Host "Successfully created 'Wazuh-BitLocker-Check' scheduled task to run every 5 minutes." -ForegroundColor Green
}
catch {
    Write-Error "CRITICAL: Failed to create the scheduled task. Error: $($_.Exception.Message)"
    exit 1
}
# ====================================================================================
