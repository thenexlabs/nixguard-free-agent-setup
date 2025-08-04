# bitlocker_check.ps1 (DIAGNOSTIC VERSION)
# This script's only purpose is to see what the WMI query returns when run as SYSTEM.

try {
    # Run the WMI query to find fixed drives (disks, not CD-ROMs, etc.)
    $fixedDrives = Get-CimInstance -ClassName Win32_Volume -Filter "DriveType=3"

    # We will now create a detailed debug object
    $debug_output = @{
        "diagnostic_run" = @{
            "timestamp" = (Get-Date -Format 'u');
            "query" = "Get-CimInstance -ClassName Win32_Volume -Filter 'DriveType=3'";
            "result_is_null" = ($null -eq $fixedDrives);
            "result_count" = if ($null -ne $fixedDrives) { @($fixedDrives).Count } else { 0 };
            "raw_result" = $fixedDrives | Select-Object *; # Select all properties
        }
    }
}
catch {
    # If the WMI query itself fails, log that error
    $debug_output = @{
        "diagnostic_run" = @{
            "timestamp" = (Get-Date -Format 'u');
            "state" = "error";
            "message" = "WMI query failed. Error: $($_.Exception.Message)"
        }
    }
}

# --- Write the debug output to the log file ---
$logDir = "C:\ProgramData\Wazuh\logs"
$logFile = Join-Path -Path $logDir -ChildPath "bitlocker_status.log"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}
# Use -Depth 3 to ensure we see all the nested properties
$finalJson = ConvertTo-Json -InputObject $debug_output -Depth 3
$finalJson | Out-File -FilePath $logFile -Encoding utf8
