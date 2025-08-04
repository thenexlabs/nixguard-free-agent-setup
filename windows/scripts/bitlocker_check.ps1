# bitlocker_check.ps1 (DIAGNOSTIC VERSION)
# This script's only purpose is to see what the WMI query returns when run as SYSTEM.

try {
    # Run the WMI query to find fixed drives (physical disks, not CD-ROMs, etc.)
    # DriveType=3 is the standard value for local, fixed disks.
    $fixedDrives = Get-CimInstance -ClassName Win32_Volume -Filter "DriveType=3"

    # We will now create a detailed debug object to log everything we find.
    $debug_output = @{
        "diagnostic_run" = @{
            "timestamp" = (Get-Date -Format 'o'); # ISO 8601 format is better
            "query" = "Get-CimInstance -ClassName Win32_Volume -Filter 'DriveType=3'";
            "result_is_null" = ($null -eq $fixedDrives);
            "result_count" = if ($null -ne $fixedDrives) { @($fixedDrives).Count } else { 0 };
            "raw_result" = $fixedDrives | Select-Object *; # Select all available properties to see what we're getting
        }
    }
}
catch {
    # If the WMI query itself fails for any reason, log that error.
    $debug_output = @{
        "diagnostic_run" = @{
            "timestamp" = (Get-Date -Format 'o');
            "state" = "error";
            "message" = "The WMI query 'Get-CimInstance' failed to execute. Error: $($_.Exception.Message)"
        }
    }
}

# --- Write the debug output to the log file ---
$logDir = "C:\ProgramData\Wazuh\logs"
$logFile = Join-Path -Path $logDir -ChildPath "bitlocker_status.log"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

# Use -Depth 3 to ensure we can see all the nested properties of the WMI object.
$finalJson = ConvertTo-Json -InputObject $debug_output -Depth 3

# Overwrite the log file with the latest diagnostic data.
$finalJson | Out-File -FilePath $logFile -Encoding utf8
