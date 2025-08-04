# bitlocker_check.ps1
# This script checks the BitLocker status for all FixedData drives and writes the output
# in JSON format to a log file for Wazuh monitoring.

try {
    if (-not (Get-Module -ListAvailable -Name BitLocker)) {
        throw "BitLocker PowerShell module is not available. Ensure the 'BitLocker Drive Encryption' feature is installed."
    }
    
    $bitlockerVolumes = Get-BitLockerVolume -MountPoint (Get-Volume -DriveType Fixed).DriveLetter
    if ($null -eq $bitlockerVolumes) {
        # No BitLocker volumes found, which could be an issue in itself.
        $output = @{
            "bitlocker_status" = @{
                "state" = "error";
                "message" = "No BitLocker-managed volumes found on fixed drives."
            }
        }
    } else {
        # Process each volume
        $volume_reports = @()
        foreach ($volume in $bitlockerVolumes) {
            $volume_report = @{
                "mount_point" = $volume.MountPoint;
                "capacity_gb" = [math]::Round($volume.CapacityGB, 2);
                "protection_status" = $volume.ProtectionStatus.ToString(); # 'On', 'Off'
                "volume_status" = $volume.VolumeStatus.ToString(); # 'FullyEncrypted', 'FullyDecrypted', 'Encrypting'
                "encryption_method" = $volume.EncryptionMethod.ToString(); # e.g. 'XtsAes256'
                "key_protectors" = ($volume.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() }) -join ','
            }
            $volume_reports += $volume_report
        }
        $output = @{
            "bitlocker_status" = @{
                "state" = "success";
                "volumes" = $volume_reports
            }
        }
    }
}
catch {
    # Catch any errors during script execution
    $output = @{
        "bitlocker_status" = @{
            "state" = "error";
            "message" = "Script failed to execute. Error: $($_.Exception.Message)"
        }
    }
}

# --- NEW BEHAVIOR: Write the JSON output to a dedicated log file ---
# This file will be monitored by the Wazuh agent.

# Define the log file path. C:\ProgramData is the standard location for machine-wide application data.
$logDir = "C:\ProgramData\Wazuh\logs"
$logFile = Join-Path -Path $logDir -ChildPath "bitlocker_status.log"

# Ensure the directory exists before trying to write to it.
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

# Convert the final object to a single-line JSON string
$finalJson = ConvertTo-Json -InputObject $output -Compress

# Write the JSON to the log file, overwriting it each time with the latest status.
# Using UTF8 encoding is a best practice for compatibility with Wazuh.
$finalJson | Out-File -FilePath $logFile -Encoding utf8
