# bitlocker_check.ps1 (Final Version)
# This script checks the BitLocker status for all FixedData drives and writes the output
# in JSON format to a log file for Wazuh monitoring.

try {
    if (-not (Get-Module -ListAvailable -Name BitLocker)) {
        throw "BitLocker PowerShell module is not available. Ensure the 'BitLocker Drive Encryption' feature is installed."
    }
    
    # --- THIS IS THE CORRECTED, MORE COMPATIBLE LINE ---
    # It uses Get-CimInstance which works on all modern Windows versions, including older PowerShell.
    $bitlockerVolumes = Get-BitLockerVolume -MountPoint (Get-CimInstance -ClassName Win32_Volume -Filter "DriveType=3").DriveLetter
    
    if ($null -eq $bitlockerVolumes) {
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
                "protection_status" = $volume.ProtectionStatus.ToString();
                "volume_status" = $volume.VolumeStatus.ToString();
                "encryption_method" = $volume.EncryptionMethod.ToString();
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
    $output = @{
        "bitlocker_status" = @{
            "state" = "error";
            "message" = "Script failed to execute. Error: $($_.Exception.Message)"
        }
    }
}

# Write the JSON output to a dedicated log file.
$logDir = "C:\ProgramData\Wazuh\logs"
$logFile = Join-Path -Path $logDir -ChildPath "bitlocker_status.log"
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}
$finalJson = ConvertTo-Json -InputObject $output -Compress
$finalJson | Out-File -FilePath $logFile -Encoding utf8
