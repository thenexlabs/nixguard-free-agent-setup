# bitlocker_check.ps1 (FINAL PRODUCTION VERSION)
# This script robustly checks BitLocker status and writes the output to a log file.

try {
    if (-not (Get-Module -ListAvailable -Name BitLocker)) {
        throw "BitLocker PowerShell module is not available."
    }
    
    # 1. Get all volumes classified as 'Fixed'.
    $allFixedVolumes = Get-CimInstance -ClassName Win32_Volume -Filter "DriveType=3"
    
    # 2. Create an empty list to hold ONLY the volumes that have a drive letter.
    $validDriveLetters = @()
    
    # 3. Loop through the results and filter out any partitions without a drive letter.
    if ($null -ne $allFixedVolumes) {
        foreach ($volume in $allFixedVolumes) {
            if (-not [string]::IsNullOrWhiteSpace($volume.DriveLetter)) {
                $validDriveLetters += $volume.DriveLetter
            }
        }
    }
    
    # 4. Check if we have any valid drives left to check.
    if ($validDriveLetters.Count -eq 0) {
        throw "Found fixed volumes, but none have an assigned drive letter to check for BitLocker status."
    }

    # 5. Now, get the BitLocker status ONLY for the drives with valid letters.
    $bitlockerVolumes = Get-BitLockerVolume -MountPoint $validDriveLetters
    
    if ($null -eq $bitlockerVolumes) {
        $output = @{ "bitlocker_status" = @{ "state" = "error"; "message" = "No BitLocker-managed volumes found on fixed drives." } }
    } else {
        $volume_reports = @()
        foreach ($volume in $bitlockerVolumes) {
            $volume_report = @{
                "mount_point" = $volume.MountPoint;
                "protection_status" = $volume.ProtectionStatus.ToString();
                "volume_status" = $volume.VolumeStatus.ToString();
                "encryption_method" = $volume.EncryptionMethod.ToString();
                "key_protectors" = ($volume.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() }) -join ','
            }
            $volume_reports += $volume_report
        }
        $output = @{ "bitlocker_status" = @{ "state" = "success"; "volumes" = $volume_reports } }
    }
}
catch {
    $output = @{ "bitlocker_status" = @{ "state" = "error"; "message" = "Script failed to execute. Error: $($_.Exception.Message)" } }
}

# Write the JSON output to the dedicated log file.
$logFile = "C:\ProgramData\Wazuh\logs\bitlocker_status.log"
$finalJson = ConvertTo-Json -InputObject $output -Compress
$finalJson | Out-File -FilePath $logFile -Encoding utf8
