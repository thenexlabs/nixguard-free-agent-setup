# --- Section 2: Core Logic - Get BitLocker Status ---

$output = try {
    # Compatibility Check: Ensure the BitLocker module is even installed.
    if (-not (Get-Module -ListAvailable -Name BitLocker)) {
        throw "BitLocker PowerShell module is not available on this system."
    }

    # Use the most compatible method to get all BitLocker-managed fixed drives.
    $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue | Where-Object { $_.VolumeType -eq 'Fixed' }

    # --- THE FIX ---
    # Add a unique, high-precision timestamp to every log entry.
    # This defeats the agent's de-duplication and forces it to send every event.
    $eventTimestamp = Get-Date -Format "o" # ISO 8601 format, e.g., 2025-08-06T08:20:23.1234567Z

    if ($null -eq $bitlockerVolumes) {
        # ... (your existing failure_report logic)
        $systemDrive = (Get-CimInstance -ClassName Win32_OperatingSystem).SystemDrive
        $failure_report = @{
            "mount_point"       = $systemDrive;
            "protection_status" = "Off";
            "volume_status"     = "FullyDecrypted";
            "encryption_method" = "None";
            "key_protectors"    = ""
        }
        # Add the timestamp to the final object
        @{ "bitlocker_status" = @{ "timestamp" = $eventTimestamp; "state" = "success"; "volumes" = @($failure_report) } }
    }
    else {
        # ... (your existing volume_reports logic)
        $volume_reports = foreach ($volume in $bitlockerVolumes) {
            @{
                "mount_point"       = $volume.MountPoint;
                "protection_status" = $volume.ProtectionStatus.ToString();
                "volume_status"     = $volume.VolumeStatus.ToString();
                "encryption_method" = $volume.EncryptionMethod.ToString();
                "key_protectors"    = ($volume.KeyProtector | ForEach-Object { $_.KeyProtectorType.ToString() }) -join ','
            }
        }
        # Add the timestamp to the final object
        @{ "bitlocker_status" = @{ "timestamp" = $eventTimestamp; "state" = "success"; "volumes" = $volume_reports } }
    }
}
catch {
    # Also add a timestamp to error messages for uniqueness
    @{ "bitlocker_status" = @{ "timestamp" = (Get-Date -Format "o"); "state" = "error"; "message" = "Script failed during execution. Error: $($_.Exception.Message)" } }
}
