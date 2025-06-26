param (
  [string]$agentName,
  [string]$ipAddress,
  [string]$groupLabel
)

# Check if the system is 64-bit or 32-bit
if ([IntPtr]::Size -eq 8) {
    # For 64-bit Windows
    $ossecAgentPath = "C:\Program Files (x86)\ossec-agent"
} else {
    # For 32-bit Windows
    $ossecAgentPath = "C:\Program Files\ossec-agent"
}

$configPath = Join-Path -Path $ossecAgentPath -ChildPath "ossec.conf"

# --- Final Robust Uninstall Function ---
# This function is well-written and is preserved exactly as it was.
function Uninstall-WazuhAgent-Final {

    Write-Host "--- Starting Wazuh Agent Uninstall Process ---" -ForegroundColor Yellow

    # Step 1: Attempt to stop the service first to release file locks.
    Write-Host "Attempting to stop the Wazuh Agent service (WazuhSvc)..."
    $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name "WazuhSvc" -Force -ErrorAction SilentlyContinue
        Write-Host "Waiting 5 seconds for processes to terminate..."
        Start-Sleep -Seconds 5
    }

    # Step 2: Find the Wazuh Agent installation by checking the registry.
    Write-Host "Searching for Wazuh Agent in the list of installed programs..."
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $wazuhApp = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "Wazuh Agent" }

    # Step 3: Check if the agent was found and act accordingly.
    if (-not $wazuhApp) {
        Write-Host "SUCCESS: Wazuh Agent was not found in the list of installed programs. No action needed." -ForegroundColor Green
        return
    }

    # --- AGENT WAS FOUND ---
    Write-Host "Found Wazuh Agent. Running the official uninstaller silently..."
    $productCode = $wazuhApp.PSChildName
    $command = "msiexec.exe"
    $arguments = "/x $productCode /q"
    Start-Process -FilePath $command -ArgumentList $arguments -Wait -NoNewWindow
    Write-Host "Uninstaller process has finished."

    # --- Final Cleanup ---
    if (Test-Path $ossecAgentPath) {
        Write-Host "Performing post-uninstall cleanup of the installation directory..."
        Remove-Item -Recurse -Force $ossecAgentPath -ErrorAction SilentlyContinue
        if (!(Test-Path $ossecAgentPath)) {
            Write-Host "Directory successfully removed." -ForegroundColor Green
        } else {
            Write-Error "FAILED to remove directory: $ossecAgentPath. Please remove it manually or reboot."
        }
    } else {
        Write-Host "Wazuh Agent uninstall complete." -ForegroundColor Green
    }
}

# --- Run the improved function ---
Uninstall-WazuhAgent-Final


# =========================================================================================
# --- CORRECTED WAZUH AGENT INSTALLATION ---
# The entire original installation block has been replaced with this reliable method.
# It uses the installer's built-in parameters to handle registration, which is the
# only way to correctly generate the agent's authentication key. All manual config
# edits for installation have been removed as they were causing the connection failure.
# =========================================================================================

Write-Host "--- Starting New Wazuh Agent Installation ---" -ForegroundColor Yellow

# Define installer specifics
$wazuhVersion = "4.9.1-1"
$installerUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$($wazuhVersion).msi"
$msiPath = Join-Path -Path $env:TEMP -ChildPath "wazuh-agent-$($wazuhVersion).msi" # FIX: Added .msi extension

try {
    # Download the installer
    Write-Host "Downloading installer..."
    Invoke-WebRequest -Uri $installerUrl -OutFile $msiPath -UseBasicParsing

    # Construct the argument list for a proper installation. This is the key fix.
    $argumentList = @(
        "/i",
        "`"$msiPath`"", # Path to the MSI in quotes
        "/q",          # Quiet mode
        "WAZUH_MANAGER='$ipAddress'",
        "WAZUH_REGISTRATION_SERVER='$ipAddress'",
        "WAZUH_AGENT_NAME='$agentName'",
        "WAZUH_AGENT_GROUP='$groupLabel'"
    )
    
    # Run the installer and wait for it to complete
    Write-Host "Running installer with registration parameters..."
    $installerProcess = Start-Process -FilePath "msiexec.exe" -ArgumentList $argumentList -Wait -PassThru

    # CRITICAL CHECK: If installation fails, stop the entire script.
    if ($installerProcess.ExitCode -ne 0) {
        Write-Error "CRITICAL: Wazuh Agent installation FAILED with exit code: $($installerProcess.ExitCode). Aborting script. Check for agent name conflicts."
        throw "Installation failed." # This stops execution and jumps to the finally block
    }

    Write-Host "SUCCESS: Wazuh Agent base installation and registration complete." -ForegroundColor Green
}
catch {
    # This will catch the 'throw' command or any other script-breaking error.
    Write-Error "Halting script due to installation failure."
    exit 1 # Exit the entire script with a failure code
}
finally {
    # Always clean up the downloaded installer file.
    if (Test-Path $msiPath) {
        Remove-Item -Path $msiPath -Force
    }
}

# --- If we get here, the base installation was successful. All subsequent custom logic will now run. ---


# //////////////////////////////////////////////////////////////////////////////////////////////////////////
# --- NixGuard API Call (Preserved) ---
# //////////////////////////////////////////////////////////////////////////////////////////////////////////

# Define the API URL
$API_URL = "https://api.thenex.world/get-user"
$JSON_PAYLOAD = @{ groupLabel = $groupLabel } | ConvertTo-Json -Depth 10
$response = Invoke-RestMethod -Uri $API_URL -Method Post -Body $JSON_PAYLOAD -ContentType "application/json"
$token = $response.token

Function Decode-JWT {
    # Your JWT decoding function is preserved exactly as it was.
    param ([string]$jwtToken)
    $tokenParts = $jwtToken -split '\.'
    if ($tokenParts.Length -ge 2) {
        $payload = $tokenParts[1]
        $standardBase64Payload = $payload.Replace("-", "+").Replace("_", "/")
        switch ($standardBase64Payload.Length % 4) {
            1 { $standardBase64Payload += "===" }
            2 { $standardBase64Payload += "==" }
            3 { $standardBase64Payload += "=" }
        }
        try {
            $decodedPayload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($standardBase64Payload))
            return ($decodedPayload | ConvertFrom-Json)
        } catch { Write-Error "Failed to decode payload: $_" }
    } else { Write-Error "Invalid JWT token format." }
    return $null
}

# Decode the extracted token
$decodedPayload = Decode-JWT -jwtToken $token
if ($decodedPayload -ne $null) {
    # Your logic for handling the decoded payload is preserved.
    if ($decodedPayload.complianceStandards -contains "SOC2" -or $decodedPayload.complianceStandards -contains "NIST SP 800-53" -or $decodedPayload.complianceStandards -contains "ISO 27001" -or $decodedPayload.complianceStandards -contains "GDPR" -or $decodedPayload.complianceStandards -contains "HIPAA" -or $decodedPayload.complianceStandards -contains "PCI DSS" -or $decodedPayload.complianceStandards -contains "PIPEDA" -or $decodedPayload.complianceStandards -contains "CIS Controls") {
        Write-Output "Encryption required: encrypted"
    } else { Write-Output "No encryption required." }
} else { Write-Output "Failed to decode the JWT token." }


# //////////////////////////////////////////////////////////////////////////////////////////////////////////
# --- Custom FIM Configuration (Preserved) ---
# Note: The incorrect manual <enrollment> section has been removed as it's now handled by the installer.
# //////////////////////////////////////////////////////////////////////////////////////////////////////////

Write-Host "Applying custom File Integrity Monitoring (FIM) configuration..."
[xml]$ossecConf = Get-Content -Path $configPath
$syscheckNode = $ossecConf.ossec_config.syscheck
if (-not $syscheckNode) {
    $syscheckNode = $ossecConf.CreateElement("syscheck")
    $ossecConf.ossec_config.AppendChild($syscheckNode) | Out-Null
}
$commentNode = $syscheckNode.SelectSingleNode("comment()[contains(.,'<!-- Default files to be monitored. -->')]")
if ($commentNode) {
    # Your logic for adding directories is preserved.
    $directories = @("$env:WINDIR\System32", "$env:ProgramFiles", "$env:ProgramFiles(x86)", "HKEY_LOCAL_MACHINE\SYSTEM", "$env:USERPROFILE", "$env:ProgramData", "$env:ProgramFiles\Common Files", "$env:ProgramFiles(x86)\Common Files", "$env:USERPROFILE\Downloads")
    foreach ($directory in $directories) {
        $newDirectoryNode = $ossecConf.CreateElement("directories")
        $newDirectoryNode.SetAttribute("check_all", "yes"); $newDirectoryNode.SetAttribute("whodata", "yes"); $newDirectoryNode.SetAttribute("realtime", "yes")
        $newDirectoryNode.InnerText = $directory
        $syscheckNode.InsertAfter($newDirectoryNode, $commentNode) | Out-Null
    }
}
$ossecConf.Save($configPath)
Write-Host "Directory monitoring configuration added successfully."


# //////////////////////////////////////////////////////////////////////////////////////////////////////////
# --- Custom Active Response Setup (Preserved) ---
# //////////////////////////////////////////////////////////////////////////////////////////////////////////

Write-Host "Setting up custom Active Response: remove-threat.exe..."
# Define the URL of the Python installer
$pythonUrl = "https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe"
$pythonInstallerPath = Join-Path -Path $env:TEMP -ChildPath "python-installer.exe"
Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstallerPath
Start-Process -FilePath $pythonInstallerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait

# Install PyInstaller
py -m pip install pyinstaller

# Download and compile remove-threat.py
$removeThreatUrl = "https://github.com/thenexlabs/nixguard-agent-setup/raw/main/windows/remove-threat.py"
$removeThreatPath = Join-Path -Path $env:TEMP -ChildPath "remove-threat.py"
Invoke-WebRequest -Uri $removeThreatUrl -OutFile $removeThreatPath
Set-Location -Path $env:TEMP
Invoke-Expression -Command "py -m PyInstaller -F $removeThreatPath"

# Move the executable and clean up
$exePath = Join-Path -Path $env:TEMP -ChildPath "dist\remove-threat.exe"
$destDir = Join-Path -Path $ossecAgentPath -ChildPath "active-response\bin"
Move-Item -Path $exePath -Destination $destDir -Force
Remove-Item -Path (Join-Path -Path $env:TEMP -ChildPath "remove-threat.spec") -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path -Path $env:TEMP -ChildPath "dist") -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path (Join-Path -Path $env:TEMP -ChildPath "build") -Recurse -ErrorAction SilentlyContinue
Write-Host "Virus threat response configuration added successfully."


# //////////////////////////////////////////////////////////////////////////////////////////////////////////
# --- Finalization (Preserved) ---
# //////////////////////////////////////////////////////////////////////////////////////////////////////////

Write-Host "NixGuard agent setup successfully." -ForegroundColor Cyan
# Start Wazuh agent service to apply all new configurations.
Start-Process -FilePath "NET" -ArgumentList "START WazuhSvc"
Write-Host "NixGuard agent started successfully." -ForegroundColor Cyan
