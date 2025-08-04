param (
  [string]$agentName,
  [string]$ipAddress,
  [string]$groupLabel
)

# Check if the system is 64-bit or 32-bit
if ([IntPtr]::Size -eq 8) {
    # For 64-bit Windows
    $ossecAgentPath = "C:\\Program Files (x86)\\ossec-agent"
} else {
    # For 32-bit Windows
    $ossecAgentPath = "C:\\Program Files\\ossec-agent"
}

$configPath = $ossecAgentPath + "\\ossec.conf"

# Open PowerShell as an Administrator to run this script

# --- Final Robust Uninstall Function ---
function Uninstall-WazuhAgent {

    Write-Host "--- Starting Wazuh Agent Uninstall Process ---" -ForegroundColor Yellow

    # Step 1: Attempt to stop the service first to release file locks.
    Write-Host "Attempting to stop the Wazuh Agent service (WazuhSvc)..."
    $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name "WazuhSvc" -Force -ErrorAction SilentlyContinue
        # Give the service a few seconds to fully terminate its processes
        Write-Host "Waiting 5 seconds for processes to terminate..."
        Start-Sleep -Seconds 5
    }

    # Step 2: Find the Wazuh Agent installation by checking the registry (much faster and more reliable than Get-WmiObject).
    Write-Host "Searching for Wazuh Agent in the list of installed programs..."
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $wazuhApp = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "Wazuh Agent" }

    # Step 3: Check if the agent was found and act accordingly.
    if (-not $wazuhApp) {
        # --- AGENT NOT FOUND ---
        Write-Host "SUCCESS: Wazuh Agent was not found in the list of installed programs. No action needed." -ForegroundColor Green
        # The return command exits the function immediately.
        return
    }

    # --- AGENT WAS FOUND ---
    Write-Host "Found Wazuh Agent. Running the official uninstaller silently..."
    
    # The UninstallString contains the command to run, e.g., "MsiExec.exe /I{PRODUCT-CODE-GUID}"
    # We will modify it to run silently.
    $uninstallCommand = $wazuhApp.UninstallString
    if ($uninstallCommand -like "MsiExec.exe*") {
        # For MSI packages, we replace the interactive flag (/I) with the uninstall flag (/X) and add the quiet flag (/q).
        $productCode = $wazuhApp.PSChildName
        $command = "msiexec.exe"
        $arguments = "/x $productCode /q"
        Write-Host "Executing: $command $arguments"
        Start-Process -FilePath $command -ArgumentList $arguments -Wait -NoNewWindow
    } else {
        # Fallback for non-MSI installers, though Wazuh uses MSI.
        Write-Host "Executing non-MSI uninstaller: $uninstallCommand"
        Start-Process -FilePath $uninstallCommand -ArgumentList "/S" -Wait -NoNewWindow # /S is a common silent flag
    }
    
    Write-Host "Uninstaller process has finished."

    # --- Final Cleanup ---
    # After a proper uninstall, the directory should be gone, but we check just in case.
    $agentDir = "C:\Program Files (x86)\ossec-agent"
    if (Test-Path $agentDir) {
        Write-Host "Performing post-uninstall cleanup of the installation directory..."
        Remove-Item -Recurse -Force $agentDir -ErrorAction SilentlyContinue
        
        # Final check
        if (!(Test-Path $agentDir)) {
            Write-Host "Directory successfully removed." -ForegroundColor Green
        } else {
            # If it still fails, it's likely a stubborn orphaned process.
            Write-Error "FAILED to remove directory: $agentDir. A process may still be locking it. Please remove it manually or reboot."
        }
    } else {
        Write-Host "Wazuh Agent uninstall complete." -ForegroundColor Green
    }
}

# --- Run the function ---
Uninstall-WazuhAgent

# Kill the cached file
Remove-Item -Path (Join-Path -Path $env:TEMP -ChildPath "agent-automatic-setup.ps1") -ErrorAction SilentlyContinue

# Install the Wazuh agent
## loop until file is gone
$fileExists = $true
while ($fileExists) {
    if (Test-Path -Path $configPath) {
        Write-Host ".."
        Start-Sleep -Seconds 3
    } else {
        $fileExists = $false
        Write-Host "."
    }
}

$maxRetries = 4
$retryCount = 0

do {
    Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.1-1.msi -OutFile "${env:tmp}\wazuh-agent"

    $workingCommand = "msiexec.exe /i `"`${env:tmp}\wazuh-agent`" /q WAZUH_MANAGER='$ipAddress' WAZUH_REGISTRATION_SERVER='$ipAddress' WAZUH_AGENT_GROUP='$groupLabel' WAZUH_AGENT_NAME='$agentName'"

    $wazuhInstaller = Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -NoProfile -Command `"$workingCommand`"" -PassThru -Wait

    if ($wazuhInstaller.ExitCode -ne 0) {
        Write-Host "Installer process exited with code $($wazuhInstaller.ExitCode)"
        $retryCount++
        if ($retryCount -le $maxRetries) {
            Write-Host "Retrying installation ($retryCount of $maxRetries)..."
            Start-Sleep -Seconds 10
        } else {
            Write-Host "Installation failed after $maxRetries attempts."
            exit $wazuhInstaller.ExitCode
        }
    } else {
        break
    }
} while ($true)

$counter = 0
$fileExists = $false
while (-not $fileExists) {
    if (Test-Path -Path $configPath) {
        $fileExists = $true
        Write-Host "."
    } else {
        Write-Host ".."
        Start-Sleep -Seconds 3
    }
    $counter++
}

# This acts as a final safeguard to ensure the IP is correct.
$config = Get-Content -Path $configPath
$config = $config -replace '<address>0.0.0.0</address>', "<address>$ipAddress</address>"
Set-Content -Path $configPath -Value $config

# //////////////////////////////////////////////////////////////////////////////////////////////////////////

# Define the API URL
$API_URL = "https://api.thenex.world/get-user"
# $API_URL = "http://localhost:9000/.netlify/functions/get-user"

# Create the JSON payload
$JSON_PAYLOAD = @{
    groupLabel = $groupLabel
} | ConvertTo-Json -Depth 10

# Send the POST request and capture the response
$response = Invoke-RestMethod -Uri $API_URL -Method Post -Body $JSON_PAYLOAD -ContentType "application/json"

# Extract the "token" field from the JSON response
$token = $response.token

Function Decode-JWT {
    param (
        [string]$jwtToken
    )

    # Split the token into its three parts (header, payload, signature)
    $tokenParts = $jwtToken -split '\.'

    if ($tokenParts.Length -ge 2) {
        # Get the payload (second part of the JWT token)
        $payload = $tokenParts[1]

        # Convert Base64 URL to standard Base64
        $standardBase64Payload = $payload.Replace("-", "+").Replace("_", "/")
        switch ($standardBase64Payload.Length % 4) {
            1 { $standardBase64Payload += "===" }
            2 { $standardBase64Payload += "==" }
            3 { $standardBase64Payload += "=" }
        }

        try {
            # Decode the payload using UTF8 encoding
            $decodedPayload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($standardBase64Payload))

            # Parse the decoded payload JSON
            $payloadData = $decodedPayload | ConvertFrom-Json

            # Return the parsed object
            return $payloadData
        } catch {
            Write-Error "Failed to decode payload: $_"
        }
    } else {
        Write-Error "Invalid JWT token format."
    }

    # Return $null if the function fails
    return $null
}

# Decode the extracted token
$decodedPayload = Decode-JWT -jwtToken $token

# Print or handle the decoded payload outside the function
if ($decodedPayload -ne $null) {
    # Write-Output "Decoded Payload:"
    # Write-Output $decodedPayload | Format-List

    # Write-Output "Decoded complianceStandards:"
    # $decodedPayload.cybersecurityPreferences.complianceStandards | ForEach-Object { Write-Output "- $_" }

    # Check if compliance standards require encryption
    $requiresEncryption = $false

    $requiredStandards = @(
        'soc2',
        'nist_sp_800_53',
        'iso27001',
        'gdpr',
        'hipaa',
        'pci_dss',
        'pipeda',
        'cis_controls'
    )

    foreach ($standard in $requiredStandards) {
        if ($decodedPayload.cybersecurityPreferences.complianceStandards -contains $standard) {            $requiresEncryption = $true
            break
        }
    }

    if ($requiresEncryption) {
        # ====================================================================================
        # SECTION: CONFIGURE POWERSHELL EXECUTION POLICY
        # This block ensures that the system's execution policy is set to 'RemoteSigned'
        # to allow the Wazuh agent to run local monitoring scripts.
        # ====================================================================================

        Write-Host "--- Checking and Configuring PowerShell Execution Policy ---"

        # Step 1: Verify the script is running with Administrator privileges.
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if (-not $isAdmin) {
            Write-Error "CRITICAL: This script must be run with Administrator privileges to change the Execution Policy."
            Write-Error "Please re-run the script from an administrative PowerShell prompt. Aborting."
            # Exit the script if not running as admin.
            exit 1
        }

        # Step 2: Get the current execution policy for the LocalMachine scope.
        try {
            $currentPolicy = Get-ExecutionPolicy -Scope LocalMachine -ErrorAction Stop
        }
        catch {
            # This can happen on very old systems, but it's good practice to handle it.
            # We'll treat an undefined policy as 'Restricted'.
            $currentPolicy = 'Restricted'
        }

        # Step 3: Check the policy and change it only if necessary.
        if ($currentPolicy -eq 'RemoteSigned') {
            Write-Host "SUCCESS: Execution Policy is already set to 'RemoteSigned'. No action needed." -ForegroundColor Green
        }
        elseif ($currentPolicy -in ('Unrestricted', 'Bypass')) {
            # If the policy is already less restrictive, we don't need to change it.
            Write-Host "WARNING: Execution Policy is '$currentPolicy', which is less restrictive than 'RemoteSigned'. No action needed." -ForegroundColor Yellow
        }
        else {
            # This will handle 'Restricted' and 'AllSigned' policies.
            Write-Host "INFO: Current Execution Policy is '$currentPolicy'. Attempting to set it to 'RemoteSigned'..." -ForegroundColor Yellow
            try {
                # Use -Force to suppress the confirmation prompt, which is essential for automation.
                Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction Stop
                
                # Verify that the change was successful.
                $newPolicy = Get-ExecutionPolicy -Scope LocalMachine
                if ($newPolicy -eq 'RemoteSigned') {
                    Write-Host "SUCCESS: Execution Policy has been successfully set to 'RemoteSigned'." -ForegroundColor Green
                }
                else {
                    # This can happen if a Group Policy is overriding the local setting.
                    Write-Error "CRITICAL: Failed to set Execution Policy. A Group Policy (GPO) may be preventing this change."
                    Write-Error "The current policy is still '$newPolicy'. Please check your domain GPO settings. Aborting."
                    exit 1
                }
            }
            catch {
                Write-Error "CRITICAL: An unexpected error occurred while setting the Execution Policy. Error: $($_.Exception.Message)"
                exit 1
            }
        }

        Write-Host "--- Execution Policy configuration complete ---"
        # ====================================================================================
        # (The rest of your agent setup script continues here)
        # ====================================================================================

        Write-Host "Compliance standards require endpoint encryption. Configuring BitLocker monitoring for Wazuh." -ForegroundColor Green

        # --- Define Paths and URL ---
        $bitlockerScriptUrl = "https://github.com/thenexlabs/nixguard-free-agent-setup/raw/main/windows/scripts/bitlocker_check.ps1"
        $wazuhAgentPath = "C:\Program Files (x86)\ossec-agent"
        $destinationScriptPath = Join-Path $wazuhAgentPath "bitlocker_check.ps1"
        
        # --- 1. Download the PowerShell check script from GitHub to the endpoint ---
        Write-Host "Downloading BitLocker check script from $bitlockerScriptUrl..."
        try {
            # Ensure the destination directory exists before downloading
            if (-not (Test-Path $wazuhAgentPath)) {
                New-Item -Path $wazuhAgentPath -ItemType Directory -Force | Out-Null
            }
            # Use TLS 1.2 for security and compatibility
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $bitlockerScriptUrl -OutFile $destinationScriptPath -UseBasicParsing
            Write-Host "Successfully downloaded BitLocker check script to '$destinationScriptPath'."
        }
        catch {
            Write-Error "CRITICAL: Failed to download the BitLocker script from GitHub. Error: $($_.Exception.Message)"
            Write-Error "Please check network connectivity and firewall rules. Cannot proceed."
            # Exit the script because the rest of the configuration is dependent on this file.
            exit 1 
        }

        # --- 2. Modify ossec.conf using robust XML parsing ---
        try {
            Write-Host "Modifying '$configPath' for BitLocker monitoring..."
            [xml]$ossecConf = Get-Content -Path $configPath

            # A) Add the <localfile> command execution block if it doesn't exist
            $existingLocalfile = $ossecConf.ossec_config.localfile | Where-Object { $_.alias -eq 'bitlocker-monitoring' }
            if (-not $existingLocalfile) {
                $localfileNode = $ossecConf.CreateElement('localfile')
                
                $logFormatNode = $ossecConf.CreateElement('log_format')
                $logFormatNode.InnerText = 'json'
                $localfileNode.AppendChild($logFormatNode) | Out-Null

                $commandNode = $ossecConf.CreateElement('command')
                # Use the destination path variable here
                $commandNode.InnerText = "powershell.exe -ExecutionPolicy Bypass -File `"$destinationScriptPath`""
                $localfileNode.AppendChild($commandNode) | Out-Null
                
                $frequencyNode = $ossecConf.CreateElement('frequency')
                $frequencyNode.InnerText = '14400' # 4 hours
                $localfileNode.AppendChild($frequencyNode) | Out-Null

                $aliasNode = $ossecConf.CreateElement('alias')
                $aliasNode.InnerText = 'bitlocker-monitoring'
                $localfileNode.AppendChild($aliasNode) | Out-Null

                $ossecConf.ossec_config.AppendChild($localfileNode) | Out-Null
                Write-Host "Added '<localfile>' block for BitLocker monitoring."
            } else {
                Write-Host "BitLocker '<localfile>' block already exists. Skipping."
            }

            # B) Add File Integrity Monitoring (FIM) for the agent's own directory
            $syscheckNode = $ossecConf.ossec_config.syscheck
            if ($syscheckNode) {
                $fimPath = "C:\Program Files (x86)\ossec-agent"
                $existingFimDir = $syscheckNode.directories | Where-Object { $_.'#text' -eq $fimPath }
                if (-not $existingFimDir) {
                    $dirNode = $ossecConf.CreateElement('directories')
                    $dirNode.SetAttribute('check_all', 'yes')
                    $dirNode.SetAttribute('report_changes', 'yes')
                    $dirNode.InnerText = $fimPath
                    $syscheckNode.AppendChild($dirNode) | Out-Null
                    Write-Host "Added FIM rule to monitor '$fimPath' for tampering."
                } else {
                    Write-Host "FIM rule for '$fimPath' already exists. Skipping."
                }
            } else {
                Write-Warning "Could not find '<syscheck>' node in ossec.conf to add FIM rule."
            }
            
            # --- 3. Save the modified configuration file ---
            $ossecConf.Save($configPath)
            Write-Host "Successfully saved updated configuration to '$configPath'."

        }
        catch {
            Write-Error "An error occurred while modifying '$configPath'. Error: $($_.Exception.Message)"
        }

    } else {
        Write-Host "Compliance standards do not require endpoint encryption. Skipping BitLocker configuration." -ForegroundColor Yellow
    }
} else {
    Write-Output "Failed to decode the JWT token."
}

# //////////////////////////////////////////////////////////////////////////////////////////////////////////

# Define the enrollment section
$enrollmentSection = @"
<enrollment>
    <enabled>yes</enabled>
    <manager_address>${ipAddress}</manager_address>
    <agent_name>${agentName}</agent_name>
</enrollment>
"@

# Read the ossec.conf file
$content = Get-Content -Path $configPath -Raw

# Check if the enrollment section already exists
if ($content -notmatch '<enrollment>') {
    # Add the enrollment section to the ossec.conf file
    $content = $content -replace '(?s)(<client>.*?)(</client>)', "`$1`n$enrollmentSection`n`$2"
}

# Ensure the group section exists
if ($content -notmatch '<groups>') {
    $groupSection = "<groups>${groupLabel}</groups>"
    $content = $content -replace '</enrollment>', "$groupSection`n</enrollment>"
}

# Write the modified content back to the ossec.conf
$content | Set-Content -Path $configPath

# File Integrity Monitoring Configuration
$newDirectory = @"
<directories check_all="yes" whodata="yes" realtime="yes">$env:USERPROFILE\Downloads</directories>
"@
[xml]$ossecConf = Get-Content -Path $configPath

# Wait until the file is found
while (-not $ossecConf) {
    Start-Sleep -Seconds 1
}

$syscheckNode = $ossecConf.ossec_config.syscheck

if (-not $syscheckNode) {
    $syscheckNode = $ossecConf.CreateElement("syscheck")
    $ossecConf.ossec_config.AppendChild($syscheckNode) | Out-Null
}

# Find the comment and add the new directory after it
$commentNode = $ossecConf.ossec_config.syscheck.SelectSingleNode("comment()[contains(.,'<!-- Default files to be monitored. -->')]")
if ($commentNode) {
    $directories = @(
        "$env:WINDIR\System32",  # Critical system files
        "$env:ProgramFiles",  # Installed programs
        "$env:ProgramFiles(x86)",  # 32-bit installed programs
        "HKEY_LOCAL_MACHINE\SYSTEM",  # Registry settings
        "$env:USERPROFILE",  # User profile
        "$env:ProgramData",  # Program data
        "$env:ProgramFiles\Common Files",  # Common program files
        "$env:ProgramFiles(x86)\Common Files",  # 32-bit common program files
        "$env:USERPROFILE\Downloads"  # User Downloads directory
    )

    foreach ($directory in $directories) {
        $newDirectoryNode = $ossecConf.CreateElement("directories")
        $newDirectoryNode.SetAttribute("check_all", "yes")
        $newDirectoryNode.SetAttribute("whodata", "yes")
        $newDirectoryNode.SetAttribute("realtime", "yes")
        $newDirectoryNode.InnerText = $directory
        $syscheckNode.InsertAfter($newDirectoryNode, $commentNode) | Out-Null
    }
} else {
    $fragment = $ossecConf.CreateDocumentFragment()
    $fragment.InnerXml = $newDirectory
    $syscheckNode.AppendChild($fragment) | Out-Null
}

$ossecConf.Save($configPath)
Write-Host "Directory monitoring configuration added successfully."

###########################################################################################

# Define the URL of the Python installer
$pythonUrl = "https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe"

# Define the path to save the Python installer
$pythonInstallerPath = Join-Path -Path $env:TEMP -ChildPath "python-installer.exe"

# Download the Python installer
Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstallerPath

# Run the Python installer
Start-Process -FilePath $pythonInstallerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait

# Start a new PowerShell session to install PyInstaller
py -m pip install pyinstaller

# Define the URL of the remove-threat.py script
$removeThreatUrl = "https://github.com/thenexlabs/nixguard-agent-setup/raw/main/windows/remove-threat.py"

# Define the path to save the remove-threat.py script
$removeThreatPath = Join-Path -Path $env:TEMP -ChildPath "remove-threat.py"

# Download the remove-threat.py script
Invoke-WebRequest -Uri $removeThreatUrl -OutFile $removeThreatPath

# Change the current location to the directory containing remove-threat.py
Set-Location -Path $env:TEMP

# Convert the remove-threat.py script to a Windows executable
Invoke-Expression -Command "py -m PyInstaller -F $removeThreatPath"

# Define the path of the executable file
$exePath = Join-Path -Path $env:TEMP -ChildPath "dist\remove-threat.exe"

# Define the destination directory
$destDir = "C:\Program Files (x86)\ossec-agent\active-response\bin"

# Move the executable file to the destination directory
Move-Item -Path $exePath -Destination $destDir

# Define the paths of the spec file and the dist and build directories
$specPath = Join-Path -Path $env:TEMP -ChildPath "remove-threat.spec"
$distDir = Join-Path -Path $env:TEMP -ChildPath "dist"
$buildDir = Join-Path -Path $env:TEMP -ChildPath "build"

# Delete the spec file and the dist and build directories
Remove-Item -Path $specPath -ErrorAction SilentlyContinue
Remove-Item -Path $distDir -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path $buildDir -Recurse -ErrorAction SilentlyContinue

Write-Host "Virus threat response configuration added successfully."

###########################################################################################

Write-Host "NixGuard agent setup successfully."

# Start Wazuh agent
Start-Process -FilePath "NET" -ArgumentList "START WazuhSvc"

Write-Host "NixGuard agent started successfully."
