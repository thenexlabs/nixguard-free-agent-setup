param (
    [string]$agentName,
    [string]$ipAddress
)

# Define the URL of the Wazuh agent MSI file
$msiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.4-1.msi"
# Define the local path to save the Wazuh agent MSI file
$localMsiPath = "${env:tmp}\wazuh-agent.msi"

# Download the Wazuh agent MSI file and wait for the download to complete
$webRequest = Invoke-WebRequest -Uri $msiUrl -OutFile $localMsiPath -PassThru
while ($webRequest.IsCompleted -eq $false) {
    Start-Sleep -Milliseconds 500
}

# Install the Wazuh agent
msiexec.exe /i $localMsiPath /q WAZUH_MANAGER=$ipAddress WAZUH_AGENT_NAME=$agentName WAZUH_REGISTRATION_SERVER=$ipAddress

# Update the ossec.conf file
$configPath = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
$config = Get-Content -Path $configPath
$config = $config -replace '<address>0.0.0.0</address>', "<address>$ipAddress</address>"
Set-Content -Path $configPath -Value $config

# Define the new directory to monitor
$newDirectory = @"
  <directories realtime="yes">%USERPROFILE%\Downloads</directories>
"@

# Load the existing configuration file
[xml]$ossecConf = Get-Content -Path $configPath

# Check if the syscheck section exists
$syscheckNode = $ossecConf.ossec_config.syscheck
if (-not $syscheckNode) {
    # If syscheck section does not exist, create it
    $syscheckNode = $ossecConf.CreateElement("syscheck")
    $ossecConf.ossec_config.AppendChild($syscheckNode)
}

# Add the new directory monitoring configuration
$syscheckNode.InnerXml += $newDirectory

# Save the updated configuration file
$ossecConf.Save($configPath)

Write-Host "Directory monitoring configuration added successfully."

# start wazuh agent
NET START WazuhSvc