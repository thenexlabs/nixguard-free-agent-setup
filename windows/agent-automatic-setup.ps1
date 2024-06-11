param (
  [string]$agentName,
  [string]$ipAddress
)

# Install the Wazuh agent
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.4-1.msi -OutFile ${env:tmp}\wazuh-agent
msiexec.exe /i ${env:tmp}\wazuh-agent /q WAZUH_MANAGER=$ipAddress WAZUH_AGENT_NAME=$agentName WAZUH_REGISTRATION_SERVER=$ipAddress

# Update the ossec.conf file
$configPath = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
$config = Get-Content -Path $configPath
$config = $config -replace '<address>0.0.0.0</address>', "<address>$ipAddress</address>"
Set-Content -Path $configPath -Value $config

# 2) File Int Monitoring
# Define the path to the OSSEC configuration file
$ossecConfPath = $configPath

# Define the new directory to monitor
$newDirectory = @"
  <directories realtime="yes">%USERPROFILE%\Downloads</directories>
"@

# Load the existing configuration file
[xml]$ossecConf = Get-Content -Path $ossecConfPath

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
$ossecConf.Save($ossecConfPath)

Write-Host "Directory monitoring configuration added successfully."


# start wazuh agent
NET START WazuhSvc