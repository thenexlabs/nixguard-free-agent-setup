param (
  [string]$agentName,
  [string]$ipAddress
)

# Install the Wazuh agent
$wazuhInstaller = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i", "${env:tmp}\wazuh-agent", "/q", "WAZUH_MANAGER=$ipAddress", "WAZUH_AGENT_NAME=$agentName", "WAZUH_REGISTRATION_SERVER=$ipAddress" -PassThru
$wazuhInstaller.WaitForExit()

# Update the ossec.conf file
$configPath = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
$config = Get-Content -Path $configPath
$config = $config -replace '<address>0.0.0.0</address>', "<address>$ipAddress</address>"
Set-Content -Path $configPath -Value $config

# File Integrity Monitoring Configuration
$ossecConfPath = $configPath
$newDirectory = @"
  <directories check_all="yes" realtime="yes">%USERPROFILE%\Downloads</directories>
"@
[xml]$ossecConf = Get-Content -Path $ossecConfPath
$syscheckNode = $ossecConf.ossec_config.syscheck
if (-not $syscheckNode) {
    $syscheckNode = $ossecConf.CreateElement("syscheck")
    $ossecConf.ossec_config.AppendChild($syscheckNode)
}
$syscheckNode.InnerXml += $newDirectory
$ossecConf.Save($ossecConfPath)

Write-Host "Directory monitoring configuration added successfully."

# Start Wazuh agent
NET START WazuhSvc
