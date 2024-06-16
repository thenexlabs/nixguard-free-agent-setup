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
<directories check_all="yes" realtime="yes">$env:USERPROFILE\Downloads</directories>
"@
[xml]$ossecConf = Get-Content -Path $ossecConfPath
$syscheckNode = $ossecConf.ossec_config.syscheck
if (-not $syscheckNode) {
    $syscheckNode = $ossecConf.CreateElement("syscheck")
    $ossecConf.ossec_config.AppendChild($syscheckNode) | Out-Null
}

# Find the comment and add the new directory after it
$commentNode = $ossecConf.ossec_config.syscheck.SelectSingleNode("comment()[contains(.,'<!-- Default files to be monitored. -->')]")
if ($commentNode) {
    $newDirectoryNode = $ossecConf.CreateElement("directories")
    $newDirectoryNode.SetAttribute("check_all", "yes")
    $newDirectoryNode.SetAttribute("realtime", "yes")
    $newDirectoryNode.InnerText = "$env:USERPROFILE\Downloads"
    $syscheckNode.InsertAfter($newDirectoryNode, $commentNode) | Out-Null
} else {
    $fragment = $ossecConf.CreateDocumentFragment()
    $fragment.InnerXml = $newDirectory
    $syscheckNode.AppendChild($fragment) | Out-Null
}

$ossecConf.Save($ossecConfPath)

# Install Python and PyInstaller
Start-Process -FilePath "python-installer.exe" -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait
Start-Process -FilePath "pip" -ArgumentList "install pyinstaller" -Wait

# Define the URL of the Git repository
$gitRepoUrl = "https://github.com/thenexlabs/nixguard-droplet-scripts/raw/main/wazuh-agent-automation/windows/remove-threat.py"

# Clone the Git repository
Start-Process -FilePath "git" -ArgumentList "clone $gitRepoUrl" -Wait

# Define the path to the remove-threat.py script in the cloned repository
$removeThreatPath = Join-Path -Path (Join-Path -Path $PWD.Path -ChildPath (Split-Path -Path $gitRepoUrl -Leaf)) -ChildPath "remove-threat.py"

# Convert the remove-threat.py script to a Windows executable
Start-Process -FilePath "pyinstaller" -ArgumentList "-F $removeThreatPath" -Wait

Write-Host "Directory monitoring configuration added successfully."

# Start Wazuh agent
NET START WazuhSvc