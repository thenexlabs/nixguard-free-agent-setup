# Define the script as a function
function Uninstall-WazuhAgent {
    # Stop the Wazuh service
    Stop-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue

    # Uninstall the Wazuh agent using msiexec
    msiexec.exe /x $env:tmp\wazuh-agent.msi /q 2>$null

    # Remove the Wazuh agent installation directory
    Remove-Item -Recurse -Force "C:\Program Files (x86)\ossec-agent" -ErrorAction SilentlyContinue

    # Remove the Wazuh agent installation directory
    Remove-Item -Recurse -Force "C:\wazuh-agent" -ErrorAction SilentlyContinue
}

# Run the script twice
# Uninstall-WazuhAgent function
Uninstall-WazuhAgent
Uninstall-WazuhAgent
