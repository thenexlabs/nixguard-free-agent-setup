#!/bin/bash

# Function to detect the architecture
detect_arch() {
    arch=$(uname -m)
    if [ "$arch" == "x86_64" ]; then
        arch="intel"
    elif [ "$arch" == "arm64" ]; then
        arch="arm64"
    else
        echo "Unsupported architecture: $arch"
        exit 1
    fi
}

# Function to uninstall Wazuh agent
uninstall_wazuh_agent() {
    # Stop the Wazuh agent
    sudo /Library/Ossec/bin/wazuh-control stop

    # Remove the Wazuh agent
    sudo pkgutil --forget com.wazuh.agent

    # Clean up files
    sudo rm -rf /Library/Ossec
    sudo rm -f /usr/local/bin/agent-auth
    sudo rm -f /usr/local/bin/wazuh-control
    sudo rm -f /tmp/wazuh_envs
}

# Main script execution
detect_arch
uninstall_wazuh_agent

echo "Wazuh agent removed successfully."
