#!/bin/bash
# ./mac_setup.sh "your_manager_ip" "your_agent_name"

# Check if two arguments are passed
if [ "$#" -ne 2 ]; then
    echo "Usage: ./mac_setup.sh <manager_ip> <agent_name>"
    exit 1
fi

# Define the manager IP and agent name from command-line arguments
MANAGER_IP=$1
AGENT_NAME=$2
GROUP_LABEL="default"

# Function to uninstall Wazuh agent on macOS
uninstall_wazuh_agent() {
    if brew list --cask | grep -Fq 'wazuh-agent'; then
        sudo brew services stop wazuh-agent
        sudo brew uninstall --cask wazuh-agent
    else
        echo "wazuh-agent is not installed"
    fi
}

# Function to install Wazuh agent on macOS
install_wazuh_agent() {
    local WAZUH_MANAGER="$MANAGER_IP"
    local WAZUH_AGENT_NAME="$AGENT_NAME"

    echo "Private cloud SOC IP: $WAZUH_MANAGER"
    echo "Agent name: $WAZUH_AGENT_NAME"
    echo "Agent group: $GROUP_LABEL"

    arch=$(uname -m)
    if [ "$arch" == "x86_64" ]; then
        wget -O wazuh-agent_macos.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.9.1-1.intel64.pkg
    elif [ "$arch" == "arm64" ]; then
        wget -O wazuh-agent_macos.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.9.1-1.arm64.pkg
    else
        echo "Unsupported architecture: $arch"
        exit 1
    fi

    sudo installer -pkg wazuh-agent_macos.pkg -target /

    # Start the Wazuh agent
    sudo brew services start wazuh-agent

    echo "NixGuard agent started successfully."
}

# Main script execution
if [ $# -lt 2 ]; then
    echo "Usage: $0 <WAZUH_MANAGER_IP> <WAZUH_AGENT_NAME>"
    exit 1
fi

# Uninstall any existing Wazuh agent
uninstall_wazuh_agent

# Install and configure the Wazuh agent
install_wazuh_agent
