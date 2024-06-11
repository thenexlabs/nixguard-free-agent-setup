#!/bin/bash

# Check if two arguments are passed
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <manager_ip> <agent_name>"
    exit 1
fi

# Define the manager IP and agent name from command-line arguments
MANAGER_IP=$1
AGENT_NAME=$2

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

# Function to install Wazuh agent
install_wazuh_agent() {
    local WAZUH_MANAGER="$MANAGER_IP"
    local WAZUH_AGENT_NAME="$AGENT_NAME"

    if [ "$arch" == "intel" ]; then
        curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.7.3-1.intel64.pkg
    elif [ "$arch" == "arm64" ]; then
        curl -so wazuh-agent.pkg https://packages.wazuh.com/4.x/macos/wazuh-agent-4.7.3-1.arm64.pkg
    fi

    echo "WAZUH_MANAGER='$WAZUH_MANAGER' WAZUH_AGENT_NAME='$WAZUH_AGENT_NAME'" > /tmp/wazuh_envs
    sudo installer -pkg ./wazuh-agent.pkg -target /
}

# Function to start the Wazuh agent
start_wazuh_agent() {
    sudo /Library/Ossec/bin/wazuh-control start
}

# Main script execution
detect_arch
install_wazuh_agent
start_wazuh_agent

echo "Wazuh agent installed and started successfully."
