#!/bin/bash
# ./scriptname.sh "your_manager_ip" "your_agent_name"


# Check if two arguments are passed
if [ "$#" -ne 2 ]; then
    echo "Usage: ./scriptname.sh <manager_ip> <agent_name>"
    exit 1
fi

# Define the manager IP agent name, group label from command-line arguments
MANAGER_IP=$1
AGENT_NAME=$2
GROUP_LABEL=$3

# Function to detect the distribution and architecture
detect_distro_arch() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        distro=$ID
    else
        echo "Cannot detect distribution."
        exit 1
    fi

    arch=$(uname -m)
    if [ "$arch" == "x86_64" ]; then
        arch="amd64"
    elif [ "$arch" == "aarch64" ]; then
        arch="aarch64"
    else
        echo "Unsupported architecture: $arch"
        exit 1
    fi
}

# Function to install Wazuh agent
install_wazuh_agent() {
    local WAZUH_MANAGER="$MANAGER_IP"
    local WAZUH_AGENT_NAME="$AGENT_NAME"

    if [ "$distro" == "debian" ] || [ "$distro" == "ubuntu" ]; then
        if [ "$arch" == "amd64" ]; then
            wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.3-1_amd64.deb
            sudo WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" dpkg -i ./wazuh-agent_4.7.3-1_amd64.deb
        elif [ "$arch" == "aarch64" ]; then
            wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.3-1_arm64.deb
            sudo WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" dpkg -i ./wazuh-agent_4.7.3-1_arm64.deb
        fi
            # Define the path to the OSSEC configuration file
            ossecConfPath="/var/ossec/etc/ossec.conf"

            # Set the manager IP in the ossec.conf file
            sed -i "s/<address>.*<\/address>/<address>${MANAGER_IP}<\/address>/g" $ossecConfPath

            # Define the new directory to monitor
            newDirectory="<directories check_all=\"yes\" realtime=\"yes\">/root</directories>"

            # Check if the syscheck section exists
            if ! grep -q "<syscheck>" $ossecConfPath; then
                # If syscheck section does not exist, create it
                sed -i '/<\/ossec_config>/i \ \ <syscheck>\n\ \ </syscheck>' $ossecConfPath
            fi

            # Add the new directory monitoring configuration
            sed -i "/<syscheck>/a \ \ $newDirectory" $ossecConfPath

            echo "Directory monitoring configuration added successfully."

            ###########################################################################################

            # Set the current directory to the user's home directory
            # cd ~

            sudo apt update
            sudo apt -y install jq

            # Define the URL of the remove-threat.py script
            removeThreatUrl="https://github.com/thenexlabs/nixguard-agent-setup/raw/main/linux/remove-threat.sh"

            # Define the path to save the remove-threat.sh script
            removeThreatPath="/remove-threat.sh"

            # Download the remove-threat.py script
            curl -o $removeThreatPath $removeThreatUrl

            # Define the path of the executable file
            exePath="$(pwd)/remove-threat.sh"

            # Define the destination directory
            destDir="/var/ossec/active-response/bin"

            # Move the executable file to the destination directory
            sudo mv $exePath $destDir

            # Clean up the build artifacts
            # rm -rf /tmp/remove-threat.py /tmp/dist /tmp/build /tmp/remove-threat.spec

            echo "Virus threat response configuration added successfully."

            ###########################################################################################

            echo "NixGuard agent setup successfully."
    elif [ "$distro" == "centos" ] || [ "$distro" == "rhel" ] || [ "$distro" == "fedora" ]; then
        if [ "$arch" == "amd64" ]; then
            curl -o wazuh-agent-4.7.3-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.7.3-1.x86_64.rpm
            sudo WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" rpm -ihv wazuh-agent-4.7.3-1.x86_64.rpm
        elif [ "$arch" == "aarch64" ]; then
            curl -o wazuh-agent-4.7.3-1.aarch64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.7.3-1.aarch64.rpm
            sudo WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" rpm -ihv wazuh-agent-4.7.3-1.aarch64.rpm
        fi
    else
        echo "Unsupported distribution: $distro"
        exit 1
    fi

    # Start the Wazuh agent
    sudo systemctl daemon-reload
    sudo systemctl enable wazuh-agent
    sudo systemctl start wazuh-agent

    echo "NixGuard agent started successfully."
}

# Main script execution
if [ $# -lt 2 ]; then
    echo "Usage: $0 <WAZUH_MANAGER_IP> <WAZUH_AGENT_NAME>"
    exit 1
fi

WAZUH_MANAGER="$MANAGER_IP"
WAZUH_AGENT_NAME="$AGENT_NAME"

detect_distro_arch
install_wazuh_agent "$WAZUH_MANAGER" "$WAZUH_AGENT_NAME"