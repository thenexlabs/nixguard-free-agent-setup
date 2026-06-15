#!/bin/bash
# ./scriptname.sh "your_manager_ip" "your_agent_name" "group_label"

# Check if three arguments are passed
if [ "$#" -ne 3 ]; then
    echo "Usage: ./scriptname.sh <manager_ip> <agent_name> <group_label>"
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

# Function to uninstall Wazuh agent
uninstall_wazuh_agent() {
    if [ "$distro" == "debian" ] || [ "$distro" == "ubuntu" ] || [ "$distro" == "kali" ]; then
        if systemctl list-units --full --all | grep -Fq 'wazuh-agent'; then
            sudo systemctl stop wazuh-agent
            sudo dpkg -r wazuh-agent
        else
            echo "wazuh-agent is not installed"
        fi
    elif [ "$distro" == "centos" ] || [ "$distro" == "rhel" ] || [ "$distro" == "fedora" ]; then
        if systemctl list-units --full --all | grep -Fq 'wazuh-agent'; then
            sudo systemctl stop wazuh-agent
            sudo rpm -e wazuh-agent
        else
            echo "wazuh-agent is not installed"
        fi
    else
        echo "Unsupported distribution: $distro"
        exit 1
    fi
}

# Function to fix broken dependencies and ensure auditd is installed and running
fix_dependencies() {
    echo "Starting dependency fix process..."

    if [ "$distro" == "debian" ] || [ "$distro" == "ubuntu" ] || [ "$distro" == "kali" ]; then
        # Update the package lists
        sudo DEBIAN_FRONTEND=noninteractive apt-get update
        if [ $? -ne 0 ]; then
            echo "Failed to update package lists. Please check your network connection."
            return 1
        fi

        # Attempt to fix broken dependencies
        sudo DEBIAN_FRONTEND=noninteractive apt-get -f install -y
        if [ $? -ne 0 ]; then
            echo "Failed to fix broken dependencies. Please check the logs for more details."
            return 1
        fi

        sudo apt-get install -y auditd audispd-plugins
        if [ $? -ne 0 ]; then
            echo "Failed to install auditd on $distro. Please check the logs for more details."
            return 1
        fi
        sudo systemctl enable auditd
        sudo systemctl start auditd
        if [ $? -ne 0 ]; then
            echo "Failed to start auditd on $distro. Please check the logs for more details."
            return 1
        fi
    elif [ "$distro" == "centos" ] || [ "$distro" == "rhel" ] || [ "$distro" == "fedora" ]; then
        sudo yum install -y audit
        if [ $? -ne 0 ]; then
            echo "Failed to install auditd on $distro. Please check the logs for more details."
            return 1
        fi
        sudo systemctl enable auditd
        sudo systemctl start auditd
        if [ $? -ne 0 ]; then
            echo "Failed to start auditd on $distro. Please check the logs for more details."
            return 1
        fi
    else
        echo "Unsupported distribution: $distro"
        return 1
    fi

    # Ensure auditd is not disabled by default
    if auditctl -l | grep -q '^-a never,task'; then
        sudo sed -i '/^-a never,task/d' /etc/audit/rules.d/audit.rules
        sudo systemctl restart auditd
    fi

    echo "Dependency fix process completed successfully."
    return 0
}

remove_directories_tags() {
    local ossecConfPath=$1

    # Backup the original file
    sudo cp $ossecConfPath ${ossecConfPath}.bak

    # Remove all <directories> tags and their content
    sudo sed -i '/<directories>/,/<\/directories>/d' $ossecConfPath

    echo "All <directories> tags have been removed."
}

add_new_directories() {
    local ossecConfPath=$1
    shift
    local directories=("$@")

    # Check if the syscheck section exists
    if ! sudo grep -q "<syscheck>" $ossecConfPath; then
        # If syscheck section does not exist, create it
        sudo sed -i '/<\/ossec_config>/i \ \ <syscheck>\n\ \ </syscheck>' $ossecConfPath
    fi

    # Find the line number of the comment containing the word "Directories"
    local line_number=$(sudo grep -n "Directories" $ossecConfPath | cut -d: -f1)

    # Insert the new directories after the comment containing the word "Directories"
    for (( i=${#directories[@]}-1 ; i>=0 ; i-- )); do
        sudo sed -i "${line_number}a \ \ ${directories[$i]}" $ossecConfPath
    done

    echo "New <directories> tags have been added after the comment containing the word 'Directories'."
}

add_ignore_directories() {
    local ossecConfPath=$1
    shift
    local ignore_directories=("$@")

    # Check if the syscheck section exists
    if ! sudo grep -q "<syscheck>" $ossecConfPath; then
        # If syscheck section does not exist, create it
        sudo sed -i '/<\/ossec_config>/i \ \ <syscheck>\n\ \ </syscheck>' $ossecConfPath
    fi

    # Find the line number of the comment containing the words "Files/directories to ignore"
    local line_number=$(sudo grep -n "<!-- Files/directories to ignore -->" $ossecConfPath | cut -d: -f1)

    # Insert the new ignore directories after the comment
    for (( i=${#ignore_directories[@]}-1 ; i>=0 ; i-- )); do
        sudo sed -i "${line_number}a \ \ ${ignore_directories[$i]}" $ossecConfPath
    done

    echo "New <ignore> tags have been added after the comment 'Files/directories to ignore'."
}

# --- ADDED: Duplicate-Safe XML Performance Injection ---
optimize_syscheck_performance() {
    local ossecConfPath=$1
    echo "Optimizing Syscheck (FIM) performance to prevent high CPU/IO usage..."
    
    # Remove any pre-existing performance tags to prevent XML parser errors from duplicates
    sudo sed -i '/<frequency>/d' $ossecConfPath
    sudo sed -i '/<max_eps>/d' $ossecConfPath
    sudo sed -i '/<process_priority>/d' $ossecConfPath
    sudo sed -i '/<sleep>/d' $ossecConfPath
    sudo sed -i '/<nodiff>/d' $ossecConfPath
    
    # Inject clean, optimized parameters right after the <syscheck> tag
    sudo sed -i '/<syscheck>/a \ \ \ \ <max_eps>50</max_eps>\n\ \ \ \ <frequency>43200</frequency>\n\ \ \ \ <process_priority>10</process_priority>\n\ \ \ \ <sleep>20</sleep>' $ossecConfPath
    
    # Add nodiff tags to prevent memory spikes on large binaries
    sudo sed -i '/<\/syscheck>/i \ \ \ \ <nodiff>/bin</nodiff>\n\ \ \ \ <nodiff>/sbin</nodiff>\n\ \ \ \ <nodiff>/usr/bin</nodiff>\n\ \ \ \ <nodiff>/usr/sbin</nodiff>' $ossecConfPath
    
    echo "Syscheck performance optimized."
}

# Function to install Wazuh agent
install_wazuh_agent() {
    local WAZUH_MANAGER="$MANAGER_IP"
    local WAZUH_AGENT_NAME="$AGENT_NAME"
    local WAZUH_AGENT_GROUP="$GROUP_LABEL"

    echo "Private cloud SOC IP: $WAZUH_MANAGER"
    echo "Agent name: $WAZUH_AGENT_NAME"
    echo "Agent group: $WAZUH_AGENT_GROUP"

    # ==========================================
    # STEP 1: DISTRO-SPECIFIC PACKAGE INSTALLATION
    # ==========================================
    if [ "$distro" == "debian" ] || [ "$distro" == "ubuntu" ] || [ "$distro" == "kali" ]; then
        if [ "$arch" == "amd64" ]; then
            sudo wget -O wazuh-agent_nixguard_amd64.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.1-1_amd64.deb
            sudo DEBIAN_FRONTEND=noninteractive dpkg -i ./wazuh-agent_nixguard_amd64.deb
        elif [ "$arch" == "aarch64" ]; then
            sudo wget -O wazuh-agent_nixguard_arm64.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.9.1-1_arm64.deb
            sudo DEBIAN_FRONTEND=noninteractive dpkg -i ./wazuh-agent_nixguard_arm64.deb
        fi
    elif [ "$distro" == "centos" ] || [ "$distro" == "rhel" ] || [ "$distro" == "fedora" ]; then
        if [ "$arch" == "amd64" ]; then
            sudo wget -O wazuh-agent_nixguard.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.1-1.x86_64.rpm
            sudo WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" WAZUH_AGENT_GROUP="$WAZUH_AGENT_GROUP" rpm -ihv wazuh-agent_nixguard.x86_64.rpm
        elif [ "$arch" == "aarch64" ]; then
            sudo wget -O wazuh-agent_nixguard.aarch64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.1-1.aarch64.rpm
            sudo WAZUH_MANAGER="$WAZUH_MANAGER" WAZUH_AGENT_NAME="$WAZUH_AGENT_NAME" WAZUH_AGENT_GROUP="$WAZUH_AGENT_GROUP" rpm -ihv wazuh-agent_nixguard.aarch64.rpm
        fi
    else
        echo "Unsupported distribution: $distro"
        exit 1
    fi

    # Fix dependencies immediately after package installation
    fix_dependencies

    # ==========================================
    # STEP 2: GLOBAL AGENT CONFIGURATION
    # ==========================================
    ossecConfPath="/var/ossec/etc/ossec.conf"

    # Set the manager IP in the ossec.conf file
    sudo sed -i "s/<address>.*<\/address>/<address>${WAZUH_MANAGER}<\/address>/g" "$ossecConfPath"

    # Define the enrollment section
    ENROLLMENT_SECTION="<enrollment>\n\t<enabled>yes</enabled>\n\t<manager_address>${WAZUH_MANAGER}</manager_address>\n\t<agent_name>${WAZUH_AGENT_NAME}</agent_name>\n</enrollment>"

    # Add the enrollment section to the ossec.conf file
    sudo awk -v enrollment="$ENROLLMENT_SECTION" '
        /<client>/ { print; print enrollment; next }
        !/<enrollment>/ { print }
    ' "$ossecConfPath" > temp_ossec.conf && sudo mv temp_ossec.conf "$ossecConfPath"

    # Ensure the group section exists (Critical for multi-tenant shared servers)
    if ! grep -q '<groups>' "$ossecConfPath"; then
        groupSection="<groups>${GROUP_LABEL}</groups>"
        sudo sed -i "/<\/enrollment>/i $groupSection" "$ossecConfPath"
    fi

    # Define the new directories to monitor (Optimized: /home is scheduled realtime="no" to prevent CPU melt)
    directories=(
        "<directories check_all=\"yes\" realtime=\"yes\">/root</directories>"
        "<directories check_all=\"yes\" realtime=\"no\">/home</directories>"
    )

    # Multi-Tenant Regex Ignores (Covers all users on shared servers dynamically)
    ignore_directories=(
        "<ignore type=\"sregex\">^/home/[^/]+/\.cache</ignore>"
        "<ignore type=\"sregex\">^/home/[^/]+/\.mozilla</ignore>"
        "<ignore type=\"sregex\">^/home/[^/]+/\.config</ignore>"
        "<ignore type=\"sregex\">^/home/[^/]+/\.local</ignore>"
        "<ignore type=\"sregex\">^/home/[^/]+/\.xsession-errors</ignore>"
        "<ignore>/root/.wget-hsts</ignore>"
        "<ignore>/root/.rpmdb</ignore>"
    )

    # Apply FIM directory configurations
    remove_directories_tags $ossecConfPath
    add_new_directories $ossecConfPath "${directories[@]}"
    add_ignore_directories $ossecConfPath "${ignore_directories[@]}"

    # Optimize Syscheck CPU/IO Performance
    optimize_syscheck_performance $ossecConfPath

    echo "Directory monitoring configuration added successfully."

    # ==========================================
    # STEP 3: ACTIVE RESPONSE REMEDIATION DEPLOYMENT
    # ==========================================
    # Install jq dependency
    if [ "$distro" == "debian" ] || [ "$distro" == "ubuntu" ] || [ "$distro" == "kali" ]; then
        sudo apt update -qq
        sudo apt -y install jq
    elif [ "$distro" == "centos" ] || [ "$distro" == "rhel" ] || [ "$distro" == "fedora" ]; then
        sudo yum install -y -q jq
    fi

    destDir="/var/ossec/active-response/bin"
    sudo mkdir -p $destDir

    # 1. Download the remove-threat.sh script
    # FIXED: Changed to direct raw.githubusercontent.com URL and added /active-response/ subfolder
    removeThreatUrl="https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/linux/active-response/remove-threat.sh"
    removeThreatPath="$destDir/remove-threat.sh"
    sudo wget -O $removeThreatPath $removeThreatUrl
    sudo chmod 750 $removeThreatPath
    sudo chown root:wazuh $removeThreatPath

    # 2. Download the nixguard-remediate.sh script (Added for active remediation)
    # FIXED: Changed to direct raw.githubusercontent.com URL and added /active-response/ subfolder
    remediateUrl="https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/linux/active-response/nixguard-remediate.sh"
    remediatePath="$destDir/nixguard-remediate.sh"
    sudo wget -O $remediatePath $remediateUrl
    sudo chmod 750 $remediatePath
    sudo chown root:wazuh $remediatePath

    echo "Active Response remediation configurations added successfully."

    # ==========================================
    # STEP 4: SERVICE STARTUP & VERIFICATION
    # ==========================================
    sudo systemctl daemon-reload
    sudo systemctl enable wazuh-agent
    sudo systemctl restart wazuh-agent

    # Verify if the audit rules for monitoring the selected directories are applied
    auditctl -l | grep wazuh_fim

    echo "NixGuard agent setup and started successfully."
}

# Main script execution
if [ $# -lt 2 ]; then
    echo "Usage: $0 <WAZUH_MANAGER> <WAZUH_AGENT_NAME>"
    exit 1
fi

# Function calls
detect_distro_arch
uninstall_wazuh_agent
install_wazuh_agent