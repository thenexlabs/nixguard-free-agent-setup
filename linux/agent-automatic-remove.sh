#!/bin/bash

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
    if [ "$distro" == "debian" ] || [ "$distro" == "ubuntu" ]; then
        sudo systemctl stop wazuh-agent
        sudo dpkg -r wazuh-agent
    elif [ "$distro" == "centos" ] || [ "$distro" == "rhel" ] || [ "$distro" == "fedora" ]; then
        sudo systemctl stop wazuh-agent
        sudo rpm -e wazuh-agent
    else
        echo "Unsupported distribution: $distro"
        exit 1
    fi
}

detect_distro_arch
uninstall_wazuh_agent

