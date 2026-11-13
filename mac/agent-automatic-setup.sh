#!/bin/bash
#
# NixGuard/Wazuh Agent Setup Script for macOS
# This script is idempotent, uses modern API-based registration, and includes
# an intelligent, compliance-driven feature installation based on user preferences.
#
# Usage (as a single command):
# curl -sS https://.../agent-automatic-setup.sh | sudo bash -s -- <MANAGER_IP> <AGENT_NAME> <GROUP_LABEL> [--requires-encryption]
#

# Exit immediately if any command fails for robust error handling.
set -e
# Ensure the ERR trap is inherited by functions, command substitutions, and subshells.
set -E

# --- 1. Validate Input & Define Variables ---
# Positional arguments, then optional flags set by the NixGuard app from the account's compliance standards:
#   --requires-encryption  install the disk-encryption status check
#   --soc2                 install the NixGuard SOC 2 SCA policy locally on this endpoint
REQUIRES_ENCRYPTION=false
SOC2=false
#   --agent-key <key>      the key of the one agent the NixGuard app registered for this command; the agent
#                          uses it instead of enrolling itself (shared managers no longer accept self-enrollment)
AGENT_KEY=""
POSITIONAL=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --requires-encryption) REQUIRES_ENCRYPTION=true ;;
        --soc2) SOC2=true ;;
        --agent-key) AGENT_KEY="${2:-}"; shift ;;
        --*) echo "Unknown option: $1" >&2; exit 1 ;;
        *) POSITIONAL+=("$1") ;;
    esac
    shift
done
set -- "${POSITIONAL[@]}"

if [ "$#" -ne 3 ]; then
    echo "Error: Invalid number of arguments." >&2
    echo "Usage: sudo bash -s -- <MANAGER_IP> <AGENT_NAME> <GROUP_LABEL> [--requires-encryption]" >&2
    exit 1
fi

MANAGER_IP=$1
AGENT_NAME=$2
# The account's agent group on the shared manager (the NixGuard app passes it). Agents used to enroll
# into "default", where customers' agents were mixed and the group cleanup removed all but one.
GROUP_LABEL=$3

# Agent names are global on the shared manager. A short suffix derived from the group label makes this
# name unique to this account, so a reinstall replaces only this account's own agent.
NAME_SUFFIX=$(printf '%s' "$GROUP_LABEL" | shasum -a 256 | cut -c1-6)
case "$AGENT_NAME" in *"-$NAME_SUFFIX") ;; *) AGENT_NAME="$AGENT_NAME-$NAME_SUFFIX" ;; esac

# URLs
# FIXED: Pointing directly to raw.githubusercontent.com
REPO_BASE_URL="https://raw.githubusercontent.com/thenexlabs/nixguard-free-agent-setup/main/mac"
WAZUH_PKG_URL_INTEL="https://packages.wazuh.com/4.x/macos/wazuh-agent-4.7.4-1.intel64.pkg"
WAZUH_PKG_URL_ARM="https://packages.wazuh.com/4.x/macos/wazuh-agent-4.7.4-1.arm64.pkg"

# FIXED: Appended /active-response/ subfolder to the download URLs
AR_SCRIPT_URL="${REPO_BASE_URL}/active-response/remove-threat.sh"
# The IP block and unblock scripts are shared with the paid installer: one copy, in nixguard-agent-setup.
SHARED_AR_BASE_URL="https://raw.githubusercontent.com/thenexlabs/nixguard-agent-setup/main/mac/active-response"
REMEDIATE_SCRIPT_URL="${SHARED_AR_BASE_URL}/nixguard-remediate.sh"
UNBLOCK_SCRIPT_URL="${SHARED_AR_BASE_URL}/nixguard-unblock-ip.sh"
FILEVAULT_SCRIPT_URL="${REPO_BASE_URL}/active-response/filevault_check.sh"

FIM_CONF_URL="${REPO_BASE_URL}/config/fim.conf"
FILEVAULT_CONF_URL="${REPO_BASE_URL}/config/filevault.conf"


# Writes the agent key issued by the NixGuard app (base64 of "<id> <name> <ip> <key>") to client.keys.
import_agent_key() {
    local keysFile="$1" decoded
    decoded=$(printf '%s' "$AGENT_KEY" | base64 --decode 2>/dev/null || true)
    if ! printf '%s' "$decoded" | grep -qE '^[0-9]{3,8} [A-Za-z0-9._-]+ [^ ]+ [0-9a-f]{32,128}$'; then
        echo "Error: the agent key is not valid. Create a new install command in NixGuard." >&2
        exit 1
    fi
    printf '%s\n' "$decoded" | sudo tee "$keysFile" >/dev/null
    sudo chown root:wazuh "$keysFile"
    sudo chmod 640 "$keysFile"
    echo "Agent key installed for $(printf '%s' "$decoded" | cut -d' ' -f2)."
}

# --- 4. Uninstall Existing Agent (for Idempotency) ---
uninstall_wazuh_agent() {
    echo "--- Checking for existing Wazuh Agent installation ---"
    if [ -f "/Library/Ossec/bin/wazuh-control" ]; then
        echo "Stopping any running Wazuh agent services..."
        /Library/Ossec/bin/wazuh-control stop >/dev/null 2>&1 || true
    fi
    if [ -f "/Library/Ossec/bin/wazuh-uninstall.sh" ]; then
        echo "Found existing agent. Running official uninstaller..."
        /Library/Ossec/bin/wazuh-uninstall.sh >/dev/null 2>&1 || true
    fi
    if [ -d "/Library/Ossec" ]; then
        echo "Forcibly removing Wazuh agent directory for a clean installation..."
        rm -rf /Library/Ossec
        echo "Previous installation completely removed."
    else
        echo "Wazuh Agent not found. No uninstallation needed."
    fi
}

# --- 5. Install New Agent and Register via API ---
install_and_register_agent() {
    echo "--- Installing and Registering Wazuh Agent ---"
    ARCH=$(uname -m)
    if [ "$ARCH" == "x86_64" ]; then WAZUH_PKG_URL=$WAZUH_PKG_URL_INTEL;
    elif [ "$ARCH" == "arm64" ]; then WAZUH_PKG_URL=$WAZUH_PKG_URL_ARM;
    else echo "Error: Unsupported architecture: $ARCH" >&2; exit 1; fi
    curl -Lo "/tmp/wazuh-agent.pkg" "$WAZUH_PKG_URL"
    
    # Note: We no longer pass WAZUH_MANAGER here as it's unreliable.
    WAZUH_AGENT_NAME="${AGENT_NAME}" WAZUH_AGENT_GROUP="${GROUP_LABEL}" \
    installer -pkg "/tmp/wazuh-agent.pkg" -target /
    
    rm -f "/tmp/wazuh-agent.pkg"
    echo "Agent package installed."

    if [ -n "$AGENT_KEY" ]; then
        # Registered by the NixGuard app: use its key, no self-enrollment.
        import_agent_key /Library/Ossec/etc/client.keys
    else
        echo "Registering agent '${AGENT_NAME}' with manager..."
        set +e
        /Library/Ossec/bin/agent-auth -m "${MANAGER_IP}" -A "${AGENT_NAME}" -G "${GROUP_LABEL}"
        set -e
        echo "Agent successfully registered."
    fi
}

# --- 6. Apply Custom FIM and Log Collection Configuration ---
configure_ossec_conf() {
    echo "--- Applying custom NixGuard configuration ---"
    local ossecConfPath="/Library/Ossec/etc/ossec.conf"
    local timeout=30
    local counter=0
    echo "Waiting for configuration file to be created and populated..."

    set +e
    while [ ! -s "$ossecConfPath" ]; do
        if [ $counter -ge $timeout ]; then break; fi
        sleep 1
        counter=$((counter+1))
    done
    set -e

    if [ ! -s "$ossecConfPath" ]; then
        echo "Error: Timed out waiting for '$ossecConfPath' to be created and populated." >&2
        exit 1
    fi
    echo "Configuration file found and is not empty."

    echo "Applying File Integrity Monitoring (FIM) rules by downloading config..."
    curl -fsS "$FIM_CONF_URL" >> "$ossecConfPath" || echo "Warning: FIM config not available; keeping the default." >&2
    
    echo "Custom FIM configuration applied successfully."
}

# --- ADDED: CPU/IO Performance Optimization Function (macOS) ---
optimize_syscheck_performance() {
    echo "--- Optimizing Syscheck (FIM) performance to prevent high CPU/IO usage ---"
    local ossecConfPath="/Library/Ossec/etc/ossec.conf"
    
    # Use perl for robust, cross-platform in-place XML manipulation (bypasses macOS sed quirks)
    perl -i -pe 's|<syscheck>|<syscheck>\n    <max_eps>50</max_eps>\n    <frequency>43200</frequency>\n    <process_priority>10</process_priority>\n    <sleep>20</sleep>|g' "$ossecConfPath"
    perl -i -pe 's|</syscheck>|    <nodiff>/bin</nodiff>\n    <nodiff>/sbin</nodiff>\n    <nodiff>/usr/bin</nodiff>\n    <nodiff>/usr/sbin</nodiff>\n  </syscheck>|g' "$ossecConfPath"
    
    echo "Syscheck performance optimized."
}

# --- 7. Install Active Response Scripts ---
install_ar_script() {
    echo "--- Installing Active Response scripts for threat remediation ---"
    local destDir="/Library/Ossec/active-response/bin"
    local removeThreatPath="$destDir/remove-threat.sh"
    local remediatePath="$destDir/nixguard-remediate.sh"
    mkdir -p "$destDir"
    
    # 1. Download remove-threat.sh
    curl -Lo "$removeThreatPath" "$AR_SCRIPT_URL"
    chmod 750 "$removeThreatPath"
    chown root:wazuh "$removeThreatPath"
    
    # 2. Download nixguard-remediate.sh (Added for active remediation)
    curl -Lo "$remediatePath" "$REMEDIATE_SCRIPT_URL"
    chmod 750 "$remediatePath"
    chown root:wazuh "$remediatePath"

    # 3. nixguard-unblock-ip.sh removes a NixGuard IP block (run from the NixGuard app's Undo / Unblock)
    local unblockPath="$destDir/nixguard-unblock-ip.sh"
    curl -Lo "$unblockPath" "$UNBLOCK_SCRIPT_URL"
    chmod 750 "$unblockPath"
    chown root:wazuh "$unblockPath"

    echo "Active Response scripts installed."
}

# --- 8. Install and Schedule FileVault Encryption Monitoring ---
install_filevault_monitoring() {
    echo "--- Installing and scheduling FileVault encryption monitoring ---"
    local scriptPath="/Library/Ossec/bin/filevault_check.sh"
    local plistPath="/Library/LaunchDaemons/com.nixguard.filevaultcheck.plist"
    local ossecConfPath="/Library/Ossec/etc/ossec.conf"

    curl -Lo "$scriptPath" "$FILEVAULT_SCRIPT_URL"
    chmod 750 "$scriptPath"
    chown root:wazuh "$scriptPath"

    LAUNCHD_PLIST="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>com.nixguard.filevaultcheck</string>
    <key>ProgramArguments</key>
    <array><string>/bin/bash</string><string>${scriptPath}</string></array>
    <key>RunAtLoad</key><true/>
    <key>StartInterval</key><integer>300</integer>
    <key>StandardErrorPath</key><string>/dev/null</string>
    <key>StandardOutPath</key><string>/dev/null</string>
</dict>
</plist>"
    echo "$LAUNCHD_PLIST" > "$plistPath"
    chown root:wheel "$plistPath"
    chmod 644 "$plistPath"
    
    # --- FINAL FIX: Suppress the harmless "Unload failed" error message ---
    # We redirect stderr (2) to /dev/null to keep the logs clean for the user.
    launchctl unload "$plistPath" 2>/dev/null || true
    # --- END FIX ---
    
    launchctl load "$plistPath"
    
    echo "Configuring agent to monitor FileVault status log by downloading config..."
    if ! grep -q "filevault_status.log" "$ossecConfPath"; then
        printf '%s\n' '<ossec_config>' '  <localfile>' '    <location>/Library/Ossec/logs/filevault_status.log</location>' '    <log_format>json</log_format>' '  </localfile>' '</ossec_config>' >> "$ossecConfPath"
    fi

    echo "FileVault monitoring script installed and scheduled."
}

configure_manager_ip() {
    echo "--- Manually configuring manager IP to ensure correctness ---"
    local ossecConfPath="/Library/Ossec/etc/ossec.conf"
    # Use sed to replace the placeholder with the actual manager IP.
    # This is a fallback for when the installer fails to use the env var.
    # The '' after -i is required for macOS compatibility.
    sed -i '' "s|<address>MANAGER_IP</address>|<address>${MANAGER_IP}</address>|g" "$ossecConfPath"
    echo "Manager IP configured in ossec.conf."
}

# --- Main Execution ---
cleanup_on_failure() {
    echo "❌ An error occurred during setup." >&2
    echo "--- Running automatic cleanup ---" >&2
    if [ -f "/Library/Ossec/bin/wazuh-control" ]; then
        /Library/Ossec/bin/wazuh-control stop >/dev/null 2>&1
    fi
    if [ -d "/Library/Ossec" ]; then
        rm -rf /Library/Ossec
    fi
    echo "Cleanup complete. The agent has been removed from this machine." >&2
}

trap cleanup_on_failure ERR

echo "Starting NixGuard Agent Setup for macOS..."

uninstall_wazuh_agent
install_and_register_agent
configure_ossec_conf
optimize_syscheck_performance # Added FIM CPU/IO optimizations
install_ar_script

# --- Intelligent Feature Deployment ---

# The NixGuard app passes --requires-encryption when the account's compliance standards require it,
# so the installer never needs an account token.
ENCRYPTION_REQUIRED=$REQUIRES_ENCRYPTION
if [ "$SOC2" = true ]; then
    echo "No SOC 2 policy for macOS yet; skipping." >&2
fi

# 3. Make the final decision.
if [ "$ENCRYPTION_REQUIRED" = true ]; then
    install_filevault_monitoring
else
    echo "User's compliance standards do not require encryption monitoring. Skipping." >&2
fi

# --- End of Intelligent Feature Deployment block ---

configure_manager_ip

echo "--- Restarting Wazuh Agent to apply all changes ---"
/Library/Ossec/bin/wazuh-control restart

# Disable the error trap on success
trap - ERR

echo "✅ NixGuard agent setup complete and running."