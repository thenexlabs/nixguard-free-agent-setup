# NixGuard Free Agent Setup — Wazuh agent installer with group-based enrollment

Wazuh agent installers for NixGuard, the AI-native SOC platform. Enroll Linux and Windows endpoints into a NixGuard agent group with a group label, no API key.

## What is it

This repository holds endpoint onboarding scripts for [NixGuard](https://nixguard.com), an AI-native active security operations center (SOC) and continuous compliance platform built on Wazuh open-source SIEM/XDR telemetry.

It is the group-label variant of [nixguard-agent-setup](https://github.com/thenexlabs/nixguard-agent-setup). On Linux and Windows the setup script takes a **group label** instead of an API key and enrolls the agent into that group on your NixGuard manager, which suits a shared, multi-tenant manager. Each script installs the official [Wazuh](https://wazuh.com) agent, applies a tuned file integrity monitoring (FIM) profile and deploys NixGuard active-response scripts for threat remediation. Matching removal scripts uninstall the agent cleanly.

## Features

- **Cross-platform endpoint security agent**: Linux (Debian, Ubuntu, Kali, CentOS, RHEL, Fedora), macOS (Intel and Apple silicon) and Windows.
- **Group-based enrollment**: the agent is registered with an agent group (`<groups>` in the enrollment block), so endpoints land in the right tenant or policy group.
- **Clean reinstall**: any existing Wazuh agent is stopped and removed before the new one is installed.
- **Tuned file integrity monitoring**: rate-limited, low-priority syscheck scans on a 12-hour baseline. On Linux, `/root` is watched in real time, `/home` on a schedule, and per-user cache and config folders are ignored.
- **Compliance-driven BitLocker monitoring (Windows)**: the script looks up the compliance preferences for your group label from the NixGuard API. If they include SOC 2, NIST SP 800-53, ISO 27001, GDPR, HIPAA, PCI DSS, PIPEDA or CIS Controls, it installs a BitLocker status check whose JSON output the agent forwards for compliance reporting.
- **Active response for threat detection and remediation**: installs `remove-threat` (quarantine or delete a flagged file) and `nixguard-remediate` (block an IP, restart a service, or upgrade a package).
- **Linux audit support**: installs and enables `auditd`.

## Requirements

| Platform | Requirements |
| --- | --- |
| Linux | Debian, Ubuntu or Kali (apt/dpkg) or CentOS, RHEL or Fedora (yum/rpm); x86_64 or aarch64; systemd; root via `sudo` |
| macOS | Intel (x86_64) or Apple silicon (arm64); root via `sudo`; Homebrew recommended (used to install `jq`) |
| Windows | 64-bit Windows; PowerShell run as Administrator |

You also need the **address of your NixGuard manager**, an **agent name** for this machine, and your **group label** (Linux and Windows). The macOS script in this repository takes a **NixGuard API key** instead of a group label (see below).

## Quick start / Installation

Download the script for your platform, review it, then run it with administrator rights. Replace the placeholders in angle brackets.

### Linux

```bash
curl -fsSLO https://raw.githubusercontent.com/thenexlabs/nixguard-free-agent-setup/main/linux/agent-automatic-setup.sh
sudo bash agent-automatic-setup.sh <manager_address> <agent_name> <group_label>
```

### Windows (PowerShell as Administrator)

```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/thenexlabs/nixguard-free-agent-setup/main/windows/agent-automatic-setup.ps1 -OutFile agent-automatic-setup.ps1
powershell -ExecutionPolicy Bypass -File .\agent-automatic-setup.ps1 -agentName <agent_name> -ipAddress <manager_address> -groupLabel <group_label>
```

### macOS

The macOS script is the same as in [nixguard-agent-setup](https://github.com/thenexlabs/nixguard-agent-setup) and takes an API key as its third argument:

```bash
curl -fsSLO https://raw.githubusercontent.com/thenexlabs/nixguard-free-agent-setup/main/mac/agent-automatic-setup.sh
sudo bash agent-automatic-setup.sh <manager_address> <agent_name> <api_key>
```

If your NixGuard compliance standards require it, it also installs FileVault monitoring.

## Usage

### Uninstall the agent

Run from a clone of this repository (`git clone https://github.com/thenexlabs/nixguard-free-agent-setup.git`):

| Platform | Command |
| --- | --- |
| Linux | `sudo bash linux/agent-automatic-remove.sh` |
| macOS | `sudo bash mac/agent-automatic-remove.sh` |
| Windows | `.\windows\agent-automatic-remove.ps1` (PowerShell as Administrator) |

### Verify the agent is running

- Linux: `systemctl status wazuh-agent`
- macOS: `sudo /Library/Ossec/bin/wazuh-control status`
- Windows: `Get-Service WazuhSvc`

### What the scripts change

| | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Wazuh agent | 4.9.1 (`.deb` / `.rpm`), service `wazuh-agent` | 4.7.4 (`.pkg`), installed under `/Library/Ossec` | 4.9.1 (`.msi`), service `WazuhSvc` |
| Extra packages | `auditd` and `audispd-plugins` (`audit` on RHEL family), `jq`; runs `apt-get -f install` on Debian family | `jq` via Homebrew if missing | Python 3.12.4 (all users) and PyInstaller, used to build the active-response `.exe` files |
| Encryption check | Not installed by the setup script | `filevault_check.sh` via LaunchDaemon `com.nixguard.filevaultcheck` every 5 minutes (if required) | `bitlocker_check.ps1` via scheduled task `Wazuh-BitLocker-Check` every 5 minutes, as SYSTEM (if required) |
| Active response | `remove-threat.sh`, `nixguard-remediate.sh` | `remove-threat.sh`, `nixguard-remediate.sh` | `remove-threat.exe`, `nixguard-remediate.exe` |
| Config | Replaces FIM `<directories>` in `ossec.conf` (backup saved as `ossec.conf.bak`), sets manager address and group | Appends FIM tuning to `ossec.conf` | Adds FIM directories, tuning and group to `ossec.conf` |

**Network:** the agent connects outbound to your NixGuard manager using the standard Wazuh agent ports (1514/TCP for events, 1515/TCP for enrollment; the scripts do not change them). During setup the scripts also make HTTPS requests to `packages.wazuh.com`, `raw.githubusercontent.com` (this repository and [nixguard-agent-setup](https://github.com/thenexlabs/nixguard-agent-setup), which hosts the shared active-response scripts), the NixGuard API (Windows and macOS, to read compliance preferences), and on Windows `python.org` and PyPI. No inbound ports are opened.

**Warning:** setup removes any existing Wazuh agent on the machine first. On macOS the whole `/Library/Ossec` directory is deleted.

## Repository layout

```text
linux/    agent-automatic-setup.sh, agent-automatic-remove.sh, active-response/
mac/      agent-automatic-setup.sh, agent-automatic-remove.sh, active-response/
windows/  agent-automatic-setup.ps1, agent-automatic-remove.ps1, active-response/
```

## Security

The setup scripts run with root or Administrator rights, so read them before running. To report a vulnerability, please use the security contact listed on [nixguard.com](https://nixguard.com) rather than opening a public issue.

## About NEX Level Labs

NixGuard is built by NEX Level Labs Inc., a deeptech cybersecurity company. Learn more about the [NixGuard AI SOC platform](https://nixguard.com) and [NEX Level Labs](https://thenex.world).
