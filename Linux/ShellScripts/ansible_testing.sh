#!/bin/bash

# Define the directories to search for Ansible files
ANSIBLE_DIRS=("/etc/ansible" "$HOME/ansible" "$HOME/.ansible" "/var/log/ansible")
SYSLOG_FILE="/var/log/syslog"
LOG_FILE="ansible_security_audit.log"

# Check if Ansible is installed
if ! command -v ansible &> /dev/null; then
    echo "Ansible is not installed."
    exit 1
fi

# Initialize the log file
echo "Ansible Security Audit - $(date)" > "$LOG_FILE"
echo "--------------------------------------" >> "$LOG_FILE"

# Function to check for insecure permissions
check_permissions() {
    local dir="$1"
    echo "Checking file permissions in $dir..." | tee -a "$LOG_FILE"
    
    # Find files and directories with world-writable permissions
    find "$dir" -type f -perm -o+w -exec ls -l {} \; | tee -a "$LOG_FILE"
    find "$dir" -type d -perm -o+w -exec ls -ld {} \; | tee -a "$LOG_FILE"
}

# Function to search for sensitive information in Ansible files
search_sensitive_info() {
    local dir="$1"
    echo "Searching for sensitive information in $dir..." | tee -a "$LOG_FILE"
    
    # Search for hardcoded credentials
    grep -rIE '(password|secret|key|token|passwd)[[:space:]]*=' "$dir" | tee -a "$LOG_FILE"
    
    # Search for private keys
    grep -rIE '-----BEGIN (RSA|DSA|EC|PRIVATE) KEY-----' "$dir" | tee -a "$LOG_FILE"
    
    # Search for Ansible Vault passwords stored in plaintext
    grep -r 'ANSIBLE_VAULT_PASSWORD_FILE' "$dir" | tee -a "$LOG_FILE"
    
    # Search for usage of sudo with password in playbooks
    grep -rIE 'become:.*yes|become_user:.*' "$dir" | tee -a "$LOG_FILE"
    
    # Search for plaintext passwords in inventory files
    grep -rIE 'ansible_ssh_pass|ansible_become_pass' "$dir" | tee -a "$LOG_FILE"
}

# Function to find Ansible Vault files
find_vault_files() {
    local dir="$1"
    echo "Searching for Ansible Vault files in $dir..." | tee -a "$LOG_FILE"
    
    # Find all files that appear to be Ansible Vault files
    find "$dir" -type f -name "*.yml" -exec grep -l '^\$ANSIBLE_VAULT;' {} \; | tee -a "$LOG_FILE"
}

# Function to check for ad-hoc command usage in syslog
check_ad_hoc_commands() {
    echo "Checking syslog for Ansible ad-hoc commands..." | tee -a "$LOG_FILE"
    
    # Look for ansible ad-hoc commands in syslog
    grep -i 'ansible' "$SYSLOG_FILE" | grep -E '(command|shell)' | tee -a "$LOG_FILE"
}

# Enumerate through possible Ansible directories
for dir in "${ANSIBLE_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        echo "Analyzing directory: $dir" | tee -a "$LOG_FILE"
        check_permissions "$dir"
        search_sensitive_info "$dir"
        find_vault_files "$dir"
    else
        echo "Directory $dir does not exist." | tee -a "$LOG_FILE"
    fi
done

# Search syslog for ad-hoc command usage
if [ -f "$SYSLOG_FILE" ]; then
    check_ad_hoc_commands
else
    echo "Syslog file $SYSLOG_FILE not found." | tee -a "$LOG_FILE"
fi

echo "Ansible security audit completed. Results are logged in $LOG_FILE."
