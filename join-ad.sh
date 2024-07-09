#!/bin/bash
# Script to join a Debian system to an Active Directory domain and configure sudo access

# --- Configuration ---
LOG_FILE="/var/log/join-ad.log" # Log file for error and output logging

# --- Functions ---

# Function to log messages and print to console
log_and_echo() {
    local message="$1"
    echo "$message"
    echo "$(date '+%Y-%m-%d %H:%M:%S'): $message" >> "$LOG_FILE"
}

# Function to check and execute commands (only if needed)
check_and_execute() {
    local command="$1"
    local description="$2"

    if bash -c "$command" >/dev/null 2>&1; then # Execute in a subshell
        echo "$description already done. Skipping."
    else
        echo "Executing: $description"
        if ! bash -c "$command"; then # Execute in a subshell
            echo "Error executing command: $description (exit code $?)" >&2
            exit 1
        fi
    fi
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    local ip_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'  # Basic IP address regex

    if [[ $ip =~ $ip_regex ]]; then
        IFS='.' read -r i1 i2 i3 i4 <<< "$ip"
        if (( i1 <= 255 && i2 <= 255 && i3 <= 255 && i4 <= 255 )); then
            return 0  # Valid IP
        fi
    fi

    return 1  # Invalid IP
}
DOMAIN_CONTROLLERS=$(realm discover $DOMAIN_NAME | grep 'domain-name:' | awk '{print $2}')
if [ -z "$DOMAIN_CONTROLLERS" ]; then
    log_and_echo "Error: No domain controllers found for $DOMAIN_NAME. Exiting."
    exit 1
fi

DNS_SERVERS=$(dig +short @$DOMAIN_CONTROLLERS _ldap._tcp.dc._msdcs.$DOMAIN_FQDN SRV | awk '{print $4}')
if [ -z "$DNS_SERVERS" ]; then
    log_and_echo "Error: Could not determine DNS servers from domain controllers. Exiting." 
    exit 1
fi

cat <<EOF > /etc/resolv.conf
domain $DOMAIN_FQDN
search $DOMAIN_FQDN
$(echo $DNS_SERVERS | sed 's/\([^ ]*\)/nameserver \1/') # add nameserver lines
EOF

log_and_echo "Finished: Discovering domain controllers and configuring DNS."

# --- Join the Domain ---  
log_and_echo "Starting: Joining the domain..."

# Prompt for the AD admin user 
read -p "Enter AD Administrator Username: " ADMIN_USER

# Prompt for the password 
read -sp "Enter AD Administrator Password: " ADMIN_PASSWORD
echo "" # Add a newline for better readability

check_and_execute "realm list | grep -q '$DOMAIN_NAME'" "Joining the domain..."
log_and_echo "Finished: Joining the domain."

# --- Configure Time Synchronization ---
log_and_echo "Starting: Configuring time synchronization..."
check_and_execute "timedatectl set-ntp true" "Enabling NTP"
DOMAIN_CONTROLLER_IP=$(echo "$DOMAIN_CONTROLLERS" | awk '{print $1}')
check_and_execute "ntpdate -u $DOMAIN_CONTROLLER_IP" "Synchronizing time with domain controller"
DOMAIN_CONTROLLERS=$(realm discover $DOMAIN_NAME | grep 'domain-name:' | awk '{print $2}')
if [ -z "$DOMAIN_CONTROLLERS" ]; then
    log_and_echo "Error: No domain controllers found for $DOMAIN_NAME. Exiting."
    exit 1
fi

DNS_SERVERS=$(dig +short @$DOMAIN_CONTROLLERS _ldap._tcp.dc._msdcs.$DOMAIN_FQDN SRV | awk '{print $4}')
if [ -z "$DNS_SERVERS" ]; then
    log_and_echo "Error: Could not determine DNS servers from domain controllers. Exiting." 
    exit 1
fi

cat <<EOF > /etc/resolv.conf
domain $DOMAIN_FQDN
search $DOMAIN_FQDN
$(echo $DNS_SERVERS | sed 's/\([^ ]*\)/nameserver \1/') # add nameserver lines
EOF

log_and_echo "Finished: Discovering domain controllers and configuring DNS."

# --- Join the Domain ---  
log_and_echo "Starting: Joining the domain..."

# Prompt for the AD admin user 
read -p "Enter AD Administrator Username: " ADMIN_USER

# Prompt for the password 
read -sp "Enter AD Administrator Password: " ADMIN_PASSWORD
echo "" # Add a newline for better readability

check_and_execute "realm list | grep -q '$DOMAIN_NAME'" "Joining the domain..."
log_and_echo "Finished: Joining the domain."
log_and_echo "Finished: Configuring time synchronization."

# --- Configure PAM for Automatic Home Directory Creation ---
log_and_echo "Starting: Configuring PAM..."
check_and_execute "grep -q 'pam_mkhomedir.so' /etc/pam.d/common-session" "Configuring PAM for automatic home directory creation..."
log_and_echo "Finished: Configuring PAM."


# --- Configure SSSD (use short names) ---
log_and_echo "Starting: Configuring SSSD..."
check_and_execute "grep -q 'use_fully_qualified_names = False' /etc/sssd/sssd.conf" "Configuring SSSD to use short names..." # Updated description
log_and_echo "Finished: Configuring SSSD."

# --- Configure SUDO Access ---
log_and_echo "Starting: Configuring sudo access..."
SERVER_HOSTNAME=$(hostname -s)
SUDO_GROUP="SYS-${SERVER_HOSTNAME}-SUDO@$DOMAIN_NAME"  # Sudo group based on hostname (uppercase)

# Check if the SUDO group is already in sudoers
if ! grep -q "^%$SUDO_GROUP " /etc/sudoers; then
    echo "%$SUDO_GROUP ALL=(ALL) ALL" >> /etc/sudoers
    echo "Added $SUDO_GROUP to sudoers."
else
    echo "Sudo group $SUDO_GROUP already in sudoers. Skipping."
fi

echo "Finished: Configuring sudo access."
# --- Configure SSH Access (using server's hostname) ---
echo "Starting: Configuring SSH Access..."
SERVER_HOSTNAME=$(hostname -s)
SSH_GROUP="SYS-$SERVER_HOSTNAME-SSH@$DOMAIN_NAME"

# Check if the SSH group is already permitted
if ! realm permit -g "$SSH_GROUP" | grep -q "$SSH_GROUP"; then 
    realm deny --all  # Deny all first if not already done
    realm permit -g "$SSH_GROUP"
fi
echo "Finished: Configuring SSH Access."


echo "Debian system successfully joined to $DOMAIN_NAME!"
