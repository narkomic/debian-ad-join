#!/bin/bash
# Script to join a Debian system to an Active Directory domain and configure sudo access

# --- Configuration ---
LOG_FILE="/var/log/join-ad.log" # Log file for error and output logging

# Create the log file if it doesn't exist
touch "$LOG_FILE"

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
# Function to validate netmask (Continued from Part 1)
validate_netmask() {
    local netmask=$1
    local netmask_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'  # Same regex as IP, but different validation

    if [[ $netmask =~ $netmask_regex ]]; then
        IFS='.' read -r n1 n2 n3 n4 <<< "$netmask"
        if (( (n1 == 255 && n2 == 255 && n3 == 255 && n4 <= 254) || 
              (n1 == 255 && n2 == 255 && n3 == 0 && n4 == 0) || 
              (n1 == 255 && n2 == 0 && n3 == 0 && n4 == 0) )); then
            return 0  # Valid netmask
        fi
    fi

    return 1  # Invalid netmask
}

# Function to clean up and exit on error
cleanup_and_exit() {
    # Revert DNS changes (if applicable)
    if [ -f /etc/resolv.conf.bak ]; then
        log_and_echo "Reverting DNS changes..."
        mv /etc/resolv.conf.bak /etc/resolv.conf
    fi

    # Uninstall partially installed packages (if applicable)
    if [ -n "$INSTALLED_PACKAGES" ]; then
        log_and_echo "Uninstalling partially installed packages..."
        apt-get purge -y "${INSTALLED_PACKAGES[@]}"
    fi

    log_and_echo "Exiting due to error. Please check the logs for details."
    exit 1
}
# --- Update and Upgrade System ---
log_and_echo "Starting: Updating and upgrading system packages..."
check_and_execute "apt-get update" "Updating package lists"
if [ $? -eq 0 ]; then
    APT_UPDATE_SUCCESS=true
else
    APT_UPDATE_SUCCESS=false
fi
check_and_execute "apt-get upgrade -y" "Upgrading packages"
if [ $? -eq 0 ]; then
    APT_UPGRADE_SUCCESS=true
else
    APT_UPGRADE_SUCCESS=false
fi
check_and_execute "apt-get autoremove -y" "Removing unused packages"
if [ $? -eq 0 ]; then
    APT_AUTOREMOVE_SUCCESS=true
else
    APT_AUTOREMOVE_SUCCESS=false
fi
log_and_echo "Finished: Updating and upgrading system packages."

# --- Check and Install Packages ---
log_and_echo "Starting: Checking and installing packages..."
PACKAGES_TO_INSTALL=("realmd" "sssd" "sssd-tools" "libnss-sss" "libpam-sss" "adcli" "samba-common-bin" "oddjob" "oddjob-mkhomedir" "packagekit" "sudo" "ntp") # Added ntp for time sync
INSTALLED_PACKAGES=() # Track installed packages for cleanup
for PACKAGE in "${PACKAGES_TO_INSTALL[@]}"; do
    if ! dpkg -l | grep -q "^ii  $PACKAGE "; then
        if ! apt-get install -y "$PACKAGE"; then
            log_and_echo "Error installing $PACKAGE! (Exit code $?)"
            cleanup_and_exit  # Call the cleanup function on error
        else
            INSTALLED_PACKAGES+=("$PACKAGE")
        fi
    fi
done
log_and_echo "Finished: Checking and installing packages."

# --- Discover Domain Controllers and Configure DNS ---
log_and_echo "Starting: Discovering domain controllers..."  
# Use realm discover to find the domain name automatically
DOMAIN_NAME=$(realm discover | awk '/realm-name:/ {print $2}')
DOMAIN_FQDN=$(realm discover | awk '/domain-name:/ {print $2}')

# Check Domain Reachability
if ! host "$DOMAIN_FQDN" >/dev/null 2>&1; then
    log_and_echo "Error: Domain $DOMAIN_FQDN is not reachable. Exiting." 
    exit 1
fi

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

cp /etc/resolv.conf /etc/resolv.conf.bak  # Backup existing resolv.conf
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

if ! realm join -U "$ADMIN_USER" "$DOMAIN_NAME" <<< "$ADMIN_PASSWORD"; then
    JOIN_EXIT_CODE=$?
    if [ $JOIN_EXIT_CODE -eq 4 ]; then
        log_and_echo "Error: Domain join failed due to incorrect credentials (exit code $JOIN_EXIT_CODE)."
    elif [ $JOIN_EXIT_CODE -eq 6 ]; then
        log_and_echo "Error: Domain join failed due to network issues (exit code $JOIN_EXIT_CODE)."
    elif [ $JOIN_EXIT_CODE -eq 11 ]; then
        log_and_echo "Error: Domain join failed. The machine is already a member of a domain. (exit code $JOIN_EXIT_CODE)."
    else
        log_and_echo "Error: Domain join failed (exit code $JOIN_EXIT_CODE). Please check the log file for details."
    fi
    cleanup_and_exit
fi
DOMAIN_JOIN_SUCCESS=true # Track if domain join is successful
log_and_echo "Finished: Joining the domain."


# --- Configure Time Synchronization ---
echo "Starting: Configuring time synchronization..."
check_and_execute "timedatectl set-ntp true" "Enabling NTP"

if ! DOMAIN_CONTROLLER_IP=$(echo "$DOMAIN_CONTROLLERS" | awk '{print $1}'); then
    echo "Error: Could not determine domain controller IP. Skipping time synchronization."
else
    if ! ntpdate -u "$DOMAIN_CONTROLLER_IP"; then
        echo "Error: Failed to synchronize time with domain controller (exit code $?)."
    fi
fi

echo "Finished: Configuring time synchronization."



# --- Configure PAM for Automatic Home Directory Creation ---
log_and_echo "Starting: Configuring PAM..."
check_and_execute "grep -q 'pam_mkhomedir.so' /etc/pam.d/common-session" "Configuring PAM for automatic home directory creation..."
PAM_CONFIG_SUCCESS=$?
log_and_echo "Finished: Configuring PAM."


# --- Configure SSSD (use short names) ---
log_and_echo "Starting: Configuring SSSD..."
check_and_execute "grep -q 'use_fully_qualified_names = False' /etc/sssd/sssd.conf" "Configuring SSSD to use short names..." # Updated description
SSSD_CONFIG_SUCCESS=$?
log_and_echo "Finished: Configuring SSSD."
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
# --- Configure SUDO Access ---
log_and_echo "Starting: Configuring sudo access..."
SERVER_HOSTNAME=$(hostname -s)
SUDO_GROUP="SYS-${SERVER_HOSTNAME}-SUDO@$DOMAIN_NAME"  # Sudo group based on hostname (uppercase)

# Check if the SUDO group is already in sudoers
if ! grep -q "^%$SUDO_GROUP " /etc/sudoers; then
    echo "%$SUDO_GROUP ALL=(ALL) ALL" >> /etc/sudoers
    log_and_echo "Added $SUDO_GROUP to sudoers."
else
    log_and_echo "Sudo group $SUDO_GROUP already in sudoers. Skipping."
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
# --- Summary Report ---
echo "\n--- Summary ---"
echo "Static IP Configuration:"
if $STATIC_IP_SUCCESS; then  # Check if static IP was configured
    echo "- IP Address: $IP_ADDRESS"
    echo "- Gateway: $GATEWAY"
    echo "- Netmask: $NETMASK"
    echo "- DNS Servers: $DNS_SERVERS"
else
    echo "- No static IP configured."
fi

echo "\nPackage Installation:"
if $PACKAGE_INSTALL_SUCCESS; then
    echo "- All packages installed successfully."
else
    echo "- Some packages failed to install. Check the log for details."
fi

echo "\nDomain Join:"
if realm list | grep -q "$DOMAIN_NAME"; then
    echo "- Successfully joined domain $DOMAIN_NAME"
else
    echo "- Failed to join domain $DOMAIN_NAME"
fi

echo "\nTime Synchronization:"
if timedatectl show | grep -q "NTP enabled: yes"; then
    echo "- NTP enabled."
else
    echo "- NTP not enabled."
fi

echo "\nPAM Configuration:"
if $PAM_CONFIG_SUCCESS; then
    echo "- PAM configured successfully."
else
    echo "- PAM configuration failed."
fi

echo "\nSSSD Configuration:"
if $SSSD_CONFIG_SUCCESS; then
    echo "- SSSD configured successfully."
else
    echo "- SSSD configuration failed."
fi

echo "\nSUDO Configuration:"
if grep -q "^%$SUDO_GROUP " /etc/sudoers; then
    echo "- SUDO group $SUDO_GROUP configured successfully."
else
    echo "- SUDO group $SUDO_GROUP configuration failed."
fi

echo "\nSSH Configuration:"
if realm permit -g "$SSH_GROUP" | grep -q "$SSH_GROUP"; then
    echo "- SSH group $SSH_GROUP configured successfully."
else
    echo "- SSH group $SSH_GROUP configuration failed."
fi

echo "\n--- End of Summary ---"

echo "Debian system successfully joined to $DOMAIN_NAME!"
