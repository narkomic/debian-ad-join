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

# Function to validate netmask
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


# --- Check for Static IP Configuration ---
log_and_echo "Starting: Checking for static IP configuration..."

# Get available network interfaces
INTERFACES=($(ip -o link show | awk '{print $2}' | cut -d':' -f1))

# Check if multiple interfaces are available
if [ ${#INTERFACES[@]} -gt 1 ]; then
    echo "Multiple network interfaces detected:"
    PS3="Select the interface to configure: "
    select DEFAULT_INTERFACE in "${INTERFACES[@]}"
    do
        break
    done
else
    DEFAULT_INTERFACE=${INTERFACES[0]}  # Use the only available interface
fi

if ! ip addr show "$DEFAULT_INTERFACE" | grep -q "inet [0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/[0-9]\{1,2\}.* brd"; then
    read -p "No static IP detected. Do you want to configure one? (y/n): " configure_static_ip
    if [[ $configure_static_ip =~ ^[Yy]$ ]]; then
        while true; do
            read -p "Enter IP address: " IP_ADDRESS
            if validate_ip "$IP_ADDRESS"; then break; fi
            echo "Invalid IP address. Please try again."
        done

        while true; do
            read -p "Enter Gateway: " GATEWAY
            if validate_ip "$GATEWAY"; then break; fi
            echo "Invalid gateway address. Please try again."
        done

        while true; do
            read -p "Enter Subnet Mask (e.g., 255.255.255.0): " NETMASK
            if validate_netmask "$NETMASK"; then break; fi
            echo "Invalid subnet mask. Please try again."
        done
        # Validate each DNS server individually
        while true; do
            read -p "Enter DNS Servers (comma-separated): " DNS_SERVERS
            all_valid=true
            IFS=',' read -ra DNS_ARRAY <<< "$DNS_SERVERS"
            for DNS in "${DNS_ARRAY[@]}"; do
                if ! validate_ip "$DNS" || ! ping -c 1 -W 1 "$DNS" >/dev/null; then
                    echo "Invalid or unreachable DNS server: $DNS. Please try again."
                    all_valid=false
                    break  # Exit the inner loop
                fi
            done
            if $all_valid; then break; fi # Exit the outer loop if all DNS servers are valid
        done

        # Basic IP conflict check (ping the IP address)
        if ping -c 1 -W 1 "$IP_ADDRESS" >/dev/null; then
            echo "Error: IP address $IP_ADDRESS seems to be in use. Exiting." >&2
            exit 1
        fi

        # Configure static IP
        cat <<EOF > /etc/network/interfaces
# Loopback interface
auto lo
iface lo inet loopback

# Primary interface ($DEFAULT_INTERFACE)
auto $DEFAULT_INTERFACE
iface $DEFAULT_INTERFACE inet static
address $IP_ADDRESS
netmask $NETMASK
gateway $GATEWAY
dns-nameservers $DNS_SERVERS
EOF

        # Inform the user about the connection loss BEFORE restarting the network
        echo "Static IP configured. You will lose connection and need to reconnect." 

        echo "Restarting networking service to apply changes..."
        systemctl restart networking

        exit 0  # Exit the script after configuring the IP
    fi
fi
log_and_echo "Finished: Checking for static IP configuration."


# --- Update and Upgrade System ---
log_and_echo "Starting: Updating and upgrading system packages..."
check_and_execute "apt-get update" "Updating package lists"
check_and_execute "apt-get upgrade -y" "Upgrading packages"
check_and_execute "apt-get autoremove -y" "Removing unused packages"
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
