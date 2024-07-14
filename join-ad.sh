#!/bin/bash
# Script to join a Debian system to an Active Directory domain and configure sudo access

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

# Tjek for root-privilegier
if [[ $EUID -ne 0 ]]; then
    # Tjek om sudo er installeret
    if command -v sudo &> /dev/null; then
        echo "Requesting sudo privileges..."
        sudo "$0" "$@"
        exit $? # Afslut med samme status som sudo-kommandoen
    else
        echo "Error: This script must be run as root. Sudo is not installed."
        exit 1
    fi
fi

# --- Configuration ---
LOG_FILE="/var/log/join-ad.log" # Log file for error and output logging

# Create the log file if it doesn't exist
touch "$LOG_FILE"

log_and_echo "Running as root..."

# --- Check for Static IP Configuration ---
log_and_echo "Starting: Checking for static IP configuration..."

# Get available network interfaces (excluding loopback)
INTERFACES=($(ip -o link show | awk '/^[0-9]+: / && !/lo/ {print $2}' | cut -d':' -f1))

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

# Check if a static IP is configured on the selected interface
if grep -q "iface $DEFAULT_INTERFACE inet static" /etc/network/interfaces; then 
    log_and_echo "Static IP already configured on $DEFAULT_INTERFACE."

    # Get and display current IP settings
    CURRENT_IP=$(ip addr show "$DEFAULT_INTERFACE" | awk '/inet / {print $2}' | cut -d'/' -f1)
    CURRENT_NETMASK=$(ip addr show "$DEFAULT_INTERFACE" | awk '/inet / {print $2}' | cut -d'/' -f2)
    CURRENT_GATEWAY=$(ip route | awk '/default/ {print $3}')
    CURRENT_DNS=$(awk '/nameserver / {print $2}' /etc/resolv.conf)

    log_and_echo "Current IP settings:"
    log_and_echo "- IP Address: $CURRENT_IP"
    log_and_echo "- Netmask: $CURRENT_NETMASK"
    log_and_echo "- Gateway: $CURRENT_GATEWAY"
    log_and_echo "- DNS Servers: $CURRENT_DNS"

    read -p "Do you want to change the IP settings? (y/n): " change_ip
    if [[ $change_ip =~ ^[Yy] ]]; then
        # Prompt for new IP settings
        while true; do
            read -p "Enter new IP address: " IP_ADDRESS
            if validate_ip "$IP_ADDRESS"; then break; fi
            echo "Invalid IP address. Please try again."
        done

        while true; do
            read -p "Enter new Gateway: " GATEWAY
            if validate_ip "$GATEWAY"; then break; fi
            echo "Invalid gateway address. Please try again."
        done

        while true; do
            read -p "Enter new Subnet Mask (e.g., 255.255.255.0): " NETMASK
            if validate_netmask "$NETMASK"; then break; fi
            echo "Invalid subnet mask. Please try again."
        done

        # Validate each DNS server individually
        while true; do
            read -p "Enter new DNS Servers (comma-separated): " DNS_SERVERS
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

        # Inform the user about the connection loss BEFORE restarting the network
        echo "Static IP configured. You will lose connection and need to reconnect." 

        # Basic IP conflict check (ping the IP address)
        if ping -c 1 -W 1 "$IP_ADDRESS" >/dev/null; then
            echo "Error: IP address $IP_ADDRESS seems to be in use. Exiting." >&2
            exit 1
        fi

        # Configure static IP (using 'ip' command and updating /etc/network/interfaces)
        ip addr flush dev "$DEFAULT_INTERFACE"
        ip addr add "$IP_ADDRESS/$NETMASK" dev "$DEFAULT_INTERFACE"
        ip route add default via "$GATEWAY"

        # Update DNS servers in /etc/resolv.conf
        echo "nameserver $DNS_SERVERS" > /etc/resolv.conf

        # Update /etc/network/interfaces (replace existing configuration)
        sed -i "/iface $DEFAULT_INTERFACE inet.*/c\\
iface $DEFAULT_INTERFACE inet static\\
    address $IP_ADDRESS\\
    netmask $NETMASK\\
    gateway $GATEWAY\\
    dns-nameservers $(echo $DNS_SERVERS | sed 's/,/ /g')" /etc/network/interfaces

        # Apply changes and restart networking
        systemctl restart networking.service

        exit 0  # Exit the script after configuring the IP
    fi
else
    log_and_echo "No static IP detected on $DEFAULT_INTERFACE. Configuring static IP..."
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
while ping -c 1 -W 1 "$IP_ADDRESS" >/dev/null; do
    echo "Error: IP address $IP_ADDRESS seems to be in use. Please try again."
    read -p "Enter new IP address: " IP_ADDRESS
done

# Update DNS servers in /etc/resolv.conf
# Check if domain and search settings already exist in resolv.conf
EXISTING_DOMAIN=$(awk '/^domain/ {print $2}' /etc/resolv.conf)
EXISTING_SEARCH=$(awk '/^search/ {print $2}' /etc/resolv.conf)

if [ -n "$EXISTING_DOMAIN" ] && [ -n "$EXISTING_SEARCH" ]; then
    log_and_echo "Existing domain and search settings found in /etc/resolv.conf:"
    log_and_echo "- domain $EXISTING_DOMAIN"
    log_and_echo "- search $EXISTING_SEARCH"

    while true; do
        read -p "Is this the correct domain you want to join ($EXISTING_DOMAIN)? (y/n): " confirm_domain
        if [[ $confirm_domain =~ ^[Yy] ]]; then
            DOMAIN_NAME="$EXISTING_DOMAIN"  # Use existing domain
            break
        elif [[ $confirm_domain =~ ^[Nn] ]]; then
            # Remove existing domain and search lines
            sed -i '/^domain /d' /etc/resolv.conf
            sed -i '/^search /d' /etc/resolv.conf
            break
        else
            log_and_echo "Invalid input. Please enter 'y' or 'n'."
        fi
    done
fi

# Write to /etc/resolv.conf
cat <<EOF > /etc/resolv.conf
search $DOMAIN_NAME
$(echo "$DNS_SERVERS" | awk '{print "nameserver " $1}')
EOF

# Configure static IP (using 'ip' command and updating /etc/network/interfaces)
ip addr flush dev "$DEFAULT_INTERFACE"
ip addr add "$IP_ADDRESS/$NETMASK" dev "$DEFAULT_INTERFACE"
ip route add default via "$GATEWAY"

# Update /etc/network/interfaces (replace existing configuration)
sed -i "/iface $DEFAULT_INTERFACE inet.*/c\\
iface $DEFAULT_INTERFACE inet static\\
    address $IP_ADDRESS\\
    netmask $NETMASK\\
    gateway $GATEWAY\\
    dns-nameservers $(echo $DNS_SERVERS | sed 's/,/ /g')" /etc/network/interfaces

# Inform the user about the connection loss BEFORE restarting the network
echo "Static IP configured. You will lose connection and need to reconnect." 

# Apply changes and restart networking
systemctl restart networking.service

exit 0  # Exit the script after configuring the IP
fi

log_and_echo "Finished: Checking for static IP configuration."



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

# Forsøg at finde domænenavn automatisk
method=""  # Variabel til at gemme metodenavn

domain=$(grep -m1 '^search' /etc/resolv.conf | awk '{print $2}')
if [ ! -z "$domain" ]; then
    method="search i /etc/resolv.conf"
fi

if [ -z "$domain" ]; then
    domain=$(grep -m1 '^domain' /etc/resolv.conf | awk '{print $2}')
    if [ ! -z "$domain" ]; then
        method="domain i /etc/resolv.conf"
    fi
fi

if [ -z "$domain" ]; then
    domain=$(hostname -d)
    if [ ! -z "$domain" ]; then
        method="hostname -d"
    fi
fi

if [ -z "$domain" ]; then
    domain=$(dig +short -x $(hostname -i) | awk -F'.' '{print $(NF-1)"."$NF}')
    if [ ! -z "$domain" ]; then
        method="reverse DNS (dig)"
    fi
fi

if [ -z "$domain" ]; then
    domain=$(host $(hostname) | awk '/domain name pointer/{print $NF}')
    if [ ! -z "$domain" ]; then
        method="DNS (host)"
    fi
fi

# Hvis domænenavn ikke blev fundet, spørg brugeren
if [ -z "$domain" ]; then
    read -p "Indtast domænenavn: " domain
    method="manuel indtastning"
fi

# Udskriv resultatet
log_and_echo "Fundet domænenavn: $domain (metode: $method)"
DOMAIN_NAME=$domain

# Find domain controllers using DNS
DOMAIN_CONTROLLERS=$(dig +short SRV _ldap._tcp.dc._msdcs.$DOMAIN_NAME | awk '{print $4}')

if [ -n "$DOMAIN_CONTROLLERS" ]; then
    log_and_echo "Domain controllers found for $DOMAIN_NAME:"

    # Find IP addresses of domain controllers
    for CONTROLLER in $DOMAIN_CONTROLLERS; do
        CONTROLLER_IP=$(dig +short "$CONTROLLER" | head -n1) # Get the first IP address
        if [ -n "$CONTROLLER_IP" ]; then
            echo "$CONTROLLER_IP ($CONTROLLER)"
        else
            log_and_echo "Warning: Could not resolve IP address for domain controller $CONTROLLER"
        fi
    done
else
    log_and_echo "Error: No domain controllers found for $DOMAIN_NAME."
    exit 1
fi

# --- Join the Domain ---  
log_and_echo "Starting: Joining the domain..."

# Check if already joined to the domain
if realm list -a | grep -iq "$DOMAIN_NAME"; then
  log_and_echo "Already joined to domain $DOMAIN_NAME. Skipping..."
else

# Prompt for the AD admin user 
read -p "Enter AD Administrator Username: " ADMIN_USER

# Prompt for the password 
read -sp "Enter AD Administrator Password: " ADMIN_PASSWORD
echo "" # Add a newline for better readability
    # If not joined, try to join
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
fi
log_and_echo "Finished: Joining the domain."


# --- Configure Time Synchronization ---
log_and_echo "Starting: Configuring time synchronization..."

# Stop systemd-timesyncd (if running)
if systemctl is-active --quiet systemd-timesyncd.service; then
    check_and_execute "systemctl stop systemd-timesyncd.service" "Stopping systemd-timesyncd"
    check_and_execute "systemctl disable systemd-timesyncd.service" "Disabling systemd-timesyncd"
fi

# Configure NTP servers in /etc/ntpsec/ntp.conf
DOMAIN_CONTROLLER_IPS=$(echo "$DOMAIN_CONTROLLERS" | awk '{print $1}')  # Extract only IP addresses

# Remove existing pool and server lines
sed -i '/^pool /d' /etc/ntpsec/ntp.conf
sed -i '/^server /d' /etc/ntpsec/ntp.conf

# Add domain controller servers
for CONTROLLER_IP in $DOMAIN_CONTROLLER_IPS; do
    echo "server $CONTROLLER_IP prefer" >> /etc/ntpsec/ntp.conf
done

# Restart ntpsec
check_and_execute "systemctl restart ntpsec.service" "Restarting ntpsec"

log_and_echo "Finished: Configuring time synchronization."



# --- Configure PAM for Automatic Home Directory Creation ---
log_and_echo "Starting: Configuring PAM..."

# File to modify
PAM_FILE="/etc/pam.d/common-session"

# Line to search for (and replace if necessary)
PAM_LINE="session optional        pam_mkhomedir.so skel=/etc/skel umask=077"

# Check if the line exists
if grep -q "$PAM_LINE" "$PAM_FILE"; then
    log_and_echo "PAM already configured for automatic home directory creation. Skipping..."
else
    # Add the line to the end of the file
    echo "$PAM_LINE" >> "$PAM_FILE"
    log_and_echo "PAM configured for automatic home directory creation."
fi

log_and_echo "Finished: Configuring PAM."


configure_sssd() {
    log_and_echo "Starting: Configuring SSSD..."
    SSSD_CONFIG_FILE="/etc/sssd/sssd.conf"

    # Change setting if you need
    if grep -q '^use_fully_qualified_names =' "$SSSD_CONFIG_FILE"; then  
        sed -i 's/^use_fully_qualified_names = .*/use_fully_qualified_names = False/' "$SSSD_CONFIG_FILE"
        log_and_echo "use_fully_qualified_names was changed in $SSSD_CONFIG_FILE."
    else
        log_and_echo "use_fully_qualified_names not found in $SSSD_CONFIG_FILE. Skipping..."
    fi

    if ! systemctl restart sssd; then
        log_and_echo "Error: Failed to restart SSSD."
        cleanup_and_exit 1
    fi

    log_and_echo "Finished: Configuring SSSD."
}

# Assuming DOMAIN_CONTROLLERS is a space-separated list of IPs and hostnames
DNS_SERVERS=$(echo "$DOMAIN_CONTROLLERS" | awk '{print $1}')  # Extract only IP addresses

if [ -z "$DNS_SERVERS" ]; then
  log_and_echo "Error: No DNS servers found. Exiting."
  exit 1
fi

# Update /etc/resolv.conf
cp /etc/resolv.conf /etc/resolv.conf.bak  # Backup existing resolv.conf

# Find IP addresses of domain controllers
DNS_SERVERS=""
for CONTROLLER in $DOMAIN_CONTROLLERS; do
    CONTROLLER_IP=$(dig +short "$CONTROLLER" | head -n1) # Get the first IP address
    if [ -n "$CONTROLLER_IP" ]; then
        DNS_SERVERS="$DNS_SERVERS $CONTROLLER_IP"
    else
        log_and_echo "Warning: Could not resolve IP address for domain controller $CONTROLLER"
    fi
done

# Write to /etc/resolv.conf
cat <<EOF > /etc/resolv.conf
search $DOMAIN_NAME
$(echo "$DNS_SERVERS" | awk '{print "nameserver " $1}')
EOF

log_and_echo "Finished: Discovering domain controllers and configuring DNS."

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
if ! realm list | grep -iq "permitted-groups:.*$SSH_GROUP"; then 
    log_and_echo "Adding SSH group $SSH_GROUP to permitted groups..."
    realm deny --all  # Deny all first if not already done
    realm permit -g "$SSH_GROUP"
else
    log_and_echo "SSH group $SSH_GROUP already in permitted groups. Skipping..."
fi

log_and_echo "Finished: Configuring SSH Access."
# --- Summary Report ---
echo "\n--- Summary ---"
echo "Static IP Configuration:"
if [ -n "$IP_ADDRESS" ]; then  # Check if static IP was configured
    echo "- IP Address: $IP_ADDRESS"
    echo "- Gateway: $GATEWAY"
    echo "- Netmask: $NETMASK"

    # Get IP addresses of DNS servers from the configured list
    DNS_SERVER_IPS=$(echo "$DNS_SERVERS" | awk -F ',' '{for (i=1; i<=NF; i++) system("dig +short "$i"")}')
    echo "- DNS Servers: $DNS_SERVER_IPS"

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
if systemctl is-active --quiet ntpsec; then  # Check if ntpsec service is running
    echo "- NTP (ntpsec) is enabled."
else
    echo "- NTP is not enabled."
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
if realm list | grep -iq "permitted-groups:.*$SSH_GROUP"; then 
    echo "- SSH group $SSH_GROUP configured successfully."
else
    echo "- SSH group $SSH_GROUP configuration failed."
fi

echo "\n--- End of Summary ---"

echo "Debian system successfully joined to $DOMAIN_NAME!"
