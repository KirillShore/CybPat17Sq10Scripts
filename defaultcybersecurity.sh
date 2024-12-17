#!/bin/bash

read -p "Do you want to set permissions for /etc/shadow and /etc/passwd to 600? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    sudo chmod 600 /etc/shadow
    sudo chmod 600 /etc/passwd
    echo "/etc/shadow and /etc/passwd permissions have been set to 600."
fi

read -p "Do you want to disable root login via SSH? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    if grep -q '^PermitRootLogin' /etc/ssh/sshd_config; then
        sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    else
        echo "PermitRootLogin no" | sudo tee -a /etc/ssh/sshd_config > /dev/null
    fi
    echo "Root login via SSH has been disabled."
fi

read -p "Do you want to configure the firewall (UFW) to allow only SSH and deny other incoming connections? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow 22/tcp
    sudo ufw enable
    echo "Firewall (UFW) has been configured to allow SSH and deny all other incoming connections."
fi

read -p "Do you want to enforce strong password policies by configuring the common-password file? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    if ! grep -q 'pam_pwquality' /etc/pam.d/common-password; then
        sudo sed -i '/pam_unix.so/ s/$/ retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1/' /etc/pam.d/common-password
    fi
    echo "Password complexity policies have been enforced."
fi

read -p "Do you want to set permissions for critical configuration files to 600? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    CONFIG_FILES=("/etc/ssh/sshd_config" "/etc/pam.d/common-password" "/etc/fstab" "/etc/hosts")
    for file in "${CONFIG_FILES[@]}"; do
        if [ -f "$file" ]; then
            sudo chmod 600 "$file"
            echo "Permissions set to 600 for $file."
        fi
    done
fi

read -p "Do you want to enable TCP SYN cookies to protect against SYN flood attacks? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    sudo sysctl -w net.ipv4.tcp_syncookies=1
    if ! grep -q 'net.ipv4.tcp_syncookies' /etc/sysctl.conf; then
        echo "net.ipv4.tcp_syncookies = 1" | sudo tee -a /etc/sysctl.conf
    fi
    echo "TCP SYN cookies have been enabled to protect against SYN flood attacks."
fi

read -p "Do you want to enable Address Space Layout Randomization (ASLR) to protect against memory corruption attacks? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    sudo sysctl -w kernel.randomize_va_space=2
    if ! grep -q 'kernel.randomize_va_space' /etc/sysctl.conf; then
        echo "kernel.randomize_va_space = 2" | sudo tee -a /etc/sysctl.conf
    fi
    echo "Address Space Layout Randomization (ASLR) has been enabled."
fi

read -p "Do you want to disable Apache server signature, set server tokens to least information, and configure the UFW profile to 'Apache Secure'? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    if [ -f /etc/apache2/conf-available/security.conf ]; then
        sudo sed -i 's/^ServerSignature.*/ServerSignature Off/' /etc/apache2/conf-available/security.conf
        sudo sed -i 's/^ServerTokens.*/ServerTokens Prod/' /etc/apache2/conf-available/security.conf
        echo "Apache server signature and server tokens have been configured to prevent information disclosure."
        sudo systemctl restart apache2
    else
        echo "Apache security configuration file not found: /etc/apache2/conf-available/security.conf"
    fi
    echo "Configuring UFW to use 'Apache Secure' profile..."
    sudo ufw allow 'Apache Secure'
    if [[ $? -eq 0 ]]; then
        echo "UFW has been configured to use 'Apache Secure' profile."
    else
        echo "Failed to configure UFW. Please check your UFW setup."
    fi
fi

read -p "Do you want to update the system to apply the latest security patches (requires internet access)? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    echo "System update requires APT, which may cause the system to crash. Please manually update the system."
fi

DEFAULT_USERS=("games" "news" "uucp" "lp")
for user in "${DEFAULT_USERS[@]}"; do
    if id "$user" &>/dev/null; then
        read -p "Default user '$user' found. Do you want to remove this user? (y/n) " confirm
        if [[ "$confirm" == "y" ]]; then
            sudo deluser --remove-home "$user"
            echo "User '$user' has been removed."
        fi
    fi
done

read -p "Do you want to set the session idle timeout to 300 seconds? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    gsettings set org.gnome.desktop.session idle-delay 300
    echo "Session idle timeout has been set to 300 seconds."
fi

read -p "Do you want to remove ophcrack? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    sudo apt-get remove --purge -y ophcrack
    echo "ophcrack has been removed."
fi

read -p "Do you want to remove wireshark? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    sudo apt-get remove --purge -y wireshark
    echo "wireshark has been removed."
fi

read -p "Do you want to set FTP to use TLS? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    if [ -f /etc/vsftpd.conf ]; then
        sudo sed -i 's/^#\(ssl_enable=\)NO/\1YES/' /etc/vsftpd.conf
        sudo sed -i 's/^#\(rsa_cert_file=\).*/\1\/etc\/ssl\/certs\/vsftpd.pem/' /etc/vsftpd.conf
        sudo sed -i 's/^#\(rsa_private_key_file=\).*/\1\/etc\/ssl\/private\/vsftpd.key/' /etc/vsftpd.conf
        echo "ssl_enable=YES" | sudo tee -a /etc/vsftpd.conf > /dev/null
        echo "force_local_data_ssl=YES" | sudo tee -a /etc/vsftpd.conf > /dev/null
        echo "force_local_logins_ssl=YES" | sudo tee -a /etc/vsftpd.conf > /dev/null
        echo "allow_anon_ssl=NO" | sudo tee -a /etc/vsftpd.conf > /dev/null
        echo "ssl_tlsv1=YES" | sudo tee -a /etc/vsftpd.conf > /dev/null
        echo "ssl_sslv2=NO" | sudo tee -a /etc/vsftpd.conf > /dev/null
        echo "ssl_sslv3=NO" | sudo tee -a /etc/vsftpd.conf > /dev/null
        echo "require_ssl_reuse=NO" | sudo tee -a /etc/vsftpd.conf > /dev/null
        echo "ssl_ciphers=HIGH" | sudo tee -a /etc/vsftpd.conf > /dev/null
        sudo systemctl restart vsftpd
        echo "FTP has been configured to use TLS, and vsftpd has been restarted."
    else
        echo "vsftpd configuration file not found. Please ensure vsftpd is installed."
    fi
fi

read -p "Do you want to set Firefox to block dangerous and deceptive content? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    FIREFOX_PREFS_DIR="$HOME/.mozilla/firefox"
    PROFILE_DIR=$(find "$FIREFOX_PREFS_DIR" -type d -name "*.default*" | head -n 1)

    if [ -n "$PROFILE_DIR" ] && [ -d "$PROFILE_DIR" ]; then
        PREFS_FILE="$PROFILE_DIR/prefs.js"
        if [ -f "$PREFS_FILE" ]; then
            echo 'user_pref("browser.safebrowsing.malware.enabled", true);' >> "$PREFS_FILE"
            echo 'user_pref("browser.safebrowsing.phishing.enabled", true);' >> "$PREFS_FILE"
            echo "Firefox has been set to block dangerous and deceptive content."
        else
            echo "Firefox prefs.js file not found. Please ensure Firefox is installed and has a user profile."
        fi
    else
        echo "Firefox profile directory not found. Please ensure Firefox is installed and has a user profile."
    fi
fi

read -p "Do you want to disable automatic login in /etc/gdm3/custom.conf? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    if [ -f /etc/gdm3/custom.conf ]; then
        sudo sed -i 's/^.*AutomaticLoginEnable\s*=\s*true/AutomaticLoginEnable=false/' /etc/gdm3/custom.conf
        sudo sed -i 's/^.*AutomaticLogin\s*=.*//' /etc/gdm3/custom.conf
        echo "Automatic login has been disabled in /etc/gdm3/custom.conf."
    else
        echo "/etc/gdm3/custom.conf not found. Please ensure GDM3 is installed."
    fi
fi

read -p "Do you want to disable or remove NFS and related services? (disable/remove/skip) " confirm
if [[ "$confirm" == "disable" ]]; then
    SERVICES=("nfs-server" "rpcbind")
    for service in "${SERVICES[@]}"; do
        if systemctl is-active --quiet "$service"; then
            sudo systemctl stop "$service"
            sudo systemctl disable "$service"
            echo "$service has been stopped and disabled."
        fi
    done
elif [[ "$confirm" == "remove" ]]; then
    sudo apt-get remove --purge -y nfs-kernel-server nfs-common rpcbind
    echo "NFS and related services have been removed."
fi

read -p "Do you want to disable or remove Avahi and CUPS services? (disable/remove/skip) " confirm
if [[ "$confirm" == "disable" ]]; then
    SERVICES=("avahi-daemon" "cups")
    for service in "${SERVICES[@]}"; do
        if systemctl is-active --quiet "$service"; then
            sudo systemctl stop "$service"
            sudo systemctl disable "$service"
            echo "$service has been stopped and disabled."
        fi
    done
elif [[ "$confirm" == "remove" ]]; then
    sudo apt-get remove --purge -y avahi-daemon cups
    echo "Avahi and CUPS services have been removed."
fi
 
read -p "Do you want to disable IPv6 to reduce the attack surface? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1

    if ! grep -q 'net.ipv6.conf.all.disable_ipv6' /etc/sysctl.conf; then
        echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
        echo "net.ipv6.conf.default.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf
    fi

    echo "IPv6 has been disabled to reduce the attack surface."
fi
read -p "Do you want to enable Kernel Lockdown and ExecShield for security? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    if [ -f /sys/kernel/security/lockdown ]; then
        echo "integrity" | sudo tee /sys/kernel/security/lockdown
        echo "Kernel Lockdown has been enabled with integrity mode."
    else
        echo "Kernel Lockdown feature not found. It may not be supported on this system."
    fi

    if [ -f /etc/sysctl.conf ]; then
        echo "kernel.exec-shield = 1" | sudo tee -a /etc/sysctl.conf
        sudo sysctl -w kernel.exec-shield=1
        echo "ExecShield has been enabled."
    else
        echo "ExecShield configuration could not be updated."
    fi
fi

read -p "Do you want to configure IPv4 for Martian packet logging, ICMP redirect ignoring, source address verification, TIME-WAIT ASSASSINATION protection, and disable IPv4 forwarding? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    sudo sysctl -w net.ipv4.conf.all.log_martians=1
    sudo sysctl -w net.ipv4.conf.default.log_martians=1
    if ! grep -q 'net.ipv4.conf.all.log_martians' /etc/sysctl.conf; then
        echo "net.ipv4.conf.all.log_martians = 1" | sudo tee -a /etc/sysctl.conf
        echo "net.ipv4.conf.default.log_martians = 1" | sudo tee -a /etc/sysctl.conf
    fi
    echo "Martian packet logging has been enabled."
    sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
    sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
    if ! grep -q 'net.ipv4.conf.all.accept_redirects' /etc/sysctl.conf; then
        echo "net.ipv4.conf.all.accept_redirects = 0" | sudo tee -a /etc/sysctl.conf
        echo "net.ipv4.conf.default.accept_redirects = 0" | sudo tee -a /etc/sysctl.conf
    fi
    echo "ICMP redirect ignoring has been enabled."
    sudo sysctl -w net.ipv4.conf.all.rp_filter=1
    sudo sysctl -w net.ipv4.conf.default.rp_filter=1
    if ! grep -q 'net.ipv4.conf.all.rp_filter' /etc/sysctl.conf; then
        echo "net.ipv4.conf.all.rp_filter = 1" | sudo tee -a /etc/sysctl.conf
        echo "net.ipv4.conf.default.rp_filter = 1" | sudo tee -a /etc/sysctl.conf
    fi
    echo "Source address verification has been enabled."
    sudo sysctl -w net.ipv4.tcp_rfc1337=1
    if ! grep -q 'net.ipv4.tcp_rfc1337' /etc/sysctl.conf; then
        echo "net.ipv4.tcp_rfc1337 = 1" | sudo tee -a /etc/sysctl.conf
    fi
    echo "IPv4 TIME-WAIT ASSASSINATION protection has been enabled."
    sudo sysctl -w net.ipv4.ip_forward=0
    if ! grep -q 'net.ipv4.ip_forward' /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward = 0" | sudo tee -a /etc/sysctl.conf
    fi
    echo "IPv4 forwarding has been disabled."
    echo "IPv4 security settings have been fully configured."
fi

read -p "Do you want to enable GRUB signature checks, set authorized superusers, and remove unauthorized superusers from GRUB config? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    GRUB_CFG="/etc/grub.d/40_custom"
    GRUB_DEFAULT_FILE="/etc/default/grub"
    GRUB_USERS_FILE="/boot/grub/grub.cfg"

    if ! grep -q "set check_signatures" "$GRUB_CFG"; then
        echo "set check_signatures=enforce" | sudo tee -a "$GRUB_CFG"
        echo "GRUB signature checks have been enabled."
    fi

    SUDO_USERS=$(getent group sudo | awk -F: '{print $4}' | tr ',' ' ')
    ADMIN_USERS=$(getent group admin | awk -F: '{print $4}' | tr ',' ' ')
    ALL_ADMIN_USERS="$SUDO_USERS $ADMIN_USERS"

    if [ -z "$ALL_ADMIN_USERS" ]; then
        echo "No sudo/admin users found on this system."
    else
        UNIQUE_ADMIN_USERS=$(echo "$ALL_ADMIN_USERS" | tr ' ' '\n' | sort -u | tr '\n' ' ')

        echo "set superusers=\"${UNIQUE_ADMIN_USERS}\"" | sudo tee -a "$GRUB_CFG"

        for user in $UNIQUE_ADMIN_USERS; do
            if ! grep -q "password_pbkdf2 $user" "$GRUB_CFG"; then
                read -p "Enter password for GRUB superuser '$user': " grub_password
                grub_password_hash=$(echo -e "$grub_password" | grub-mkpasswd-pbkdf2 | awk '/grub.pbkdf2/ {print $7}')
                echo "password_pbkdf2 $user $grub_password_hash" | sudo tee -a "$GRUB_CFG"
            fi
        done

        sudo update-grub

        if [ -f "$GRUB_USERS_FILE" ]; then
            CURRENT_USERS=$(grep -oP 'set superusers="[^"]+"' "$GRUB_USERS_FILE" | cut -d'"' -f2)

            for user in $CURRENT_USERS; do
                if [[ ! " ${UNIQUE_ADMIN_USERS[@]} " =~ " ${user} " ]]; then
                    echo "Unauthorized GRUB superuser '$user' found and will be removed."
                    sudo sed -i "/password_pbkdf2 $user/d" "$GRUB_CFG"
                fi
            done

            if ! grep -q 'GRUB_PASSWORD' "$GRUB_DEFAULT_FILE"; then
                read -p "Enter password for GRUB superuser: " grub_password
                grub_password_hash=$(echo -e "$grub_password" | grub-mkpasswd-pbkdf2 | awk '/grub.pbkdf2/ {print $7}')
                echo "GRUB_PASSWORD=$grub_password_hash" | sudo tee -a "$GRUB_DEFAULT_FILE"
            fi

            echo "Unauthorized superusers have been removed, and GRUB has been secured."
        else
            echo "GRUB configuration file not found. Please ensure GRUB is installed."
        fi
    fi
fi

read -p "Do you want to check and remove SUID permissions from the cp command if present? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    CP_PATH=$(which cp)

    if [ -x "$CP_PATH" ]; then
        if [ -u "$CP_PATH" ]; then
            echo "SUID bit is set on $CP_PATH. Removing SUID bit to prevent misuse."
            sudo chmod u-s "$CP_PATH"
            echo "SUID bit has been removed from the cp command."
        else
            echo "SUID bit is not set on the cp command."
        fi
    else
        echo "cp command not found."
    fi
fi

read -p "Do you want to disable source routing to enhance security? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    sudo sysctl -w net.ipv4.conf.all.accept_source_route=0
    sudo sysctl -w net.ipv4.conf.default.accept_source_route=0
    if ! grep -q '^net\.ipv4\.conf\.all\.accept_source_route' /etc/sysctl.conf; then
        echo "net.ipv4.conf.all.accept_source_route = 0" | sudo tee -a /etc/sysctl.conf
    else
        sudo sed -i 's/^net\.ipv4\.conf\.all\.accept_source_route.*/net.ipv4.conf.all.accept_source_route = 0/' /etc/sysctl.conf
    fi
    if ! grep -q '^net\.ipv4\.conf\.default\.accept_source_route' /etc/sysctl.conf; then
        echo "net.ipv4.conf.default.accept_source_route = 0" | sudo tee -a /etc/sysctl.conf
    else
        sudo sed -i 's/^net\.ipv4\.conf\.default\.accept_source_route.*/net.ipv4.conf.default.accept_source_route = 0/' /etc/sysctl.conf
    fi
    echo "Source routing has been disabled for all and default interfaces."
fi

read -p "Do you want to ensure that auditd is configured to log local events? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    if ! command -v auditctl &> /dev/null; then
        echo "auditd is not installed. Installing auditd..."
        sudo apt-get update && sudo apt-get install -y auditd
    fi
    AUDIT_CONF="/etc/audit/auditd.conf"
    if [ -f "$AUDIT_CONF" ]; then
        if ! grep -q "^local_events" "$AUDIT_CONF"; then
            echo "local_events = yes" | sudo tee -a "$AUDIT_CONF"
            echo "Auditd has been configured to log local events."
        else
            sudo sed -i 's/^local_events.*/local_events = yes/' "$AUDIT_CONF"
            echo "Auditd configuration updated to ensure local events are logged."
        fi
        sudo systemctl restart auditd
        echo "auditd service has been restarted with the new configuration."
    else
        echo "auditd configuration file not found. Please check your system configuration."
    fi
fi

read -p "Do you want to disable core dumps globally to enhance security? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    LIMITS_CONF="/etc/security/limits.conf"
    if ! grep -q "\*\s*hard\s*core" "$LIMITS_CONF"; then
        echo "* hard core 0" | sudo tee -a "$LIMITS_CONF"
        echo "Core dumps have been disabled globally in limits.conf."
    else
        sudo sed -i 's/^\*\s*hard\s*core.*/\* hard core 0/' "$LIMITS_CONF"
        echo "Core dumps setting in limits.conf has been updated to disable core dumps globally."
    fi

    SYSCTL_CONF="/etc/sysctl.conf"
    if ! grep -q "fs.suid_dumpable" "$SYSCTL_CONF"; then
        echo "fs.suid_dumpable = 0" | sudo tee -a "$SYSCTL_CONF"
    else
        sudo sed -i 's/^fs.suid_dumpable.*/fs.suid_dumpable = 0/' "$SYSCTL_CONF"
    fi
    sudo sysctl -w fs.suid_dumpable=0
    echo "Core dumps for SUID programs have been disabled using sysctl."

    sudo sysctl -p

    echo "Core dumps have been disabled globally."
fi

read -p "Do you want to add a system-wide login warning message to /etc/bash.bashrc? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    BASHRC_SYSTEM="/etc/bash.bashrc"
    WARNING_MESSAGE='echo "WARNING: Unauthorized access to this system is strictly prohibited."'

    if [ -f "$BASHRC_SYSTEM" ]; then
        if ! grep -q "WARNING: Unauthorized access" "$BASHRC_SYSTEM"; then
            echo "$WARNING_MESSAGE" | sudo tee -a "$BASHRC_SYSTEM" > /dev/null
            echo "System-wide warning message added to /etc/bash.bashrc."
        else
            echo "System-wide warning message is already present in /etc/bash.bashrc."
        fi
    else
        echo "System-wide bashrc file not found."
    fi
fi

read -p "Do you want to set permissions on /etc/bash.bashrc to 644? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    if [ -f "/etc/bash.bashrc" ]; then
        sudo chmod 644 /etc/bash.bashrc
        echo "Permissions for /etc/bash.bashrc have been set to 644 (owner read/write, group and others read-only)."
    else
        echo "/etc/bash.bashrc not found. Please ensure the system-wide bashrc file exists."
    fi
fi

echo "Basic cybersecurity tasks have been completed."

read -p "Do you want to configure the system to automatically check for updates daily? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    if [ -d /etc/apt/apt.conf.d ]; then
        echo "Configuring the system to check for updates daily..."
        sudo bash -c 'cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOL
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOL'
        echo "Daily updates have been successfully configured."
    else
        echo "/etc/apt/apt.conf.d directory not found. Please ensure the system uses APT for package management."
    fi
else
    echo "Operation canceled."
fi

PROHIBITED_TYPES=("*.mp3" "*.mp4" "*.jpg")

find_files() {
    echo "Scanning the system for prohibited file types..."
    for filetype in "${PROHIBITED_TYPES[@]}"; do
        echo "Finding files of type: $filetype"
        sudo find / -type f -name "$filetype" 2>/dev/null
    done
}

delete_all_of_type() {
    local filetype="$1"
    echo "Finding and deleting all files of type: $filetype"
    sudo find / -type f -name "$filetype" -exec rm -i {} \; 2>/dev/null
    echo "All files of type $filetype have been processed."
}

delete_specific_file() {
    local filename="$1"
    if [ -f "$filename" ]; then
        read -p "Are you sure you want to delete $filename? (y/n) " confirm
        if [[ "$confirm" == "y" ]]; then
            sudo rm "$filename"
            echo "$filename has been deleted."
        else
            echo "Skipped deleting $filename."
        fi
    else
        echo "File $filename not found."
    fi
}

echo "Welcome to the file management part of the script."
find_files
while true; do
    echo "Options:"
    echo "1. Remove all files of a specific type (e.g., .jpg, .mp3)"
    echo "2. Delete a specific file by name"
    echo "3. Skip and exit"
    read -p "Enter your choice (1/2/3): " choice
    case $choice in
        1)
            read -p "Enter the file extension to remove (e.g., .jpg, .mp3): " extension
            delete_all_of_type "*$extension"
            ;;
        2)
            read -p "Enter the full name (including path) of the file to delete: " filename
            delete_specific_file "$filename"
            ;;
        3)
            echo "Exiting the script. Goodbye!"
            break
            ;;
        *)
            echo "Invalid choice. Please enter 1, 2, or 3."
            ;;
    esac
done

read -p "Do you want to remove Nginx and its configuration files? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    echo "Stopping Nginx service..."
    sudo systemctl stop nginx
    echo "Uninstalling Nginx..."
    sudo apt-get remove --purge -y nginx nginx-common nginx-full
    echo "Removing residual configuration and log files..."
    sudo rm -rf /etc/nginx /var/www/html /var/log/nginx
    echo "Cleaning up unnecessary dependencies..."
    sudo apt-get autoremove -y
    echo "Nginx has been completely removed from your system."
else
    echo "Nginx removal canceled."
fi

SUDOERS_FILE="/etc/sudoers"
echo "Removing insecure 'NOPASSWD: ALL' rules from the sudoers file..."
sudo sed -i '/^[^#]*ALL=(ALL:ALL)\s*NOPASSWD:\s*ALL/d' "$SUDOERS_FILE"
echo "Verifying the integrity of the sudoers file..."
sudo visudo -c
if [[ $? -ne 0 ]]; then
    echo "The sudoers file contains errors! Restoring the backup..."
    sudo cp "$BACKUP_FILE" "$SUDOERS_FILE"
    echo "Backup restored. Please review the sudoers file manually."
    exit 1
fi
echo "Insecure 'NOPASSWD: ALL' rules have been removed successfully."

read -p "Do you want to disable sending redirects to enhance security? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    sudo sysctl -w net.ipv4.conf.all.send_redirects=0
    sudo sysctl -w net.ipv4.conf.default.send_redirects=0
    if ! grep -q '^net\.ipv4\.conf\.all\.send_redirects' /etc/sysctl.conf; then
        echo "net.ipv4.conf.all.send_redirects = 0" | sudo tee -a /etc/sysctl.conf
    else
        sudo sed -i 's/^net\.ipv4\.conf\.all\.send_redirects.*/net.ipv4.conf.all.send_redirects = 0/' /etc/sysctl.conf
    fi
    if ! grep -q '^net\.ipv4\.conf\.default\.send_redirects' /etc/sysctl.conf; then
        echo "net.ipv4.conf.default.send_redirects = 0" | sudo tee -a /etc/sysctl.conf
    else
        sudo sed -i 's/^net\.ipv4\.conf\.default\.send_redirects.*/net.ipv4.conf.default.send_redirects = 0/' /etc/sysctl.conf
    fi
    echo "Send redirects have been disabled for all and default interfaces."
fi

read -p "Do you want to enable source address verification to enhance security? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    sudo sysctl -w net.ipv4.conf.all.rp_filter=1
    sudo sysctl -w net.ipv4.conf.default.rp_filter=1
    if ! grep -q '^net\.ipv4\.conf\.all\.rp_filter' /etc/sysctl.conf; then
        echo "net.ipv4.conf.all.rp_filter = 1" | sudo tee -a /etc/sysctl.conf
    else
        sudo sed -i 's/^net\.ipv4\.conf\.all\.rp_filter.*/net.ipv4.conf.all.rp_filter = 1/' /etc/sysctl.conf
    fi
    if ! grep -q '^net\.ipv4\.conf\.default\.rp_filter' /etc/sysctl.conf; then
        echo "net.ipv4.conf.default.rp_filter = 1" | sudo tee -a /etc/sysctl.conf
    else
        sudo sed -i 's/^net\.ipv4\.conf\.default\.rp_filter.*/net.ipv4.conf.default.rp_filter = 1/' /etc/sysctl.conf
    fi
    echo "Source address verification has been enabled for all and default interfaces."
fi

read -p "Do you want to configure the account lockout policy? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    AUTH_FAIL_LINE="auth    [default=die]    pam_faillock.so authfail"
    AUTH_SUCC_LINE="auth    sufficient    pam_faillock.so authsucc"
    echo "Creating a backup of /etc/pam.d/common-auth..."
    sudo cp /etc/pam.d/common-auth /etc/pam.d/common-auth.bak
    echo "Backup created at /etc/pam.d/common-auth.bak."
    if ! grep -q '^\s*auth\s+\[default=die\]\s+pam_faillock.so\s+authfail\s*$' /etc/pam.d/common-auth; then
        echo "Adding account lockout policy line for authfail..."
        echo "$AUTH_FAIL_LINE" | sudo tee -a /etc/pam.d/common-auth
    else
        echo "Account lockout policy line for authfail already exists."
    fi
    if ! grep -q '^\s*auth\s+sufficient\s+pam_faillock.so\s+authsucc\s*$' /etc/pam.d/common-auth; then
        echo "Adding account lockout policy line for authsucc..."
        echo "$AUTH_SUCC_LINE" | sudo tee -a /etc/pam.d/common-auth
    else
        echo "Account lockout policy line for authsucc already exists."
    fi
    echo "Verifying PAM configuration..."
    if sudo pam-auth-update --force; then
        echo "PAM configuration updated and verified successfully."
    else
        echo "Error verifying PAM configuration! Restoring from backup..."
        sudo cp /etc/pam.d/common-auth.bak /etc/pam.d/common-auth
        echo "Backup restored. Please review the PAM configuration manually."
    fi
    echo "Account lockout policy configuration complete."
fi

read -p "Do you want to configure secure password and authentication policies? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    echo "Configuring secure password and authentication policies..."
    LOGIN_DEFS="/etc/login.defs"
    PWQUALITY_CONF="/etc/security/pwquality.conf"
    echo "Creating backups..."
    sudo cp "$LOGIN_DEFS" "${LOGIN_DEFS}.bak"
    sudo cp "$PWQUALITY_CONF" "${PWQUALITY_CONF}.bak"
    echo "Backups created at ${LOGIN_DEFS}.bak and ${PWQUALITY_CONF}.bak."
    MAX_DAYS_REGEX='^PASS_MAX_DAYS\s+(?:[1-9]|[12][0-9]|30)\s*$'
    if ! grep -Pq "$MAX_DAYS_REGEX" "$LOGIN_DEFS"; then
        sudo sed -i '/^PASS_MAX_DAYS/d' "$LOGIN_DEFS"
        echo "PASS_MAX_DAYS 30" | sudo tee -a "$LOGIN_DEFS"
    fi
    MIN_DAYS_REGEX='^PASS_MIN_DAYS\s*(?:[5-9]|[1-9][0-9]|100)\s*$'
    if ! grep -Pq "$MIN_DAYS_REGEX" "$LOGIN_DEFS"; then
        sudo sed -i '/^PASS_MIN_DAYS/d' "$LOGIN_DEFS"
        echo "PASS_MIN_DAYS 7" | sudo tee -a "$LOGIN_DEFS"
    fi
    MINLEN_REGEX='^minlen\s*=\s*(?:[89]|[1-9][0-9]{1,2}|1000)'
    if ! grep -Pq "$MINLEN_REGEX" "$PWQUALITY_CONF"; then
        sudo sed -i '/^minlen/d' "$PWQUALITY_CONF"
        echo "minlen = 12" | sudo tee -a "$PWQUALITY_CONF"
    fi
    COMPLEXITY_VARS=("ucredit = -1" "lcredit = -1" "ocredit = -1" "dcredit = -1")
    for var in "${COMPLEXITY_VARS[@]}"; do
        key=$(echo "$var" | cut -d' ' -f1)
        if ! grep -q "^$key" "$PWQUALITY_CONF"; then
            echo "$var" | sudo tee -a "$PWQUALITY_CONF"
        else
            sudo sed -i "s/^$key.*/$var/" "$PWQUALITY_CONF"
        fi
    done
    DICTCHECK_REGEX='dictcheck\s*=\s*-?[1-9]\d*'
    if ! grep -Pq "$DICTCHECK_REGEX" "$PWQUALITY_CONF"; then
        sudo sed -i '/^dictcheck/d' "$PWQUALITY_CONF"
        echo "dictcheck = 1" | sudo tee -a "$PWQUALITY_CONF"
    fi
    USERCHECK_REGEX='usercheck\s*=\s*-?[1-9]\d*'
    if ! grep -Pq "$USERCHECK_REGEX" "$PWQUALITY_CONF"; then
        sudo sed -i '/^usercheck/d' "$PWQUALITY_CONF"
        echo "usercheck = 1" | sudo tee -a "$PWQUALITY_CONF"
    fi
    ENCRYPT_METHOD_REGEX='ENCRYPT_METHOD\s*SHA512'
    if ! grep -Pq "$ENCRYPT_METHOD_REGEX" "$LOGIN_DEFS"; then
        sudo sed -i '/^ENCRYPT_METHOD/d' "$LOGIN_DEFS"
        echo "ENCRYPT_METHOD SHA512" | sudo tee -a "$LOGIN_DEFS"
    fi
    LOGIN_RETRIES_REGEX='LOGIN_RETRIES\s+[1-5]'
    if ! grep -Pq "$LOGIN_RETRIES_REGEX" "$LOGIN_DEFS"; then
        sudo sed -i '/^LOGIN_RETRIES/d' "$LOGIN_DEFS"
        echo "LOGIN_RETRIES 3" | sudo tee -a "$LOGIN_DEFS"
    fi
    echo "Verifying changes..."
    echo "==== /etc/login.defs ===="
    grep -E "PASS_MAX_DAYS|PASS_MIN_DAYS|ENCRYPT_METHOD|LOGIN_RETRIES" "$LOGIN_DEFS"
    echo "==== /etc/security/pwquality.conf ===="
    grep -E "minlen|ucredit|lcredit|ocredit|dcredit|dictcheck|usercheck" "$PWQUALITY_CONF"
    echo "Configuration completed successfully. Please restart your system or services as necessary."
else
    echo "No changes were made."
fi

read -p "Do you want to configure a secure password history policy? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    COMMON_PASSWORD="/etc/pam.d/common-password"
    PASSWORD_HISTORY_REGEX='pam_unix\.so.*?remember=(?:[5-9]|[1-9][0-9]{1,2}|1000)'
    echo "Creating a backup of $COMMON_PASSWORD..."
    sudo cp "$COMMON_PASSWORD" "${COMMON_PASSWORD}.bak"
    echo "Backup created at ${COMMON_PASSWORD}.bak."
    if grep -Pq "$PASSWORD_HISTORY_REGEX" "$COMMON_PASSWORD"; then
        echo "A secure password history policy is already configured."
    else
        echo "Configuring password history policy..."
        if grep -q 'pam_unix.so' "$COMMON_PASSWORD"; then
            sudo sed -i '/pam_unix.so/ s/\(pam_unix.so.*\)/\1 remember=5/' "$COMMON_PASSWORD"
        else
            echo "password required pam_unix.so remember=5" | sudo tee -a "$COMMON_PASSWORD"
        fi
        echo "Password history policy has been configured to remember 5 previous passwords."
    fi
    echo "Verifying changes..."
    if grep -Pq "$PASSWORD_HISTORY_REGEX" "$COMMON_PASSWORD"; then
        echo "Password history policy successfully configured."
    else
        echo "Failed to configure password history policy. Restoring from backup..."
        sudo cp "${COMMON_PASSWORD}.bak" "$COMMON_PASSWORD"
        echo "Backup restored. Please review $COMMON_PASSWORD manually."
    fi
else
    echo "No changes were made."
fi

read -p "Do you want to enable GRUB signature checks? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    GRUB_CUSTOM="/etc/grub.d/40_custom"
    echo "Creating a backup of $GRUB_CUSTOM..."
    sudo cp "$GRUB_CUSTOM" "${GRUB_CUSTOM}.bak"
    echo "Backup created at ${GRUB_CUSTOM}.bak."
    if ! grep -q '^set check_signatures=enforce' "$GRUB_CUSTOM"; then
        echo "Adding 'set check_signatures=enforce' to $GRUB_CUSTOM..."
        echo "set check_signatures=enforce" | sudo tee -a "$GRUB_CUSTOM"
    else
        echo "'set check_signatures=enforce' is already configured in $GRUB_CUSTOM."
    fi
    if ! grep -q '^export check_signatures' "$GRUB_CUSTOM"; then
        echo "Adding 'export check_signatures' to $GRUB_CUSTOM..."
        echo "export check_signatures" | sudo tee -a "$GRUB_CUSTOM"
    else
        echo "'export check_signatures' is already configured in $GRUB_CUSTOM."
    fi
    echo "Updating GRUB configuration..."
    sudo update-grub
    echo "Verifying changes..."
    if grep -q '^set check_signatures=enforce' "$GRUB_CUSTOM" && grep -q '^export check_signatures' "$GRUB_CUSTOM"; then
        echo "GRUB signature checks have been successfully enabled."
    else
        echo "Failed to enable GRUB signature checks. Restoring from backup..."
        sudo cp "${GRUB_CUSTOM}.bak" "$GRUB_CUSTOM"
        sudo update-grub
        echo "Backup restored. Please review $GRUB_CUSTOM manually."
    fi
else
    echo "No changes were made."
fi

read -p "Do you want to secure SSH configurations? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    SSHD_CONFIG="/etc/ssh/sshd_config"
    echo "Creating a backup of $SSHD_CONFIG..."
    sudo cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"
    echo "Backup created at ${SSHD_CONFIG}.bak."
    echo "Disabling password authentication..."
    if grep -q '^PasswordAuthentication' "$SSHD_CONFIG"; then
        sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
    else
        echo "PasswordAuthentication no" | sudo tee -a "$SSHD_CONFIG"
    fi
    echo "Setting SSH port to 1382..."
    if grep -q '^Port' "$SSHD_CONFIG"; then
        sudo sed -i 's/^Port.*/Port 1382/' "$SSHD_CONFIG"
    else
        echo "Port 1382" | sudo tee -a "$SSHD_CONFIG"
    fi
    echo "Restarting SSH service..."
    sudo systemctl restart sshd
    echo "Enabling UFW profile for OpenSSH..."
    sudo ufw allow OpenSSH
    sudo ufw reload
    echo "Verifying configurations..."
    if grep -q '^PasswordAuthentication no$' "$SSHD_CONFIG"; then
        echo "Password authentication is disabled."
    else
        echo "Failed to disable password authentication."
    fi
    if grep -q '^Port 1382$' "$SSHD_CONFIG"; then
        echo "SSH port is correctly set to 1382."
    else
        echo "Failed to set SSH port to 1382."
    fi
    if sudo ufw status | grep -q 'OpenSSH *ALLOW *Anywhere'; then
        echo "UFW profile for OpenSSH is enabled."
    else
        echo "Failed to enable UFW profile for OpenSSH."
    fi
    echo "SSH configurations have been secured."
else
    echo "No changes were made."
fi

read -p "Do you want to secure SSH configurations? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    SSHD_CONFIG="/etc/ssh/sshd_config"
    echo "Disabling password authentication..."
    if grep -q '^PasswordAuthentication' "$SSHD_CONFIG"; then
        sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONFIG"
    else
        echo "PasswordAuthentication no" | sudo tee -a "$SSHD_CONFIG"
    fi
    echo "Setting SSH port to 1382..."
    if grep -q '^Port' "$SSHD_CONFIG"; then
        sudo sed -i 's/^Port.*/Port 1382/' "$SSHD_CONFIG"
    else
        echo "Port 1382" | sudo tee -a "$SSHD_CONFIG"
    fi
    echo "Restarting SSH service..."
    sudo systemctl restart sshd
    echo "Enabling UFW profile for OpenSSH..."
    sudo ufw allow OpenSSH
    sudo ufw reload
    echo "Verifying configurations..."
    if grep -q '^PasswordAuthentication no$' "$SSHD_CONFIG"; then
        echo "Password authentication is disabled."
    else
        echo "Failed to disable password authentication."
    fi
    if grep -q '^Port 1382$' "$SSHD_CONFIG"; then
        echo "SSH port is correctly set to 1382."
    else
        echo "Failed to set SSH port to 1382."
    fi
    if sudo ufw status | grep -q 'OpenSSH *ALLOW *Anywhere'; then
        echo "UFW profile for OpenSSH is enabled."
    else
        echo "Failed to enable UFW profile for OpenSSH."
    fi
    echo "SSH configurations have been secured."
else
    echo "No changes were made."
fi

read -p "Do you want to ensure TLS/SSL is enabled and anonymous TLS/SSL is disabled for vsftpd? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    VSFTPD_CONF="/etc/vsftpd.conf"
    echo "Creating a backup of $VSFTPD_CONF..."
    sudo cp "$VSFTPD_CONF" "${VSFTPD_CONF}.bak"
    echo "Backup created at ${VSFTPD_CONF}.bak."
    if grep -q '^ssl_enable=YES$' "$VSFTPD_CONF"; then
        echo "TLS/SSL is already enabled in $VSFTPD_CONF."
    else
        echo "Enabling TLS/SSL in $VSFTPD_CONF..."
        if grep -q '^ssl_enable=' "$VSFTPD_CONF"; then
            sudo sed -i 's/^ssl_enable=.*/ssl_enable=YES/' "$VSFTPD_CONF"
        else
            echo "ssl_enable=YES" | sudo tee -a "$VSFTPD_CONF"
        fi
        echo "TLS/SSL has been enabled."
    fi
    if grep -q '^allow_anon_ssl=YES$' "$VSFTPD_CONF"; then
        echo "Anonymous TLS/SSL is enabled. Disabling it..."
        sudo sed -i 's/^allow_anon_ssl=YES/allow_anon_ssl=NO/' "$VSFTPD_CONF"
        echo "Anonymous TLS/SSL has been disabled."
    else
        echo "Anonymous TLS/SSL is already disabled."
    fi
    echo "Restarting vsftpd service..."
    sudo systemctl restart vsftpd
    echo "Verifying configuration..."
    if grep -q '^ssl_enable=YES$' "$VSFTPD_CONF" && ! grep -q '^allow_anon_ssl=YES$' "$VSFTPD_CONF"; then
        echo "Configuration verified: TLS/SSL is enabled and anonymous TLS/SSL is disabled."
    else
        echo "Failed to verify configuration. Restoring from backup..."
        sudo cp "${VSFTPD_CONF}.bak" "$VSFTPD_CONF"
        sudo systemctl restart vsftpd
        echo "Backup restored. Please review $VSFTPD_CONF manually."
    fi
else
    echo "No changes were made."
fi

read -p "Do you want to configure the passive port range (50000-50100) for vsftpd and open it in UFW? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    VSFTPD_CONF="/etc/vsftpd.conf"
    if grep -q '^pasv_min_port=' "$VSFTPD_CONF"; then
        sudo sed -i 's/^pasv_min_port=.*/pasv_min_port=50000/' "$VSFTPD_CONF"
    else
        echo "pasv_min_port=50000" | sudo tee -a "$VSFTPD_CONF"
    fi
    if grep -q '^pasv_max_port=' "$VSFTPD_CONF"; then
        sudo sed -i 's/^pasv_max_port=.*/pasv_max_port=50100/' "$VSFTPD_CONF"
    else
        echo "pasv_max_port=50100" | sudo tee -a "$VSFTPD_CONF"
    fi
    echo "Passive port range (50000-50100) has been configured in $VSFTPD_CONF."
    echo "Allowing passive port range (50000-50100) in UFW..."
    sudo ufw allow 50000:50100/tcp
    sudo ufw reload
    echo "Restarting vsftpd service..."
    sudo systemctl restart vsftpd
    echo "Verifying configuration..."
    if grep -q '^pasv_min_port=50000$' "$VSFTPD_CONF" && grep -q '^pasv_max_port=50100$' "$VSFTPD_CONF"; then
        echo "Passive port range configuration in $VSFTPD_CONF is correct."
    else
        echo "Passive port range configuration in $VSFTPD_CONF is incorrect. Restoring from backup..."
        sudo cp "${VSFTPD_CONF}.bak" "$VSFTPD_CONF"
        sudo systemctl restart vsftpd
        echo "Backup restored. Please review $VSFTPD_CONF manually."
    fi
    if sudo ufw status | grep -q '50000:50100/tcp *ALLOW *Anywhere'; then
        echo "UFW is configured to allow the passive port range (50000-50100)."
    else
        echo "Failed to configure UFW for the passive port range. Please check UFW manually."
    fi
else
    echo "No changes were made."
fi

read -p "Do you want to configure gdm3 to disallow TCP connections and disable automatic login? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    GDM3_CONF="/etc/gdm3/custom.conf"
    if [[ ! -f "$GDM3_CONF" ]]; then
        echo "Configuration file $GDM3_CONF not found. Aborting."
        exit 1
    fi
    if ! grep -q '^DisallowTCP=true$' "$GDM3_CONF"; then
        sudo sed -i '/^DisallowTCP=/d' "$GDM3_CONF"
        echo "DisallowTCP=true" | sudo tee -a "$GDM3_CONF"
        echo "DisallowTCP=true has been added."
    else
        echo "gdm3 is already configured to disallow TCP connections."
    fi
    if grep -q '^DisallowTCP=false$' "$GDM3_CONF"; then
        sudo sed -i '/^DisallowTCP=false$/d' "$GDM3_CONF"
        echo "'DisallowTCP=false' has been removed."
    fi
    sudo sed -i '/^AutomaticLoginEnable=/d' "$GDM3_CONF"
    sudo sed -i '/^AutomaticLogin=/d' "$GDM3_CONF"
    echo "Automatic login has been disabled."
    if ! grep -q '^DisallowTCP=true$' "$GDM3_CONF"; then
        echo "'DisallowTCP=true' is missing. Configuration invalid. Please manually fix $GDM3_CONF."
        exit 1
    fi
    if grep -q '^DisallowTCP=false$' "$GDM3_CONF"; then
        echo "'DisallowTCP=false' is still present. Configuration invalid. Please manually fix $GDM3_CONF."
        exit 1
    fi
    echo "Configuration changes have been applied."
    echo "Please restart gdm3 manually for the changes to take effect:"
    echo "Run: sudo systemctl restart gdm3"
else
    echo "No changes were made."
fi

read -p "Do you want to check for and remove the kisni keylogger kernel module? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    MODULE_PATH="/lib/modules/$(uname -r)/updates/dkms/kisni.ko"
    echo "Checking if the kisni module is currently loaded..."
    if lsmod | grep -q '^kisni'; then
        echo "The kisni module is loaded. Unloading it..."
        sudo rmmod kisni
        if [[ $? -eq 0 ]]; then
            echo "kisni module successfully unloaded."
        else
            echo "Failed to unload kisni module. Please investigate further."
            exit 1
        fi
    else
        echo "The kisni module is not currently loaded."
    fi
    echo "Checking for kisni module file in $MODULE_PATH..."
    if [[ -f "$MODULE_PATH" ]]; then
        echo "kisni module file found. Removing it..."
        sudo rm -f "$MODULE_PATH"
        if [[ $? -eq 0 ]]; then
            echo "kisni module file successfully removed."
        else
            echo "Failed to remove kisni module file. Please investigate further."
            exit 1
        fi
    else
        echo "No kisni module file found in $MODULE_PATH."
    fi
    echo "Rebuilding module dependencies..."
    sudo depmod -a
    echo "Module dependencies rebuilt."
    echo "Blacklisting kisni module to prevent future loading..."
    if ! grep -q '^blacklist kisni' /etc/modprobe.d/blacklist.conf; then
        echo "blacklist kisni" | sudo tee -a /etc/modprobe.d/blacklist.conf
        echo "kisni module has been blacklisted."
    else
        echo "kisni module is already blacklisted."
    fi
    echo "All steps completed. The kisni keylogger module has been handled."
else
    echo "No changes were made."
fi

read -p "Do you want to check and enable Kernel Lockdown? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    LOCKDOWN_FILE="/sys/kernel/security/lockdown"
    if [[ -f "$LOCKDOWN_FILE" ]]; then
        echo "Kernel Lockdown is supported. Checking current state..."
        if grep -q '\[integrity\]' "$LOCKDOWN_FILE"; then
            echo "Kernel Lockdown is enabled in 'integrity' mode."
        elif grep -q '\[confidentiality\]' "$LOCKDOWN_FILE"; then
            echo "Kernel Lockdown is enabled in 'confidentiality' mode."
        else
            echo "Kernel Lockdown is not currently enabled."
            read -p "Do you want to enable Kernel Lockdown in 'integrity' mode? (y/n) " enable_lockdown
            if [[ "$enable_lockdown" == "y" ]]; then
                echo "Enabling Kernel Lockdown in 'integrity' mode..."
                sudo mokutil --enable-validation
                echo "Kernel Lockdown will be enabled on the next boot."
            else
                echo "Kernel Lockdown was not enabled."
            fi
        fi
    else
        echo "Kernel Lockdown is not supported on this system."
    fi
else
    echo "No changes were made."
fi

read -p "Do you want to configure a hard process limit of 2500 or less? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    LIMITS_CONF="/etc/security/limits.conf"
    HARD_LIMIT_REGEX='^\*\s*hard\s*nproc\s*(?:[1-9]|[1-9][0-9]{1,2}|1[0-9]{3}|2[0-4][0-9]{2}|2500)$'
    if grep -Pq "$HARD_LIMIT_REGEX" "$LIMITS_CONF"; then
        echo "A hard process limit of 2500 or less is already configured."
    else
        echo "Configuring a hard process limit of 2500..."
        sudo sed -i '/^\*\s*hard\s*nproc/d' "$LIMITS_CONF"
        echo "* hard nproc 2500" | sudo tee -a "$LIMITS_CONF"
        echo "Hard process limit has been configured."
    fi
    echo "Verifying configuration..."
    if grep -Pq "$HARD_LIMIT_REGEX" "$LIMITS_CONF"; then
        echo "Hard process limit configuration is correct."
    else
        echo "Failed to configure the hard process limit. Restoring from backup..."
        sudo cp "${LIMITS_CONF}.bak" "$LIMITS_CONF"
        echo "Backup restored. Please review $LIMITS_CONF manually."
    fi
else
    echo "No changes were made."
fi

read -p "Do you want to check and secure the syslog account? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    PASSWD_FILE="/etc/passwd"
    CURRENT_SHELL=$(grep '^syslog:' "$PASSWD_FILE" | cut -d: -f7)
    if [[ "$CURRENT_SHELL" == "/usr/sbin/nologin" || "$CURRENT_SHELL" == "/bin/false" ]]; then
        echo "The syslog account is already secured with shell: $CURRENT_SHELL."
    else
        echo "The syslog account is not secured. Current shell: $CURRENT_SHELL."
        read -p "Do you want to set the shell to /usr/sbin/nologin? (y/n) " set_nologin
        if [[ "$set_nologin" == "y" ]]; then
            echo "Setting shell to /usr/sbin/nologin..."
            sudo usermod -s /usr/sbin/nologin syslog
            echo "Shell for syslog account has been set to /usr/sbin/nologin."
        else
            read -p "Do you want to set the shell to /bin/false instead? (y/n) " set_false
            if [[ "$set_false" == "y" ]]; then
                echo "Setting shell to /bin/false..."
                sudo usermod -s /bin/false syslog
                echo "Shell for syslog account has been set to /bin/false."
            else
                echo "No changes were made to the syslog account."
            fi
        fi
    fi
    NEW_SHELL=$(grep '^syslog:' "$PASSWD_FILE" | cut -d: -f7)
    if [[ "$NEW_SHELL" == "/usr/sbin/nologin" || "$NEW_SHELL" == "/bin/false" ]]; then
        echo "Verification successful: syslog account shell is secured with $NEW_SHELL."
    else
        echo "Verification failed: syslog account shell is still $NEW_SHELL. Please check manually."
    fi
else
    echo "No changes were made."
fi

read -p "Do you want to secure /home ownership and /swapfile permissions? (y/n) " confirm
if [[ "$confirm" == "y" ]]; then
    echo "Checking ownership of /home..."
    CURRENT_OWNER=$(stat -c '%U' /home)
    if [[ "$CURRENT_OWNER" != "root" ]]; then
        echo "/home is owned by $CURRENT_OWNER. Changing ownership to root..."
        sudo chown root:root /home
        echo "Ownership of /home has been set to root."
    else
        echo "/home is already owned by root."
    fi
    echo "Checking permissions of /swapfile..."
    CURRENT_PERMS=$(stat -c '%a' /swapfile)
    if [[ "$CURRENT_PERMS" != "600" ]]; then
        echo "/swapfile has permissions $CURRENT_PERMS. Setting permissions to 600..."
        sudo chmod 600 /swapfile
        echo "Permissions of /swapfile have been set to 600 (read/write for root only)."
    else
        echo "/swapfile already has the correct permissions (600)."
    fi
    echo "Verifying settings..."
    FINAL_HOME_OWNER=$(stat -c '%U' /home)
    FINAL_SWAPFILE_PERMS=$(stat -c '%a' /swapfile)

    if [[ "$FINAL_HOME_OWNER" == "root" && "$FINAL_SWAPFILE_PERMS" == "600" ]]; then
        echo "Verification successful: /home is owned by root and /swapfile has permissions set to 600."
    else
        echo "Verification failed. Please review /home ownership and /swapfile permissions manually."
    fi
else
    echo "No changes were made."
fi
