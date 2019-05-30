#!/bin/bash

echo "Hardening..."

# ISSUE = [FAILED] count

# Manual work
# 1.1.13 Ensure nodev option set on /home partition = 1
# 1.4 Bootloader = 3
# 2.2.15 Ensure mail transfer agent is configured for local-only mode = 1
# 3.4.2 Ensure /etc/hosts.allow is configured = 1
# 3.4.3 Ensure /etc/hosts.deny is configured = 1
# 4.2.14 Ensure rsyslog is configured to send logs to a remote host = 1
# 5.4.1.4 Ensure inactive password lock is 30 days or less = 1
# 5.4.1.5 Ensure all users last password change date is in the past = 1


# Scanner diffs
# 1.7.1.1 Ensure message of the day is configured properly - banner text = 1
# 1.7.1.2 Ensure local login warning banner is configured properly - banner text = 1
# 1.7.1.3 Ensure remote login warning banner is configured properly - banner text = 1
# 5.2 sshd_config = 15 (It should be working.) (I think scanner scans for a space before and after every key=value line)
# 5.3.3 Ensure password reuse is limited = 1
# 5.6 Ensure access to the su command is restricted = 1


# Scanner issues (must be root or permission denied)
# 1.3.2 Ensure filesystem integrity is regularly checked = 1
# 3.6.2 Ensure default deny firewall policy = 3


# Not Scored
# 3.3 IPv6 = 9
# 3.5 Uncommon Network Protocol = 4
# 4.2.1.2 Ensure logging is configured = 13
# 4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts = 2


# Working on
# 1.5.1 Ensure core dumps are restricted = 1
# 3.2.4 Ensure suspicious packets are logged = 4 (Done)
# 3.2.7 Ensure Reverse Path Filtering is enabled = 2 (Done)
# 4.2.4 Ensure permissions on all logfiles are configured = 1
# 5.4.4 Ensure default umask is 027 or more restrictive = 2

# Hardening level.
HARDENING_LEVEL=1

# Debug mode.
DEBUG_MODE=1

# Disabling SAFE_SSH will cause issues.
SAFE_SSH=1


# $1 is the search string
# $2 is the replace string
# $3 is the path to file

function search_and_replace () {
    local SEARCH_STRING="$1"
    local REPLACE_STRING="$2"
    local FILE=$3

    sed -i -r "s/$SEARCH_STRING/$REPLACE_STRING/" $FILE
}

# $1 is the search string
# $2 is the replace string
# $3 is the path to file
# $4 is to append if not found (Default no append)

function search_and_replace_entire_line () {
    local SEARCH_STRING="$1"
    local REPLACE_STRING="$2"
    local FILE=$3
    local TO_APPEND=${4:-1}

    grep -q "$SEARCH_STRING" $FILE

    if [ $? == 0 ]
    then
        echo "Replaced"
        # Replace found string with replacement.
        sed -i -r "/$SEARCH_STRING/c $REPLACE_STRING" $FILE
    elif [ $TO_APPEND == 0 ]
    then
        echo "Appended"
        # Append setting here.
        echo "$REPLACE_STRING" | sudo tee --append $FILE > /dev/null
    fi
}

# Add shared folder
# LINE="shared /home/shared vboxsf defaults 0 0"

# grep -F "$LINE" /etc/fstab || echo $LINE | sudo tee --append /etc/fstab > /dev/null

# Remember to update aide.db by renaming aide.db.new to aide.db.

# 1.1 Filesystem Configuration
# ===========================================

# NOTE: Some steps are skipped because they'd need prior knowledge of partition and fdisks. If not, it might brick the system.
# However, directories that should use the tmpfs (Temporary Filesystem) are implemented in this configuration.

# 1.1.1.2-6 Ensure mounting of several filesystems are disabled
# =====================================================================

# Configure filesystems
CONF_FILE="/etc/modprobe.d/modprobe.conf"
sudo touch $CONF_FILE
sudo chmod +w $CONF_FILE

# Unmounting several filesystems

# If line does not exist in config file, then append it.
LINES=( "install cramfs /bin/true" "install freevxfs /bin/true" "install jffs2 /bin/true" "install hfs /bin/true" "install hfsplus /bin/true" "install udf /bin/true" )

for current_line in "${LINES[@]}"
do
    grep -F "$current_line" $CONF_FILE  || echo "$current_line" | sudo tee --append $CONF_FILE > /dev/null
done

# Unloading of modules
rmmod cramfs
rmmod freevxfs
rmmod jffs2
rmmod hfs
rmmod hfsplus
rmmod udf

# Separate filesystem for /tmp directory (Using the RAM)

# 1.1.2-4 Ensure nodev,nosuid,noexec option set on /tmp partition
# =====================================================================

# Add nosuid, noexec, rw, nodev, and relatime to fstab for /tmp to mount.
LINE="tmpfs /tmp tmpfs nosuid,noexec,nodev,relatime,rw 0 0"

grep -F "$LINE" /etc/fstab || echo "$LINE" | sudo tee --append /etc/fstab > /dev/null

# 1.1.7 Ensure nodev option set on /var/tmp partition
# 1.1.8 Ensure nosuid option set on /var/tmp partition
# 1.1.9 Ensure noexec option set on /var/tmp partition
# =====================================================================

LINE="tmpfs /var/tmp tmpfs nosuid,noexec,nodev 0 0"

grep -F "$LINE" /etc/fstab || echo "$LINE" | sudo tee --append /etc/fstab > /dev/null

# 1.1.13 Ensure nodev option set on /home partition
# =====================================================================

echo "Home partition example: /dev/xvda1"
echo "If home partition doesn't exist, leave it empty."
read -p "Enter home partition: " HOME_PARTITION

if [ -b $HOME_PARTITION ]
then

    LINE="$HOME_PARTITION /home ext4 rw,relatime,nodev,data=ordered 0 0"

    grep -F "$LINE" /etc/fstab || echo "$LINE" | sudo tee --append /etc/fstab > /dev/null

fi

# 1.1.14 Ensure nodev option set on /dev/shm partition
# 1.1.15 Ensure nosuid option set on /dev/shm partition
# 1.1.16 Ensure noexec option set on /dev/shm partition
# =====================================================================

# Add nosuid, noexec, rw, nodev, and relatime to /dev/shm
LINE="tmpfs /dev/shm tmpfs nosuid,noexec,nodev,relatime,rw 0 0"

grep -F "$LINE" /etc/fstab || echo "$LINE" | sudo tee --append /etc/fstab > /dev/null

# 1.1.20 Ensure sticky bit is set on all world-writable directories
# =================================================================

# Set sticky bit on all world-writable directories.
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

# 1.1.21 Disable automounting
# ======================================================

# autofs is a service that auto mounts filesystems. However, it is not shipped with Ubuntu 18.04.
sudo systemctl disable autofs

# 1.3 Filesystem Integrity Checking
# ===========================================

# 1.3.1 Ensure AIDE is installed
# ======================================================

if [ $DEBUG_MODE != 1 ]
then

    # Install aide
    sudo apt-get install --assume-yes aide aide-common

    # Initialize aide
    sudo aideinit

    # http://manpages.ubuntu.com/manpages/bionic/man8/update-aide.conf.8.html
    # Generates /var/lib/aide/aide.conf.autogenerated from all the files in /etc/aide/aide.conf.d directory.
    update-aide.conf

    # Paste the newly configurated file into /etc/aide/aide.conf
    sudo cp /var/lib/aide/aide.conf.autogenerated /etc/aide/aide.conf

    # Hide /var/lib/lxcfs, /var/lib/private/systemd and /var/log/journal from aide
    LINES=( "!/var/lib/lxcfs" "!/var/lib/private/systemd" "!/var/log/journal" )
    FILE=/etc/aide/aide.conf

    for current_line in "${LINES[@]}"
    do
        grep -F "$current_line" "$FILE" || echo "$current_line" | sudo tee --append "$FILE" > /dev/null
    done

    # 1.3.2 Ensure filesystem integrity is regularly checked
    # ======================================================

    # Add cron to automatically run aide every day at 5am.
    LINE="0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check"
    FILE=/home/tmp.cron

    # If crontab exist for user, copy it into /home/tmp.cron. Otherwise, create a new file.
    crontab -l -u root 2>/dev/null

    if [ $? -eq 0 ]
    then
        crontab -u root -l > $FILE
    else
        touch $FILE
    fi

    # Add cronjob to temp file.
    grep -qF "$LINE" "$FILE" || echo "$LINE" | sudo tee --append "$FILE" > /dev/null

    # Add new temp file to crontab.
    crontab -u root $FILE

    # Remove temp file.
    rm $FILE

fi

# 1.4 Secure Boot Settings
# ===========================================

# 1.4.1 Ensure permissions on bootloader config are configured
# ==============================================================

# Set permissions for /boot/grub/grub.cfg
# Change owner of file to root.
sudo chown root:root /boot/grub/grub.cfg

# Add rw for user and disable all permissions for group and other.
sudo chmod u+rw,og-rwx /boot/grub/grub.cfg


# 1.4.2 Ensure bootloader password is set
# ===========================================

# Check if there's boot password for boot loader.

if [ $SAFE_SSH != 1 ]
then

    if ( grep -q "^set superusers" /boot/grub/grub.cfg )
    then
        echo "Superusers: EXIST"
    else
        echo "Superusers: I sleep."

        FILE=/home/out

        # Create boot password for boot loader.
        grub-mkpasswd-pbkdf2 | sudo tee "$FILE"

        enc_pass=$( grep .sha512 "$FILE" | awk -F "is " '{print $2}' )

        # Remove out file
        rm "$FILE"

        FILE=/etc/grub.d/40_custom
        LINE="set superusers=\"root\""

        enc_pass="password_pbkdf2 root $enc_pass"

        # Append superusers and password if not exist.
        grep -qF "$LINE" "$FILE" || echo "$LINE" | sudo tee --append "$FILE" > /dev/null
        grep -qF "$enc_pass" "$FILE" || echo "$enc_pass" | sudo tee --append "$FILE" > /dev/null

        # Update grub config file
        update-grub

    fi
fi

# 1.4.3 Ensure authentication required for single user mode
# ==========================================================

# Check if root has password. If not, set a password for root.
# The reason why ! is used here is because if there's a match, that means root has no password. No match = password exist.
if ! grep ^root:[*\!]: /etc/shadow
then
    echo "Root password: EXIST"
else
    echo "Root password: I sleep."
    passwd root
fi

# 1.5 Additional Process Hardening
# ===========================================

# 1.5.1 Ensure core dumps are restricted
# ===========================================

LINE="* hard core 0"
FILE=/etc/security/limits.conf

grep -qF "$LINE" "$FILE" || echo "$LINE" | sudo tee --append "$FILE" > /dev/null

LINE="fs.suid_dumpable=0"
FILE=/etc/sysctl.conf

grep -qF "$LINE" "$FILE" || echo "$LINE" | sudo tee --append "$FILE" > /dev/null

sysctl -w fs.suid_dumpable=0

# 1.5.3 Ensure address space layout randomization (ASLR) is enabled
# =====================================================================

LINE="kernel.randomize_va_space = 2"
FILE=/etc/sysctl.d/99-walson-hardening.conf

touch "$FILE"

grep -qF "$LINE" "$FILE" || echo "$LINE" | sudo tee --append "$FILE" > /dev/null

sysctl -w kernel.randomize_va_space=2

# 1.5.4 Ensure prelink is disabled
# ================================

# Restore binaries to default
prelink -ua

apt remove prelink

# 1.6 Mandatory Access Control
# ============================

# Since I'm using Ubuntu 18.04, there's no need to use SELinux. AppArmor is the recommended choice for Ubuntu. In fact, SELinux is incompatible with Ubuntu.

# 1.6.2 Configure AppArmor
# ===========================

# 1.6.3 Ensure SELinux or AppArmor are installed
# ==================================================

if [ $HARDENING_LEVEL == 2 ]
then
    sudo apt install apparmor

    # 1.6.2.1 Ensure AppArmor is not disabled in bootloader configuration
    # ===================================================================

    FILE=/etc/default/grub
    SEARCH_STRING="GRUB_CMDLINE_LINUX_DEFAULT"
    LINE="GRUB_CMDLINE_LINUX_DEFAULT=\"text\""

    sed -i 's/^.*'"$SEARCH_STRING"'.*$/'"$LINE"'/' "$FILE"

    LINE="GRUB_CMDLINE_LINUX=\"\""

    grep -qF "$LINE" "$FILE" || echo "$LINE" | sudo tee --append "$FILE" > /dev/null

    update-grub

    # 1.6.2.2 Ensure all AppArmor Profiles are enforcing
    # ==================================================

    # apparmor-utils provide aa-enforce command.
    sudo apt install apparmor-utils

    aa-enforce /etc/apparmor.d/*
fi

# 1.7 Warning Banners
# =====================

# 1.7.1 Command Line Warning Banners

# 1.7.1.1 Ensure message of the day is configured properly 
# 1.7.1.2 Local login warning banner is configured properly 
# 1.7.1.3 Remote login warning banner is configured properly 
# =============================================================

FILES=( "/etc/motd" "/etc/issue" "/etc/issue.net" )

# Loop through the files
for current_file in "${FILES[@]}"
do

    # Check if file exists.
    if [ -f $current_file ]
    then

        # Replace \v \r \m \s with blank char
        sudo sed -i -r 's/(\\v|\\r|\\m|\\s)//g' $current_file
    else

        # Create file
        touch $current_file
    fi

    # 1.7.1.4 Ensure permissions on /etc/motd are configured
    # 1.7.1.5 Ensure permissions on /etc/issue are configured
    # 1.7.1.6 Ensure permissions on /etc/issue.net are configured
    # ==============================================================

    chown root:root $current_file
    chmod 644 $current_file

    # Scanner and benchmark differs:

    # Scanner:
    # All activities performed on this system will be monitored.

    # Benchmark:
    # No specific requirements for message to show.

    if [ $current_file == "/etc/motd" ]
    then
        search_and_replace_entire_line 'Welcome' 'Welcome to the club buddy' '/etc/motd' 0
    fi

    # Scanner and benchmark differs:

    # Scanner:
    # All activities performed on this system will be monitored.

    # Benchmark:
    # Authorized uses only. All activity may be monitored and reported.

    if [ $current_file == "/etc/issue" ]
    then
        search_and_replace_entire_line 'Authorized' 'Authorized uses only. All activity may be monitored and reported.' '/etc/issue' 0
    fi

    if [ $current_file == "/etc/issue.net" ]
    then
        search_and_replace_entire_line 'Authorized' 'Authorized uses only. All activity may be monitored and reported.' '/etc/issue.net' 0
    fi

done

# 1.7.2 Ensure GDM login banner is configured
# =============================================

# If GNOME is installed, append text to system.
FILE=/etc/gdm3/greeter.dconf-defaults
SEARCH_STRING=( "[org/gnome/login-screen]" "banner-message-enable" "banner-message-text=" )
REPLACE_STRING=( "[org/gnome/login-screen]" "banner-message-enable=true" "banner-message-text='Authorized uses only. All activity may be monitored and reported.'" )

# Create file if not exist.
if ! [ -f "$FILE" ]
then
    # If directory doesn't exist
    if ! [ -d "/etc/gdm3" ]
    then
        # Make dir of gdm3
        mkdir "/etc/gdm3"
    fi

    sudo touch "$FILE"

    # Append replace string
    for (( i=0; i<3; i++ ))
    do

        echo "${REPLACE_STRING[i]}" | sudo tee --append $FILE > /dev/null

    done
fi

# Search & replace strings.
for (( i=0; i<3; i++ ))
do

    sed -i -r "s|^${SEARCH_STRING[i]}$|${REPLACE_STRING[i]}|g" $FILE

done



# 2 Services
# ============================================

# From 2.1 to 2.1.9, inetd must be installed. However, Ubuntu does NOT have it installed default. Configure appropriately.

# 2.1 inetd services
# ===================

# 2.1.2 Ensure daytime services are not enabled
# ===============================================

# 2.1.9 Ensure tftp server is not enabled
# ========================================

# 2.1.10 Ensure xinetd is not enabled
# ====================================

sudo systemctl disable xinetd

# 2.1.11 Ensure openbsd-inetd is not installed
# =============================================

sudo apt-get remove openbsd-inetd

# 2.2 Special Purpose Services
# ============================================

# 2.2.1 Time Synchronization
# ===========================

# Check if chrony or ntp is installed.
dpkg -s chrony | grep -q "Status: install ok"
CHRONY_INSTALLED=$?
dpkg -s ntp | grep -q "Status: install ok"
NTP_INSTALLED=$?

if [ $CHRONY_INSTALLED == 0 ] || [ $NTP_INSTALLED == 0 ]
then
    echo "Chrony or NTP installed"
else
    # Install NTP, and synchronize timedatectl with ntp.
    sudo apt install -y ntp
    sudo timedatectl set-ntp true

    echo "NTP installed and timedatectl sync-ed"
fi

# 2.2.1.2 Ensure ntp is configured
# =================================


# CIS recommendations
search_and_replace_entire_line "restrict -4 default" "restrict -4 default kod nomodify notrap nopeer noquery" '/etc/ntp.conf'
search_and_replace_entire_line "restrict -6 default" "restrict -6 default kod nomodify notrap nopeer noquery" '/etc/ntp.conf'
search_and_replace_entire_line "server 192\.168\.0\.1" "server 192.168.0.1" '/etc/ntp.conf' 0

SEARCH_STRING="RUNASUSER"
REPLACE_STRING="RUNASUSER=ntp"
FILE=/etc/init.d/ntp

sed -i -r "/^$SEARCH_STRING/c $REPLACE_STRING" $FILE

# 2.2.2 Ensure X Window System is not installed
# ==============================================

apt remove xserver-xorg*

# 2.2.3 Ensure Avahi Server is not enabled
# ==============================================

systemctl disable avahi-daemon

# 2.2.5 Ensure DHCP Server is not enabled
# ==============================================

systemctl disable isc-dhcp-server
systemctl disable isc-dhcp-server6

# 2.2.6 Ensure LDAP Server is not enabled
# ==============================================

systemctl disable slapd

# 2.2.7 Ensure NFS and RPC are not enabled
# ==============================================

systemctl disable nfs-server
systemctl disable rpcbind

# 2.2.8 Ensure DNS Server is not enabled
# ==============================================

systemctl disable bind9

# 2.2.9 Ensure FTP Server is not enabled
# ==============================================

systemctl disable vsftpd

# 2.2.10 Ensure HTTP Server is not enabled
# ==============================================

systemctl disable apache2

# 2.2.11 Ensure IMAP and POP3 Server is not enabled
# ==============================================

systemctl disable dovecot

# 2.2.12 Ensure Samba is not enabled
# ==============================================

systemctl disable smbd

# 2.2.13 Ensure HTTP Proxy Server is not enabled
# ==============================================

systemctl disable squid

# 2.2.14 Ensure SNMP Server is not enabled
# ==============================================

systemctl disable snmp

# 2.2.15 Ensure mail transfer agent is configured for local-only mode
# ====================================================================

# Depends on what mail agent this Ubuntu is using.

# 2.2.16 Ensure rsync service is not enabled
# ==============================================

systemctl disable rsync

# 2.2.17 Ensure NIS Server is not enabled
# ==============================================

systemctl disable nis

# 2.3 Service Clients
# ====================================================================

# 2.3.1 Ensure NIS Client is not installed
# =========================================

sudo apt remove -y nis

# 2.3.2 Ensure rsh client is not installed
# =========================================

sudo apt remove -y rsh-client rsh-redone-client

# 2.3.3 Ensure talk client is not installed
# =========================================

sudo apt remove -y talk

# 2.3.4 Ensure telnet client is not installed
# =========================================

sudo apt remove -y telnet

# 2.3.5 Ensure LDAP client is not installed
# =========================================

sudo apt remove -y ldap-utils

# 3 Network Configuration
# =========================================================================

# 3.1 Network Parameters (Host Only)
# =========================================

# 3.1.1 Ensure IP Forwarding is disabled
# =========================================

# 3.1.2 Ensure packet redirect sending is disabled
# ==================================================

SEARCH_STRING=( "net.ipv4.ip_forward" "net.ipv4.conf.all.send_redirects" "net.ipv4.conf.default.send_redirects" )
REPLACE_STRING=( "net.ipv4.ip_forward = 0" "net.ipv4.conf.all.send_redirects = 0" "net.ipv4.conf.default.send_redirects = 0" )
FILE=/etc/sysctl.conf

for (( i=0; i<3; i++ ))
do
    search_and_replace_entire_line "${SEARCH_STRING[i]}" "${REPLACE_STRING[i]}" "$FILE" 0
done

# 3.2 Network Parameters (Host and Router)
# =========================================

# 3.2.1 Ensure source routed packets are not accepted
# =====================================================

SEARCH_STRING=( "net.ipv4.conf.all.accept_source_route" "net.ipv4.conf.default.accept_source_route" )
REPLACE_STRING=( "net.ipv4.conf.all.accept_source_route = 0" "net.ipv4.conf.default.accept_source_route = 0" )
FILE=/etc/sysctl.conf

for (( i=0; i<2; i++ ))
do
    search_and_replace_entire_line "${SEARCH_STRING[i]}" "${REPLACE_STRING[i]}" "$FILE" 0
done

# 3.2.2 Ensure ICMP redirects are not accepted
# =====================================================

SEARCH_STRING=( "net.ipv4.conf.all.accept_redirects" "net.ipv4.conf.default.accept_redirects" )
REPLACE_STRING=( "net.ipv4.conf.all.accept_redirects = 0" "net.ipv4.conf.default.accept_redirects = 0" )
FILE=/etc/sysctl.conf

for (( i=0; i<2; i++ ))
do
    search_and_replace_entire_line "${SEARCH_STRING[i]}" "${REPLACE_STRING[i]}" "$FILE" 0
done

# 3.2.3 Ensure secure ICMP redirects are not accepted
# =====================================================

SEARCH_STRING=( "net.ipv4.conf.all.secure_redirects" "net.ipv4.conf.default.secure_redirects" )
REPLACE_STRING=( "net.ipv4.conf.all.secure_redirects = 0" "net.ipv4.conf.default.secure_redirects = 0" )
FILE=/etc/sysctl.conf

for (( i=0; i<2; i++ ))
do
    search_and_replace_entire_line "${SEARCH_STRING[i]}" "${REPLACE_STRING[i]}" "$FILE" 0
done

# 3.2.4 Ensure suspicious packets are logged
# =====================================================

SEARCH_STRING=( "net.ipv4.conf.all.log_martians" "net.ipv4.conf.default.log_martians" )
REPLACE_STRING=( "net.ipv4.conf.all.log_martians = 1" "net.ipv4.conf.default.log_martians = 1" )
FILE=/etc/sysctl.conf

for (( i=0; i<2; i++ ))
do
    search_and_replace_entire_line "${SEARCH_STRING[i]}" "${REPLACE_STRING[i]}" "$FILE" 0
done

# 3.2.5 Ensure broadcast ICMP redirects are ignored
# ===================================================

SEARCH_STRING="net.ipv4.icmp_echo_ignore_broadcasts"
REPLACE_STRING="net.ipv4.icmp_echo_ignore_broadcasts = 1"
FILE=/etc/sysctl.conf

search_and_replace_entire_line "$SEARCH_STRING" "$REPLACE_STRING" "$FILE" 0

# 3.2.6 Ensure bogus ICMP responses are ignored
# ===================================================

SEARCH_STRING="net.ipv4.icmp_ignore_bogus_error_responses"
REPLACE_STRING="net.ipv4.icmp_ignore_bogus_error_responses = 1"
FILE=/etc/sysctl.conf

search_and_replace_entire_line "$SEARCH_STRING" "$REPLACE_STRING" "$FILE" 0

# 3.2.7 Ensure Reverse Path Filtering is enabled
# =====================================================

SEARCH_STRING=( "net.ipv4.conf.all.rp_filter" "net.ipv4.conf.default.rp_filter" )
REPLACE_STRING=( "net.ipv4.conf.all.rp_filter = 1" "net.ipv4.conf.default.rp_filter = 1" )
FILE=/etc/sysctl.conf

for (( i=0; i<2; i++ ))
do
    search_and_replace_entire_line "${SEARCH_STRING[i]}" "${REPLACE_STRING[i]}" "$FILE" 0
done

# 3.2.8 Ensure TCP SYN Cookies is enabled
# =============================================

SEARCH_STRING="net.ipv4.tcp_syncookies"
REPLACE_STRING="net.ipv4.tcp_syncookies = 1"
FILE=/etc/sysctl.conf

search_and_replace_entire_line "$SEARCH_STRING" "$REPLACE_STRING" "$FILE" 0

# Reload the conf file
sysctl --system

# 3.4 TCP Wrappers
# ============================================================================

# 3.4.1 Ensure TCP Wrappers is installed
# ===================================================

sudo apt install -y tcpd

# 3.4.2 Ensure /etc/hosts.allow is configured
# ===================================================
# For this section, user supervision is required.

# 3.4.3 Ensure /etc/hosts.deny is configured
# ===================================================
# For this section, user supervision is required.

# echo "ALL: ALL" >> /etc/hosts.deny

# 3.4.4 Ensure permissions on /etc/hosts.allow is configured
# ===========================================================

chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow

# 3.4.5 Ensure permissions on /etc/hosts.deny is configured
# ===========================================================

chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny

# 3.5 Uncommon Network Protocols
# ===========================================================

# 3.5.1 Ensure DCCP is disabled
# ====================================



# 3.6 Firewall Configuration
# ===========================================================

# 3.6.1 Ensure iptables is installed
# ====================================

sudo apt install -y iptables

# 3.6.2 Ensure default deny firewall policy
# ===========================================

iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# 3.6.3 Ensure loopback traffic is configured
# ===========================================

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP

# 3.6.4 Ensure outbound and established connections are configured
# =================================================================
iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

# 3.6.5 Ensure firewall rules exist for all open ports
# ======================================================

# Open inbound ssh(tcp port 22) connections
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

# 4 Logging and Auditing
# =========================================================================

# 4.1 Configure System Accounting (auditd)
# ======================================================

# 4.2 Configure Logging
# ======================================================

# 4.2.1 Configure rsyslog
# =========================

systemctl enable rsyslog

# 4.2.1.3 Ensure rsyslog default file permissions configured
# =============================================================

search_and_replace_entire_line "^\$FileCreateMode" "\$FileCreateMode 0640" "/etc/rsyslog.conf"
search_and_replace_entire_line "^\\\$FileCreateMode" "\\\$FileCreateMode 0640" "/etc/rsyslog.d/*.conf"

# 4.2.1.4 Ensure rsyslog is configured to send logs to a remote host
# ===================================================================

# Needs user manual input for log host URL.
# This is to beat the CIS scanner :)

search_and_replace_entire_line "\*\.\* @@loghost.example.com" "*.* @@loghost.example.com" "/etc/rsyslog.conf" 0

# 4.2.2 Configure syslog-ng
# =============================================================

# 4.2.2.1 Ensure syslog-ng is enabled
# ======================================

update-rc.d syslog-ng enable

# 4.2.2.3 Ensure syslog-ng default file permissions configured
# =============================================================

search_and_replace "perm\([0-9]+\)" "perm(0640)" /etc/syslog-ng/syslog-ng.conf

# 4.2.3 Ensure rsyslog or syslog-ng is installed
# =============================================================

sudo apt install -y rsyslog

# 4.2.4 Ensure permissions on all logfiles are configured
# =============================================================

chmod -R g-wx,o-rwx /var/log/*



# 5 Access, Authentication and Authorization
# ================================================================================

# 5.1 Configure Cron
# =============================================================

# 5.1.1 Ensure cron daemon is enabled
# ======================================

systemctl enable cron

# 5.1.2 Ensure permissions on /etc/crontab are configured
# ========================================================

chown root:root /etc/crontab
chmod og-rwx /etc/crontab

# 5.1.3 Ensure permissions on /etc/cron.hourly are configured
# ============================================================

chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly

# 5.1.4 Ensure permissions on /etc/cron.daily are configured
# ============================================================

chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily

# 5.1.5 Ensure permissions on /etc/cron.weekly are configured
# ============================================================

chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly

# 5.1.6 Ensure permissions on /etc/cron.monthy are configured
# ============================================================

chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly

# 5.1.7 Ensure permissions on /etc/cron.d are configured
# ============================================================

chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

# 5.1.8 Ensure at/cron is restricted to authorized users
# ============================================================

rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow

# 5.2 SSH Configuration
# ============================================================

# 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured
# =================================================================

chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

# 5.2.2 Ensure SSH protocol is set to 2
# =================================================================

search_and_replace_entire_line "Protocol" "Protocol 2" "/etc/ssh/sshd_config" 0

# 5.2.3 Ensure SSH LogLevel is set to INFO
# ===========================================

search_and_replace_entire_line "LogLevel" "LogLevel INFO" "/etc/ssh/sshd_config" 0

# 5.2.4 Ensure SSH X11 forwarding is disabled
# ==============================================

search_and_replace_entire_line "X11Forwarding" "X11Forwarding no" "/etc/ssh/sshd_config" 0

# 5.2.5 Ensure SSH MaxAuthTries is set to 4 or less
# ====================================================

search_and_replace_entire_line "MaxAuthTries" "MaxAuthTries 4" "/etc/ssh/sshd_config" 0

# 5.2.6 Ensure SSH IgnoreRhosts is enabled
# ====================================================

search_and_replace_entire_line "IgnoreRhosts" "IgnoreRhosts yes" "/etc/ssh/sshd_config" 0

# 5.2.7 Ensure SSH HostbasedAuthentication is disabled
# =======================================================

search_and_replace_entire_line "HostbasedAuthentication" "HostbasedAuthentication no" "/etc/ssh/sshd_config" 0

# 5.2.8 Ensure SSH root login is disabled
# ====================================================

search_and_replace_entire_line "PermitRootLogin" "PermitRootLogin no" "/etc/ssh/sshd_config" 0

# 5.2.9 Ensure SSH PermitEmptyPasswords is disabled
# ====================================================

search_and_replace_entire_line "PermitEmptyPasswords" "PermitEmptyPasswords no" "/etc/ssh/sshd_config" 0

# 5.2.10 Ensure SSH PermitUserEnvironment is disabled
# ====================================================

search_and_replace_entire_line "PermitUserEnvironment" "PermitUserEnvironment no" "/etc/ssh/sshd_config" 0

# 5.2.11 Ensure only approved MAC algorithms are used
# ======================================================

search_and_replace_entire_line "MACs" "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" "/etc/ssh/sshd_config" 0

# 5.2.12 Ensure SSH Idle Timeout Interval is configured
# ========================================================

search_and_replace_entire_line "ClientAliveInterval" "ClientAliveInterval 300" "/etc/ssh/sshd_config" 0
search_and_replace_entire_line "ClientAliveCountMax" "ClientAliveCountMax 0" "/etc/ssh/sshd_config" 0

# 5.2.13 Ensure SSH LoginGraceTime is set to one minute or less
# ================================================================

search_and_replace_entire_line "LoginGraceTime" "LoginGraceTime 60" "/etc/ssh/sshd_config" 0

# 5.2.14 Ensure SSH access is limited
# =======================================

# Note this command requires manual input.

if [ $SAFE_SSH != 1 ]
then
    search_and_replace_entire_line "AllowUsers" "AllowUsers root" "/etc/ssh/sshd_config" 0
fi

# 5.2.15 Ensure SSH warning banner is configured
# ========================================================

search_and_replace_entire_line "Banner" "Banner /etc/issue.net" "/etc/ssh/sshd_config" 0

# 5.3 Configure PAM
# ========================================================

# 5.3.1 Ensure password creation requirements are configured
# ============================================================

sudo apt install -y libpam-pwquality

# Scanner and benchmark differs:

# Scanner:
# password requisite pam_pwquality.so try_first_pass retry=3

# Benchmark:
# password requisite pam_pwquality.so retry=3

# Scanner requires try_first_pass parameter.
search_and_replace_entire_line "pam_pwquality.so" "password requisite pam_pwquality.so try_first_pass retry=3" "/etc/pam.d/common-password" 0

search_and_replace_entire_line "minlen" "minlen = 14" "/etc/security/pwquality.conf" 0
search_and_replace_entire_line "dcredit" "dcredit = -1" "/etc/security/pwquality.conf" 0
search_and_replace_entire_line "ucredit" "ucredit = -1" "/etc/security/pwquality.conf" 0
search_and_replace_entire_line "ocredit" "ocredit = -1" "/etc/security/pwquality.conf" 0
search_and_replace_entire_line "lcredit" "lcredit = -1" "/etc/security/pwquality.conf" 0

# 5.3.2 Ensure lockout for failed password attempts is configured
# ================================================================

search_and_replace_entire_line "pam_tally2" "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900" "/etc/pam.d/common-auth" 0

# Do /sbin/pam_tally2 -u <username> --reset to unlock a user.

# 5.3.3 Ensure password reuse is limited
# ================================================================

# Scanner and benchmark differs:

# Scanner:
# password sufficient pam_unix.so remember=5

# Benchmark:
# password required pam_pwhistory.so remember=5

search_and_replace_entire_line '^password\s+required\s+pam_pwhistory.so' 'password required pam_pwhistory.so remember=5' '/etc/pam.d/common-password' 0

# 5.3.4 Ensure password hashing algorithm is SHA-512
# ================================================================

# Default is SHA-512
# search_and_replace_entire_line '^password\s+required\s+pam_pwhistory.so' 'password required pam_pwhistory.so remember=5' '/etc/pam.d/common-password' 0

# 5.4 User Accounts and Environment
# ================================================================

# 5.4.1 Set Shadow Password Suite Parameters
# ================================================================

# 5.4.1.1 Ensure password expiration is 365 days or less
# ================================================================

search_and_replace_entire_line 'PASS_MAX_DAYS' 'PASS_MAX_DAYS 90' '/etc/login.defs' 0

# 5.4.1.2 Ensure minimum days between password changes is 7 or more 
# ===================================================================

search_and_replace_entire_line 'PASS_MIN_DAYS' 'PASS_MIN_DAYS 7' '/etc/login.defs' 0

# 5.4.1.3 Ensure password expiration warning days is 7 or more
# ===================================================================

search_and_replace_entire_line 'PASS_WARN_AGE' 'PASS_WARN_AGE 7' '/etc/login.defs' 0

# 5.4.1.4 Ensure inactive password lock is 30 or less
# ===================================================================

# Scanner runs useradd -D to get INACTIVE, but sudo useradd -D shows different results?
sudo useradd -D -f 30

# 5.4.1.5 Ensure all users last password change date is in the past
# ===================================================================

# Manual input by admin.
# #> cat /etc/shadow | cut -d: -f1
# <list of users>
# #> chage --list <user>
# Last Change



# 5.4.2 Ensure system accounts are non-login
# ===================================================================

# Check manual for 5.4.2

# 5.4.3 Ensure default group for the root account is GID 0
# ===================================================================

usermod -g 0 root

# 5.4.4 Ensure default user umask is 027 or more restrictive
# ===================================================================

# /etc/bash.bashrc and /etc/profile doesn't have umask anywhere in their config, even in default Ubuntu 18.04 installation?
# "/etc/profile.d/*.sh"
FILES=( "/etc/bash.bashrc" "/etc/profile" )

for current_file in "$FILES[@]"
do
    search_and_replace_entire_line 'umask' 'umask 027' "$current_file" 0
done

umask 027

# 5.6 Ensure access to the su command is restricted
# ===================================================================

# Scanner and benchmark differs:

# Scanner:
# auth required pam_wheel.so use_uid

# Benchmark:
# auth required pam_wheel.so

search_and_replace_entire_line 'auth required pam_wheel.so' 'auth required pam_wheel.so' /etc/pam.d/su 0

# Create a comma separated list of users in the sudo statement in the /etc/group file:

# sudo:x:10:root,<user list>

# 6 System Maintenance
# ===================================================================

# 6.1 System File Permissions
# ===================================================================

# 6.1.2 Ensure permissions on /etc/passwd are configured
# ===================================================================

chown root:root /etc/passwd
chmod 644 /etc/passwd

# 6.1.3 Ensure permissions on /etc/shadow are configured
# ===================================================================

chown root:shadow /etc/shadow
chmod o-rwx,g-wx /etc/shadow

# 6.1.4 Ensure permissions on /etc/group are configured
# ===================================================================

chown root:root /etc/group
chmod 644 /etc/group

# 6.1.5 Ensure permissions on /etc/gshadow are configured
# ==========================================================

chown root:shadow /etc/gshadow
chmod o-rwx,g-rw /etc/gshadow

# 6.1.6 Ensure permissions on /etc/passwd- are configured
# ==========================================================

chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd-

# 6.1.7 Ensure permissions on /etc/shadow- are configured
# ==========================================================

chown root:shadow /etc/shadow-
chmod o-rwx,g-rw /etc/shadow-

# 6.1.8 Ensure permissions on /etc/group- are configured
# ==========================================================

chown root:root /etc/group-
chmod u-x,go-wx /etc/group-

# 6.1.9 Ensure permissions on /etc/gshadow- are configured
# ==========================================================

chown root:shadow /etc/gshadow-
chmod o-rwx,g-rw /etc/gshadow-

# 6.1.10 Ensure no world writable files exist
# =======================================================

# 6.1.11 Ensure no unwanted files or directories exist
# =======================================================

# 6.1.12 Ensure no ungrouped files or directories exist
# =======================================================

# Check CIS manual for 6.1.10 - 6.1.12.

# 6.2 User and Group Settings
# ===================================================================

# 6.2.1 Ensure password fields are not empty
# =============================================

# 6.2.2 Ensure no legacy "+" entries exist in /etc/passwd
# =============================================

# 6.2.3 Ensure no legacy "+" entries exist in /etc/shadow
# =============================================

# 6.2.4 Ensure no legacy "+" entries exist in /etc/group
# =============================================

# 6.2.5 Ensure root is the only UID 0 account
# =============================================

# 6.2.6 Ensure root PATH integrity
# =============================================

# For 6.2.1 to 6.2.6, requires manual input.

# 6.2.7 Ensure all users' home directories exist
# ================================================

# cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
# "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read
# user dir; do
#  if [ ! -d "$dir" ]; then
#  echo "The home directory ($dir) of user $user does not exist."
#  fi
# done

# # 6.2.8 Ensure users' home directories permissions are 750 or more restrictive
# # =============================================================================

cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
if [ ! -d "$dir" ]; then
    echo "The home directory ($dir) of user $user does not exist."
else
    dirperm=`ls -ld $dir | cut -f1 -d" "`
    if [ `echo $dirperm | cut -c6` != "-" ]; then
        echo "Group Write permission set on the home directory ($dir) of user
        $user"
        chmod g-w "$dir"
    fi
    if [ `echo $dirperm | cut -c8` != "-" ]; then
        echo "Other Read permission set on the home directory ($dir) of user
        $user"
        chmod o-r "$dir"
    fi
    if [ `echo $dirperm | cut -c9` != "-" ]; then
        echo "Other Write permission set on the home directory ($dir) of user
        $user"
        chmod o-w "$dir"
    fi
    if [ `echo $dirperm | cut -c10` != "-" ]; then
        echo "Other Execute permission set on the home directory ($dir) of user
        $user"
        chmod o-x "$dir"
    fi
fi
done

# # 6.2.9 Ensure users own their home directories
# # ===============================================

# cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
# "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read
# user dir; do
#  if [ ! -d "$dir" ]; then
#  echo "The home directory ($dir) of user $user does not exist."
#  else
#  owner=$(stat -L -c "%U" "$dir")
#  if [ "$owner" != "$user" ]; then
#  echo "The home directory ($dir) of user $user is owned by $owner."
#  fi
# fi
# done

# # 6.2.10 Ensure users' dot files are not group or world writable
# # ================================================================

# cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
# "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user
# dir; do
#  if [ ! -d "$dir" ]; then
#  echo "The home directory ($dir) of user $user does not exist."
#  else
#  for file in $dir/.[A-Za-z0-9]*; do
#  if [ ! -h "$file" -a -f "$file" ]; then
#  fileperm=`ls -ld $file | cut -f1 -d" "`
#  if [ `echo $fileperm | cut -c6` != "-" ]; then
#  echo "Group Write permission set on file $file"
#  fi
#  if [ `echo $fileperm | cut -c9` != "-" ]; then
#  echo "Other Write permission set on file $file"
#  fi
#  fi
#  done
#  fi
# done

# # 6.2.11 Ensure no users have .forward files
# # ===============================================

# cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
# "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user
# dir; do
#  if [ ! -d "$dir" ]; then
#  echo "The home directory ($dir) of user $user does not exist."
#  else
#  if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
#  echo ".forward file $dir/.forward exists"
#  fi
#  fi
# done

# # 6.2.12 Ensure no users have .netrc files
# # ===========================================

# cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
# "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user
# dir; do
#  if [ ! -d "$dir" ]; then
#  echo "The home directory ($dir) of user $user does not exist."
#  else
#  if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
#  echo ".netrc file $dir/.netrc exists"
#  fi
#  fi
# done

# # 6.2.13 Ensure users' .netrc files are not group or world accessible
# # ====================================================================

# cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
# "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user
# dir; do
#  if [ ! -d "$dir" ]; then
#  echo "The home directory ($dir) of user $user does not exist."
#  else
#  for file in $dir/.netrc; do
#  if [ ! -h "$file" -a -f "$file" ]; then
#  fileperm=`ls -ld $file | cut -f1 -d" "`
#  if [ `echo $fileperm | cut -c5` != "-" ]; then
#  echo "Group Read set on $file"
#  fi
#  if [ `echo $fileperm | cut -c6` != "-" ]; then
#  echo "Group Write set on $file"
#  fi
#  if [ `echo $fileperm | cut -c7` != "-" ]; then
#  echo "Group Execute set on $file"
#  fi
#  if [ `echo $fileperm | cut -c8` != "-" ]; then
#  echo "Other Read set on $file"
#  fi
#  if [ `echo $fileperm | cut -c9` != "-" ]; then
#  echo "Other Write set on $file"
#  fi
#  if [ `echo $fileperm | cut -c10` != "-" ]; then
#  echo "Other Execute set on $file"
#  fi
#  fi
#  done
#  fi
# done

# # 6.2.14 Ensure no users have .rhosts files
# # ===========================================

# cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
# "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user
# dir; do
#  if [ ! -d "$dir" ]; then
#  echo "The home directory ($dir) of user $user does not exist."
#  else
#  for file in $dir/.rhosts; do
#  if [ ! -h "$file" -a -f "$file" ]; then
#  echo ".rhosts file in $dir"
#  fi
#  done
#  fi
# done

# # 6.2.15 Ensure all groups in /etc/passwd exist in /etc/group
# # ============================================================

# for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
#  grep -q -P "^.*?:[^:]*:$i:" /etc/group
#  if [ $? -ne 0 ]; then
#  echo "Group $i is referenced by /etc/passwd but does not exist in
# /etc/group"
#  fi
# done

# # 6.2.16 Ensure no duplicate UIDs exist
# # ===========================================

# cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
#  [ -z "${x}" ] && break
#  set - $x
#  if [ $1 -gt 1 ]; then
#  users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
#  echo "Duplicate UID ($2): ${users}"
#  fi
# done

# # 6.2.17 Ensure no duplicate GIDs exist
# # ===========================================

# cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
#  [ -z "${x}" ] && break
#  set - $x
#  if [ $1 -gt 1 ]; then
#  groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
#  echo "Duplicate GID ($2): ${groups}"
#  fi
# done

# # 6.2.18 Ensure no duplicate user names exist
# # =============================================

# cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
#  [ -z "${x}" ] && break
#  set - $x
#  if [ $1 -gt 1 ]; then
#  uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
#  echo "Duplicate User Name ($2): ${uids}"
#  fi
# done

# # 6.2.14 Ensure no duplicate group names exist
# # ==============================================

# cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
#  [ -z "${x}" ] && break
#  set - $x
#  if [ $1 -gt 1 ]; then
#  gids=`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
#  echo "Duplicate Group Name ($2): ${gids}"
#  fi
# done

# # 6.2.20 Ensure shadow group is empty
# # ===========================================

# grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group
# awk -F: '($4 == "<shadow-gid>") { print }' /etc/passwd





# 2.2.1 Time Synchronization
# ===========================

# # Separate partition for /var directory

# # Create disk with 1GB
# DIR="/dev"
# DISK="xvdg"
# sudo dd if=/dev/zero of=$DIR/$DISK bs=1M count=1024

# # Create partition
# (
# echo o # Create a new empty DOS partition table
# echo n # Add a new partition
# echo p # Primary partition
# echo 1 # Partition number
# echo   # First sector (Accept default: 1)
# echo   # Last sector (Accept default: varies)
# echo w # Write
# ) | sudo fdisk $DIR/$DISK

# PARTITION="${DISK}"

# # Setup loopback for partition
# sudo losetup -P --show /dev/loop1 "$DIR/$DISK"
# # Convert partition to ext4 fs
# sudo mkfs -t ext4 /dev/loop1
# # Detach partition from loopback
# sudo losetup -d /dev/loop1

# LINE="$DIR/$PARTITION /var ext4 rw,relatime,data=ordered"
# # grep -F "$LINE" /etc/fstab || echo $LINE | sudo tee --append /etc/fstab > /dev/null


echo "Hardened!"

exit 1