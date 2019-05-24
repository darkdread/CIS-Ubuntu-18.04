#!/bin/bash

echo "Hardening..."

# ISSUE = [FAILED] count

# Manual work
# Ensure nodev option set on /home partition = 1
# Bootloader = 3
# Ensure /etc/hosts.allow is configured = 1
# Ensure /etc/hosts.deny is configured = 1
# Ensure rsyslog is configured to send logs to a remote host = 1
# Ensure mail transfer agent is configured for local-only mode = 1
# Ensure inactive password lock is 30 days or less = 1
# Ensure all users last password change date is in the past = 1


# Scanner diffs
# Ensure message of the day is configured properly = 3
# Ensure password reuse is limited = 1
# Ensure access to the su command is restricted = 1


# Scanner issues (must be root or permission denied)
# 1.3.2 Ensure filesystem integrity is regularly checked = 1
# 3.6.2 Ensure default deny firewall policy = 3


# Not Scored
# Ensure IPv6 router advertisements are not accepted = 9
# Uncommon Network Protocol = 4
# 4.2.1.2 Ensure logging is configured = 13
# Ensure remote rsyslog messages are only accepted on designated log hosts = 2


# Working on
# 1.5.1 Ensure core dumps are restricted = 1
# 3.2.4 Ensure suspicious packets are logged = 4
# 3.2.7 Ensure Reverse Path Filtering is enabled = 2
# 4.2.4 Ensure permissions on all logfiles are configured = 1
# sshd_config = 15 ? (It should be working.)
# 5.4.4 Ensure default umask is 027 or more restrictive = 2

# Hardening level.
HARDENING_LEVEL=1

# Debug mode.
DEBUG_MODE=0

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

echo "Hardened!"

exit 1