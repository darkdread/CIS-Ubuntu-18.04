#!/bin/bash

echo "Hardening..."

# Hardening level.
HARDENING_LEVEL=1

# Debug mode.
DEBUG_MODE=0

# Disabling SAFE_SSH will cause issues.
SAFE_SSH=0


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

echo "Hardened!"

exit 1