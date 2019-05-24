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
# sshd_config = 15 ? (It should be working.) (I think scanner scans for a space before and after every key=value line)


# Scanner issues (must be root or permission denied)
# 1.3.2 Ensure filesystem integrity is regularly checked = 1
# 3.6.2 Ensure default deny firewall policy = 3


# Not Scored
# Ensure IPv6 router advertisements are not accepted = 9
# Uncommon Network Protocol = 4
# 4.2.1.2 Ensure logging is configured = 13
# Ensure remote rsyslog messages are only accepted on designated log hosts = 2


# Working on
# 1.5.1 Ensure core dumps are restricted = 1 (Done)
# 3.2.4 Ensure suspicious packets are logged = 4 (Done)
# 3.2.7 Ensure Reverse Path Filtering is enabled = 2 (Done)
# 4.2.4 Ensure permissions on all logfiles are configured = 1 (This should work without changing)
# 5.4.4 Ensure default umask is 027 or more restrictive = 2

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

echo "Hardened!"

exit 1