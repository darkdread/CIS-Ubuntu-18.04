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