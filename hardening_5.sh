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

# 5 Access, Authentication and Authorization
# ================================================================================

# 5.1 Configure Cron
# =============================================================

# 5.1.1 Ensure cron daemon is enabled
# ======================================

systelctl enable cron

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

echo "Hardened!"

exit 1