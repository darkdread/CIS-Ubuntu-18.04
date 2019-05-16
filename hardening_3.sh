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
REPLACE_STRING=( "net.ipv4.conf.all.log_martians = 0" "net.ipv4.conf.default.log_martians = 0" )
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
REPLACE_STRING=( "net.ipv4.conf.all.rp_filter = 0" "net.ipv4.conf.default.rp_filter = 0" )
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

echo "Hardened!"

exit 1