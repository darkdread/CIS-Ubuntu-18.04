#!/bin/bash

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

echo "testing..."

if false
then
    echo "Root password: EXIST"
else

    # SEARCH_STRING=( "net.ipv4.ip_forward" "net.ipv4.conf.all.send_redirects" "net.ipv4.conf.default.send_redirects" )
    # REPLACE_STRING=( "net.ipv4.ip_forward = 0" "net.ipv4.conf.all.send_redirects = 0" "net.ipv4.conf.default.send_redirects = 0" )

    # regex not working?
    search_and_replace_entire_line "Protocol" "Protocol 2" "/etc/ssh/sshd_config" 0

    # sysctl -w net.ipv4.ip_forward=0
    # sysctl -w net.ipv4.conf.all.send_redirects=0
    # sysctl -w net.ipv4.conf.default.send_redirects=0

    # sysctl -w net.ipv4.route.flush=1

    echo "Root password: I sleep."
fi