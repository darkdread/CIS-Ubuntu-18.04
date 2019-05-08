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

    # 1.4.2 Ensure bootloader password is set
    # ===========================================

    # Check if there's boot password for boot loader.
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

    echo "Root password: I sleep."
fi