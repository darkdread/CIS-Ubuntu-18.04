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

    echo "Root password: I sleep."
fi