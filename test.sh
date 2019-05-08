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

    FILES=( "/etc/motd" "/etc/issue" "/etc/issue.net" )

    # Loop through the files
    for current_file in "${FILES[@]}"
    do

        # Check if file exists.
        if [ -f $current_file ]
        then

            # Replace \v \r \m \s with blank char
            sudo sed -i -r 's/(\\v|\\r|\\m|\\s)//g' $current_file

            # 1.7.1.4 Ensure permissions on /etc/motd are configured
            # 1.7.1.5 Ensure permissions on /etc/issue are configured
            # 1.7.1.6 Ensure permissions on /etc/issue.net are configured
            # ==============================================================

            chown root:root $current_file
            chmod 644 $current_file
        else
            # Create file

            # touch $current_file

            if [ $current_file == "${FILES[1]}" ]
            then
                # search_and_replace_entire_line 'Authorized' 'Authorized uses only. All activity may be monitored and reported.' '/etc/issue' 0
                echo "ayylmao"
            fi

        fi

    done

    echo "Root password: I sleep."
fi