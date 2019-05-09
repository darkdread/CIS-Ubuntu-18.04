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

    cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
    if [ ! -d "$dir" ]; then
        echo "The home directory ($dir) of user $user does not exist."
    else
        dirperm=`ls -ld $dir | cut -f1 -d" "`
        if [ `echo $dirperm | cut -c6` != "-" ]; then
            echo "Group Write permission set on the home directory ($dir) of user
            $user"
            chmod g-w "$dir"
        fi
        if [ `echo $dirperm | cut -c8` != "-" ]; then
            echo "Other Read permission set on the home directory ($dir) of user
            $user"
            chmod o-r "$dir"
        fi
        if [ `echo $dirperm | cut -c9` != "-" ]; then
            echo "Other Write permission set on the home directory ($dir) of user
            $user"
            chmod o-w "$dir"
        fi
        if [ `echo $dirperm | cut -c10` != "-" ]; then
            echo "Other Execute permission set on the home directory ($dir) of user
            $user"
            chmod o-x "$dir"
        fi
    fi
    done

    echo "Root password: I sleep."
fi