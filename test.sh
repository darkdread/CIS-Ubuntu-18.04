# Today's date in seconds
today=$(date +'%s')

# Get all users
ALL_USERS=($(awk -F: '{print $1}' /etc/passwd))

# Get all users' last password change date in seconds
ALL_USERS_LAST_CHANGE_DATE=$(awk -F: '{print $1}' /etc/passwd \
    | xargs -I {} chage --list {} \
    | grep "Last password change" \
    | awk -F: '{print $2'} \
    | xargs -I {} date --date "{}" +'%s' \
    | xargs -I {} echo "{}, "
)

str=$ALL_USERS_LAST_CHANGE_DATE

arr_dates=()
while [[ $str =~ ([^,]+)(,[ ]+|$) ]]; do
    arr_dates+=("${BASH_REMATCH[1]}")   # capture the field
    i=${#BASH_REMATCH}              # length of field + delimiter
    str=${str:i}                    # advance the string by that length
done                                # the loop deletes $str, so make a copy if needed

echo "Today: $today"
echo $arr_dates

for index in "${!arr_dates[@]}"
do
    change_date=${arr_dates[index]}
    user=${ALL_USERS[index]}
    echo $change_date
    if [ $change_date -lt $today ]
    then
        echo "User: $user last password change > today!"
    fi
done