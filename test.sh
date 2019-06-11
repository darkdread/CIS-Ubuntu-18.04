# Today's date
today=$(date --date "")

# Get all users' last password change date
ALL_USERS_LAST_CHANGE_DATE=$(awk -F: '{print $1}' /etc/passwd | xargs -I {} chage --list {} | grep "Last password change" | awk -F: '{print $2'} | xargs -I {} date --date "{}" | xargs -I {} echo "{}, ")

str=$ALL_USERS_LAST_CHANGE_DATE

arr_dates=()
while [[ $str =~ ([^,]+)(,[ ]+|$) ]]; do
    arr_dates+=("${BASH_REMATCH[1]}")   # capture the field
    i=${#BASH_REMATCH}              # length of field + delimiter
    str=${str:i}                    # advance the string by that length
done                                # the loop deletes $str, so make a copy if needed

echo "Today: $today"
echo $ALL_USERS_LAST_CHANGE_DATE
echo $arr_dates

for change_date in "${arr_dates[@]}"
do
    echo $change_date
done