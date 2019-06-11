# Today's date
today=$(date --date "")

# Get all users' last password change date
ALL_USERS_LAST_CHANGE_DATE=$(awk -F: '{print $1}' /etc/passwd | xargs -I {} chage --list {} | grep "Last password change" | awk -F: '{print $2'} | xargs -I {} date --date "{}" | xargs -I {} echo "{}\n")

SAVEIFS=$IFS
IFS=$'\n'
ARR_DATES=$($ALL_USERS_LAST_CHANGE_DATE)
IFS=$SAVEIFS

echo "Today: $today"
echo $ALL_USERS_LAST_CHANGE_DATE
echo $ARR_DATES

for change_date in "${ALL_USERS_LAST_CHANGE_DATE[@]}"
do
    echo $change_date
done