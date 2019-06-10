# Today's date
$today = date --date ""

# Get all users' last password change date
$ALL_USERS_LAST_CHANGE_DATE=$(awk -F: '{print $1}' /etc/passwd | xargs -I {} chage --list {} | grep "Last password change" | awk -F: '{print $2'} | xargs -I {} date --date "{}")

echo "Today: $today"