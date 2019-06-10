# Today's date
$today = date --date

# Get all users' last password change date
awk -F: '{print $1}' /etc/passwd | xargs -I {} chage --list {} | grep "Last password change" | awk -F: '{print $2'} | xargs -I {} date --date "{}"

echo "Today: $today"