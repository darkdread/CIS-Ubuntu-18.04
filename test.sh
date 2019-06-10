# List of all users
awk -F: '{print $1}' /etc/passwd |
# Get passwd info of each user
xargs -I {} chage --list {} |
# Get last password change of user
grep "Last password change" |
awk -F: '{pring $2'} |
xargs -I {} echo {}