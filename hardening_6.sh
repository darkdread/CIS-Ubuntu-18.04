#!/bin/bash

echo "Hardening..."

# Hardening level.
HARDENING_LEVEL=1

# Debug mode.
DEBUG_MODE=0

# Disabling SAFE_SSH will cause issues.
SAFE_SSH=0


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

# Add shared folder
# LINE="shared /home/shared vboxsf defaults 0 0"

# grep -F "$LINE" /etc/fstab || echo $LINE | sudo tee --append /etc/fstab > /dev/null

# Remember to update aide.db by renaming aide.db.new to aide.db.

# 6 System Maintenance
# ===================================================================

# 6.1 System File Permissions
# ===================================================================

# 6.1.2 Ensure permissions on /etc/passwd are configured
# ===================================================================

chown root:root /etc/passwd
chmod 644 /etc/passwd

# 6.1.3 Ensure permissions on /etc/shadow are configured
# ===================================================================

chown root:shadow /etc/shadow
chmod o-rwx,g-wx /etc/shadow

# 6.1.4 Ensure permissions on /etc/group are configured
# ===================================================================

chown root:root /etc/group
chmod 644 /etc/group

# 6.1.5 Ensure permissions on /etc/gshadow are configured
# ==========================================================

chown root:shadow /etc/gshadow
chmod o-rwx,g-rw /etc/gshadow

# 6.1.6 Ensure permissions on /etc/passwd- are configured
# ==========================================================

chown root:root /etc/passwd-
chmod u-x,go-wx /etc/passwd-

# 6.1.7 Ensure permissions on /etc/shadow- are configured
# ==========================================================

chown root:shadow /etc/shadow-
chmod o-rwx,g-rw /etc/shadow-

# 6.1.8 Ensure permissions on /etc/group- are configured
# ==========================================================

chown root:root /etc/group-
chmod u-x,go-wx /etc/group-

# 6.1.9 Ensure permissions on /etc/gshadow- are configured
# ==========================================================

chown root:shadow /etc/gshadow-
chmod o-rwx,g-rw /etc/gshadow-

# 6.1.10 Ensure no world writable files exist
# =======================================================

# 6.1.11 Ensure no unwanted files or directories exist
# =======================================================

# 6.1.12 Ensure no ungrouped files or directories exist
# =======================================================

# Check CIS manual for 6.1.10 - 6.1.12.

# 6.2 User and Group Settings
# ===================================================================

# 6.2.1 Ensure password fields are not empty
# =============================================

# 6.2.2 Ensure no legacy "+" entries exist in /etc/passwd
# =============================================

# 6.2.3 Ensure no legacy "+" entries exist in /etc/shadow
# =============================================

# 6.2.4 Ensure no legacy "+" entries exist in /etc/group
# =============================================

# 6.2.5 Ensure root is the only UID 0 account
# =============================================

# 6.2.6 Ensure root PATH integrity
# =============================================

# For 6.2.1 to 6.2.6, requires manual input.

# 6.2.7 Ensure all users' home directories exist
# ================================================

# cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
# "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read
# user dir; do
#  if [ ! -d "$dir" ]; then
#  echo "The home directory ($dir) of user $user does not exist."
#  fi
# done

# # 6.2.8 Ensure users' home directories permissions are 750 or more restrictive
# # =============================================================================

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

# # 6.2.9 Ensure users own their home directories
# # ===============================================

# cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
# "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read
# user dir; do
#  if [ ! -d "$dir" ]; then
#  echo "The home directory ($dir) of user $user does not exist."
#  else
#  owner=$(stat -L -c "%U" "$dir")
#  if [ "$owner" != "$user" ]; then
#  echo "The home directory ($dir) of user $user is owned by $owner."
#  fi
# fi
# done

# # 6.2.10 Ensure users' dot files are not group or world writable
# # ================================================================

# cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
# "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user
# dir; do
#  if [ ! -d "$dir" ]; then
#  echo "The home directory ($dir) of user $user does not exist."
#  else
#  for file in $dir/.[A-Za-z0-9]*; do
#  if [ ! -h "$file" -a -f "$file" ]; then
#  fileperm=`ls -ld $file | cut -f1 -d" "`
#  if [ `echo $fileperm | cut -c6` != "-" ]; then
#  echo "Group Write permission set on file $file"
#  fi
#  if [ `echo $fileperm | cut -c9` != "-" ]; then
#  echo "Other Write permission set on file $file"
#  fi
#  fi
#  done
#  fi
# done

# # 6.2.11 Ensure no users have .forward files
# # ===============================================

# cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
# "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user
# dir; do
#  if [ ! -d "$dir" ]; then
#  echo "The home directory ($dir) of user $user does not exist."
#  else
#  if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
#  echo ".forward file $dir/.forward exists"
#  fi
#  fi
# done

# # 6.2.12 Ensure no users have .netrc files
# # ===========================================

# cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
# "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user
# dir; do
#  if [ ! -d "$dir" ]; then
#  echo "The home directory ($dir) of user $user does not exist."
#  else
#  if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
#  echo ".netrc file $dir/.netrc exists"
#  fi
#  fi
# done

# # 6.2.13 Ensure users' .netrc files are not group or world accessible
# # ====================================================================

# cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
# "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user
# dir; do
#  if [ ! -d "$dir" ]; then
#  echo "The home directory ($dir) of user $user does not exist."
#  else
#  for file in $dir/.netrc; do
#  if [ ! -h "$file" -a -f "$file" ]; then
#  fileperm=`ls -ld $file | cut -f1 -d" "`
#  if [ `echo $fileperm | cut -c5` != "-" ]; then
#  echo "Group Read set on $file"
#  fi
#  if [ `echo $fileperm | cut -c6` != "-" ]; then
#  echo "Group Write set on $file"
#  fi
#  if [ `echo $fileperm | cut -c7` != "-" ]; then
#  echo "Group Execute set on $file"
#  fi
#  if [ `echo $fileperm | cut -c8` != "-" ]; then
#  echo "Other Read set on $file"
#  fi
#  if [ `echo $fileperm | cut -c9` != "-" ]; then
#  echo "Other Write set on $file"
#  fi
#  if [ `echo $fileperm | cut -c10` != "-" ]; then
#  echo "Other Execute set on $file"
#  fi
#  fi
#  done
#  fi
# done

# # 6.2.14 Ensure no users have .rhosts files
# # ===========================================

# cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
# "/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user
# dir; do
#  if [ ! -d "$dir" ]; then
#  echo "The home directory ($dir) of user $user does not exist."
#  else
#  for file in $dir/.rhosts; do
#  if [ ! -h "$file" -a -f "$file" ]; then
#  echo ".rhosts file in $dir"
#  fi
#  done
#  fi
# done

# # 6.2.15 Ensure all groups in /etc/passwd exist in /etc/group
# # ============================================================

# for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
#  grep -q -P "^.*?:[^:]*:$i:" /etc/group
#  if [ $? -ne 0 ]; then
#  echo "Group $i is referenced by /etc/passwd but does not exist in
# /etc/group"
#  fi
# done

# # 6.2.16 Ensure no duplicate UIDs exist
# # ===========================================

# cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
#  [ -z "${x}" ] && break
#  set - $x
#  if [ $1 -gt 1 ]; then
#  users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
#  echo "Duplicate UID ($2): ${users}"
#  fi
# done

# # 6.2.17 Ensure no duplicate GIDs exist
# # ===========================================

# cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
#  [ -z "${x}" ] && break
#  set - $x
#  if [ $1 -gt 1 ]; then
#  groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
#  echo "Duplicate GID ($2): ${groups}"
#  fi
# done

# # 6.2.18 Ensure no duplicate user names exist
# # =============================================

# cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
#  [ -z "${x}" ] && break
#  set - $x
#  if [ $1 -gt 1 ]; then
#  uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
#  echo "Duplicate User Name ($2): ${uids}"
#  fi
# done

# # 6.2.14 Ensure no duplicate group names exist
# # ==============================================

# cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
#  [ -z "${x}" ] && break
#  set - $x
#  if [ $1 -gt 1 ]; then
#  gids=`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
#  echo "Duplicate Group Name ($2): ${gids}"
#  fi
# done

# # 6.2.20 Ensure shadow group is empty
# # ===========================================

# grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group
# awk -F: '($4 == "<shadow-gid>") { print }' /etc/passwd





# 2.2.1 Time Synchronization
# ===========================

# # Separate partition for /var directory

# # Create disk with 1GB
# DIR="/dev"
# DISK="xvdg"
# sudo dd if=/dev/zero of=$DIR/$DISK bs=1M count=1024

# # Create partition
# (
# echo o # Create a new empty DOS partition table
# echo n # Add a new partition
# echo p # Primary partition
# echo 1 # Partition number
# echo   # First sector (Accept default: 1)
# echo   # Last sector (Accept default: varies)
# echo w # Write
# ) | sudo fdisk $DIR/$DISK

# PARTITION="${DISK}"

# # Setup loopback for partition
# sudo losetup -P --show /dev/loop1 "$DIR/$DISK"
# # Convert partition to ext4 fs
# sudo mkfs -t ext4 /dev/loop1
# # Detach partition from loopback
# sudo losetup -d /dev/loop1

# LINE="$DIR/$PARTITION /var ext4 rw,relatime,data=ordered"
# # grep -F "$LINE" /etc/fstab || echo $LINE | sudo tee --append /etc/fstab > /dev/null


echo "Hardened!"

exit 1