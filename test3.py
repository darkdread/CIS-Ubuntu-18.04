# 6.2.7 Ensure all users' home directories exist
# ================================================

# cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
# "/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read
# user dir; do
#  if [ ! -d "$dir" ]; then
#  echo "The home directory ($dir) of user $user does not exist."
#  fi
# done

# 6.2.8 Ensure users' home directories permissions are 750 or more restrictive
# =============================================================================

cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
"/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read
user dir; do
 if [ ! -d "$dir" ]; then
 echo "The home directory ($dir) of user $user does not exist."
 else
 dirperm=`ls -ld $dir | cut -f1 -d" "`
 if [ `echo $dirperm | cut -c6` != "-" ]; then
 echo "Group Write permission set on the home directory ($dir) of user
$user"
 fi
 if [ `echo $dirperm | cut -c8` != "-" ]; then
 echo "Other Read permission set on the home directory ($dir) of user
$user"
 fi
 if [ `echo $dirperm | cut -c9` != "-" ]; then
 echo "Other Write permission set on the home directory ($dir) of user
$user"
 fi
 if [ `echo $dirperm | cut -c10` != "-" ]; then
 echo "Other Execute permission set on the home directory ($dir) of user
$user"
 fi
 fi
done

# 6.2.9 Ensure users own their home directories
# ===============================================

cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
"/usr/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read
user dir; do
 if [ ! -d "$dir" ]; then
 echo "The home directory ($dir) of user $user does not exist."
 else
 owner=$(stat -L -c "%U" "$dir")
 if [ "$owner" != "$user" ]; then
 echo "The home directory ($dir) of user $user is owned by $owner."
 fi
fi
done

# 6.2.10 Ensure users' dot files are not group or world writable
# ================================================================

cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
"/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user
dir; do
 if [ ! -d "$dir" ]; then
 echo "The home directory ($dir) of user $user does not exist."
 else
 for file in $dir/.[A-Za-z0-9]*; do
 if [ ! -h "$file" -a -f "$file" ]; then
 fileperm=`ls -ld $file | cut -f1 -d" "`
 if [ `echo $fileperm | cut -c6` != "-" ]; then
 echo "Group Write permission set on file $file"
 fi
 if [ `echo $fileperm | cut -c9` != "-" ]; then
 echo "Other Write permission set on file $file"
 fi
 fi
 done
 fi
done

# 6.2.11 Ensure no users have .forward files
# ===============================================

cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
"/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user
dir; do
 if [ ! -d "$dir" ]; then
 echo "The home directory ($dir) of user $user does not exist."
 else
 if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
 echo ".forward file $dir/.forward exists"
 fi
 fi
done

# 6.2.12 Ensure no users have .netrc files
# ===========================================

cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
"/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user
dir; do
 if [ ! -d "$dir" ]; then
 echo "The home directory ($dir) of user $user does not exist."
 else
 if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
 echo ".netrc file $dir/.netrc exists"
 fi
 fi
done

# 6.2.13 Ensure users' .netrc files are not group or world accessible
# ====================================================================

cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
"/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user
dir; do
 if [ ! -d "$dir" ]; then
 echo "The home directory ($dir) of user $user does not exist."
 else
 for file in $dir/.netrc; do
 if [ ! -h "$file" -a -f "$file" ]; then
 fileperm=`ls -ld $file | cut -f1 -d" "`
 if [ `echo $fileperm | cut -c5` != "-" ]; then
 echo "Group Read set on $file"
 fi
 if [ `echo $fileperm | cut -c6` != "-" ]; then
 echo "Group Write set on $file"
 fi
 if [ `echo $fileperm | cut -c7` != "-" ]; then
 echo "Group Execute set on $file"
 fi
 if [ `echo $fileperm | cut -c8` != "-" ]; then
 echo "Other Read set on $file"
 fi
 if [ `echo $fileperm | cut -c9` != "-" ]; then
 echo "Other Write set on $file"
 fi
 if [ `echo $fileperm | cut -c10` != "-" ]; then
 echo "Other Execute set on $file"
 fi
 fi
 done
 fi
done

# 6.2.14 Ensure no users have .rhosts files
# ===========================================

cat /etc/passwd | egrep -v '^(root|halt|sync|shutdown)' | awk -F: '($7 !=
"/sbin/nologin" && $7 != "/bin/false") { print $1 " " $6 }' | while read user
dir; do
 if [ ! -d "$dir" ]; then
 echo "The home directory ($dir) of user $user does not exist."
 else
 for file in $dir/.rhosts; do
 if [ ! -h "$file" -a -f "$file" ]; then
 echo ".rhosts file in $dir"
 fi
 done
 fi
done

# 6.2.15 Ensure all groups in /etc/passwd exist in /etc/group
# ============================================================

for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
 grep -q -P "^.*?:[^:]*:$i:" /etc/group
 if [ $? -ne 0 ]; then
 echo "Group $i is referenced by /etc/passwd but does not exist in
/etc/group"
 fi
done

# 6.2.16 Ensure no duplicate UIDs exist
# ===========================================

cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
 [ -z "${x}" ] && break
 set - $x
 if [ $1 -gt 1 ]; then
 users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
 echo "Duplicate UID ($2): ${users}"
 fi
done

# 6.2.17 Ensure no duplicate GIDs exist
# ===========================================

cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
 [ -z "${x}" ] && break
 set - $x
 if [ $1 -gt 1 ]; then
 groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
 echo "Duplicate GID ($2): ${groups}"
 fi
done

# 6.2.18 Ensure no duplicate user names exist
# =============================================

cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
 [ -z "${x}" ] && break
 set - $x
 if [ $1 -gt 1 ]; then
 uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
 echo "Duplicate User Name ($2): ${uids}"
 fi
done

# 6.2.14 Ensure no duplicate group names exist
# ==============================================

cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
 [ -z "${x}" ] && break
 set - $x
 if [ $1 -gt 1 ]; then
 gids=`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
 echo "Duplicate Group Name ($2): ${gids}"
 fi
done

# 6.2.20 Ensure shadow group is empty
# ===========================================

grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group
awk -F: '($4 == "<shadow-gid>") { print }' /etc/passwd





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