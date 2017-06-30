#!/bin/sh
# This script was written by Frank Caviggia
# Last update was 13 May 2017
#
# Script: suplemental.sh (system-hardening)
# Description: Supplemental Hardening
# License: GPLv2
# Copyright: Frank Caviggia, 2016
# Author: Frank Caviggia <fcaviggi (at) gmail.com>\
# Patch 16:
# Remove duplicate SSG audit rules from supplemental.sh
#
# While the performance impact of duplicate rules is probably minimal,
# a duplicate rule can cause rule loading to abort and leave important
# events unaudited.
#
# In particular we were seeing that the duplicate MAC-policy watch on
# /etc/selinux was halting rule processing after loading only about 80%
# of the configured rules.
#
# We also noticed that while remediating a system the SSG would leave
# some rules in a file simply named ".rules" that would be excluded when
# augenrules compiled the final rules file.
#
# Additionally the SSG is sometimes generating invalid rules with misspelled
# exit conditions: EACCESS instead of EACCES and EPRM instead of EPERM.
# This bug should be fixed in scap-security-guide 0.1.34.


#. !please_edit_me
########################################
# LEGAL BANNER CONFIGURATION
########################################
BANNER_MESSAGE_TEXT='You are accessing an Information System (IS) that is \nprovided for authorized use only. By using this IS (which includes any \ndevice attached to this IS), you consent to the following conditions:\n\n-The Owner might routinely intercept and monitor communications on this IS for \npurposes including, but not limited to, penetration testing, COMSEC monitoring, \nnetwork operations and defense, personnel misconduct (PM), law enforcement \n(LE), and counterintelligence (CI) investigations.\n\n-At any time, the Owner may inspect and seize data stored on this IS.\n\n-Communications using, or data stored on, this IS are not private, are subject \nto routine monitoring, interception, and search, and may be disclosed or used \nfor any Owner-authorized purpose.\n\n-This IS includes security measures (e.g., authentication and access controls) \nto protect Owner`s interests -- not for your personal benefit or privacy.\n\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE \nor CI investigative searching or monitoring of the content of privileged \ncommunications, or work product, related to personal representation or services \nby attorneys, psychotherapists, or clergy, and their assistants. Such \ncommunications and work product are private and confidential. See User \nAgreement(available upon request) for details.\n\n'
echo -e "${BANNER_MESSAGE_TEXT}" > /etc/issue
echo -e "${BANNER_MESSAGE_TEXT}" > /etc/issue.net

########################################
# DISA STIG PAM Configurations
########################################
cat <<EOF > /etc/pam.d/system-auth-local
#%PAM-1.0
auth required pam_env.so
auth required pam_lastlog.so inactive=35
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root root_unlock_time=900 unlock_time=never fail_interval=900
auth sufficient pam_unix.so try_first_pass
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root root_unlock_time=900 unlock_time=never fail_interval=900
auth sufficient pam_faillock.so authsucc audit deny=3 even_deny_root root_unlock_time=900 unlock_time=never fail_interval=900
auth requisite pam_succeed_if.so uid >= 1000 quiet
auth required pam_deny.so

account required pam_faillock.so
account required pam_unix.so
account required pam_lastlog.so inactive=35
account sufficient pam_localuser.so
account sufficient pam_succeed_if.so uid < 1000 quiet
account required pam_permit.so

# Password Quality now set in /etc/security/pwquality.conf
password required pam_pwquality.so retry=3
password sufficient pam_unix.so sha512 shadow try_first_pass use_authtok remember=24
password required pam_deny.so

session required pam_lastlog.so showfailed
session optional pam_keyinit.so revoke
session required pam_limits.so
-session optional pam_systemd.so
session [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session required pam_unix.so
EOF
ln -sf /etc/pam.d/system-auth-local /etc/pam.d/system-auth
cp -f /etc/pam.d/system-auth-local /etc/pam.d/system-auth-ac
### alternatively  use CIS reqs
## CIS 6.3.3
#system_auth='/etc/pam.d/system-auth'
#content="$(egrep -v "^#|^auth" ${system_auth})"
#echo -e "auth required pam_env.so
#auth sufficient pam_unix.so remember=5
#auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900
#auth [success=1 default=bad] pam_unix.so
#auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
#auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
#auth required pam_deny.so\n$content" > ${system_auth}


cat <<EOF > /etc/pam.d/password-auth-local
#%PAM-1.0
auth required pam_env.so
auth required pam_lastlog.so inactive=35
auth required pam_faillock.so preauth silent audit deny=3 even_deny_root root_unlock_time=900 unlock_time=never fail_interval=900
auth sufficient pam_unix.so try_first_pass
auth [default=die] pam_faillock.so authfail audit deny=3 even_deny_root root_unlock_time=900 unlock_time=never fail_interval=900
auth sufficient pam_faillock.so authsucc audit deny=3 even_deny_root root_unlock_time=900 unlock_time=never fail_interval=900
auth requisite pam_succeed_if.so uid >= 1000 quiet
auth required pam_deny.so

account required pam_faillock.so
account required pam_unix.so
account required pam_lastlog.so inactive=35
account sufficient pam_localuser.so
account sufficient pam_succeed_if.so uid < 1000 quiet
account required pam_permit.so

# Password Quality now set in /etc/security/pwquality.conf
password required pam_pwquality.so retry=3
password sufficient pam_unix.so sha512 shadow try_first_pass use_authtok remember=24
password required pam_deny.so

session required pam_lastlog.so showfailed
session optional pam_keyinit.so revoke
session required pam_limits.so
-session optional pam_systemd.so
session [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid
session required pam_unix.so
EOF
ln -sf /etc/pam.d/password-auth-local /etc/pam.d/password-auth
cp -f /etc/pam.d/password-auth-local /etc/pam.d/password-auth-ac

### alternatively  use CIS reqs
## CIS 6.3.3
#content="$(egrep -v "^#|^auth" /etc/pam.d/password-auth)"
#echo -e "auth required pam_env.so
#auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900
#auth [success=1 default=bad] pam_unix.so
#auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900
#auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900
#auth required pam_deny.so\n$content" > /etc/pam.d/password-auth


# CIS 6.3.2
cat <<EOF > /etc/security/pwquality.conf
# Configuration for systemwide password quality limits
# Defaults:
#
# Number of characters in the new password that must not be present in the
# old password.
# difok = 5
difok = 15
#
# Minimum acceptable size for the new password (plus one if
# credits are not disabled which is the default). (See pam_cracklib manual.)
# Cannot be set to lower value than 6.
# minlen = 9
minlen = 15
#
# The maximum credit for having digits in the new password. If less than 0
# it is the minimum number of digits in the new password.
# dcredit = 1
dcredit = -1
#
# The maximum credit for having uppercase characters in the new password.
# If less than 0 it is the minimum number of uppercase characters in the new
# password.
# ucredit = 1
ucredit = -1
#
# The maximum credit for having lowercase characters in the new password.
# If less than 0 it is the minimum number of lowercase characters in the new
# password.
# lcredit = 1
lcredit = -1
#
# The maximum credit for having other characters in the new password.
# If less than 0 it is the minimum number of other characters in the new
# password.
# ocredit = 1
ocredit = -1
#
# The minimum number of required classes of characters for the new
# password (digits, uppercase, lowercase, others).
minclass = 4
#
# The maximum number of allowed consecutive same characters in the new password.
# The check is disabled if the value is 0.
maxrepeat = 2
#
# The maximum number of allowed consecutive characters of the same class in the
# new password.
# The check is disabled if the value is 0.
maxclassrepeat = 2
#
# Whether to check for the words from the passwd entry GECOS string of the user.
# The check is enabled if the value is not 0.
# gecoscheck = 0
#
# Path to the cracklib dictionaries. Default is to use the cracklib default.
# dictpath =
EOF

### altenatively edit existing file
## CIS 6.3.2
#pwqual='/etc/security/pwquality.conf'
#sed -i 's/^# minlen =.*$/minlen = 14/' ${pwqual}
#sed -i 's/^# dcredit =.*$/dcredit = -1/' ${pwqual}
#sed -i 's/^# ucredit =.*$/ucredit = -1/' ${pwqual}
#sed -i 's/^# ocredit =.*$/ocredit = -1/' ${pwqual}
#sed -i 's/^# lcredit =.*$/lcredit = -1/' ${pwqual}


login_defs=/etc/login.defs
echo -e "FAIL_DELAY\t4" >> ${login_defs}

#sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' ${login_defs}		# CIS 7.1.1
#sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 7/' ${login_defs}		# CIS 7.1.2
#sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' ${login_defs}		# CIS 7.1.3

root_gid="$(id -g root)"
if [[ "${root_gid}" -ne 0 ]] ; then
  usermod -g 0 root							# CIS 7.3
fi


# CIS 7.4
bashrc='/etc/bashrc'
#first umask cmd sets it for users, second umask cmd sets it for system reserved uids
#we want to alter the first one
line_num=$(grep -n "^[[:space:]]*umask" ${bashrc} | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/077/ ${bashrc}
cat << EOF >> /etc/profile.d/cis.sh
#!/bin/bash

umask 077
EOF

[[ -w /etc/issue ]] && rm /etc/issue
[[ -w /etc/issue.net ]] && rm /etc/issue.net
touch /etc/issue /etc/issue.net
chown root:root /etc/issue /etc/issue.net
chmod 644 /etc/issue /etc/issue.net

grub_cfg='/boot/grub2/grub.cfg'
chown root:root ${grub_cfg}					# CIS 1.5.1
chmod 600 ${grub_cfg}						# CIS 1.5.2
chmod 644 /etc/passwd						# CIS 9.1.2
chmod 000 /etc/shadow						# CIS 9.1.3
chmod 000 /etc/gshadow						# CIS 9.1.4
chmod 644 /etc/group						# CIS 9.1.5
chown root:root /etc/passwd					# CIS 9.1.6
chown root:root /etc/shadow					# CIS 9.1.7
chown root:root /etc/gshadow				# CIS 9.1.8
chown root:root /etc/group					# CIS 9.1.9





# CIS 6.5
pam_su='/etc/pam.d/su'
line_num="$(grep -n "^\#auth[[:space:]]*required[[:space:]]*pam_wheel.so[[:space:]]*use_uid" ${pam_su} | cut -d: -f1)"
sed -i "${line_num} a auth		required	pam_wheel.so use_uid" ${pam_su}
usermod -G wheel root

# CIS 9.2.6 If /root/bin doesn't exist we fail this check I'm electing to change /root/.bash_profile
# Just adding a /root/bin dir may be better
sed -i 's/^PATH.*$/PATH=\$PATH/' /root/.bash_profile

cat <<EOF > /etc/ntp.conf
# by default act only as a basic NTP client
restrict -4 default nomodify nopeer noquery notrap
restrict -6 default nomodify nopeer noquery notrap
# allow NTP messages from the loopback address, useful for debugging
restrict 127.0.0.1
restrict ::1
# poll server at higher rate to prevent drift
maxpoll 17
# server(s) we time sync to
##server 192.168.0.1
##server 2001:DB9::1
#server time.example.net
EOF

## altenatively edit existing default config:
#ntp_conf='/etc/ntp.conf'
#sed -i "s/^restrict default/restrict default kod/" ${ntp_conf}
#line_num="$(grep -n "^restrict default" ${ntp_conf} | cut -f1 -d:)"
#sed -i "${line_num} a restrict -6 default kod nomodify notrap nopeer noquery" ${ntp_conf}
#sed -i s/'^OPTIONS="-g"'/'OPTIONS="-g -u ntp:ntp -p \/var\/run\/ntpd.pid"'/ /etc/sysconfig/ntpd

auditd_conf='/etc/audit/auditd.conf'
# CIS 5.2.1.1 Configure Audit Log Storage Size
sed -i 's/^max_log_file .*$/max_log_file = 1024/' ${auditd_conf}
# CIS 5.2.1.2 Disable system on Audit Log Full - This is VERY environment specific (and likely controversial)
sed -i 's/^space_left_action.*$/space_left_action = email/' ${auditd_conf}
sed -i 's/^action_mail_acct.*$/action_mail_acct = root/' ${auditd_conf}
sed -i 's/^admin_space_left_action.*$/admin_space_left_action = halt/' ${auditd_conf}
# CIS 5.2.1.3 Keep All Auditing Information
sed -i 's/^max_log_file_action.*$/max_log_file_action = keep_logs/' ${auditd_conf}

# CIS 6.1.2-6.1.9
chown root:root /etc/anacrontab	/etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
chmod 600 /etc/anacrontab /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d

# CIS 6.1.10 + 6.1.11
[[ -w /etc/at.deny ]] && rm /etc/at.deny
[[ -w /etc/cron.deny ]] && rm /etc/cron.deny
touch /etc/at.allow /etc/cron.allow
chown root:root /etc/at.allow /etc/cron.allow
chmod 600 /etc/at.allow /etc/cron.allow

########################################
# STIG Audit Configuration
########################################
cat <<EOF > /etc/audit/rules.d/zzz-supplemental.rules
# augenrules is a script that merges all component audit rules files;
# The last processed -D directive without an option, if present, is
# always emitted as the first line in the resultant file. Those with an
# option are replicated in place.  The last processed -b directive, if
# present, is always emitted as the second line in the resultant file.
# The last processed -f directive, if present, is always emitted as the
# third line in the resultant file.  The last processed -e directive,
# if present, is always emitted as the last line in the resultant file.

# Remove any existing rules
-D

# Increase kernel buffer size
-b 16384

# Failure of auditd causes a kernel panic
-f 2

# Make the auditd Configuration Immutable
-e 2

###########################
## DISA STIG Audit Rules ##
###########################

# Watch syslog configuration
-w /etc/rsyslog.conf
-w /etc/rsyslog.d/

# Watch PAM and authentication configuration
-w /etc/pam.d/
-w /etc/nsswitch.conf

# Watch system log files
-w /var/log/messages
-w /var/log/audit/audit.log
-w /var/log/audit/audit[1-4].log

# Watch audit configuration files
-w /etc/audit/auditd.conf -p wa
-w /etc/audit/audit.rules -p wa

# Watch login configuration
-w /etc/login.defs
-w /etc/securetty
-w /etc/resolv.conf

# Watch cron and at
-w /etc/at.allow
-w /etc/at.deny
-w /var/spool/at/
-w /etc/crontab
-w /etc/anacrontab
-w /etc/cron.allow
-w /etc/cron.deny
-w /etc/cron.d/
-w /etc/cron.hourly/
-w /etc/cron.weekly/
-w /etc/cron.monthly/

# Watch shell configuration
-w /etc/profile.d/
-w /etc/profile
-w /etc/shells
-w /etc/bashrc
-w /etc/csh.cshrc
-w /etc/csh.login

# Watch kernel configuration
-w /etc/sysctl.conf
-w /etc/modprobe.conf

# Watch linked libraries
-w /etc/ld.so.conf -p wa
-w /etc/ld.so.conf.d/ -p wa

# Watch init configuration
-w /etc/rc.d/init.d/
-w /etc/sysconfig/
-w /etc/inittab -p wa
-w /etc/rc.local
-w /usr/lib/systemd/
-w /etc/systemd/

# Watch filesystem and NFS exports
-w /etc/fstab
-w /etc/exports

# Watch xinetd configuration
-w /etc/xinetd.conf
-w /etc/xinetd.d/

# Watch Grub2 configuration
-w /etc/grub2.cfg
-w /etc/grub.d/

# Watch TCP_WRAPPERS configuration
-w /etc/hosts.allow
-w /etc/hosts.deny

# Watch sshd configuration
-w /etc/ssh/sshd_config

# Audit time
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Audit identity
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Audit hostname and locale
a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale



# Audit system events
-a always,exit -F arch=b32 -S acct -S reboot -S sched_setparam -S sched_setscheduler -S setrlimit -S swapon
-a always,exit -F arch=b64 -S acct -S reboot -S sched_setparam -S sched_setscheduler -S setrlimit -S swapon

# Audit any link creation
-a always,exit -F arch=b32 -S link -S symlink
-a always,exit -F arch=b64 -S link -S symlink

##############################
## NIST 800-53 Requirements ##
##############################

#2.6.2.4.5 Ensure auditd Collects Logon and Logout Events
-w /var/log/faillog -p wa -k logins

EOF

sed -i "1 i /var/log/boot.log" /etc/logrotate.d/syslog 			# CIS 5.3


# Find and monitor additional privileged commands
for PROG in `find / -xdev -type f -perm -4000 -o -type f -perm -2000 2>/dev/null`; do
	fgrep -r "path=$PROG" /etc/audit/rules.d/
	if [ $? -ne 0 ]; then
		echo "-a always,exit -F path=$PROG -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged"  >> /etc/audit/rules.d/zzz-supplemental.rules
	fi
done

# Sometimes the SSG leaves some rules in a file simply named ".rules".
# This is also caused by the below mentioned "key" syntax mismatch.
if [ -f /etc/audit/rules.d/.rules ]; then
	# Some of the rules in the .rules file are invalid, this should
	# be fixed in 0.1.34.
	sed -i -e 's/EACCESS/EACCES/' /etc/audit/rules.d/.rules
	sed -i -e 's/EPRM/EPERM/'     /etc/audit/rules.d/.rules

	# Inconsistent syntax can lead to duplicate rules.  I'm told that:
	# 'The "-F key=$key" is correct and should be the audit key syntax
	# going forward. ... rather than moving backward to the -k syntax.'
	# But, most of the existing rules use the "old" syntax as well as
	# all of the STIG XCCDF content, so I'm normalizing that direction.
	sed -i -e 's/-F key=/-k /'    /etc/audit/rules.d/.rules
	sed -i -e 's/-F key=/-k /'    /etc/audit/rules.d/*.rules

	# Some of the rules in the .rules file are duplicates (due to
	# the above mentioned syntax mismatch).
	sort /etc/audit/rules.d/.rules -o /etc/audit/rules.d/.rules
	sort /etc/audit/rules.d/*.rules | comm -13 - /etc/audit/rules.d/.rules > /etc/audit/rules.d/ssg-orphaned.rules
	rm /etc/audit/rules.d/.rules
fi

########################################
# Fix cron.allow
########################################
echo "root" > /etc/cron.allow
chmod 400 /etc/cron.allow
chown root:root /etc/cron.allow

########################################
# Make SELinux Configuration Immutable
########################################
chattr +i /etc/selinux/config


########################################
# Disable Control-Alt-Delete
########################################
ln -sf /dev/null /etc/systemd/system/ctrl-alt-del.target


########################################
# No Root Login to Console (use admin user)
########################################
cat /dev/null > /etc/securetty

## alternatively use CIS reqs
## CIS 6.4
#cp /etc/securetty /etc/securetty.orig
##> /etc/securetty
#cat << EOF >> /etc/securetty
#console
#tty1
#EOF

########################################
# Disable Interactive Shell (Timeout)
########################################
cat <<EOF > /etc/profile.d/autologout.sh
#!/bin/sh
TMOUT=900
export TMOUT
readonly TMOUT
EOF
cat <<EOF > /etc/profile.d/autologout.csh
#!/bin/csh
set autologout=15
set -r autologout
EOF
chown root:root /etc/profile.d/autologout.sh
chown root:root /etc/profile.d/autologout.csh
chmod 555 /etc/profile.d/autologout.sh
chmod 555 /etc/profile.d/autologout.csh

########################################
# Set Shell UMASK Setting (027)
########################################
cat <<EOF > /etc/profile.d/umask.sh
#!/bin/sh

# Non-Privledged Users get 027
# Privledged Users get 022
if [[ \$EUID -ne 0 ]]; then
	umask 027
else
	umask 022
fi
EOF
cat <<EOF > /etc/profile.d/umask.csh
#!/bin/csh
umask 027
EOF
chown root:root /etc/profile.d/umask.sh
chown root:root /etc/profile.d/umask.csh
chmod 555 /etc/profile.d/umask.sh
chmod 555 /etc/profile.d/umask.csh


########################################
# Vlock Alias (Cosole Screen Lock)
########################################
cat <<EOF > /etc/profile.d/vlock-alias.sh
#!/bin/sh
alias vlock='clear;vlock -a'
EOF
cat <<EOF > /etc/profile.d/vlock-alias.csh
#!/bin/csh
alias vlock 'clear;vlock -a'
EOF
chown root:root /etc/profile.d/vlock-alias.sh
chown root:root /etc/profile.d/vlock-alias.csh
chmod 755 /etc/profile.d/vlock-alias.sh
chmod 755 /etc/profile.d/vlock-alias.csh


########################################
# Wheel Group Require (sudo)
########################################
sed -i -re '/pam_wheel.so use_uid/s/^#//' /etc/pam.d/su
sed -i 's/^#\s*\(%wheel\s*ALL=(ALL)\s*ALL\)/\1/' /etc/sudoers
echo -e "\n## Set timeout for authentiation (5 Minutes)\nDefaults:ALL timestamp_timeout=5\n" >> /etc/sudoers


########################################
# Set Removeable Media to noexec
#   CCE-27196-5
########################################
for DEVICE in $(/bin/lsblk | grep sr | awk '{ print $1 }'); do
	mkdir -p /mnt/$DEVICE
	echo -e "/dev/$DEVICE\t\t/mnt/$DEVICE\t\tiso9660\tdefaults,ro,noexec,nosuid,nodev,noauto\t0 0" >> /etc/fstab
done
for DEVICE in $(cd /dev;ls *cd* *dvd*); do
	mkdir -p /mnt/$DEVICE
	echo -e "/dev/$DEVICE\t\t/mnt/$DEVICE\t\tiso9660\tdefaults,ro,noexec,nosuid,nodev,noauto\t0 0" >> /etc/fstab
done


########################################
# SSHD Hardening
########################################
sshd_config='/etc/ssh/sshd_config'
chown root:root ${sshd_config}							# CIS 6.2.3
chmod 600 ${sshd_config}								# CIS 6.2.3
sed -i '/Ciphers.*/d' /etc/ssh/ssh*config
sed -i '/MACs.*/d' /etc/ssh/ssh*config
sed -i "s/\#LogLevel/LogLevel/" ${sshd_config}			# CIS 6.2.2
sed -i '/Protocol.*/d' /etc/ssh/sshd_config   			# CIS 6.2.1
echo "Protocol 2" >> /etc/ssh/sshd_config
echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/ssh_config
echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config
echo "MACs hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/ssh_config
echo "MACs hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
echo "PrintLastLog yes" >> /etc/ssh/sshd_config
echo "AllowGroups sshusers" >> /etc/ssh/sshd_config
echo "MaxAuthTries 3" >> /etc/ssh/sshd_config  			# CIS 6.2.5
echo "Banner /etc/issue" >> /etc/ssh/sshd_config
echo "RhostsRSAAuthentication no" >> /etc/ssh/sshd_config
echo "GSSAPIAuthentication no" >> /etc/ssh/sshd_config
echo "KerberosAuthentication no" >> /etc/ssh/sshd_config
echo "IgnoreUserKnownHosts yes" >> /etc/ssh/sshd_config
echo "StrictModes yes" >> /etc/ssh/sshd_config
echo "UsePrivilegeSeparation yes" >> /etc/ssh/sshd_config
echo "Compression delayed" >> /etc/ssh/sshd_config
##  CIS requirements
echo "X11Forwarding no" >>  ${sshd_config}  			# CIS 6.2.4
echo "IgnoreRhosts yes" >>  ${sshd_config} 				# CIS 6.2.6
echo "HostbasedAuthentication no" >> ${sshd_config}		# CIS 6.2.7
echo "PermitRootLogin no" >> ${sshd_config}				# CIS 6.2.8
echo "PermitEmptyPasswords no" >> ${sshd_config}		# CIS 6.2.9
echo "PermitUserEnvironment no" >> ${sshd_config}		# CIS 6.2.10
#line_num=$(grep -n "^\# Ciphers and keying" ${sshd_config} | cut -d: -f1)
##sed -i "${line_num} a Ciphers aes128-ctr,aes192-ctr,aes256-ctr" ${sshd_config}	# CIS 6.2.11
#sed -i "${line_num} a Ciphers aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128" ${sshd_config}
#sed -i "${line_num} a MACs hmac-sha1,umac-64@openssh.com,hmac-ripemd160" ${sshd_config}
echo "ClientAliveInterval 900" >> ${sshd_config}		# CIS 6.2.12
echo "ClientAliveCountMax 0" >> ${sshd_config}			# CIS 6.2.12
echo "Banner /etc/issue.net"  >> ${sshd_config}   	 	# CIS 6.2.12
if [ $(grep -c sshusers /etc/group) -eq 0 ]; then
	/usr/sbin/groupadd sshusers &> /dev/null
fi


########################################
# TCP_WRAPPERS
########################################
cat <<EOF >> /etc/hosts.allow
# LOCALHOST (ALL TRAFFIC ALLOWED) DO NOT REMOVE FOLLOWING LINE
ALL: 127.0.0.1 [::1]
# Allow SSH (you can limit this further using IP addresses - e.g. 192.168.0.*)
sshd: ALL
EOF
cat <<EOF >> /etc/hosts.deny 	# CIS 4.5.4
# Deny All by Default
ALL: ALL
EOF
chown root:root /etc/hosts.deny			# CIS 4.5.5
chmod 644 /etc/hosts.deny				# CIS 4.5.5

chown root:root /etc/rsyslog.conf		# CIS 5.1.4
chmod 600 /etc/rsyslog.conf				# CIS 5.1.4
# CIS 5.1.3  Configure /etc/rsyslog.conf - This is environment specific
# CIS 5.1.5  Configure rsyslog to Send Log to a Remote Log Host - This is environment specific

########################################
# Filesystem Attributes
#  CCE-26499-4,CCE-26720-3,CCE-26762-5,
#  CCE-26778-1,CCE-26622-1,CCE-26486-1.
#  CCE-27196-5
# also CIS 1.1.6 + 1.1.14-1.1.16
########################################
FSTAB=/etc/fstab
SED=`which sed`

if [ $(grep " \/sys " ${FSTAB} | grep -c "nosuid") -eq 0 ]; then
	MNT_OPTS=$(grep " \/sys " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/sys.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/boot " ${FSTAB} | grep -c "nosuid") -eq 0 ]; then
	MNT_OPTS=$(grep " \/boot " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/boot.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/usr " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/usr " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/usr .*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/home " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/home " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/home .*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/export\/home " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/export\/home " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/export\/home .*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/usr\/local " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/usr\/local " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/usr\/local.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/dev\/shm " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/dev\/shm " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/dev\/shm.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/tmp " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/tmp " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/tmp.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/var\/tmp " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/var\/tmp " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/var\/tmp.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/var\/log " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/var\/tmp " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/var\/tmp.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/var\/log\/audit " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/var\/log\/audit " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/var\/log\/audit.*${MNT_OPTS}\)/\1,nodev,noexec,nosuid/" ${FSTAB}
fi
if [ $(grep " \/var " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/var " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/var.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/var\/www " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/var\/wwww " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/var\/www.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
if [ $(grep " \/opt " ${FSTAB} | grep -c "nodev") -eq 0 ]; then
	MNT_OPTS=$(grep " \/opt " ${FSTAB} | awk '{print $4}')
	${SED} -i "s/\( \/opt.*${MNT_OPTS}\)/\1,nodev,nosuid/" ${FSTAB}
fi
echo -e "tmpfs\t\t\t/dev/shm\t\ttmpfs\tnoexec,nosuid,nodev\t\t0 0" >> /etc/fstab

########################################
# File Ownership
########################################
find / -nouser -print | xargs chown root
find / -nogroup -print | xargs chown :root
cat <<EOF > /etc/cron.daily/unowned_files
#!/bin/sh
# Fix user and group ownership of files without user
find / -nouser -print | xargs chown root
find / -nogroup -print | xargs chown :root
EOF
chown root:root /etc/cron.daily/unowned_files
chmod 0700 /etc/cron.daily/unowned_files


########################################
# USGCB Blacklist
########################################
if [ -e /etc/modprobe.d/usgcb-blacklist.conf ]; then
	rm -f /etc/modprobe.d/usgcb-blacklist.conf
fi
touch /etc/modprobe.d/usgcb-blacklist.conf
chmod 0644 /etc/modprobe.d/usgcb-blacklist.conf
chcon 'system_u:object_r:modules_conf_t:s0' /etc/modprobe.d/usgcb-blacklist.conf

# Disable mounting of unneeded filesystems CIS 1.1.18 - 1.1.24
cat <<EOF > /etc/modprobe.d/usgcb-blacklist.conf
# Disable Bluetooth
install bluetooth /bin/true
# Disable AppleTalk
install appletalk /bin/true
# NSA Recommendation: Disable mounting USB Mass Storage
install usb-storage /bin/true
# Disable mounting of cramfs CCE-14089-7
install cramfs /bin/true
# Disable mounting of freevxfs CCE-14457-6
install freevxfs /bin/true
# Disable mounting of hfs CCE-15087-0
install hfs /bin/true
# Disable mounting of hfsplus CCE-14093-9
install hfsplus /bin/true
# Disable mounting of jffs2 CCE-14853-6
install jffs2 /bin/true
# Disable mounting of squashfs CCE-14118-4
install squashfs /bin/true
# Disable mounting of udf CCE-14871-8
install udf /bin/true
# CCE-14268-7
install dccp /bin/true
# CCE-14235-5
install sctp /bin/true
#i CCE-14027-7
install rds /bin/true
# CCE-14911-2
install tipc /bin/true
# CCE-14948-4 (row 176)
install net-pf-31 /bin/true
EOF


########################################
# GNOME 3 Lockdowns
########################################
if [ -x /bin/gsettings ]; then
	cat << EOF > /etc/dconf/db/gdm.d/99-gnome-hardening
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text="${BANNER_MESSAGE_TEXT}"
disable-user-list=true
disable-restart-buttons=true

[org/gnome/desktop/lockdown]
user-administration-disabled=true
disable-user-switching=true

[org/gnome/desktop/media-handling]
automount=false
automount-open=false
autorun-never=true

[org/gnome/desktop/notifications]
show-in-lock-screen=false

[org/gnome/desktop/privacy]
remove-old-temp-files=true
remove-old-trash-files=true
old-files-age=7

[org/gnome/desktop/interface]
clock-format="12h"

[org/gnome/desktop/screensaver]
user-switch-enabled=false

[org/gnome/desktop/session]
idle-delay=900

[org/gnome/desktop/thumbnailers]
disable-all=true

[org/gnome/nm-applet]
disable-wifi-create=true
EOF
	cat << EOF > /etc/dconf/db/gdm.d/locks/99-gnome-hardening
/org/gnome/login-screen/banner-message-enable
/org/gnome/login-screen/banner-message-text
/org/gnome/login-screen/disable-user-list
/org/gnome/login-screen/disable-restart-buttons
/org/gnome/desktop/lockdown/user-administration-disabled
/org/gnome/desktop/lockdown/disable-user-switching
/org/gnome/desktop/media-handling/automount
/org/gnome/desktop/media-handling/automount-open
/org/gnome/desktop/media-handling/autorun-never
/org/gnome/desktop/notifications/show-in-lock-screen
/org/gnome/desktop/privacy/remove-old-temp-files
/org/gnome/desktop/privacy/remove-old-trash-files
/org/gnome/desktop/privacy/old-files-age
/org/gnome/desktop/screensaver/user-switch-enabled
/org/gnome/desktop/session/idle-delay
/org/gnome/desktop/thumbnailers/disable-all
/org/gnome/nm-applet/disable-wifi-create
EOF
	cat << EOF > /usr/share/glib-2.0/schemas/99-custom-settings.gschema.override
[org.gnome.login-screen]
banner-message-enable=true
banner-message-text="${BANNER_MESSAGE_TEXT}"
disable-user-list=true
disable-restart-buttons=true

[org.gnome.desktop.lockdown]
user-administration-disabled=true
disable-user-switching=true

[org.gnome.desktop.media-handling]
automount=false
automount-open=false
autorun-never=true

[org.gnome.desktop.notifications]
show-in-lock-screen=false

[org.gnome.desktop.privacy]
remove-old-temp-files=true
remove-old-trash-files=true
old-files-age=7

[org.gnome.desktop.interface]
clock-format="12h"

[org.gnome.desktop.screensaver]
user-switch-enabled=false

[org.gnome.desktop.session]
idle-delay=900

[org.gnome.desktop.thumbnailers]
disable-all=true

[org.gnome.nm-applet]
disable-wifi-create=true
EOF
	cat << EOF > /etc/gdm/custom.conf
# GDM configuration storage

[daemon]
AutomaticLoginEnable=false
TimedLoginEnable=false

[security]

[xdmcp]

[greeter]

[chooser]

[debug]

EOF
	cp /etc/dconf/db/gdm.d/locks/99-gnome-hardening /etc/dconf/db/local.d/locks/99-gnome-hardening
 	/bin/glib-compile-schemas /usr/share/glib-2.0/schemas/
	/bin/dconf update
fi

#######################################
# Kernel - Randomize Memory Space
# CCE-27127-0, SC-30(2), 1.6.1
# CIS 1.6.2
########################################
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf

########################################
# Kernel - Accept Source Routed Packets
# AC-4, 366, SRG-OS-000480-GPOS-00227
# CIS 4.2.1
########################################
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf

#######################################
# Kernel - Disable Redirects
# CIS 4.2.2
#######################################
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf

#######################################
# Kernel - Disable ICMP Broadcasts
# CIS 4.2.5
#######################################
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf

#######################################
# Kernel - Disable Syncookies
# CIS 4.2.8
########################################
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf

#######################################
# Kernel - Disable TCP Timestamps
#######################################
echo "net.ipv4.tcp_timestamps = 0" >> /etc/sysctl.conf

cat << EOF >> /etc/sysctl.conf
fs.suid_dumpable = 0					# CIS 1.6.1
#kernel.randomize_va_space = 2				# CIS 1.6.2!
net.ipv4.ip_forward = 0					# CIS 4.1.1
net.ipv4.conf.all.send_redirects = 0			# CIS 4.1.2
net.ipv4.conf.default.send_redirects = 0		# CIS 4.1.2
#net.ipv4.conf.all.accept_source_route = 0		# CIS 4.2.1 !
#net.ipv4.conf.default.accept_source_route = 0		# CIS 4.2.1 !
#net.ipv4.conf.all.accept_redirects = 0 			# CIS 4.2.2 !
#net.ipv4.conf.default.accept_redirects = 0 		# CIS 4.2.2 !
net.ipv4.conf.all.secure_redirects = 0 			# CIS 4.2.3
net.ipv4.conf.default.secure_redirects = 0 		# CIS 4.2.3
net.ipv4.conf.all.log_martians = 1 			# CIS 4.2.4
net.ipv4.conf.default.log_martians = 1 			# CIS 4.2.4
#net.ipv4.icmp_echo_ignore_broadcasts = 1		# CIS 4.2.5 !
net.ipv4.icmp_ignore_bogus_error_responses = 1		# CIS 4.2.6
net.ipv4.conf.all.rp_filter = 1				# CIS 4.2.7
net.ipv4.conf.default.rp_filter = 1			# CIS 4.2.7
#net.ipv4.tcp_syncookies = 1				# CIS 4.2.8 !
net.ipv6.conf.all.accept_ra = 0				# CIS 4.4.1.1
net.ipv6.conf.default.accept_ra = 0 			# CIS 4.4.1.1
net.ipv6.conf.all.accept_redirect = 0			# CIS 4.4.1.2
net.ipv6.conf.default.accept_redirect = 0		# CIS 4.4.1.2
net.ipv6.conf.all.disable_ipv6 = 1			# CIS 4.4.2
EOF


echo umask 027 >> /etc/sysconfig/init			# CIS 3.1

cd /usr/lib/systemd/system				# CIS 3.2
rm default.target
ln -s multi-user.target default.target

########################################
# Disable SystemD Date Service
# Use (chrony or ntpd)
########################################
timedatectl set-ntp false

########################################
# Disable Kernel Dump Service
########################################
systemctl disable kdump.service
systemctl mask kdump.service
