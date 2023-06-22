#!/usr/bin/env bash
#################################################################
#   		    __               __             		#
#		   / /_  ____ ______/ /_  __________		#
#		  / __ \/ __ `/ ___/ __ \/ ___/ ___/		#
#		 / /_/ / /_/ (__  ) / / / /  / /__  		#
#		/_.___/\__,_/____/_/ /_/_/   \___/		#
#...............................................................#
# author        : Sascha Reimann				#
# contributor   : mrplow					#
#								#
#################################################################
shelly() {
	if [[ ${1} =~ ^[-]{0,2}h(elp|$) ]]; then
		echo -e "${bold}"
		echo "	      	           __         ____"
		echo "		     _____/ /_  ___  / / /_  __"
		echo "		    / ___/ __ \/ _ \/ / / / / /"
		echo " 		   (__  ) / / /  __/ / / /_/ /"
		echo "		  /____/_/ /_/\___/_/_/\__, / "
		echo -e "${pale}......................................${rset}${bold}/____/${pale}..............."
		echo "author		: Sascha Reimann"
		echo "contributor	: mrplow"
		echo "website		: https://github.com/s-reimann/shelly"
		echo -e "${rset}"
		echo -e "${bold}BASICS & TOOLS${rset}"
		echo -e "\troot${pale}\t\t\tdetermine if user is root. Some shelly features require root privileges.${rset}"
		echo -e "\tbecome${pale}\t\t\tif sudo is available, the user can become root and execute shelly again with root privileges.${rset}"
		echo -e "\tnotify${pale}\t\t\tnotify is a function to print colorized status information.${rset}"
		echo -e "\tprint_os${pale}\t\tcan be used to display the operating system during login and to help other functions identify the distribution and act accordingly.${rset}"
		echo -e "\tssh_safe${pale}\t\tsecure sshd config to deny password authentication and only accept pki authentication for root.${rset}"
		echo -e "\tssh_unsafe${pale}\t\tchange sshd config to allow password authentication for debugging or temporary file sharing purposes.${rset}"
		echo -e "\tpsauxf${pale}\t\t\tshow compact process list.${rset}"
		echo -e "\tmkcdir${pale}\t\t\tcreate a directory and immediately change into it.${rset}"
		echo -e "\tcontainer${pale}\t\tcheck if we are operating inside of a container.${rset}"
		echo -e "\tinvoke_service${pale}\t\tcan be used to control a daemon.${rset}"
		echo -e "\tsysupdate${pale}\t\tperforms an update of the system.${rset}"
		echo -e "\twhich_pkg${pale}\t\tfind out to which package a file belongs.${rset}"
		echo -e "\tcmount${pale}\t\t\tshow a reduced output of mount.${rset}"
		echo -e "\tconnects${pale}\t\tshow TCP connection stats.${rset}"
		echo -e "\tmagic_sysrq_reboot${pale}\tquick way to reboot your system.${rset}"
		echo -e "\tmailme${pale}\t\t\tcan be used to send a simple test mail.${rset}"
		echo -e "\tnew_screen${pale}\t\topens a new screen session with a status bar similar to the information provided by PROMPT_COMMAND.${rset}"
		echo -e "\tfix_syncookies${pale}\t\tsets net.ipv4.tcp_syncookies to 1 in /etc/sysctl.conf.${rset}"
		echo -e "\tfix_pamsu${pale}\t\tDisables su for normal users.${rset}"
		echo
		echo -e "${bold}CHECKS${rset}"
		echo -e "\tcheck_cdns${pale}\t\twarning if just one caching dns is configured, critical if none at all.${rset}"
		echo -e "\tcheck_date${pale}\t\tcompares the local time with a google server and alerts if unequal.${rset}"
		echo -e "\tcheck_dir${pale}\t\tsimply checks if a given directory exists.${rset}"
		echo -e "\tcheck_disk_usage${pale}\twarning if a partition is -ge 80%, critical if -gt 90%.${rset}"
		echo -e "\tcheck_diskerr${pale}\t\tchecks dmesg for common about-to-fail disk error messages.${rset}"
		echo -e "\tcheck_dmesg${pale}\t\tchecks dmesg for common kernel messages.${rset}"
		echo -e "\tcheck_file${pale}\t\tsame as check_dir, but for files.${rset}"
		echo -e "\tcheck_hostname${pale}\t\tmakes sure that the system has a valid hostname.${rset}"
		echo -e "\tcheck_hosts${pale}\t\tchecks if the hostname appears in the hosts file more than once.${rset}"
		echo -e "\tcheck_inodes${pale}\t\tsame as check_disk_usage, but with inodes. Same threshholds.${rset}"
		echo -e "\tcheck_iowait${pale}\t\tlooks for processes that indicate I/O wait.${rset}"
		echo -e "\tcheck_iptables${pale}\t\tchecks if there are any restricting firewall rules at all.${rset}"
		echo -e "\tcheck_issues${pale}\t\tthis is the core function that gathers the results of all other checks and prints them eventually - unless there's nothing to report at all.${rset}"
		echo -e "\tcheck_ntp${pale}\t\talerts if no time sync daemon is found on the system.${rset}"
		echo -e "\tcheck_pam${pale}\t\tchecks if password authentication is off. Supports Yubikeys and checks if challange response authentication is turned on.${rset}"
		echo -e "\tcheck_pamsu${pale}\t\tchecks if normal users are denied to use su.${rset}"
		echo -e "\tcheck_perm${pale}\t\tchecks the given permissions for a given directory.${rset}"
		echo -e "\tcheck_perm_file${pale}\t\tsame as above, but for files${rset}"
		echo -e "\tcheck_pkg${pale}\t\tchecks if the binaries defined in the \"$TOOLS\" variable are installed.${rset}"
		echo -e "\tcheck_postconf${pale}\t\talerts if postfix listens on external interfaces. This can be an issue with mail servers. You can use profiles to disable that check for certain systems.${rset}"
		echo -e "\tcheck_ps_count${pale}\t\talerts if amount of processes differs from directories in /proc. This could indicate a security breach.${rset}"
		echo -e "\tcheck_procs${pale}\t\tchecks the amount of processes and alerts if certain thresholds are reached.${rset}"
		echo -e "\tcheck_reboot${pale}\t\talerts if the system should be rebooted.${rset}"
		echo -e "\tcheck_rootl${pale}\t\tchecks if ssh root login is possible and raises an alert if so.${rset}"
		echo -e "\tcheck_selinux${pale}\t\tchecks the status of SELinux if installed.${rset}"
		echo -e "\tcheck_smotd${pale}\t\twarns if PrintMotd is disabled in SSH config.${rset}"
		echo -e "\tcheck_spass${pale}\t\talerts if password authentication is turned on in SSH config.${rset}"
		echo -e "\tcheck_sshcra${pale}\t\talerts if challange response is allowed in SSH config (except when Yubikeys are used).${rset}"
		echo -e "\tcheck_syncookies${pale}\talerts if net.ipv4.tcp_syncookies is set to 1.${rset}"
		echo -e "\tcheck_unpriv_unsc${pale}\talerts if kernel.unprivileged_userns_clone is set to 1.${rset}"
		echo
		echo -e "${bold}NOTIFICATIONS${rset}"
		echo -e "\tprint_dns_info${pale}\t\tlooks for nameservers and default domain(s).${rset}"
		echo -e "\tprint_drbd_status${pale}\tdisplays the current status of DRBD resources.${rset}"
		echo -e "\tprint_hardware_info${pale}\tdisplays details about the hardware (or type of hypervisor), CPU and RAM resources.${rset}"
		echo -e "\tprint_network_info${pale}\tdisplays the primary IP and optionally details about a bonding configuration.${rset}"
		echo -e "\tprint_os${pale}\t\tdisplays details about the OS. Additionally if executed with \"-o\" prints the distribution is short form (useful for other functions).${rset}"
		echo -e "\tprint_pacemaker_status${pale}\tsimply displays the output of \"crm_mon -s\".${rset}"
		echo -e "\tprint_ssh_keys${pale}\t\tdisplays the authorized SSH keys (just the comment of course) for the current user.${rset}"
		echo -e "\tprint_system_info${pale}\tdisplays several information about the system: kernel version, number of processes, uptime, SELinux status and number of logged in users.${rset}"
		echo -e "\tprint_tcp_ports${pale}\t\tchecks listening TCP ports (IPv4 and IPv6) and displays the according applications.${rset}"
	else
		# export shelly stuff to $BASHRC. This is required for unprivileged users to use the "become" function
		# and needs to be done before .bashrc or profile are sourced, as there could be issues with possible bash completion includes.

		BASHRC=$(echo "$(declare -f);shelly"|base64 -w0); export BASHRC
		PROMPT_COMMAND='echo -en "\e]0;${USER}@${HOSTNAME}:${PWD/#$HOME/~} | $PRETTY_NAME | Load: $(load=$(</proc/loadavg);echo ${load:0:4}) \007"'

		# source basic files
		for file in /etc/profile ~/.bashrc /etc/os-release; do
			if test -f $file; then source $file; fi
		done

		set_prompt
		if grep -q "^[0-$(grep -c processor /proc/cpuinfo)]\." /proc/loadavg || [ "$1" = "force" ]  ; then
			print_os
			print_ssh_keys
			print_hardware_info
			print_system_info
			print_network_info
			print_dns_info
			print_drbd_status
			print_pacemaker_status
			print_tcp_ports
			check_issues
		else
			echo "load too high. Execute \"shelly force\" if you would like to use shelly nevertheless."
			# TODO: doesn't exist so far :)
		fi
	fi
}

#################################################################
#		     basic tools and functions			#
#################################################################
root() {
	if [[ $EUID -ne 0 ]]; then
		return 1
	fi
}
become() {
	if [ -x "$(command -v sudo)" ]; then
		sudo --preserve-env bash -c 'cd;bash --rcfile <(echo $BASHRC|base64 -d)'
	else
		notify wide crit "sorry, sudo command not found, unable to become root."
	fi
}
notify() {
	if [ -z "${1}" ]; then
		echo "Usage: notify [tile|wide|head] [okay|crit|warn|unkn|vary] [text]"; return
	fi
	local style="$1"
	local status="$2"
	local msg="$3"
	case ${status} in
		okay)	local status="[OK]"
			local color="${okay}"
			;;
		crit) 	local status="[CRITICAL]"
			local color="${crit}"
			;;
		warn)	local status="[WARN]"
			local color="${warn}"
			;;
		unkn)	local status="[UNKNOWN]"
			local color="${unkn}"
			;;
		info)	local status="[INFO]"
			;;
		vary)	local color="${pale}"
			;;
	esac
	if [ $style = tile ]; then
		if (( $head_counter % 2 )) && [ "$color" = "$pale" ]; then
			unset color
		fi
		echo -en "${color}[${msg}]${rset}"
	elif [ $style = wide ]; then
		printf "\r${color}%*s${rset}${color}\r%s${rset}\n" ${COLUMNS} "${status}" "${msg}";
	elif [ $style = head ]; then
		((head_counter++))
		let spaces="16-${#msg}"
		if (( $head_counter % 2 )) && [ "$color" = "$pale" ]; then
			unset color
		fi
		printf "${color}$msg %${spaces}s${rset}"
	fi
}
ssh_unsafe() {
	if ! [ -x /usr/sbin/sshd ]; then
		return
	fi
	value_pauth=$(awk '/^PasswordAuthentication./ {print $2}' /etc/ssh/sshd_config)
	if [ -z ${value_pauth} ]; then
		sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
	fi
	sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/;s/^PasswordAuthentication.*/PasswordAuthentication yes/;s/^UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config
	invoke_service sshd restart
	invoke_service ssh restart
}
ssh_safe() {
	if ! [ -x /usr/sbin/sshd ]; then
		return
	fi
	value_pauth=$(awk '/^PasswordAuthentication./ {print $2}' /etc/ssh/sshd_config)
	if [ -z $value_pauth ]; then
		sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
		sed -i 's/#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
	fi
	sed -i 's/^PermitRootLogin.*/PermitRootLogin without-password/;s/^PasswordAuthentication.*/PasswordAuthentication no/;s/^PrintMotd.*/PrintMotd yes/;s/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
	invoke_service sshd restart
	invoke_service ssh restart
}
container() {
	if [ -f /.dockerenv ]; then
		return 0
	fi
}
invoke_service() {
	local service="${1}"
	local action="${2}"
	if [ "$(pidof init)" = 1 ] ; then
		if [ -x /etc/init.d/${service} ] ; then
			/etc/init.d/${service} ${action}
		fi
	else
		if [ -f /lib/systemd/system/${service}.service ] ; then
			/bin/systemctl ${action} ${service}.service
		elif [ -f /etc/systemd/system/${service}@.service ] ; then
			if [ -f /etc/systemd/system/${service}.socket ] ; then
				/bin/systemctl ${action} ${service}.socket
			fi
		elif [ -x /etc/init.d/${service} ] ; then
			/etc/init.d/${service} ${action}
		fi
	fi
}
partitions() {
	awk 'FNR>2 {printf ("/dev/"$4"\t"); printf( "%.0f GB\n",$3/1024/1024) }' /proc/partitions|sort;
}
which_pkg() {
        local sysos=$(print_os -o)
	arg1="${1}"
	pattern=$(which ${1} 2>/dev/null)
	: ${pattern:="${arg1}"}
	if [ -h ${pattern} ]; then
		echo -en "is a symlink to "
		pattern=$(readlink -f ${pattern})
		echo -en "${pattern} \n"
	fi
        if [[ "${sysos}" = debian || "${sysos}" = ubuntu ]]; then
		dpkg -S ${pattern} 2>/dev/null
		if [[ ${?} != 0 ]]; then
			notify wide unkn "Unable to determine package."
		fi
        elif [[ "${sysos}" = ol || "${sysos}" = centos ]]; then
                rpm -qf ${pattern}
		if [[ ${?} != 0 ]]; then
			notify wide unkn "Unable to determine package."
		fi
	fi
}
psauxf() {
	ps auxfw|grep -v ]$
}
mkcdir() {
	mkdir $1 && cd $_
}
magic_sysrq_reboot() {
	echo 1 > /proc/sys/kernel/sysrq
	echo b > /proc/sysrq-trigger
}
cmount() {
	mount |grep -Ev "(sysfs|proc|tmpfs|securityfs|cgroup|autofs|mqueue|hugetlbfs|rpc|devpts|pstore|debugfs)"|column -t
}
connects() {
	ss -Hnt | awk -F: '{print $2}'|uniq -c|sort -n
}
killitbutmakeitlooklikeanaccident() {
	if [ -x "$(which gdb)" ] ; then
		gdb -p "$1" -batch -ex 'set {short}$rip = 0x050f' -ex 'set $rax=231' -ex 'set $rdi=0' -ex 'cont'
	else
		echo "Sorry, no gdb found." >&2
		exit 1
	fi
}
sysupdate() {
	if [ -f /etc/os-release ] ; then
		local sysos=$(print_os -o)
        	if [[ "${sysos}" = debian || "${sysos}" = ubuntu ]]; then
			apt-get check && apt-get update && apt-get upgrade && apt-get clean && apt-get autoclean && apt-get autoremove;
		elif [[ "${sysos}" = ol || "${sysos}" = centos ]] ; then
			yum upgrade
		else
			notify wide crit "Unknown OS. I don't know what to do :("
			return
		fi
	else
		notify wide crit "I cannot figure out your OS."
		return
	fi
}
mailme() {
	if [ -x "$(command -v mail)" ]; then
		echo -en "rcpt to: "
		read address
		echo ${?}|mail -s $(hostname --fqdn) ${address}
	else
		notify wide crit "Error: unable to find mail binary."
	fi
}
new_screen() {
        if [ -x "$(command -v screen)" ]; then
                unset TTY
                TTY=$(tty)
                screen -dmS TTY${TTY:9}
		screen -r TTY${TTY:9} -X backtick 1 0 0 echo "${USER}@${HOSTNAME}|$PRETTY_NAME | $(grep -c processor /proc/cpuinfo) CPU | $(awk '$1 == "MemTotal:" {printf("%.1f\n",$2/1024/1024);}' /proc/meminfo)GiB RAM | Load: $(awk "{print \$1}" /proc/loadavg)"
                screen -r TTY${TTY:9} -X caption always
                screen -r TTY${TTY:9} -X defscrollback 5000
                screen -r TTY${TTY:9} -X vbell off
                screen -r TTY${TTY:9} -X caption string '%{= bw}[ %1` ]'
                screen -r TTY${TTY:9}
        fi
}
fix_pamsu() {
	if [ -f /etc/pam.d/su ] ; then
		if ! grep -q '^auth[ \t]\+requisite[ \t]\+pam_deny.so$' /etc/pam.d/su; then
			sed -i '/^auth[ \t]\+sufficient[ \t]\+pam_rootok.so$/a # disable su for all other users\nauth       requisite  pam_deny.so' /etc/pam.d/su
			if [ "$?" = "0" ]; then
				notify wide okay "Fixing PAM.d su settings (disabling su for normal users)... "
			else
				notify wide crit "Fixing PAM.d su settings failed!"
			fi
		else
			notify wide info "Nothing to do."
		fi
	fi
}
fix_syncookies() {
	local txt="Activating tcp_syncookies"
	if [ -f /etc/sysctl.conf ]; then
		sed -i 's/^#net.ipv4.tcp_syncookies.*/net.ipv4.tcp_syncookies=1/' /etc/sysctl.conf
		if [ "$?" = "0" ]; then
			notify wide okay "${txt}" 0
			sysctl -p /etc/sysctl.conf
		else
			notify wide crit "${txt}"
		fi
	else
		notify wide warn "${txt} failed! File not found."
	fi
}
#################################################################
#			     checks				#
#################################################################
check_selinux() {
	local selinux_state=$(if [ -x "$(command -v getenforce)" ]; then getenforce; fi)
	if [ -n "$selinux_state" ]; then
		if [ $selinux_state = Enforcing ]; then
			notify tile okay "SELinux Enforcing"
		elif [ $selinux_state = Permissive ]; then
			notify tile warn "SELinux Permissive"
		elif [ $selinux_state = Disabled ]; then
			notify tile crit "SELinux Disabled"
		fi
	fi
}
check_users() {
	local users=$(who|wc -l)
	if [ ${users} -gt "3" ]; then
		notify tile crit "users: ${users}"
	elif [ ${users} -gt "1" ]; then
		notify tile warn "users: ${users}"
	fi
}
check_procs() {
	local procs=$(ps aux|wc -l)
	if [ ${procs} -le "150" ]; then
		notify tile vary "${procs} processes"
	elif [ ${procs} -le "300" ]; then
		notify tile warn "${procs} processes"
	elif [ ${procs} -gt "300" ]; then
		notify tile crit "${procs} processes"
	fi
	echo
}
check_issues() {
	if root; then
		issues="$issues$(check_reboot 2>/dev/null)"
		issues="$issues$(check_perm ~/.ssh 700 755 2>/dev/null)"
		issues="$issues$(check_perm /tmp 1777 1777 2>/dev/null)"
		issues="$issues$(check_dmesg 2>/dev/null)"
		issues="$issues$(check_diskerr 2>/dev/null)"
		issues="$issues$(check_disk_usage 2>/dev/null)"
		issues="$issues$(check_date 2>/dev/null)"
		issues="$issues$(check_ntp 2>/dev/null)"
		issues="$issues$(check_iptables 2>/dev/null)"
		issues="$issues$(check_unpriv_unsc 2>/dev/null)"
		issues="$issues$(check_rootl 2>/dev/null)"
		issues="$issues$(check_pam 2>/dev/null)"
		issues="$issues$(check_smotd 2>/dev/null)"
		issues="$issues$(check_spass 2>/dev/null)"
		issues="$issues$(check_sshcra 2>/dev/null)"
		issues="$issues$(check_pamsu 2>/dev/null)"
		issues="$issues$(check_ps_count 2>/dev/null)"
		issues="$issues$(check_cdns 2>/dev/null)"
		issues="$issues$(check_hosts 2>/dev/null)"
		issues="$issues$(check_postconf 2>/dev/null)"
		issues="$issues$(check_hostname 2>/dev/null)"
		issues="$issues$(check_iowait 2>/dev/null)"
		issues="$issues$(check_inodes 2>/dev/null)"
		issues="$issues$(check_file /var/log/wtmp 2>/dev/null)"
		for pkg in $TOOLS; do
			issues="$issues$(check_pkg $pkg 2>/dev/null)"
		done
		if [ -n "$issues" ]; then
			notify head crit "issues"
			echo -en "${issues}\n"
		fi
	else
		notify head warn "issues"
		notify tile vary "You are not root, some features are disabled. run \"become\" to become root"; echo
	fi
	unset issues
}
check_pamsu() {
	local txt="PAM su"
	if [ -f /etc/pam.d/su ]; then
		if ! grep -q '^auth[ \t]\+requisite[ \t]\+pam_deny.so$' /etc/pam.d/su; then
			if ! grep -q '^auth[ \t]\+required[ \t]\+pam_wheel.so$' /etc/pam.d/su; then
				notify tile crit "${txt}"
			fi
		fi
	fi
}
check_perm() {
	local dst="$1"
	local permok="$2"
	local txt="perms $dst (${permok})"
	if [ -d ${dst} ]; then
		if ! stat -c '%a' ${dst}|grep -q ${permok}; then
			notify tile crit "${txt}"
		fi
	fi
}
check_perm_file () {
	local dst="$1"
	local permok="$2"
	local txt="perms $dst (${permok})"
	if [ -f ${dst} ]; then
		if [ "$permok" -lt "$(stat -c '%a' ${dst})" ]; then
			notify tile crit "$txt"
		fi
	fi
}
check_dmesg() {
	local txt="dmesg"
	if ! container; then
		if dmesg |grep -qiE "(segfault|call trace|blocked for more)";then
			notify tile crit "${txt}"
		fi
	fi
}
check_diskerr() {
	local txt="disk failure"
	if ! container; then
		if dmesg|grep -qiE "(media error|DRDY|I/O error)"; then
			notify tile crit "${txt}"
		fi
	fi
}
check_inodes() {
	local txt="inode usage"
	if df -ix tmpfs|grep -qE "(100%|9.%)"; then
		notify tile crit "${txt}"
	elif
		df -ix tmpfs|grep -qE "8.%"; then
		notify tile warn "${txt}"
	fi
}
check_reboot() {
	local txt="reboot required"
	if [ -f /var/run/reboot-required ] ; then
		notify tile crit "${txt}"
	fi
}
check_date() {
	local txt="time/date"
	local date=$(TZ=GMT date '+%a, %d %b %Y %H:%M')
	if [ "$1" = "-v" ]; then
		if ! grep "$date" <(exec 5<> /dev/tcp/google.com/80 ; printf "HEAD / HTTP/1.1\r\nhost: www.google.com\r\nConnection: close\r\n\r\n" >&5 ; cat <&5); then
			notify tile crit "${txt}"
		fi
	else
		if ! grep -q "$date" <(exec 5<> /dev/tcp/google.com/80 ; printf "HEAD / HTTP/1.1\r\nhost: www.google.com\r\nConnection: close\r\n\r\n" >&5 ; cat <&5); then
			notify tile crit "${txt}"
		fi
	fi
}
check_ntp() {
	local txt="NTP daemon"
	if [ -x "$(command -v systemctl)" ]; then
		for daemon in ntp systemd-timesyncd chronyd openntpd; do
			systemctl is-active --quiet ${daemon}.service
			if [ $? = 0 ]; then
				if [ "$1" = detect ]; then
					echo $daemon
				fi
				return
			fi
		done
		notify tile crit "${txt}"
	else
		notify tile warn "${txt}"
	fi
}
check_pkg() {
	local pkg="$1"
	local full=$(/usr/bin/which $1 2>/dev/null); : ${full:="false"}
	local txt="${pkg}"
	if ! [ -x ${full} ]; then
		notify tile warn "${txt}"
	fi
}
check_rootl() {
	local txt="SSH root login"
	if ! [ -x /usr/sbin/sshd ]; then
		return
	fi
	[ -f /etc/ssh/sshd_config ] || { notify tile warn "${txt}"; return 1; }
	if [ -f /etc/pam.d/sshd ]; then
		if ! grep -q "pam_yubico.so" /etc/pam.d/sshd ; then
			if grep -qE "^PermitRootLogin.*yes" /etc/ssh/sshd_config; then
				notify tile crit "${txt}"
			fi
		fi
	fi
}
check_pam() {
	local txt="SSH password auth"
	if ! [ -x /usr/sbin/sshd ]; then
		return
	fi
	[ -f /etc/ssh/sshd_config ] || { notify tile warn "${txt}"; return 1; }
	if [ -f /etc/pam.d/sshd ]; then
		if ! grep -q "pam_yubico.so" /etc/pam.d/sshd ; then
			if grep -qE "^UsePAM.*yes" /etc/ssh/sshd_config; then
				if grep -qE "^ChallengeResponseAuthentication.*yes" /etc/ssh/sshd_config; then
					notify tile crit "${txt}"
				fi
				if grep -qE "^PasswordAuthentication.*yes" /etc/ssh/sshd_config; then
					notify tile crit "${txt}"
				fi
			fi
		fi
	fi
}
check_smotd() {
	local txt="SSH MOTD"
	if ! [ -x /usr/sbin/sshd ]; then
		return
	fi
	if ! [ -f /etc/ssh/sshd_config ]; then
		notify tile warn "${txt}"
		return 1
	fi
	if grep -qE "^PrintMotd no" /etc/ssh/sshd_config; then
		notify tile warn "${txt}"
	fi
}
check_spass() {
	local txt="SSH pass auth"
	if ! [ -x /usr/sbin/sshd ]; then
		return
	fi
	if ! [ -f /etc/ssh/sshd_config ]; then
		notify tile warn "${txt}"
		return 1
	fi
	value=$(awk '/^PasswordAuthentication./ {print $2}' /etc/ssh/sshd_config)
	if [ "${value}" != "no" ]; then
		notify tile crit "${txt}"
	fi
}
check_sshcra() {
	txt="SSH CRA"
	if ! [ -x /usr/sbin/sshd ]; then
		return
	fi
	[ -f /etc/ssh/sshd_config ] || { notify tile warn "${txt}"; return 1; }
	if [ -f /etc/pam.d/sshd ]; then
		if ! grep -q "pam_yubico.so" /etc/pam.d/sshd ; then
			if /bin/grep -qE "^ChallengeResponseAuthentication yes" /etc/ssh/sshd_config; then
				notify tile crit "${txt}"
			fi
		fi
	fi
}
check_iptables() {
	local txt="firewall"
	if iptables -L -n &>/dev/null ; then
		if ! iptables -L -n |grep -qE "(REJECT|DROP)"; then
			notify tile warn "${txt}"
		fi
	else
		notify tile warn "no ${txt}"
	fi
}
check_ps_count() {
	local txt="procs"
	ps_count=$(ps aux|wc -l)
	proc_count=$(\ls /proc|grep "[0-9]"|wc -l)
	if [ ${ps_count} != ${proc_count} ]; then
		notify tile crit "${txt}"
	fi
}
check_cdns() {
	local txt="caching dns"
	count=$(grep -c nameserver /etc/resolv.conf)
	if [ ${count} = 0 ]; then
		notify tile crit "${txt}"
	elif [ ${count} = 1 ]; then
		notify tile warn "${txt}"
	fi
}
check_hosts() {
	local txt="hosts"
	if getent hosts | awk '{ for ( host=2; host <= NF; host++ ) { hosts[$host] ++  } } END { for ( h in hosts ) { print h, hosts[h] }}'|egrep -qv "(^localhost|1$)"; then
		notify tile crit "${txt}"
	fi
}
check_postconf() {
	local txt="external postfix"
	if [ -x /usr/sbin/postconf ]; then
		if ! grep -qE "reject_rbl_client" <<<$(postconf smtpd_recipient_restrictions smtpd_client_restrictions); then
			if ! grep -qE "(loopback-only|127.0.0.1|localhost)" <<< $(postconf inet_interfaces); then
				notify tile warn "${txt}"
			else
				if grep -q all <<< $(postconf inet_interfaces); then
					notify tile crit  "${txt}"
				fi
			fi
		fi
	fi
}
check_dir() {
	local directory="${1}"
	local txt="${directory}"
	if [ ! -d $directory ]; then
		notify tile crit "${txt}"
	fi
}
check_file() {
	local file="${1}"
	local txt="${file}"
	if [ ! -f ${file} ]; then
		notify tile crit "${txt}"
	fi
}
check_disk_usage() {
	df -x tmpfs -x overlay | grep -o -e "8.%.*"|while read percent mount; do
		notify tile warn "$mount ($percent)";
	done
	df -x tmpfs -x overlay | grep -o -e "9.%.*" -e "100%.*"|while read percent mount; do
		notify tile crit "$mount ($percent)"
	done
}
check_hostname() {
	if ! hostname -f &>/dev/null; then
		notify tile crit "hostname"
	fi
}
check_syncookies() {
	if ! [ $(sysctl net.ipv4.tcp_syncookies|awk '{print $3}') = "1" ]; then
		notify tile crit "syncookies"
	fi
}
check_unpriv_unsc() {
	if sysctl kernel.unprivileged_userns_clone &>/dev/null ; then
		if [ $(sysctl kernel.unprivileged_userns_clone|awk '{print $3}') = "1" ]; then
			notify tile crit "sysctl: user namespace"
		fi
	fi
}
check_iowait() {
	if ps x | awk '{if ($3 ~ "D") print}'|grep -q D; then
		notify tile crit "IOwait"
	fi
}
#################################################################
#			Notifications				#
#################################################################
print_os() {
	if [ -f /etc/os-release ] ; then
		source /etc/os-release
		if [ "$1" = "-o" ] ; then
			echo "${ID}"; return
		else
			notify head vary "distribution"
			notify tile vary "${PRETTY_NAME}"
		fi
	elif [ -x "$(command -v lsb_release)" ]; then
		if [ "$1" = "-o" ] ; then
			lsb_release -i|awk -F: '{print $2}'|xargs echo|tr '[:upper:]' '[:lower:]'
		else
			notify head vary "distribution"
			notify tile vary "$(lsb_release -ir|awk -F: '{print $2}'|xargs echo)"
		fi
	elif [ -f /etc/issue.net ]; then
		if [ "$1" = "-o" ] ; then
			cat /etc/issue.net |awk '{print $1}'|tr '[:upper:]' '[:lower:]'
		else
			notify head vary "distribution"
			notify tile vary "$(cat /etc/issue.net)"
		fi
	else
		notify head vary "distribution"
		notify tile unkn "Unable to detect distribution"
	fi
	echo
}
print_hardware_info() {
	notify head vary "hardware"
	notify tile vary "$(awk '$1 == "MemTotal:" {printf("%.1f\n",$2/1024/1024);}' /proc/meminfo)GiB RAM"
	notify tile vary "$(/bin/grep -c processor /proc/cpuinfo) CPU"
	if dmesg 2>/dev/null | grep -q "Hypervisor detected: Xen" ; then
		notify tile vary "Xen Virtual Platform"; echo; return
	fi
	if dmesg 2>/dev/null | grep -q "VirtualBox" ; then
		notify tile vary "VirtualBox"; echo; return
	fi
	if [ -f /.dockerenv ]; then
		notify tile vary "Docker Container"; echo; return
	fi
	if root; then
		if [ -x "$(command -v dmidecode)" ] && dmidecode | grep -q "SMBIOS.*present." ; then
			if [ "$(dmidecode --type system|awk -F ":" '$1 == "\tManufacturer" {print $NF}')" = " VMware, Inc." ]; then
				notify tile vary "VMware Virtual Platform"
			elif [ "$(dmidecode --type system|awk -F ":" '$1 == "\tProduct Name" {print $NF}')" = " KVM" ]; then
				notify tile vary "KVM Virtual Platform"
			elif [ "$(dmidecode --type system|awk -F ":" '$1 == "\tProduct Name" {print $NF}')" = " VirtualBox" ]; then
				notify tile vary "Virtualbox"
			else
				notify tile vary "$(dmidecode --type system|awk -F : '{if ($1 ~ /Manu/ || $1 ~ /Product/) print $2}' | xargs echo|sed -e 's/To be filled.*/n\/a/')"
				notify tile vary "$(dmidecode --type system|awk -F : '{if ($1 ~ /Serial/) print "SN"$2}' | xargs echo|sed -e 's/To be filled.*/n\/a/')"
				notify tile vary "$(dmidecode --type bios|awk -F : '{if ($1 ~ /Vendor/ || $1 ~ /Version/ || $1 ~/Release/) print $2}' | xargs echo|sed -e 's/To be filled.*/n\/a/')"
			fi
		fi
	fi
	echo
}
print_system_info() {
	notify head vary "system"
	notify tile vary "$(uname -r)"
	notify tile vary "uptime: $(uptime | awk -F\, '{print $1}' | awk '{print $3,$4}')"
	check_selinux
	check_users
	check_procs
}
print_network_info() {
	if [ -x "$(command -v ip)" ]; then
		default_gwnic=$(ip route | awk '$1 == "default" {print $5}' | uniq)
		if [ -z $default_gwnic ]; then
			issues="$issues$(notify tile crit "default gw")"
		else
			primary_ip=$(ip addr show dev $default_gwnic | awk '$1 ~ /^inet$/ {print $2}' | head -1)
			notify head vary "network"
			notify tile vary "${primary_ip}"
			echo
		fi
	fi
	for dev in $(find /proc/net/bonding/ -type f 2>/dev/null); do
		notify head vary "network $(basename $dev)"
		notify tile vary "$(ip addr show dev $(basename $dev) | awk '$1 ~ /^inet$/ {print $2}' | head -1)"
		local mode="$(awk -F ": " '/^Bonding Mode/ {print $2}'  ${dev})"
		if [ "${mode}" = "IEEE 802.3ad Dynamic link aggregation" ] ; then
			notify tile vary "LACP"
		elif [ "${mode}" = "fault-tolerance (active-backup)" ] ; then
			notify tile vary "fault-tolerance"
		else
			echo -en "${mode} "
		fi
		active=$(awk '/Currently Active Slave/ {print $4}' ${dev})
		for slave in $(awk '/Slave Interface/ {print $3}' ${dev}); do
			state=$(grep -A1 "Slave Interface: ${slave}" ${dev} | awk 'FNR>1 {print $3}')
			if [ "${state}" = "up" ]; then
				if [ "${active}" ] && [ "${slave}" = ${active} ]; then
					notify tile okay "Active: ${slave}"
				else
					notify tile vary "Backup: ${slave}"
				fi
			else
				notify tile vary "${slave}"
			fi
		done
		echo
	done
}
print_ssh_keys() {
	if [ -s ~/.ssh/authorized_keys ] || [ -s ~/.ssh/authorized_keys2 ] ; then
		notify head vary "keys"
		for key in $(awk '!/^(#|$)/ {print $NF}' ~/.ssh/authorized_keys ~/.ssh/authorized_keys2 2>/dev/null); do
			notify tile vary "${key}"
		done
		echo
	fi
}
print_dns_info() {
	if [ -f /etc/resolv.conf ]; then
		notify head vary "dns"
		for nameserver in $(awk '/^nameserver/ {print $2}' /etc/resolv.conf); do
			if [ -x "$(command -v nc)" ]; then
				if nc -zw1 $nameserver 53; then
					notify tile vary "$nameserver"
				else
					notify tile crit "$nameserver"
				fi
			fi
		done
		for domain in $(awk '/^search/ {for (i=2; i<=NF; i++) print $i}' /etc/resolv.conf); do
			notify tile vary "search $domain"
		done
		echo
	fi
}
print_drbd_status() {
	if [ -x "$(command -v drbdadm)" ]; then
		resources=$(find /etc/drbd.d/*.res 2>/dev/null)
		if [ -n "$resources" ]; then
			notify head vary "DRBD"
			for res in $(awk '/^resource/ {print $2}' /etc/drbd.d/*.res); do
				state=$(drbdadm cstate $res 2>/dev/null)
				if [ "${state}" = "Connected" ]; then
					notify tile vary "${res}: ${state}"
				elif [ "${state}" = "WFConnection" ]; then
					notify tile crit "${res}: ${state}"
				else
					notify tile unkn "${res}: undetermined"
				fi
			done
			echo
		fi
	fi
}
print_pacemaker_status() {
	if root; then
		if [ -x "$(command -v crm_mon)" ]; then
			notify head vary "pacemaker"
			if crm_mon --version|grep -q "Pacemaker 1"; then
				notify tile vary "$(crm_mon -s)"
			else
				notify tile vary "$(crm_mon -s|tail -n1)"
			fi
			echo
		fi
	fi
}
print_tcp_ports() {
	if ! [ -x "$(command -v lsof)" ]; then return; fi
	for proto in 4 6 ; do
		daemons=$(lsof +c0 -n -i ${proto} -sTCP:LISTEN -P|awk 'FNR>1 {print $1}'|sort|uniq)
		if [[ -n $daemons ]]; then
			notify head vary "IPv${proto} ports"
			for daemon in $daemons; do
				notify tile vary "${daemon}"
			done
			echo
		fi
	done
}
