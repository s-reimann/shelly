shelly_help() {
	local green=$(tput setaf 2);
	local yellow=$(tput setaf 3);
	local blue=$(tput setaf 6);
	local white=$(tput setaf 7);
	local normal=$(tput sgr0);
	echo -e "${green}Shelly(tm) On-System Commands${normal}\n";
	echo -e "${blue}--- Tools ---${normal}\n";
	echo -e "${yellow}maildel ${white}<pattern>${normal}\tSearch mailqueue for \$pattern and delete mails\n";
	echo -e "${yellow}sysupdate${normal}\t\tPerform a system upgrade (Debian, Ubuntu and CentOS only)\n";
	echo -e "${yellow}sos${normal}\t\t\tWrite system analysis data to /tmp/sos\n";
	echo -e "${yellow}php_sendmail${normal}\t\tWrite an e-mail using PHP (if installed)\n";
	echo -e "${yellow}mailme${normal}\t\t\tWrite an e-mail using system mailer\n";
	echo -e "${yellow}magic_sysrq_reboot${normal}\tSend magic sysrq key to system to cause an unexpected reboot\n";
	echo -e "${yellow}new_screen${normal}\t\tOpen a fancy new Screen session\n";
	echo -e "${blue}--- System-specific ---${normal}\n";
	echo -e "${yellow}fix_pamsu${normal}\t\tDisable su availability for all users except root\n";
	echo -e "${yellow}fix_locales${normal}\t\tAdd common locales (Debian only)\n";
	echo -e "${blue}--- SSH ---${normal}\n";
	echo -e "${yellow}ssh_unsafe${normal}\t\tMake SSHd unsafe (allow password login)\n";
	echo -e "${yellow}ssh_safe${normal}\t\tMake SSHd safe (key authentication only)\n";
};
mkcdir() {
	mkdir $1 && cd $_;
};
invoke_service() {
	service="${1}";
	action="${2}";
	if [ "$(pidof init)" = 1 ] ; then
		if [ -x /etc/init.d/${service} ] ; then
			/etc/init.d/${service} ${action};
		fi;
	else
		if [ -f /lib/systemd/system/${service}.service ] ; then
			/bin/systemctl ${action} ${service}.service;
		elif [ -f /etc/systemd/system/${service}@.service ] ; then
			if [ -f /etc/systemd/system/${service}.socket ] ; then
				/bin/systemctl ${action} ${service}.socket;
			fi;
		elif [ -x /etc/init.d/${service} ] ; then
			/etc/init.d/${service} ${action};
		fi;
	fi;
};
hide() {
	history -d $((HISTCMD-1));
};
not_debian() {
	if [ -f /etc/debian_version ] ; then 
		return 1;
	fi;
};
colorcheck() {
	red=$(tput setaf 1);
	green=$(tput setaf 2);
	boldgreen=$(tput setaf 2; tput bold);
	orange=$(tput setaf 3);
	normal=$(tput sgr0);
	msg="$1";
	status="$2";
	case ${status} in
		0) msgcolor="${green}${msg}${normal}" ;;
		1) msgcolor="${red}${msg}${normal}" ;;
		2) msgcolor="${orange}${msg}${normal}" ;;
		3) msgcolor="${boldgreen}${msg}${normal}" ;;
	esac;
	echo -en "[$msgcolor]";
};
log_msg() {
	red=$(tput setaf 1);
	green=$(tput setaf 2);
	orange=$(tput setaf 3);
	normal=$(tput sgr0);
	msg="$1";
	status="$2";
	case ${status} in
		0)	status="[OK]";
			statuscolor="$green${status}$normal";
			msgcolor="${green}${msg}${normal}";
			;;
		1)	status="[CRITICAL]";
			statuscolor="$red${status}$normal";
			msgcolor="${red}${msg}${normal}";
			;;
		2)	status="[WARN]";
			statuscolor="$orange${status}$normal";
			msgcolor="${orange}${msg}${normal}";
			;;
	esac;
	let col=$(tput cols)-${#msg}+${#statuscolor}-${#status};
	echo -n $msgcolor;
	printf "%${col}s" "$statuscolor";
};
maildel() {
	n="0";
	pattern="${1}";
	if [ -z ${pattern} ]; then 
		echo "please provide a pattern to search for";
		return 1;
	fi;
	for id in $(postqueue -p|awk "/$pattern/ {print \$1}"|tr -d '*!'); do
		postsuper -d ${id};
		((n++));
	done;
	echo "$n mails deleted";
};
ssh_unsafe() {
	if ! [ -x /usr/sbin/sshd ]; then
		return;
	fi;
        value_pauth=$(awk '/^PasswordAuthentication./ {print $2}' /etc/ssh/sshd_config);
	if [ -z ${value_pauth} ]; then
		sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config;
	fi;
	sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/;s/^PasswordAuthentication.*/PasswordAuthentication yes/;s/^UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config;
	invoke_service sshd restart;
	invoke_service ssh restart;
};
ssh_safe() {
	if ! [ -x /usr/sbin/sshd ]; then
		return;
	fi;
	value_pauth=$(awk '/^PasswordAuthentication./ {print $2}' /etc/ssh/sshd_config);
	if [ -z $value_pauth ]; then
		sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config;
		sed -i 's/#ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config;
	fi;
	sed -i 's/^PermitRootLogin.*/PermitRootLogin without-password/;s/^PasswordAuthentication.*/PasswordAuthentication no/;s/^PrintMotd.*/PrintMotd yes/;s/^ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config;
	invoke_service sshd restart;
	invoke_service ssh restart;
};
pf_safe() {
	config_dir="$(postconf config_directory|awk '{print $3}')";
	if [ -d $config_dir ]; then
		postconf -e "inet_interfaces = 127.0.0.1";
		invoke_service postfix restart;
	fi;
};
psauxf() {
	ps auxfw|grep -v ]$;
};
new_screen() {
	if [ -x /usr/bin/screen ]; then
		unset TTY;
		TTY=$(tty|awk -F/ '{print $4}');
		screen -dmS TTY${TTY};
		screen -r TTY${TTY} -X backtick 1 0 0 echo "$(hostname -f) | $([[ -x /usr/bin/lsb_release ]] && lsb_release -ris|xargs || head -n1 /etc/issue) | $(/bin/grep -c processor /proc/cpuinfo) CPU | $(echo $(( $(free -m|awk "/Mem/ {print \$2}")/990 )))G RAM | Load: $(awk "{print \$1}" /proc/loadavg)";
		screen -r TTY${TTY} -X caption always;
		screen -r TTY${TTY} -X defscrollback 5000;
		screen -r TTY${TTY} -X vbell off;
		screen -r TTY${TTY} -X caption string '%{= bw}[ %1` ]';
		hide;
		screen -r TTY${TTY};
	fi;
	hide;
};
which_pkg() {
	local sysos=$(print_os -o);
	if [[ "${sysos}" -ne "debian" ]] || [[ "${sysos}" -ne "ubuntu" ]]; then 
		echo "Sorry, this command only runs on Debian or Ubuntu (for now).";
		return 1;
	fi;
	arg1="${1}";
	pattern=$(which ${1});
	: ${pattern:="${arg1}"};
	if [ -h ${pattern} ]; then
		echo -en "is a symlink to ";
		pattern=$(readlink -f ${pattern});
		echo -en "${pattern} \n";
	fi;
	dpkg -S ${pattern} 2>/dev/null;
	if [ ${?} != 0 ]; then
		if [ -x /usr/bin/apt-file ]; then
			if [ -x /usr/bin/apt-cache ]; then
				echo "Not installed. Using apt-file and apt-cache to determine .deb package.";
				apt-file --regexp search "${pattern}"|grep --color "$(/usr/bin/apt-cache search ${pattern}|/usr/bin/awk "{print \$1}")";
			fi;
		else
			if [ -x /usr/bin/apt-cache ]; then
				echo "Not installed. Using apt-cache to determine .dev package";
				apt-cache search ${pattern};
			fi;
		fi;
	fi;
};
magic_sysrq_reboot() {
	echo 1 > /proc/sys/kernel/sysrq;
	echo b > /proc/sysrq-trigger;
};
vhosts_search() {
	string="$1";
	if [ -z ${string} ]; then
		apache2ctl -t -D DUMP_VHOSTS 2>&1;
	else
		apache2ctl -t -D DUMP_VHOSTS 2>&1|grep ${string};
	fi;
};
cmount() {
	mount |grep -Ev "(sysfs|proc|tmpfs|securityfs|cgroup|autofs|mqueue|hugetlbfs|rpc|devpts|pstore|debugfs)"|column -t;
};
connects() {
	netstat -nt | awk -F: '{print $2}' | sort | uniq -c | sort -n | column -t;
};
sysupdate() {
	if [ -f /etc/os-release ] ; then
		local sysos=$(print_os -o);
		if [ "${sysos}" = "debian" ] || [ "${sysos}" = "ubuntu" ] ; then
			apt-get check && apt-get update && apt-get upgrade && apt-get clean && apt-get autoclean && apt-get autoremove;
		elif [ "${sysos}" = "centos" ] ; then
			yum upgrade;
		else
			echo "Unknown OS. I don't know what to do :(";
			return;
		fi;
	else
		echo "I cannot figure out your OS";
		return;
	fi;
};
sos() {
	file="/tmp/sos";
	uname -a > ${file};
	uptime >> ${file};
	ps auxw >> ${file};
	top -bi -n 1 >> ${file};
	ifconfig -a >> ${file};
	ip a >> ${file};
	netstat -i >> ${file};
	netstat -ltn >> ${file};
	arp -an >> ${file};
	cat /proc/cpuinfo >> ${file};
	lspci >> ${file};
	mount|column -t >> ${file};
	df -h >> ${file};
	echo "saved to: /tmp/sos";
	less /tmp/sos;
};
php_sendmail() {
	if [ -x $(which php) ] ; then
		read -p "RCPT TO: " PHP_MY_ADDRESS;
		export PHP_MY_ADDRESS;
		php -r '$to = getenv("'PHP_MY_ADDRESS'"); address; $subject = "Test mail"; $message = "Hello. This is a simple email message."; $from = "root@test.de"; $headers = "From:" . $from; mail("$to","$subject","$message","$headers");';
		echo "Mail Sent.";
		unset PHP_MY_ADDRESS;
	else
		echo "PHP not found on this system.";
		return 1;
	fi;
};
mailme() {
	echo -en "rcpt to: ";
	read address;
	echo ${?}|mail -s $(hostname --fqdn) ${address};
};
root_or_exit() {
	id=$(which id);
	if [ ! -x ${id} ]; then
		return 0;
	else
		if [ $(${id} -u) != "0" ]; then
			return 0;
		fi;
	fi;
};
check_pamsu() {
	txt="PAM su";
	if [ -f /etc/pam.d/su ]; then
		if ! grep -q '^auth[ \t]\+requisite[ \t]\+pam_deny.so$' /etc/pam.d/su; then
			colorcheck "${txt}" 1;
		fi;
	fi;
};
check_perm() {
	dst="$1";
	permok="$2";
	txt="perms $dst (${permok})";
	if [ -d ${dst} ]; then
		if ! stat -c '%a' ${dst}|grep -q ${permok}; then 
			colorcheck "${txt}" 1;
		fi;
	fi;
};
check_perm_file ()
{
	dst="$1";
	permok="$2";
	txt="perms $dst (${permok})";
	if [ -f ${dst} ]; then
		if [ "$permok" -lt "$(stat -c '%a' ${dst})" ]; then
			colorcheck "$txt" 1;
		fi;
	fi;
};
check_dmesg() {
	txt="dmesg";
	if dmesg |grep -qiE "(segfault|call trace|blocked for more)";then
		colorcheck "${txt}" 1;
	fi;
};
check_diskerr() {
	txt="disk failure";
	if dmesg|grep -qE "(media error|DRDY|I/O error)"; then
		colorcheck "${txt}" 1;
	fi;
};
check_inodes() {
	txt="inode usage";
	if df -ix tmpfs|grep -qE "(100%|9.%)"; then
		log_msg "${txt}" 1;
	elif
		df -ix tmpfs|grep -qE "8.%"; then
		log_msg "${txt}" 2;
	else
		return 0; echo "remove this line if you want to see the OK message" 1>/dev/null;
		log_msg "${txt}" 0;
	fi;
};
check_reboot() {
	txt="REBOOT";
	if [ -f /var/run/reboot-required ] ; then
		colorcheck "${txt}" 1;
	fi;
};
check_date() {
	txt="date";
	if [[ ! -x $(which wget 2>/dev/null) ]]; then
		colorcheck "${txt}" 1;
		return 0;
	fi;
	value="$(( $(wget -T1 -t1 -qO- www.currenttimestamp.com|awk '/current_time =/ {print $3}'|sed -e 's/;//') - $(/bin/date '+%s') ))";
	if [[ "$value" -lt 0 ]] ; then
		(( value=value*-1 ));
	fi;
	if ! [[ $value -le 60 ]] ; then
		colorcheck "${txt}" 1;
	fi;
};
check_ntp() {
	txt="NTP state";
	if [ -x /usr/sbin/ntpd ]; then
		if [ "$1" = "detect" ]; then
			NTP="ntpd";
			echo $NTP;
			return;
		fi;
		if ! ps -C ntpd &>/dev/null; then
			colorcheck "$txt" 2;
		fi;
	elif [ -x /usr/sbin/chronyd ]; then
		if [ "$1" = "detect" ]; then
			NTP="chronyd";
			echo $NTP;
			return;
		fi;
		if ! ps -C chronyd &>/dev/null; then
			colorcheck "${txt}" 2;
		fi;
	else
		if [ "$1" = "detect" ]; then
			NTP="ntpd";
			echo $NTP;
			return;
		fi;
		colorcheck "${txt}" 1;
	fi;
};
NTP=$(check_ntp detect);
check_pkg() {
	pkg="$1";
	full=$(/usr/bin/which $1 2>/dev/null); : ${full:="false"};
	txt="${pkg}";
	if ! [ -x ${full} ]; then
		colorcheck "${txt}" 2;
	fi;
};
check_rootl() {
	txt="SSH root login";
	if ! [ -x /usr/sbin/sshd ]; then
		return;
	fi;
	[ -f /etc/ssh/sshd_config ] || { colorcheck "${txt}" 2; return 1; };
	if [ -f /etc/pam.d/sshd ]; then
		if ! grep -q "pam_yubico.so" /etc/pam.d/sshd ; then
			if grep -qE "^PermitRootLogin.*yes" /etc/ssh/sshd_config; then
				colorcheck "${txt}" 1;
			fi;
		fi;
	fi;
};
check_pam() {
	txt="SSH password auth";
	if ! [ -x /usr/sbin/sshd ]; then
		return;
	fi;
	[ -f /etc/ssh/sshd_config ] || { colorcheck "${txt}" 2; return 1; };
	if [ -f /etc/pam.d/sshd ]; then
		if ! grep -q "pam_yubico.so" /etc/pam.d/sshd ; then
			if grep -qE "^UsePAM.*yes" /etc/ssh/sshd_config; then
				if grep -qE "^ChallengeResponseAuthentication.*yes" /etc/ssh/sshd_config; then
                                        colorcheck "${txt}" 1;
                                fi;
				if grep -qE "^PasswordAuthentication.*yes" /etc/ssh/sshd_config; then
                                        colorcheck "${txt}" 1;
                                fi;
			fi;
		fi;
	fi;
};
check_smotd() {
	txt="SSH MOTD";
	if ! [ -x /usr/sbin/sshd ]; then
		return;
	fi;
	[ -f /etc/ssh/sshd_config ] || { colorcheck "${txt}" 2; return 1; };
	if grep -qE "^PrintMotd no" /etc/ssh/sshd_config; then
		colorcheck "${txt}" 2;
	fi;
};
check_spass() {
	txt="SSH pass auth";
	if ! [ -x /usr/sbin/sshd ]; then
		return;
	fi;
	if ! [ -f /etc/ssh/sshd_config ]; then
		colorcheck "${txt}" 2;
		return 1;
	fi;
	value=$(awk '/^PasswordAuthentication./ {print $2}' /etc/ssh/sshd_config);
	if [ "${value}" != "no" ]; then
		colorcheck "${txt}" 1;
	fi;
};
check_sshcra() {
	txt="SSH CRA";
	if ! [ -x /usr/sbin/sshd ]; then
		return;
	fi;
	[ -f /etc/ssh/sshd_config ] || { colorcheck "${txt}" 2; return 1; };
	if [ -f /etc/pam.d/sshd ]; then
		if ! grep -q "pam_yubico.so" /etc/pam.d/sshd ; then
			if /bin/grep -qE "^ChallengeResponseAuthentication yes" /etc/ssh/sshd_config; then
				colorcheck "${txt}" 1;
			fi;
		fi;
	fi;
};
check_iptables() {
	txt="firewall";
	if iptables -L -n &>/dev/null ; then
		if ! iptables -L -n |grep -qE "(REJECT|DROP)"; then
			colorcheck "${txt}" 2;
		fi;
	else
		colorcheck "no ${txt}" 2;
	fi;
};
check_procs() {
	txt="procs";
	ps_count=$(ps aux|wc -l);
	proc_count=$(/bin/ls /proc|grep "[0-9]"|wc -l);
	if [ ${ps_count} != ${proc_count} ]; then
		colorcheck "${txt}" 1;
	fi;
};
check_cdns() {
	txt="caching dns";
	count=$(grep -c nameserver /etc/resolv.conf);
	if [ ${count} = 0 ]; then
		colorcheck "${txt}" 1;
	elif [ ${count} = 1 ]; then
		colorcheck "${txt}" 2;
	fi;
};
check_hosts() {
	txt="hosts";
	if getent hosts | awk '{ for ( host=2; host <= NF; host++ ) { hosts[$host] ++  } } END { for ( h in hosts ) { print h, hosts[h] }}'|egrep -qv "(^localhost|1$)"; then
		colorcheck "${txt}" 1;
	fi;
};
check_postconf() {
	txt="external postfix";
	if [ -x /usr/sbin/postconf ]; then
		if ! grep -qE "reject_rbl_client" <<<$(postconf smtpd_recipient_restrictions smtpd_client_restrictions); then
			if ! grep -qE "(loopback-only|127.0.0.1|localhost)" <<< $(postconf inet_interfaces); then
				colorcheck "${txt}" 2;
			else
				if grep -q all <<< $(postconf inet_interfaces); then
					colorcheck "${txt}" 1;
				fi;
			fi;
		fi;
	fi;
};
check_dir() {
	directory="${1}";
	txt="${directory}";	
	if [ ! -d $directory ]; then
		colorcheck "${txt}" 1;
	fi;
};
check_file() {
	file="${1}";
	txt="${file}";
	if [ ! -f ${file} ]; then
		colorcheck "${txt}" 1;
	fi;
};
check_disk_usage() {
	df -x tmpfs | grep -E "(8.%)" | awk '{print $(NF-1), $NF}' | uniq | while read line; do colorcheck "$line" 2; done;
	df -x tmpfs | grep -E "(100%|9.%)"| awk '{print $(NF-1), $NF}' | uniq | while read line; do colorcheck "$line" 1; done;
};
check_hostname() {
	if ! hostname -f &>/dev/null; then
		colorcheck "hostname" 1;
	fi;
};
check_syncookies() {
        if ! [ $(sysctl net.ipv4.tcp_syncookies|awk '{print $3}') = "1" ]; then
		colorcheck "syncookies" 1;
	fi;
};
check_unpriv_unsc() {
	if sysctl kernel.unprivileged_userns_clone &>/dev/null ; then
		if [ $(sysctl kernel.unprivileged_userns_clone|awk '{print $3}') = "1" ]; then
			colorcheck "sysctl: user namespace" 1;
		fi;
	fi;
};

check_iowait() {
	if ps x | awk '{if ($3 ~ "D") print}'|grep -q D; then
		colorcheck "IOwait" 1;
	fi;
};

fix_syncookies() {
	txt="Activating tcp_syncookies";
	if [ -f /etc/sysctl.conf ]; then
		sed -i 's/^#net.ipv4.tcp_syncookies.*/net.ipv4.tcp_syncookies=1/' /etc/sysctl.conf;
		if [ "$?" = "0" ]; then
			log_msg "${txt}" 0;
			sysctl -p /etc/sysctl.conf;
		else
			log_msg "${txt}" 1;
		fi;
	else
		log_msg "${txt} failed! File not found." 1;
	fi;
};
fix_pamsu() {
        if [ -f /etc/pam.d/su ] ; then
                if ! grep -q '^auth[ \t]\+requisite[ \t]\+pam_deny.so$' /etc/pam.d/su; then
                        echo -n "Fixing PAM.d su settings (disabling su for normal users)... ";
                        sed -i '/^auth[ \t]\+sufficient[ \t]\+pam_rootok.so$/a # disable su for all other users\nauth       requisite  pam_deny.so' /etc/pam.d/su;
                        echo "Done";
                else
                        echo "Nothing to repair";
                fi;
        fi;
};
fix_locales() {
	if not_debian ; then
		echo "Sorry, this command is Debian only (for now).";
		return;
	else
		cat /etc/locale.gen | awk '{if ($1 == "#" && ($2 ~ /en_US/ || $2 ~ /en_GB/ || $2 ~ /de_DE/)) print $2,$3; else print $0 ;}' > /etc/locale.gen.new;
		mv /etc/locale.gen /etc/locale.gen.old;
		mv /etc/locale.gen.new /etc/locale.gen;
		locale-gen;
		en_US;
		echo "Installed common locales. Please relog to this server for changes to take effect.";
	fi;
};
partitions() {
	awk 'FNR>2 {printf ("/dev/"$4"\t"); printf( "%.0f GB\n",$3/1024/1024) }' /proc/partitions|sort;
};
print_os() {
	if [ -f /etc/os-release ] ; then
		if [ "$1" = "-o" ] ; then
			local sysos=$(awk -F "=" '$1 == "ID" {print $NF}' /etc/os-release | sed 's/"//g');
			echo ${sysos};
			return;
		else
			echo -en "OS\t\t: ";
			colorcheck "$(awk -F "=" '$1 == "PRETTY_NAME" {print $NF}' /etc/os-release | sed 's/"//g')" 0;
			echo;
		fi;	
	elif [ -x /usr/bin/lsb_release ]; then
		if [ "$1" = "-o" ] ; then
			lsb_release -i|awk -F: '{print $2}'|xargs echo|tr '[:upper:]' '[:lower:]';
		else
			echo -en "OS\t\t: ";
			colorcheck "$(lsb_release -ir|awk -F: '{print $2}'|xargs echo)" 0;
			echo;
		fi;
	elif [ -f /etc/issue.net ]; then
		if [ "$1" = "-o" ] ; then
			cat /etc/issue.net |awk '{print $1}'|tr '[:upper:]' '[:lower:]';
		else
			echo -en "OS\t\t: ";
			colorcheck "$(cat /etc/issue.net)" 0;
			echo;
		fi
	else
		colorcheck "Unable to detect OS" 1;
		echo;
	fi;
};
print_tcp_ports() {
	local sysos=$(print_os -o);
	if [ "${sysos}" = debian ] ; then
		deb_ver=$(grep -oE "(^[0-9]|sid)" /etc/debian_version);
		if [ "${deb_ver}" != "sid" ]; then
			if [ ${deb_ver} -lt "5" ]; then return 0; fi;
		fi;
	fi;
	if [[ ! -x $(which lsof 2>/dev/null) ]]; then return 0; fi;
	if [ "${deb_ver}" = 5 ] ; then
		for proto in 4 6 ; do
			if [ "${proto}" = 4 ] ; then
				local protocolor=0;
			elif [ "${proto}" = 6 ] ; then
				local protocolor=3;
			fi;
			for command in $(lsof +c0 -n -i ${proto} -sT -P|awk 'FNR>1 {print $1}'|sort|uniq); do
				colorcheck "${command}" ${protocolor};
			done;
		done;
	else
		for proto in 4 6 ; do
			if [ "${proto}" = 4 ] ; then
				local protocolor=0;
			elif [ "${proto}" = 6 ] ; then
				local protocolor=3;
			fi;
			for command in $(lsof +c0 -n -i ${proto} -sTCP:LISTEN -P|awk 'FNR>1 {print $1}'|sort|uniq); do
				colorcheck "${command}" ${protocolor};
			done;
		done;
	fi;
};
print_hardware_info() {
	if [ -x /usr/sbin/dmidecode ] && dmidecode | grep -q "SMBIOS.*present." ; then
		echo -en "hardware\t: ";
		colorcheck "$(echo $(($(awk "/MemT/ {print \$2}" /proc/meminfo)/1000000)))G RAM" 2;
		colorcheck "$(/bin/grep -c processor /proc/cpuinfo) CPU" 2;

		if [ "$(dmidecode --type system|awk -F ":" '$1 == "\tManufacturer" {print $NF}')" = " VMware, Inc." ]; then
			colorcheck "VMware Virtual Platform" 2;
		echo;
		else
			colorcheck "$(dmidecode --type system|awk -F : '{if ($1 ~ /Manu/ || $1 ~ /Product/) print $2}' | xargs echo|sed -e 's/To be filled.*/n\/a/')" 2;
			colorcheck "$(dmidecode --type system|awk -F : '{if ($1 ~ /Serial/) print "SN"$2}' | xargs echo|sed -e 's/To be filled.*/n\/a/')" 2;
			colorcheck "$(dmidecode --type bios|awk -F : '{if ($1 ~ /Vendor/ || $1 ~ /Version/ || $1 ~/Release/) print $2}' | xargs echo|sed -e 's/To be filled.*/n\/a/')" 2;
			echo;
		fi;
	fi;
};
print_system_info() {
	users=$(/usr/bin/who|/usr/bin/wc -l);
	procs=$(/bin/ps aux|/usr/bin/wc -l);
	echo -en "system\t\t: kernel $(uname -rm), uptime: $(uptime | awk -F\, '{print $1}' | awk '{print $3,$4}'), $(if [ ${users} -gt "1" ]; then echo -e "\033[0;31m"${users}"\033[0m"; else echo "${users}"; fi) logged in user(s), $(if [ ${procs} -gt "300" ]; then echo -e "\033[0;31m"${procs}"\033[0m"; else echo "${procs}"; fi) processes\n";
};
print_network_info() {
	c_grn_ul="\e[4;32m";
	c_grn="\e[3;32m";
	c_red="\e[3;31m";
	c_reset="\e[0m";
	if [ -x "$(which ip)" ]; then
		primary_ip=$(ip addr show dev $(ip route | awk '$1 == "default" {print $5}' | uniq) | awk '$1 ~ /^inet$/ {print $2}' | head -1);
		echo -en "network\t\t: ${primary_ip}\n";
	else
		data=$(ifconfig $(route -n | awk '$1 ~ /^0.0.0.0$/ {print $NF}' | uniq) | awk '$1 ~ /^inet$/ {print $2";"$NF}' | sed 's/^addr://;s/;Mask:/;/');
		primary_ip=$(echo "$data" | awk -F ";" '{print $1}');
		netmask=$(echo "$data" | awk -F ";" '{print $2}');
		echo -en "network\t\t: ${primary_ip}\nnetmask\t\t: ${netmask}";
	fi;
	for dev in $(find /proc/net/bonding/ -type f 2>/dev/null); do
		echo -en "network $(basename ${dev})\t: ";
		local mode="$(awk -F ": " '/^Bonding Mode/ {print $2}'  ${dev})";
		if [ "${mode}" = "IEEE 802.3ad Dynamic link aggregation" ] ; then
			echo -en "LACP ";
		else
			echo -en "${mode} ";
		fi;
		active=$(awk '/Currently Active Slave/ {print $4}' ${dev});
		for slave in $(awk '/Slave Interface/ {print $3}' ${dev}); do
			state=$(grep -A1 "Slave Interface: ${slave}" ${dev} | awk 'FNR>1 {print $3}');
			if [ "${state}" = "up" ]; then
				if [ "${active}" ] && [ "${slave}" = ${active} ]; then
					echo -en "(${c_grn_ul}${slave}${c_reset})";
				else
					echo -en "(${c_grn}${slave}${c_reset})";
				fi;
			else
				echo -en "(${c_red}${slave}${c_reset})";
			fi;
		done;
		echo;
	done;
};
print_ssh_keys() {
	if [ -f ~/.ssh/authorized_keys ] || [ -f ~/.ssh/authorized_keys2 ] ; then
		echo -en "ssh keys\t: ";
		sed 's/^.*ssh/ssh/;/^$/d;/^#/d;s/\(ssh\|ecdsa\).*AAAA[^ ]\+ //;s/^[ \t]//' ~/.ssh/authorized_keys ~/.ssh/authorized_keys2 2>/dev/null | while read key; do
			echo -en "\033[0;34m[$key] \033[0m";
		done
	else
		log_msg "no ssh keys" 1;
	fi;
	echo;
};
print_dns_info() {
	if [ -f /etc/resolv.conf ]; then
		echo -e "DNS\t\t: $(awk '$1 == "nameserver" {print "\033[0;35m"$2"\033[0m"};$1 == "domain" {print "\033[0;35m(domain: "$2")\033[0m"};$1 == "search" {print "\033[0;35m(search: "$2")\033[0m"}' /etc/resolv.conf | sort -r | xargs)";
	fi;
};
print_drbd_status() {
	if ! not_debian ; then
		if [ -e /proc/drbd ] ; then
			tail -n+3 /proc/drbd | awk '$1 ~ /^[0-9]+:$/ {print $1,$2,$3,$4}' | while read line ; do echo -e "DRBD\t\t: \033[0;36m${line}\033[0m"; done;
		fi;
	fi;
};
print_pacemaker_status() {
	if [ -x /usr/sbin/crm_mon ]; then
		echo -e "pacemaker\t: \033[0;36m$(crm_mon -s)\033[0m";
	fi;
};
: bind is used to make F10 work as shelly. e21 = "F10";
bind '"\e[21~":"eval $(echo \"$BASHRC\"|base64 -d|gunzip -c);history -d $((HISTCMD-1))\n"';
alias ls='ls --color';
alias grep='grep --color';
alias vim='vim -c ":set mouse=" -c ":set incsearch" -c "syn on" -c ":set ignorecase"';
alias leave_without_prints='kill -9 $$';
alias act='cat';
export MYSQL_PS1="\u@mysql [\r:\m] (\d) > ";
if [[ -z $PROMPT_COMMAND ]]; then
	. /etc/os-release ; PROMPT_COMMAND="echo -en \"\033]0;\$(hostname -f)|\$PRETTY_NAME|Load: \$(awk '{print \$1}' /proc/loadavg) \007\"";
else
	. /etc/os-release ; PROMPT_COMMAND="$PROMPT_COMMAND;echo -en \"\033]0;\$(hostname -f)|\$PRETTY_NAME|Load: \$(awk '{print \$1}' /proc/loadavg) \007\"";
fi;
PS1='\[\e[1;31m\]$(rc=$?;if [ "$rc" != "0" ]; then echo -n "$rc ";fi)\[\e[0m\]\[\e[1;34m\]\A ($(who|wc -l)) \h:\w$\[\e[0m\] ';
: Output of bashrc starts below;
print_os;
print_ssh_keys;
print_hardware_info;
print_system_info;
print_network_info;
print_dns_info;
print_drbd_status;
print_pacemaker_status;
unset issues;
issues="$(check_reboot)";
issues="$issues$(check_perm ~/.ssh 700 755)";
issues="$issues$(check_perm /tmp 1777 1777)";
issues="$issues$(check_dmesg)";
issues="$issues$(check_diskerr)";
issues="$issues$(check_disk_usage)";
issues="$issues$(check_date)";
issues="$issues$(check_ntp)";
issues="$issues$(check_iptables)";
issues="$issues$(check_unpriv_unsc)";
issues="$issues$(check_rootl)";
issues="$issues$(check_pam)";
issues="$issues$(check_smotd)";
issues="$issues$(check_spass)";
issues="$issues$(check_sshcra)";
issues="$issues$(check_pamsu)";
issues="$issues$(check_procs)";
issues="$issues$(check_cdns)";
issues="$issues$(check_hosts)";
issues="$issues$(check_postconf)";
issues="$issues$(check_hostname)";
if [ "${sysos}" = "debian" ] || [ "${sysos}" = "ubuntu" ]; then
	issues="$issues$(check_dir /var/log/fsck)";
fi;
issues="$issues$(check_file /var/log/wtmp)";
issues="$issues$(check_pkg ${NTP})"; unset NTP;
issues="$issues$(check_pkg vim)";
issues="$issues$(check_pkg less)";
issues="$issues$(check_pkg screen)";
issues="$issues$(check_pkg tcpdump)";
issues="$issues$(check_pkg rsync)";
issues="$issues$(check_pkg fuser)";
issues="$issues$(check_pkg telnet)";
issues="$issues$(check_pkg lspci)";
issues="$issues$(check_pkg lsof)";
issues="$issues$(check_pkg wget)";
issues="$issues$(check_pkg lsb_release)";
issues="$issues$(check_pkg dmidecode)";
issues="$issues$(check_iowait)";
if [ "$issues" != "" ] ; then
	echo -en "issues\t\t: ${issues}";
	echo -en "\n";
fi;
ports="$(print_tcp_ports)";
if [ "$ports" != "" ] ; then
	echo -en "ports\t\t: ${ports}";
	echo -en "\n";
fi;
check_inodes;
if [ -n "${LC_NAME}" ]; then
	export LC_BASHRC="${LC_NAME}";
fi;
unset LC_IDENTIFICATION LC_NAME;
if ! [ -z "$LC_EDITOR" ] ; then
	if [ -x $(which "$LC_EDITOR") ] ; then
		export EDITOR=$LC_EDITOR;
	else
		export EDITOR="vim";
	fi;
else
	export EDITOR="vim";
fi;
