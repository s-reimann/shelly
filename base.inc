#!/usr/bin/env bash
#===============================================================#
#								#
#		$$$$$$\ $$\   $$\  $$$$$$\ 			#
#		\_$$  _|$$$\  $$ |$$  __$$\ 			#
#		  $$ |  $$$$\ $$ |$$ /  \__|			#
#		  $$ |  $$ $$\$$ |$$ |      			#
#		  $$ |  $$ \$$$$ |$$ |      			#
#		  $$ |  $$ |\$$$ |$$ |  $$\ 			#
#		$$$$$$\ $$ | \$$ |\$$$$$$  |			#
#		\______|\__|  \__| \______/			#
#								#
#          FILE:  inc						#
#   DESCRIPTION:  used to include functions			#
#								#
#        AUTHOR:  Sascha Reimann				#
#   CONTRIBUTOR:  mrplow					#
#								#
#===============================================================#

#===============================================================#
#			basic variables				#
#===============================================================#
date=$(date '+%d%m%y_%H%M%S')
export LC_WHO_AM_I=$(whoami)

#===============================================================#
#			 basic commands				#
#===============================================================#
# pre-flight checks
for bin in $(echo "awk cat dig grep gzip nc ping script sed ssh tput tr"); do
        if ! [ -x "$(command -v ${bin})" ]; then echo "UNKNOWN: ${bin} not available, unable to determine status"; exit ${state_unknown}; fi
done
expect="${SHELLYBASE}/expect.sh"

#===============================================================#
#			   colors				#
#===============================================================#
t_ul="\e[4m"
c_dbl="\e[34m"
b_dbl="\e[1;34m"
c_gre="\e[32m"
b_gre="\e[1;32m"
c_lbl="\e[36m"
b_lbl="\e[1;36m"
c_red="\e[31m"
b_red="\e[1;31m"
c_pur="\e[35m"
b_pur="\e[1;35m"
c_yel="\e[33m"
b_yel="\e[1;33m"
c_whi="\e[97m"
b_whi="\e[1;97m"
c_res="\e[0m"

#===============================================================#
#			   functions				#
#===============================================================#
function valid_ip () {
	local ip=$1
	local stat=1
	if [ "${ip}" != "" ] ; then
		if [[ ${ip} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
			OIFS=${IFS}
			IFS='.'
			ip=(${ip})
			IFS=${OIFS}
		[[ ${ip[0]} -le 255 && ${ip[1]} -le 255  && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
		stat=$?
		fi
	fi
	return $stat
}

function type () {
	# define text to print and control character
	local text=$1
	local cc=$2

	# read characters one by one and print
	for char in $(seq 0 $(( $(wc -c <<< ${text}) - 2 )) ); do
		echo -n "${text:$char:1}"
		pool=('0.01' '0.02')
		time=${#pool[*]}
		sleep ${pool[$((RANDOM % time))]}
	done

	# print control character
	echo -en "\\${cc}"
}

function available () {
        local host=${1}
	if ! [[ "${host}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
		echo "the available function should only be invoked with an IP as 1st argument."
		echo "The fact that you see this message most likely indicates a bug in a script using this function"
		exit 1
	fi
        local port=${2:-22} # take given port or default 22
	# check if host is dead (-c = count, -W = timeout, -q = quiet)
	lc_temp=$(mktemp)
	(SUBPID=${$} ; trap "kill -INT -${SUBPID} ; exit 1" TERM INT ; until ping -c1 -W1 -nq ${host} 2>&1 &>/dev/null ; do sleep 1 ; done ; rm ${lc_temp} ) &
	sleep 0.01
	while [ -f ${lc_temp} ] ; do
		for num in 52 88 124 160 196 160 124 88 ; do
			echo -en "\r\033[38;5;${num}mwaiting for host to come online\033[0m\r"
			sleep 0.12
		done
	done
	tput el
	lc_temp=$(mktemp)
	(SUBPID=${$} ; trap "kill -INT -${SUBPID} ; exit 1" TERM INT ; until nc -nzw2 ${host} ${port} &>/dev/null ; do sleep 1 ; done ; rm ${lc_temp}) &
	sleep 0.01
	while [ -f ${lc_temp} ] ; do
		for num in 130 166 172 214 11 214 172 166 ; do
			echo -en "\r\033[38;5;${num}mwaiting for port ${port} to come online.\033[0m\r"
			sleep 0.12
		done
	done
	tput el
}
