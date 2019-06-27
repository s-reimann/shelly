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
#          FILE:  base.inc					#
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
for bin in awk cat dig grep gzip nc ping script sed ssh tr; do
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
usage() {
        echo "Usage: $0 hostname [port] [SSH options]"
        exit 0
}

ctrlc() {
        echo -e "\e[0m\n\rCtrl+C pressed. Exiting... "
        exit 1
}

valid_ip() {
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

available() {
	local avail_tmout=120
	local host=${1}
	if ! valid_ip ${host} ; then
		echo "the available function should only be invoked with an IP as 1st argument."
		echo "The fact that you see this message most likely indicates a bug in a script using this function"
		exit 1
	fi
	local port=${2:-22} # take given port or default 22
	if ! nc -w 1 -n -z ${host} ${port} &>/dev/null ; then
		lc_temp=$(mktemp)
		(SUBPID=${$} ; trap "kill -INT -${SUBPID} ; exit 1" TERM INT ; until nc -w 1 -n -z ${host} ${port} &>/dev/null ; do sleep 1 ; done ; rm ${lc_temp}) &
		sleep 0.05
		local avail_ts=$(printf '%(%s)T' -1)
		local dot_c=0
		local dots=(".  " ".. " "...")
		while [ -f ${lc_temp} ] ; do
			for steps in 22:130:52 28:166:88 34:172:124 40:214:160 46:11:196 40:214:160 34:172:124 28:166:88 ; do
				local step=(${steps//:/ })
				local avail_step=$(( $(printf '%(%s)T' -1) - ${avail_ts} ))
				if [[ ${avail_step} -le ${avail_tmout} ]] ; then
					num=${step[0]}
				elif [[ ${avail_step} -gt ${avail_tmout} ]] &&[[ ${avail_step} -le $(( ${avail_tmout} * 2 )) ]] ; then
					num=${step[1]}
					local extra_txt="some time "
				else
					num=${step[2]}
					local extra_txt="a long time "
				fi
				printf "\r%*s\r\033[38;5;${num}m%s\033[0m" ${COLUMNS} "($(( $(printf '%(%s)T' -1) - ${avail_ts} ))s) " "waiting ${extra_txt}for SSH (port ${port}) to come online${dots[${dot_c}]} "
				sleep 0.125
				if ! [ -f ${lc_temp} ] ; then
					break
				fi
			done
			if [ ${dot_c} = 2 ] ; then
				dot_c=0
			else
				((dot_c++))
			fi
		done
		unset lc_temp
		echo -en "\e[0m"
	fi
}
