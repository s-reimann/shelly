#################################################################
#		        __                  			#
#		       / /_  ____ _________ 			#
#		      / __ \/ __ `/ ___/ _ \			#
#		     / /_/ / /_/ (__  )  __/			#
#		    /_.___/\__,_/____/\___/ 			#
#...............................................................#
# author	: Sascha Reimann				#
# contributor	: mrplow					#
#								#
#################################################################

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
				printf "\r%*s\r\033[38;5;${num}m(${avail_step}s) waiting ${extra_txt}for SSH (port ${port}) to come online${dots[${dot_c}]} %s\033[0m"
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
