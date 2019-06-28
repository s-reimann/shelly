#!/usr/bin/env bash

#################################################################
#		           __         ____     			#
#		     _____/ /_  ___  / / /_  __			#
#		    / ___/ __ \/ _ \/ / / / / /			#
# 		   (__  ) / / /  __/ / / /_/ / 			#
#		  /____/_/ /_/\___/_/_/\__, /  			#
#...................................../____/....................#
# author	: Sascha Reimann				#
# contributor	: mrplow					#
#								#
#################################################################

set +o pipefail
shopt -s checkwinsize
SHELLYBASE=$(dirname $0)

# if the first argument is empty or "-h/-help/--help", print usage
if [[ ${1} =~ ^$|^[-]{1,2}h(elp|$) ]]; then
	echo "Usage: $0 [-xd] host [SSH options]"
	echo " -x : debug mode"
	echo " -d : disable port check"
	exit
elif [ "${1}" = "-x" ]; then
	debug="-x"; shift
	available="0"
	set -x
fi

SHELLYMODULES=${SHELLYBASE}/modules
if ! [ -f ${SHELLYMODULES}/00-base.sh ]; then
	echo "${SHELLYMODULES}/00-base.sh missing!"; exit 1
fi

# quit if a required tool is missing
for bin in cat dig grep nc ping ssh; do
        if ! [ -x "$(command -v ${bin})" ]; then
		echo "required tool \"${bin}\" not available!"; exit 1
	fi
done

host="${1}"; shift
ip=($(dig +search +short ${host}|grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$'))
if [[ -z ${ip} ]]; then
	if [ ${host} = localhost ]; then
		ip="127.0.0.1"
	elif valid_ip ${host}; then
		ip=${host}
	else
		echo "Sorry, unable to determine remote target."
		exit 1
	fi
elif [ ${#ip[@]} -gt 1 ]; then
	echo "Multiple results detected, using first match: ${ip[0]}"
	ip=${ip[0]}
fi

# due to a minor syntax difference in base64, we'll need to differentiate between mac and linux
if [[ ${MACHTYPE} =~ apple ]]; then
	export BASHRC=$(echo "$(for file in ${SHELLYBASE}/bashrc.sh ${SHELLYBASE}/modules/*.sh ${SHELLYBASE}/profiles/${ip}_${port:-22}; do if test -f $file; then cat $file; fi; done);shelly"|base64 -)
else
	export BASHRC=$(echo "$(for file in ${SHELLYBASE}/bashrc.sh ${SHELLYBASE}/modules/*.sh ${SHELLYBASE}/profiles/${ip}_${port:-22}; do if test -f $file; then cat $file; fi; done);shelly"|base64 -w0 -)
fi

# parse the port number if provided as an argument
opt=$(echo $@|grep -oE "\-p.[0-9]{1,5}")
# remove all but the port number itself
port=${opt//[!0-9]/}
if [ "$available" != "0" ]; then
	available ${ip} ${port:-22}
fi
# takeoff time
ssh -t ${ip} $@ "bash --noprofile --rcfile <(echo ${BASHRC}|base64 -d) ${debug}"
