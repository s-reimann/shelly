#!/usr/bin/env bash
#=======================================================================#
#									#
#		 $$$$$$\   $$$$$$\  $$\   $$\ 				#
#		$$  __$$\ $$  __$$\ $$ |  $$ |				#
#		$$ /  \__|$$ /  \__|$$ |  $$ |				#
#		\$$$$$$\  \$$$$$$\  $$$$$$$$ |				#
#		 \____$$\  \____$$\ $$  __$$ |				#
#		$$\   $$ |$$\   $$ |$$ |  $$ |				#
#		\$$$$$$  |\$$$$$$  |$$ |  $$ |				#
#		 \______/  \______/ \__|  \__|				#
#									#
#	TITLE:	ssh.sh							#
# DESCRIPTION:	SSH wrapper used to feed expect.sh			#
#									#
#      AUTHOR:	Sascha Reimann						#
# CONTRIBUTOR:	mrplow 							#
#									#
#=======================================================================#
set +o pipefail
shopt -s checkwinsize
SHELLYBASE=$(dirname $0)
trap ctrlc INT

# include variables and functions
if ! [ -f ${SHELLYBASE}/base.inc ]; then
	echo "${SHELLYBASE}/base.inc missing!"
	exit 1
else
	. ${SHELLYBASE}/base.inc
	# load additional custom includes as well
	for file in inc/*.inc; do
		[[ -f "$file" ]] && source $file
	done
fi

if ! [ -f ${SHELLYBASE}/ssh.conf ]; then
	echo "${SHELLYBASE}/ssh.conf missing!"
	exit 1
else
	. ${SHELLYBASE}/ssh.conf
fi

if [ -z "${1}" ] || [ "${1}" = "-h" ] || [ "${1}" = "--help" ] ; then
	echo "Usage: $0 hostname [-l <user>] [-p <port>] [SSH options]"
	exit 0
fi

host="${1}"; shift
ip=$(dig +short ${host}|grep '^[.0-9]*$')
if [[ -z ${ip} ]]; then
	ip=${host}
fi
if ! valid_ip ${ip}; then
	echo "Could not find valid hostname or IP address."
	exit 1
fi

while getopts "p:l:" opt > /dev/null 2>&1 ; do
	case ${opt} in
		p)
			port=${OPTARG}
			;;
		l)
			user=${OPTARG}
			;;
	esac
done

available ${ip} ${port:-22}
${expect} ssh -t ${ip} -l${user:-root} -p${port:-22} $@ "bash --noprofile"
