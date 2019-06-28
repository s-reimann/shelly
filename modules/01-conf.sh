#!/usr/bin/env bash

# Make your prompt more powerful: If the return code is not 0, the return code will be echoed 
# at the start of the prompt. The number of logged in users will be display in parantheses.
set_prompt() {
	PS1='\[\e[1;31m\]$(rc=$?;if [ "$rc" != "0" ]; then echo -n "$rc ";fi)\[\e[0m\]\[\e[36m\]\A ($(who|grep -c .)) \h:\w$\[\e[0m\] '
}

# Make your MySQL / MariaDB prompt more powerful as well.
export MYSQL_PS1="\u@mysql [\r:\m] (\d) > "

# You can disable checks globally here or for particular hosts using the profiles directory.
# Create a file named profiles/<IP>_<port> and unset checks to skip them.
# Some functions can simply be unset, others need to be overwritten.
#unset check_reboot
#unset ...
#check_issues() { :; }
#...

# Basic variables, uncomment or adjust to your needs.
EDITOR="vim"
TOOLS="nc vim less screen tcpdump rsync fuser lspci lsof curl wget dmidecode"

# The following color codes are used by the notify function. Change them to match your color scheme.
export crit="\e[0;31m"
export okay="\e[0;32m"
export warn="\e[0;33m"
export unkn="\e[0;35m"
export rset="\e[0m"
export bold="\e[1m"
export pale="\e[2m"

# Some simple aliases
alias ls='ls --color'
alias grep='grep --color'
alias vim='vim -c ":set mouse=" -c ":set incsearch" -c "syn on" -c ":set ignorecase"'
alias leave_without_prints='kill -9 $$'
