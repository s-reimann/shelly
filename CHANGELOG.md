# CHANGELOG

All recent changes. Newest come first.

## 2019-06-28
+ major changes:
	- ssh.sh is now shelly.sh.
	- expect (and therefore expect.sh) is not needed anymore. You won't see "eval $(echo "${LC_IDENTIFICATION}" | base64 -d); history -d $((HISTCMD-1))" anymore!
	- new subdirectories:
		- modules/ includes basic functions and personal configuration (ssh.conf is now modules/01-conf.sh).
		- profiles/ can be used to individualize shelly for particular hosts.
	- bashrc is now bashrc.sh, allow comments and lines do not need to end with a semicolon anymore.
	- you can take a look at all shelly functions by executing "shelly help" on a remote system.
	- shelly is now working for non-privileged users as well.
		- if sudo is available, you can use the "become" function to get root and execute shelly afterwards.
	- log_msg() and colorcheck() are now notify(). 
		- updated color scheme (less colorful if there are no issues).
	- sysupdate supports oracle linux now.
	- removal of functions: maildel, sos
	- new check_date function, as the old one was not working anymore
	- some minor changes in a couple of functions.
	- support for docker containers added.
	- support for SELinux added.
	- print_dns_info warns about unreachable caching dns servers.

## 2019-03-18
+ minor change: if the SSH port of a system is open, the available() function will immediately end.

## 2019-03-08
+ Mac users: come right in! Slight adjustments were made to get shelly working on MacOS as well.

## 2018-11-13
 - An update of the "base-files" package Ubuntu released on August 20th caused shelly to fail. The newly added file /etc/profile.d/01-locale-fix.sh is meant to overwrite LC_ variables during login in case they don't contain an already installed locale (changelog: http://changelogs.ubuntu.com/changelogs/pool/main/b/base-files/base-files_10.1ubuntu2.3/changelog). To respect this behavior and to worship the first rule of shelly ("no adjustment required on remote side to run shelly"), a few adaptions were made:
	 - ssh.sh: the ssh command will start a bash on the remote system with the --noprofile option to bypass /etc/profile (and eventually /etc/profile.d/01-locale-fix.sh as well)
	 - init: /etc/profile will be sourced, since ssh.sh bypasses it.
	 - init: LC_IDENTIFICATION and LC_NAME will be "renamed" to LC_INIT and LC_BASHRC
	 - bashrc: renaming of LC_NAME to LC_BASHRC will be done in init and does not need to be in bashrc anymore
	 - expect.sh: legacy support for systems without base64 ends now.

## 2018-10-12
+ New function: "mkcdir <directory>" will create a directory and jump into it right away.

## 2018-10-12
+ Bugfix: added sanity check for included files

## 2018-10-11
+ You can add custom scripts in inc/ that will be sourced after the basic include file (base.inc)

## 2018-10-05
+ Shelly is now publicly available!
