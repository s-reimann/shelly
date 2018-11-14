# CHANGELOG

All recent changes. Newest come first.

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
