#!/usr/bin/env expect
set timeout 5
set cmd1 {eval $(echo "${LC_IDENTIFICATION}" | base64 -d); history -d $((HISTCMD-1))}

trap {
	set cols [stty columns]
	set rows [stty rows]
	stty rows $rows columns $cols < $spawn_out(slave,name)
} WINCH

spawn -noecho {*}$argv
expect {
	eof { exit 1 }
	timeout { puts "\n\nSorry, could not detect a valid prompt. Shelly is not available.\n" ; interact }
	"(yes/no)?" {
		send "yes\r"
		expect {
			":~#" { send "$cmd1\r"; interact }
			-re :~\[$\] { puts "\n\nYou are not root! Shelly is not available\nPlease press return...\n"; interact }

			"~ #" { send "$cmd1\r"; interact }
			-re "~ \[$\]" { puts "\n\nYou are not root! Shelly is not available\nPlease press return...\n"; interact }

			"~]#" { send "$cmd1\r"; interact }
			-re ~]\[$\] { puts "\n\nYou are not root! Shelly is not available\nPlease press return...\n"; interact }
		}
	}
	"#" { send "$cmd1\r"; interact }
	-re :~\[$\] { puts "\n\nYou are not root! Shelly is not available\nPlease press return...\n"; interact }

	":~#" { send "$cmd1\r"; interact }
	-re :~\[$\] { puts "\n\nYou are not root! Shelly is not available\nPlease press return...\n"; interact }

	"~ #" { send "$cmd1\r"; interact }
	-re "~ \[$\]" { puts "\n\nYou are not root! Shelly is not available\nPlease press return...\n"; interact }

	"~]#" { send "$cmd1\r"; interact }
	-re ~]\[$\] { puts "\n\nYou are not root! Shelly is not available\nPlease press return...\n"; interact }

	"*assword:" {
		interact -o "#" return
		send "$cmd1\r"
		interact
	}
}

