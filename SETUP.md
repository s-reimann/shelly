# Setup

## Git Checkout

Check out the current version from our Git into your user's `bin` directory:

	git clone https://github.com/s-reimann/shelly.git

## Usage
You can either execute the main script ssh.sh directly or you can take advantage of the bash builtin "command_not_found_handle" (http://tldp.org/LDP/abs/html/bashver4.html) to simply enter your hostname or IP address on command line you want to connect to just like you would to start a binary.

## Updating

Updating is just the matter of pulling the current files from the Git repository:

	git pull

## Debugging

For debugging and error reporting purposes, always run the script like this:

`bash -x ./ssh.sh ...`

Post the content as attachment to your bug report.
