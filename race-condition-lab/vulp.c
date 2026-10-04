/*
 * vulp.c  -  The vulnerable "privileged" program for the SEED Race Condition Lab.
 *
 * This program is INTENTIONALLY VULNERABLE. It is installed as a Set-UID root
 * program. It contains a classic TOCTOU (Time-Of-Check-To-Time-Of-Use) race
 * condition: it uses access() to CHECK whether the *real* user is allowed to
 * write to /tmp/XYZ, and only then uses fopen() to actually USE (open) the file.
 * Between the check and the use there is a window during which an attacker can
 * swap /tmp/XYZ (a symbolic link) to point at a file the real user could not
 * otherwise write, e.g. /etc/passwd.
 *
 * NOTE ON THE sleep() BELOW:
 *   - For Task 2A: keep the sleep(10) (or sleep(20)). It artificially widens the
 *     race window so the attack can be performed BY HAND in a second terminal.
 *   - For Task 2B and 2C: DELETE the sleep() line (or set it to 0). The window
 *     is then tiny and must be won by an automated attack program run in a loop.
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main()
{
	char *fn = "/tmp/XYZ";
	char buffer[60];
	FILE *fp;

	/* get user input */
	scanf("%50s", buffer);

	if (!access(fn, W_OK)) {            /* CHECK: does the REAL uid have write perm? */
		sleep(10);                 /* <-- Task 2A: widen the window. REMOVE for 2B/2C. */
		fp = fopen(fn, "a+");      /* USE: open as EFFECTIVE uid (root) */
		if (fp == NULL) {
			return 1;
		}
		fwrite("\n", sizeof(char), 1, fp);
		fwrite(buffer, sizeof(char), strlen(buffer), fp);
		fclose(fp);
	} else {
		printf("No permission \n");
	}

	return 0;
}
