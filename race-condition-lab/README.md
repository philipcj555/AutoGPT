# Race Condition Attack Lab (SEED Labs, Ubuntu 20.04)

Lab deliverables for the SEED **Race Condition Attack** lab
(<https://seedsecuritylabs.org/Labs_20.04/Software/Race_Condition/>).

## Files

| File | Purpose |
|------|---------|
| `LAB_REPORT.md` | Full write-up: steps for Parts 1–4, where each screenshot goes, and the answers to the three questions. **Start here.** |
| `vulp.c` | The intentionally-vulnerable Set-UID root program (TOCTOU between `access()` and `fopen()`). Contains `sleep(10)` for Task 2A — remove it for Tasks 2B/2C. |
| `attack_unlink_symlink.c` | Task 2B attack: flips `/tmp/XYZ` between `/dev/null` and `/etc/passwd` using `unlink()` + `symlink()` in a loop. |
| `attack_renameat2.c` | Task 2C attack: atomic swap of two symlinks via `renameat2(RENAME_EXCHANGE)` — more reliable. |
| `target_process.sh` | Driver that runs `vulp` in a loop until `/etc/passwd` changes (Tasks 2B/2C). |
| `passwd_input` | The malicious `/etc/passwd` line fed to `vulp` (no-password, UID 0). |

## Important

- Run **all privileged steps (`sudo`, `chmod 4755`, `/etc/passwd` edits) inside
  your own SEED Ubuntu 20.04 VM**, never on a shared machine.
- Replace `firstname` in the username placeholders with your actual first name
  (see the table at the top of `LAB_REPORT.md`).
- The build-and-install recipe that makes the attack possible:

  ```bash
  gcc vulp.c -o vulp
  sudo chown root vulp      # root must own it
  sudo chmod 4755 vulp      # turn ON the Set-UID bit  ->  -rwsr-xr-x
  ```

- Setup requires `sudo sysctl -w fs.protected_symlinks=0` (SEED's symlink
  protection otherwise blocks the attack).
