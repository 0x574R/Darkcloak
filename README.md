# DARKCLOAK

**Linux process identity cloaking: x86-64 NASM, no libc**

DARKCLOAK chains the manipulation of all userspace-visible identity sources into an 11-phase sequential pipeline that progressively transforms a process until it is indistinguishable from the impersonated one to monitoring tools. To our knowledge, no published tool combines simultaneous manipulation of all userspace-visible identity sources.

The full technical write-up is available on the [RAZOR blog](https://0x574r.github.io).

## How it works

The pipeline runs in a strict order defined by the dependencies between the kernel subsystems being manipulated:

1. **ELF introspection**: parses the auxiliary vector at `_start` to resolve the PHT and obtain the virtual address ranges of all three `PT_LOAD` segments
2. **Credential read**: `getresuid` / `getresgid` to store original UIDs and GIDs for later restoration
3. **UID escalation**: `setresuid(0,0,0)` if any of the three UIDs is 0
4. **Capability escalation**: copies the permitted set into the effective and inheritable sets via `capget`/`capset`
5. **Identity spoofing**:
   - `prctl(PR_SET_NAME)` → overwrites `task_struct->comm`
   - direct stack write at `[rsp+8]` → overwrites `argv[0]`
   - `prctl(PR_SET_DUMPABLE, 0)` → blocks `/proc/$PID/mem` access and `ptrace(PTRACE_ATTACH)` from unprivileged processes
   - VMA anonymization via mmap trampoline (see below) → removes all file-backed mappings
   - `prctl(PR_SET_MM_ARG_START/END)` → redirects `/proc/$PID/cmdline`
   - `prctl(PR_SET_MM_ENV_START/END)` → redirects `/proc/$PID/environ`
   - `prctl(PR_SET_MM_EXE_FILE)` → replaces `mm_struct->exe_file`
6. **Capability retention**: `PR_SET_SECUREBITS` (if `CAP_SETPCAP`) or `PR_SET_KEEPCAPS` (fallback) to survive the UID drop
7. **UID de-escalation**: `setresuid(1000,1000,1000)` or restore originals
8. **GID de-escalation**: `setresgid(1000,1000,1000)` or restore originals
9. **Capability de-escalation**: clears effective and inheritable sets
10. **Namespace isolation**: `unshare(CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC)`
11. **Hold**: `nanosleep(120s)` then `exit`

## The mmap trampoline

`PR_SET_MM_EXE_FILE` fails with `EBUSY` while any VMA is still backed by the original binary. Since the `.text` segment cannot be unmapped while RIP is inside it, the anonymization runs from a temporary anonymous page:

1. Allocate a 4096-byte anonymous page (`mmap`)
2. Copy the anonymization code (`mm_start`→`mm_end`) and segment metadata into it
3. Make the page executable (`mprotect`)
4. Jump into it: RIP leaves `.text`
5. For each of the three `PT_LOAD` segments: `mmap` a fresh anonymous region → `memcpy` segment contents → `munmap` the original → `mremap` the anonymous copy back to the original address → `mprotect` to restore original permissions
6. Return to now-anonymous `.text`, unmap the trampoline page

The binary is a static ELF with no interpreter, so the runtime VMA layout is fully deterministic: three `PT_LOAD` segments, the stack, and the kernel vDSO.

## Build

```
nasm -f elf64 darkcloak.asm -o darkcloak.o
ld darkcloak.o -o darkcloak
```

## Configuration

Spoofing targets are defined at compile time in the `.data` section. The defaults impersonate `sshd`:

```nasm
mimic_name    db 'sshd', 0
mimic_argv    db './sshd', 0
mimic_exe     db '/usr/sbin/sshd', 0
mimic_cmdline db '/usr/sbin/sshd', 0, '-D', 0, '-oCiphers=aes256-gcm@openssh.com', 0, ...
mimic_environ db 'LANG=en_US.UTF-8', 0, 'NOTIFY_SOCKET=/run/systemd/notify', 0, ...
```

To impersonate a different process, update these values before building.

## Usage

```
sudo ./darkcloak
```

Requires `CAP_SYS_RESOURCE`, `CAP_SETUID`, `CAP_SETGID`, and `CAP_SETPCAP` in the permitted set. If `CAP_SYS_RESOURCE` is absent, the MM spoofing block (VMA anonymization + `EXE_FILE` swap) is skipped entirely. If `CAP_SETPCAP` is absent, the tool falls back from `PR_SET_SECUREBITS` to `PR_SET_KEEPCAPS`.

## Verify

```bash
./darkcloak &
PID=$!

cat /proc/$PID/comm
readlink /proc/$PID/exe
cat /proc/$PID/cmdline | tr '\0' ' '
cat /proc/$PID/environ | tr '\0' '\n' | head -3
cat /proc/$PID/maps | head -5
cat /proc/$PID/status | grep -E 'Uid|Gid|Cap'
ps aux | grep $PID
```

## Disclaimer

Published exclusively for educational and research purposes. Use only on systems you own or have explicit written authorization to test.

