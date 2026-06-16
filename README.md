<div align="center">
  <h1>DARKCLOAK</h1>
  <p>Linux process identity cloaking — pure x86-64 NASM, zero libc</p>

  <img src="https://img.shields.io/badge/arch-x86__64-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/language-NASM-informational?style=flat-square"/>
  <img src="https://img.shields.io/badge/platform-Linux-lightgrey?style=flat-square"/>
  <img src="https://img.shields.io/badge/libc-none-success?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-research%20only-red?style=flat-square"/>

  <br/><br/>
  <p><i>Part of the <a href="https://0x574r.github.io">RAZOR</a> offensive security research series.</i></p>
</div>

---

## What is DARKCLOAK?

DARKCLOAK is a process identity spoofing tool written entirely in x86-64 NASM assembly with no libc dependency and no dynamic linker. It manipulates five Linux kernel subsystems in a precise, ordered pipeline to make a running process appear as a legitimate system service — at the level of `ps`, `/proc`, auditd, and eBPF-based detectors.

No C. No wrappers. Syscalls only.

## How it works

The execution pipeline has four phases:

```
Phase 1 — Recon
  Auxv parsing  →  getresuid/getresgid  →  setresuid(0,0,0)  →  capget/capset (full permitted→effective)

Phase 2 — Spoofing  (requires CAP_SYS_RESOURCE)
  PR_SET_NAME  →  argv[0] overwrite  →  PR_SET_MM_ARG_*  →  PR_SET_MM_ENV_*
  mmap trampoline  →  VMA anonymization (3× PT_LOAD)  →  PR_SET_MM_EXE_FILE

Phase 3 — Privilege drop
  PR_SET_SECUREBITS / PR_SET_KEEPCAPS  →  setresuid  →  setresgid  →  capset (clear effective+inheritable)

Phase 4 — Isolation
  unshare(CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNS)  →  nanosleep  →  exit
```

### Surfaces addressed

| Kernel surface | Syscall / mechanism | Visible in |
|---|---|---|
| `task_struct->comm` | `prctl(PR_SET_NAME)` | `ps`, `top`, `pgrep`, auditd, `bpf_get_current_comm()` |
| Command line | `argv[0]` stack overwrite + `PR_SET_MM_ARG_*` | `/proc/$PID/cmdline` |
| Environment | `PR_SET_MM_ENV_*` | `/proc/$PID/environ` |
| Executable path | `PR_SET_MM_EXE_FILE` | `/proc/$PID/exe` |
| File-backed VMAs | `mmap` + `memcpy` + `munmap` + `mremap` + `mprotect` | `/proc/$PID/maps` |
| Process namespace | `unshare()` | `/proc` enumeration, container scanners |

### The mmap trampoline

`PR_SET_MM_EXE_FILE` fails with `EBUSY` when any of the process's VMAs are still backed by the original binary file. DARKCLOAK resolves this by copying each `PT_LOAD` segment into a fresh anonymous mapping, unmapping the original file-backed VMA, and remapping the anonymous pages back at the same virtual address — before invoking `PR_SET_MM_EXE_FILE`. The trampoline itself executes from a temporary anonymous page to remain position-independent during the remap.

Because the binary is a static ELF with no interpreter, the runtime VMA layout is fully deterministic: three `PT_LOAD` segments (read-only headers, read+execute text, read+write data), the stack, and the kernel vDSO. The anonymization loop handles all three in sequence.

## Configuration

Spoofing targets are set at compile time in the `.data` section of `darkcloak.asm`:

```nasm
mimic_name    db 'sshd', 0                      ; task_struct->comm
mimic_argv    db './sshd', 0                     ; argv[0] replacement string
mimic_exe     db '/usr/sbin/sshd', 0            ; target for PR_SET_MM_EXE_FILE
mimic_cmdline db '/usr/sbin/sshd', 0, '-D', 0, ...  ; full spoofed cmdline
mimic_environ db 'LANG=en_US.UTF-8', 0, ...    ; spoofed environment block
```

## Build

```bash
nasm -f elf64 -o darkcloak.o darkcloak.asm
ld -o darkcloak darkcloak.o
```

Requirements: `nasm`, `ld`. No other toolchain needed.

## Usage

```bash
sudo ./darkcloak
```

The binary must run with `CAP_SYS_RESOURCE`, `CAP_SETUID`, `CAP_SETGID`, and `CAP_SETPCAP` in the permitted set. If `CAP_SYS_RESOURCE` is absent, the MM spoofing phase (VMA anonymization + `EXE_FILE` swap) is skipped via a flag check on the effective capability bitmask. If `CAP_SETPCAP` is absent, the tool falls back from `PR_SET_SECUREBITS` to `PR_SET_KEEPCAPS` for capability retention across the UID drop.

## Verify

After the process is running, confirm the spoofed identity:

```bash
# Spoofed comm
cat /proc/$PID/status | grep -E "^Name:"

# Spoofed cmdline
cat /proc/$PID/cmdline | xargs -0

# Spoofed exe symlink
readlink /proc/$PID/exe

# No file-backed VMAs (all anonymous)
grep -v "^[0-9a-f].*/$" /proc/$PID/maps

# Isolated namespace inodes
ls -la /proc/$PID/ns/
```

## Limitations

- Requires elevated privileges at startup (see above)
- Spoofing data is static — target identity is baked in at compile time
- Namespace isolation targets automated scanners, not manual analysis: a root operator can enter any namespace via `nsenter`
- The `PR_SET_DUMPABLE 0` call prevents core dumps and restricts `/proc/$PID/` access to root, which is intentional but worth noting when debugging

## Write-up

The full technical series covering ELF internals, Linux process identity, and the complete DARKCLOAK implementation is published on the RAZOR blog:

**→ [0x574r.github.io](https://0x574r.github.io)**

## Disclaimer

This tool is intended strictly for authorized security research and educational purposes. Use only on systems you own or have explicit written permission to test. The author is not responsible for any misuse.
