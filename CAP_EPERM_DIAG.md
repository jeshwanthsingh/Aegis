## 1. Kernel and OS identity

### Command

```bash
uname -a
```

### Output

```text
Linux Cellardoor72 6.17.0-20-generic #20~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Mar 19 01:28:37 UTC 2 x86_64 x86_64 x86_64 GNU/Linux

```

### Command

```bash
cat /etc/os-release
```

### Output

```text
PRETTY_NAME="Ubuntu 24.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.4 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=noble
LOGO=ubuntu-logo

```

### Command

```bash
cat /proc/version
```

### Output

```text
Linux version 6.17.0-20-generic (buildd@lcy02-amd64-120) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #20~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Mar 19 01:28:37 UTC 2

```

## 2. Am I in WSL?

### Command

```bash
cat /proc/version | grep -i microsoft || echo "not WSL"
```

### Output

```text
not WSL

```

### Command

```bash
cat /proc/sys/kernel/osrelease
```

### Output

```text
6.17.0-20-generic

```

### Command

```bash
test -e /proc/sys/fs/binfmt_misc/WSLInterop && echo "WSL interop present" || echo "no WSL interop"
```

### Output

```text
no WSL interop

```

### Command

```bash
ls -la /run/WSL 2>&1 || echo "no /run/WSL"
```

### Output

```text
ls: cannot access '/run/WSL': No such file or directory
no /run/WSL

```

## 3. Am I in a user namespace?

### Command

```bash
readlink /proc/self/ns/user
```

### Output

```text
user:[4026531837]

```

### Command

```bash
readlink /proc/1/ns/user
```

### Output

```text

```

### Command

```bash
cat /proc/self/uid_map
```

### Output

```text
         0          0 4294967295

```

### Command

```bash
cat /proc/self/gid_map
```

### Output

```text
         0          0 4294967295

```

### Command

```bash
cat /proc/self/status | grep -E "^(Cap|NSpid|Uid|Gid)"
```

### Output

```text
Uid:	1000	1000	1000	1000
Gid:	1000	1000	1000	1000
NSpid:	49187
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000

```

### Command

```bash
ls -l /proc/self/ns/user /proc/1/ns/user 2>&1
```

### Output

```text
ls: cannot read symbolic link '/proc/1/ns/user': Permission denied
lrwxrwxrwx 1 root         root         0 Apr 19 23:27 /proc/1/ns/user
lrwxrwxrwx 1 cellardoor72 cellardoor72 0 Apr 19 23:32 /proc/self/ns/user -> user:[4026531837]

```

### Command

```bash
stat -Lc '%n %i' /proc/self/ns/user /proc/1/ns/user 2>&1
```

### Output

```text
/proc/self/ns/user 4026531837
stat: cannot statx '/proc/1/ns/user': Permission denied

```

## 4. Capability bounding set and status

### Command

```bash
capsh --print 2>&1 || echo "capsh not installed"
```

### Output

```text
Current: =
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf,cap_checkpoint_restore
Ambient set =
Current IAB: 
Securebits: 00/0x0/1'b0 (no-new-privs=0)
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
 secure-no-ambient-raise: no (unlocked)
uid=1000(cellardoor72) euid=1000(cellardoor72)
gid=1000(cellardoor72)
groups=4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),114(lpadmin),1000(cellardoor72)
Guessed mode: HYBRID (4)

```

### Command

```bash
cat /proc/self/status | grep -E "^Cap(Inh|Prm|Eff|Bnd|Amb)"
```

### Output

```text
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000

```

## 5. Orchestrator binary actual caps

### Command

```bash
getcap .aegis/bin/orchestrator
```

### Output

```text
.aegis/bin/orchestrator cap_net_admin,cap_net_raw=eip

```

### Command

```bash
getcap .aegis/bin/aegis
```

### Output

```text
.aegis/bin/aegis cap_net_admin,cap_net_raw=eip

```

### Command

```bash
file .aegis/bin/orchestrator
```

### Output

```text
.aegis/bin/orchestrator: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=62037ec8db03cb285d7510e68b2b0b423d2ace6b, with debug_info, not stripped

```

### Command

```bash
readelf -l .aegis/bin/orchestrator | head -40
```

### Output

```text

Elf file type is EXEC (Executable file)
Entry point 0x481380
There are 9 program headers, starting at offset 64

Program Headers:
  Type           Offset             VirtAddr           PhysAddr
                 FileSiz            MemSiz              Flags  Align
  PHDR           0x0000000000000040 0x0000000000400040 0x0000000000400040
                 0x00000000000001f8 0x00000000000001f8  R      0x1000
  INTERP         0x0000000000000fe4 0x0000000000400fe4 0x0000000000400fe4
                 0x000000000000001c 0x000000000000001c  R      0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  NOTE           0x0000000000000f5c 0x0000000000400f5c 0x0000000000400f5c
                 0x0000000000000064 0x0000000000000064  R      0x4
  LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                 0x0000000000412690 0x0000000000412690  R E    0x1000
  LOAD           0x0000000000413000 0x0000000000813000 0x0000000000813000
                 0x0000000000403180 0x0000000000403180  R      0x1000
  LOAD           0x0000000000817000 0x0000000000c17000 0x0000000000c17000
                 0x000000000005cf80 0x000000000009f5c0  RW     0x1000
  DYNAMIC        0x0000000000817340 0x0000000000c17340 0x0000000000c17340
                 0x0000000000000130 0x0000000000000130  RW     0x8
  TLS            0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000008  R      0x8
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x8

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp 
   02     .note.go.buildid 
   03     .text .plt .interp .note.gnu.build-id .note.go.buildid 
   04     .rodata .rela .rela.plt .gnu.version .gnu.version_r .hash .dynstr .dynsym .typelink .itablink .gosymtab .gopclntab 
   05     .go.buildinfo .go.fipsinfo .dynamic .got.plt .got .noptrdata .data .bss .noptrbss 
   06     .dynamic 
   07     .tbss 
   08     

```

## 6. Actual running orchestrator process cap state

### Command

```bash
ps -eo pid,comm,args | grep orchestrator
```

### Output

```text
  49293 orchestrator    /home/cellardoor72/aegis/.aegis/bin/orchestrator --db postgresql://aegisdemo@127.0.0.1:42405/aegisdemo?sslmode=disable --policy /home/cellardoor72/aegis/configs/default-policy.yaml --assets-dir /home/cellardoor72/aegis/assets --rootfs-path /home/cellardoor72/aegis/assets/alpine-base.ext4 --addr 127.0.0.1:8080
  49303 bash            bash -lc ps -eo pid,comm,args | grep orchestrator
  49308 grep            grep orchestrator

```

### Command

```bash
cat /proc/49293/status | grep -E '^Cap(Inh|Prm|Eff|Bnd|Amb)'
```

### Output

```text
CapInh:	0000000000000000
CapPrm:	0000000000003000
CapEff:	0000000000003000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000

```

### Command

```bash
readlink /proc/49293/ns/user
```

### Output

```text

```

## 7. Try the raise with strace

### Command

```bash
go build -o /tmp/capdiag ./cmd/capdiag
```

### Output

```text

```

### Command

```bash
sudo setcap cap_net_admin,cap_net_raw+eip /tmp/capdiag
```

### Output

```text
sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper
sudo: a password is required

```

### Command

```bash
getcap /tmp/capdiag
```

### Output

```text

```

### Command

```bash
/tmp/capdiag
```

### Output

```text
before
Uid:	1000	1000	1000	1000
Gid:	1000	1000	1000	1000
NSpid:	49741
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
RaiseAmbient error: raise ambient cap_net_admin: operation not permitted
after
Uid:	1000	1000	1000	1000
Gid:	1000	1000	1000	1000
NSpid:	49741
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000

```

### Command

```bash
strace -f -e trace=prctl /tmp/capdiag 2>&1 | head -40
```

### Output

```text
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e61498ef000, 262144, " Go: immortal metadata") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e61498cf000, 131072, " Go: page summary") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e6149500000, 1048576, " Go: page summary") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e6148c00000, 8388608, " Go: page summary") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e6144c00000, 67108864, " Go: page summary") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e6124c00000, 536870912, " Go: page summary") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e6104c00000, 536870912, " Go: scavenge index") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0xc000000000, 67108864, " Go: heap reservation") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e6102c00000, 33554432, " Go: heap index") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e61498bd000, 69648, " Go: immortal metadata") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0xc000000000, 4194304, " Go: heap") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e61498cf000, 131072, " Go: page alloc") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e6149580000, 4096, " Go: page alloc") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e6149006000, 4096, " Go: page alloc") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e6146c30000, 4096, " Go: page alloc") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e6134d80000, 4096, " Go: page alloc") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e6114d80000, 4096, " Go: scavenge index") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e6149400000, 1048576, " Go: page alloc index") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e6149933000, 65536, " Go: allspans array") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e61498ad000, 65536, " Go: gc bits") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e6102aa0000, 1439992, " Go: profiler hash buckets") = 0
prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e614986d000, 262144, " Go: immortal metadata") = 0
strace: Process 49759 attached
strace: Process 49760 attached
strace: Process 49761 attached
[pid 49760] prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, 0x7e614982d000, 262144, " Go: immortal metadata") = 0
strace: Process 49762 attached
strace: Process 49763 attached
strace: Process 49764 attached
before
Uid:	1000	1000	1000	1000
Gid:	1000	1000	1000	1000
NSpid:	49758
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
[pid 49758] prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_NET_ADMIN, 0, 0) = 0
[pid 49758] prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_ADMIN, 0, 0) = -1 EPERM (Operation not permitted)

```

## 8. Direct sudo sanity check

### Command

```bash
sudo ./scripts/demo_egress_allowlist.sh 2>&1 | tail -40
```

### Output

```text
sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper
sudo: a password is required

```

## Diagnosis (facts only, no fixes)

- Is this WSL? no, and why: no Microsoft marker in /proc/version or osrelease, and no WSLInterop or /run/WSL marker present
- Is this inside a user namespace? no, and the evidence: /proc/self/ns/user resolves to inode 4026531837 and /proc/self/uid_map plus /proc/self/gid_map both show the full 0 0 4294967295 mapping; /proc/1/ns/user was permission-restricted from this shell.
- Does the bounding set (CapBnd) include cap_net_admin? yes.
- Does sudo work end-to-end? no.
