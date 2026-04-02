# Known Limitations

## Startup latency on the current glibc rootfs
Cold starts are still expensive, especially on WSL2. The current Ubuntu/glibc guest has noticeable startup overhead before user code even begins. The system works, but it is not low-latency. Timeout budgets need to account for VM boot, guest bootstrap, resolver behavior, and teardown.

## WSL2 caveats
WSL2 is a valid development environment for Aegis, but it is not the cleanest or fastest one. KVM access, networking behavior, mount semantics, and timing all have more edge cases on WSL2 than on a native Linux host. If something is flaky on WSL2 and solid on bare metal Linux, believe the Linux result first.

## Node.js remains more fragile than Python and bash
Python and bash are the stable paths today. Node.js is still more sensitive to guest runtime conditions, especially around entropy and startup behavior on WSL2. Treat Node support as weaker until it has the same repeatable validation coverage as the other runtimes.

## Workspace exit-code ambiguity
There is still an open ambiguity in the persistent workspace path where a successful second read can surface a nonzero `exit_code`. The data path appears to work, but the reported status is not fully trustworthy yet. That needs cleanup before workspace durability can be called finished.

## Timeout budgets are still operational, not elegant
The system is stable with the current timeout settings, but some of that stability comes from giving the runtime enough slack rather than making every path intrinsically fast. Validation is good. Latency is not yet impressive.

## Temporary diagnostic debt still exists
Some diagnostics were added to stabilize DNS and execution behavior. They were useful, but parts of that visibility are still debt that should be trimmed once CI and repeated local validation stay green.

## Rootfs migration is still gated
The repo now has an Alpine rootfs build path and rollback mechanism, but the default image should not be switched until the migration baseline, parity matrix, and before/after benchmark report are captured.
