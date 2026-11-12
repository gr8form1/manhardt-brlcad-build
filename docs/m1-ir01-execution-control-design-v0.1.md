# Manhardt Audio — M1 IR-01 Execution-Control Design v0.1
Date: 2026-11-12
Status: PROPOSED FOR INDEPENDENT REVIEW — NOT EXECUTION AUTHORIZATION

## Scope and current evidence

This document proposes a fail-closed GitHub-hosted execution controller for the previously reviewed M1 IR-01 archive. It does not authorize or execute scientific tests, alter the reviewed archive, install packages, or touch Lenovo, NV31, or other protected hosts.

Observed GitHub diagnostic runs:
- 43288685135: Python 3.12.3, cgroup v2 and memory controller discovered.
- 43290036035: unprivileged delegation unavailable; STOP.
- 43290309968: read-only privileged feasibility discovered.
- 43290532075: noninteractive sudo/system manager preflight succeeded.
- 43291128540: transient service, cgroup memory.max=1073741824 and memory.swap.max=0, ordinary child termination passed.
- 43291411801: synthetic SIGTERM-resistant parent and child under RuntimeMaxSec=3, TimeoutStopSec=1, KillMode=control-group, SendSIGKILL=yes; cgroup empty/removed at 4.28 seconds. Evidence artifact ID 13977570701; uploader-reported SHA-256 090dea21d0d18f9df9633f9cf11584bb8020843cf5c7d1ed17b6fa220fa5083a. Artifact ZIP contents have not been independently authenticated.

These observations validate a mechanism, NOT a hard 600-second end-to-end guarantee or scientific correctness.

## Threat model and invariants

1. A dedicated uniquely named transient systemd service is the sole scientific workload boundary. No scientific child may run outside that cgroup.
2. Kernel cgroup v2 memory.max must read back exactly 1073741824 and memory.swap.max exactly 0 before tests. No fallback to process-only ulimit, best-effort RSS polling, or default runner limits.
3. All scientific process descendants remain within the service cgroup. Use KillMode=control-group, SendSIGKILL=yes, and short TimeoutStopSec; confirm post-stop cgroup.procs empty or cgroup removed. A failed verification is HOLD.
4. A separate watchdog, outside the scientific service cgroup, controls a monotonic whole-invocation deadline. The watchdog must not be controlled by scientific process exit codes or signals.
5. Whole-invocation time includes startup, archive verification, scientific execution, termination, cleanup, and local evidence finalization. A GitHub job timeout is not an exact 600-second enforcement mechanism.
6. External watchdog must act BEFORE 600 seconds, with measured margin for signal delivery, SIGKILL escalation, cgroup verification and evidence finalization. Proposed *planning* budgets (not accepted guarantees): 540 s scientific window, 20 s termination, 20 s verification, 20 s local evidence finalization. These allocations require independent adversarial review and measurement; they do not establish a hard upper bound.
7. A supervisor that hangs, is killed, or loses access to systemd must not permit an unbounded scientific workload. This is currently an OPEN proof obligation: a watchdog process in the same GitHub job is not automatically independent of that job or protected from its failures. Systemd's own RuntimeMaxSec should be a second line of defense, set to leave cleanup margin; systemd itself must remain functional.
8. Any failure of integrity checks, environment checks, watchdog checks, cgroup readback, deadline accounting, descendant containment, evidence finalization, or cleanup is a hard STOP. No automatic retry with relaxed settings.
9. No package installation, network fetching of unpinned code, edits to protected paths or runner service, scientific source modification, or publication of proprietary archive to public GitHub.
10. Passing execution is not scientific acceptance; independent reviewer evaluates complete evidence.

## Proposed state machine

PREPARE -> AUTHENTICATE -> ARM_GUARDS -> CREATE_CGROUP -> VERIFY_LIMITS -> RUN -> STOP_AND_KILL -> VERIFY_EMPTY -> FINALIZE_EVIDENCE -> COMPLETE

Any error transitions immediately to STOP_AND_KILL then VERIFY_EMPTY, recording failure. No transition to RUN before all guards and readbacks pass. Watchdog must be armed before workload launch. Uncertain service creation is treated as possibly launched and cleaned by unique unit name.

## Archive authentication

Expected original archive: Manhardt_M1_IR01_SR03B1_R1_Corrective_Source_2026-11-12.zip
Reported length: 29497 bytes
Reported SHA-256: 00b7c8139a7c5a154253ce2288564e157a4bb672b903594afb574a1d3077ed4f

Authenticate the exact bytes and all extracted files against the reviewed internal manifest before use. Reject path traversal, symlinks or hardlinks unless explicitly reviewed, duplicate normalized names, extra/missing files, digest mismatches and unexpected extraction behavior. Archive must be supplied via a separately approved secure mechanism; do not commit to public repository. Record provenance, immutable hashes, Python version, source manifest and command lines. Do not assume reported size/hash constitute independent authentication.

## Evidence contract

Preserve raw stdout/stderr, start/end monotonic timestamps, wall-clock UTC timestamps, GitHub run/job/commit IDs, exact launch arguments, archive and file SHA-256s, cgroup path, kernel memory.max/memory.swap.max readbacks, systemd properties, watchdog events, child/process accounting, termination observations, exit statuses, and explicit unresolved conditions. Upload only after confidentiality review. Upload failure is a failure of evidence preservation, not a scientific PASS. Artifact upload outside a 600-second boundary cannot be counted as evidence finalization within that boundary without an explicit scope decision.

## Mandatory independent review before execution

A. Review and accept the threat model, service lifecycle, privilege scope, unique unit cleanup and host noninterference.
B. Demonstrate or reject a credible hard 600-second whole-invocation upper bound, including cleanup and evidence, not just configured RuntimeMaxSec.
C. Validate that the watchdog cannot be disabled by workload descendants; test adversarial failure cases without IR-01 source.
D. Independently authenticate the synthetic qualification artifact and verify its claims.
E. Inspect exact proposed execution workflow and archive acquisition plan, including confidentiality and supply-chain controls.
F. Obtain explicit founder authorization to run the reviewed IR-01 tests only after A–E pass.

## Disposition

ENVIRONMENT: PARTIAL PASS (mechanisms demonstrated)
WHOLE-INVOCATION 600-SECOND GUARANTEE: HOLD
ARCHIVE AUTHENTICATION: NOT PERFORMED IN EXECUTION HOST
IR-01 SCIENTIFIC EXECUTION: HOLD
SCIENTIFIC ACCEPTANCE: NOT ASSESSED
