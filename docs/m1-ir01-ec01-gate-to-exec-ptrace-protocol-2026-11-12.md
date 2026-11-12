# Manhardt Audio — M1 IR-01 EC-01 Gate-to-Exec Linearization Protocol
Date: 2026-11-12
Status: Focused documentary design; EC-01 HOLD pending independent review.
Preserved: prior EC-01 envelope/outer-deadline/queued-start closure, original monotonic T0 and deadlines, remaining-runtime derivation, PID-1 workload limits, EC-02–EC-05, healthy-host assumptions. No implementation or execution authorized.

## Selected protocol: broker-traced exec barrier
The one privileged root-owned admission/closure broker is the **sole** start-submission authority and sole issuer of admission release. The scientific workload's unprivileged in-unit gate performs the eventual execve of the unchanged scientific executable. Before any exec attempt, the broker establishes ptrace supervision of the exact gate task with PTRACE_O_TRACEEXEC and PTRACE_O_EXITKILL, using a verified stopped/traced state; fork/clone/exec descendants must remain inside the workload cgroup, with unexpected forks/execs denied and terminated. The broker is outside the workload cgroup. The gate cannot ptrace itself, release its own trace stop, alter broker state, or start replacement units. The controller and scientific process have no manager privileges.

The gate first sends an invocation-bound, single-use request. Broker verifies original T0, exact unit/cgroup/PID identity, effective properties and deadline budget. This produces only **PREAUTHORIZED**, never COMMITTED. Gate invokes execve; Linux ptrace TRACEEXEC must stop the tracee at the post-exec event before new image user code runs. Broker authenticates the exact expected exec event, traced task identity and executable; while its single-threaded serialized admission/closure state machine remains OPEN, broker issues PTRACE_CONT to release that specific stopped task. **Successful PTRACE_CONT of the verified exec-event stop is the admission linearization point**, not the earlier reply. If closure is processed first, no CONT occurs; the tracee is killed. If CONT succeeds first, admission is COMMITTED and later closure stops an already-admitted workload. A failed or ambiguous CONT is never retried as a new admission: mark UNKNOWN, close, kill, and prohibit PASS.

The broker handles closure messages and TRACEEXEC events in one serialized event loop with no other code path authorized to issue CONT. PID-1-owned deadline action independently initiates closure at the accepted original T0-based target; the broker durably records irreversible CLOSED, revokes all pending tokens and forbids new StartUnit/CONT. The action independently stops/kills the exact workload unit and reconciles queued job/unit/cgroup state even if broker is dead. A late event from a closed invocation is killed, not released. Broker restart never resumes an ambiguous tracee; CLOSED/UNKNOWN persisted state is deny-only.

## State machine
UNARMED -> ARMED (PID-1 deadline effective and read back) -> OPEN (limits, invocation and runtime verified) -> REQUESTED -> PREAUTHORIZED -> EXEC_EVENT_STOPPED -> COMMITTED (verified PTRACE_CONT success) -> RUNNING -> STOPPING -> TERMINATED_VERIFIED -> SEALED.
At any pre-COMMITTED state: closure -> CLOSED -> kill stopped/queued/activating task -> verify quiescence. At COMMITTED/RUNNING: closure -> CLOSED -> PID-1 stop/kill -> verify descendants. Unknown transition -> UNKNOWN_CLOSED; never new execution attempt. OPEN is not re-entered after CLOSED. All states keyed by exact invocation ID, manager T0, unit identity, PID/cgroup and one-use request nonce. Admission receipt includes ptrace stop identity, exec-event evidence, successful CONT result and monotonic ordering against closure. No claim of COMMITTED from a bare authorization reply.

## Race table
| Race | Required outcome |
|---|---|
| Closure before authorization | Broker marks CLOSED; no token, no exec release; queued/running unit terminated |
| Closure after PREAUTHORIZED, before TRACEEXEC | Token revoked; if exec event arrives, broker kills stopped tracee; no CONT |
| Closure while TRACEEXEC stopped | Broker serial event loop chooses order: closure first => kill; CONT first => COMMITTED then deadline stop |
| Closure concurrent with PTRACE_CONT | The broker's single serialized thread defines order; if CONT returns success first, COMMITTED; if closure processed first, no CONT; ambiguous syscall outcome => UNKNOWN_CLOSED, terminate, NOT PASS |
| Closure after COMMITTED | Science may already have begun; PID-1-owned deadline action stops/kills within reserved deadline; verify no descendants |
| Broker dies before COMMITTED | PTRACE_O_EXITKILL must terminate all tracees; deadline action independently cancels/stops unit; no new broker authorization |
| Broker dies after COMMITTED | PTRACE_O_EXITKILL is additional fail-closed protection; PID-1 workload RuntimeMaxSec and deadline action remain authoritative |
| Gate dies or execve fails | No valid TRACEEXEC event; terminate/record no admission |
| Communication failure | No release; deadline action independent; UNKNOWN_CLOSED if state cannot be proven |
| Duplicate/replayed request | Single-use nonce and exact invocation/task match reject; no second CONT |
| Stale or replacement job | Broker sole manager start authority; reject wrong unit/job/invocation; deadline reconciles |
| Ambiguous TRACEEXEC/CONT/stop state | UNKNOWN_CLOSED; kill, no retry and no PASS |

## Authority
| Actor | Authority | Explicit prohibition |
|---|---|---|
| PID 1 | Envelope, deadline action, scientific unit resource/runtime limits, stop/kill | No inference of proven timing from configured properties |
| Privileged broker | Exclusive admission/closure serialization; ptrace trace/release; sole workload start submission | Cannot reopen CLOSED or extend T0 deadlines |
| Deadline action | Independently initiate irreversible closure and stop/cancel exact workload unit/job | Cannot rely on broker responsiveness |
| Unprivileged in-unit gate | Request preauthorization and execve unchanged science under trace | Cannot release ptrace stop, start new unit or change limits |
| Controller | Request admission and inspect evidence | No direct systemd start/stop/replacement privileges |
| Scientific process | Run inside constrained cgroup only after broker release | No ptrace/broker/systemd privileges |

## Deadline and qualification obligations
All states and delays remain inside original T0 envelope. RuntimeMaxSec R is calculated conservatively from original T0, subtracting full queue/activation allowance and stop reserve; workload gate and trace stops consume R, not an added interval. Independent PID-1 deadline action closes admission and cancels/stops pending/running workload by the previously fixed T0+540 target, with termination verification by +570, local sealing by +585, envelope normal exit by +590 and whole invocation by +600. Missing/late/unknown state or seal => NOT PASS, even if science completed.

The **design-level** mutual ordering follows from a sole broker event loop, exclusive CONT authority and one-shot CLOSED state. **Not yet demonstrated:** exact kernel PTRACE_O_TRACEEXEC stop-before-user-code semantics on installed kernel; PTRACE_O_EXITKILL behavior on broker death for all traced tasks; correct tracing across fork/clone/thread/exec transitions; exact ptrace permissions/Yama/capability and cgroup interactions; proof of exclusive tracer and absence of alternate exec path; no untraced descendants; event-loop ordering and durable state receipts; PTRACE_CONT success/ambiguity treatment; PID-1 timer/job/stop races; bounded latency to deadlines. These require separately authorized harmless synthetic control-only qualification. If any kernel/permission behavior cannot be established, NO SCIENCE and EC-01 HOLD.

No general lifecycle redesign, new scientific watchdog, environment change, workflow dispatch, probe, or scientific execution is authorized.
