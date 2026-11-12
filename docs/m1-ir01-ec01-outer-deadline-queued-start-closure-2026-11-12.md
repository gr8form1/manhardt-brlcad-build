# Manhardt Audio — M1 IR-01 EC-01 Outer Deadline and Queued-Start Closure
Date: 2026-11-12
Status: Focused documentary design; independent acceptance and separately authorized control-only qualification pending.
Base: docs/m1-ir01-ec01-deadline-composition-correction-2026-11-12.md
Preserved: EC-02–EC-05, healthy-host model, original T0 and 600-second invocation boundary, conservative remaining-runtime calculation, in-unit pre-exec admission gate, 1 GiB and zero swap, unchanged scientific service and source. No execution authorization.

## Focused design diff

ADD one root-owned invocation-scoped admission/closure broker and one PID-1-owned deadline trigger/action. These are control-plane elements, not scientific watchdogs. The broker is the **sole** authority permitted to submit, replace, start, stop or cancel the invocation workload unit/job. The unprivileged controller can request admission but has no direct StartUnit/StopUnit/SetUnitProperties/transient-unit authority. The scientific workload has none. The broker persists a CLOSED tombstone before acknowledging closure; the tombstone is never cleared within that invocation. An independent deadline action invokes broker closure and, regardless of broker availability, independently asks PID 1 to stop/kill the exact workload cgroup and invalidate queued start jobs. If the broker cannot be reached or termination cannot be proved, NOT PASS.

### Ownership and ordering
T0 remains the manager-observed monotonic start of the Type=oneshot envelope. Within this already-counted activation, the privileged setup creates an exact unpredictable invocation ID and root-owned invocation record, computes deadline offsets from T0, provisions the generic root-owned deadline service/timer and broker binding, and arms the deadline action. **Before any workload start request is possible**, verify PID-1 timer/service identity, active state, monotonic next-elapse timestamp and deadline relation to T0; verify the broker's deny-by-default admission policy. If arming cannot be proved, no workload start. A timer armed after T0 must be scheduled from the remaining original T0 allowance, never from a fresh full duration. A systemd timer's AccuracySec, RandomizedDelaySec, scheduling slack and manager queue latency must be included in the reserved budget; exact deadline precision is a qualification obligation, not inferred from configuration. The deadline trigger must remain live independently of envelope/controller lifecycle. A privileged actor may intentionally disrupt PID 1 under the accepted healthy-host threat boundary; workload cannot.

Use one deadline action with a conservative closure target no later than T0+540s, with explicit slack reserved for start-job cancellation, stop escalation and descendant verification by T0+570s, local seal by T0+585s, envelope normal exit by T0+590s and total invocation ceiling T0+600s. A timer whose latest permitted effective dispatch would exceed the closure target is not armable.

### Invocation identity
Bind invocation ID, manager-monotonic T0, absolute deadlines, timer and action unit IDs, broker record, workload unit name and systemd InvocationID, pending start-job ID/path, gate token, CLOSED state, journal cursor, lifecycle/cgroup receipts and seal digest. All start/stop/cancel operations require exact unit identity and invocation record match; a stale job or unit from another invocation cannot be reused. Root-owned state has an atomic persistent CLOSED tombstone, never a reversible boolean reset. Unit name uniqueness and no restart/replacement after closure are required. If PID-1 job identity changes or is unobservable, no science / NOT PASS.

### Irreversible closure protocol
Admission begins CLOSED-BY-DEFAULT (not yet OPEN). The broker transitions to OPEN only after deadline arming, effective unit/property verification, remaining-runtime and queue budget proof, and token binding. All start submissions go through the broker's serialized root-only interface. The deadline action acquires closure authority, writes and durably commits CLOSED before any cleanup attempt, revokes token, blocks new starts, and requests PID-1 job cancellation and unit stop/kill. A controller death cannot reopen admission. Broker restart must reload the tombstone; unknown state is CLOSED. Workload in-unit gate obtains a fresh broker-issued, single-use authorization bound to exact unit/manager InvocationID and original T0 immediately before exec of scientific code. A gate that cannot obtain affirmative OPEN authorization exits. The broker must serialize gate authorization with closure. **A gate authorization already returned just before closure does not itself guarantee that science cannot exec afterward**: the design must use a held lease/handshake or a PID-1-enforced frozen/blocked execution state so that closure waits for or revokes the last possible exec transition. The exact atomicity and behavior of this critical section must be proven in control-only qualification; absent that proof the architecture remains HOLD. Once science has started, closure terminates it rather than retroactively denying its start.

### Queued and running workload
On closure, broker atomically forbids new starts, identifies the exact pending job, requests cancellation (where supported) and issues StopUnit for the exact workload unit, including one activating concurrently. PID 1 must own final process-tree termination with KillMode=control-group, SendSIGKILL=yes, TimeoutStopSec=2s and retained RuntimeMaxSec. A StopUnit request or CancelJob return is not proof that no activation remains. The action must reconcile job removal, unit state, cgroup descendants and any reappearing activation until a stable quiescent state is demonstrated. Any unknown, mismatched or resurrected job/unit fails acceptance. Because systemd D-Bus calls are not assumed atomic across job cancellation and concurrent activation, broker admission closure and in-unit gate must be independently effective. If an old queued job activates after closure, the gate denies science and the deadline action terminates it; a new effective start is unauthorized and must be prevented by root-owned access control. Deadline action must remain independent of controller and must not rely solely on late gate execution.

## Ownership / permission table

| Actor | Allowed | Forbidden |
|---|---|---|
| PID 1/system manager | Own envelope, deadline trigger/action, workload start/stop/kill, runtime limits, job lifecycle | Treat a requested timeout as proof of expiry |
| Root-owned broker | Sole submit/cancel/stop authority; immutable invocation record and CLOSED tombstone; serialize gate/closure | Reopen CLOSED or extend original deadline |
| Deadline action | Close admission independently, cancel/stop exact job/unit, reconcile termination and receipts | Delegate closure to controller |
| Unprivileged controller | Request admission, inspect receipts, seal evidence when authorized | Start/restart/replace units, alter timer, tombstone or limits |
| In-unit admission gate | Verify bound token, OPEN state, effective limits/deadline, then exec unchanged science | Submit jobs, reopen, extend runtime |
| Scientific process | Operate within workload cgroup | Manager D-Bus privileges, move cgroups, change limits or restart |
| Independent reviewer | Authenticate records and decide acceptance | Infer success from missing receipts |

## State / race table

| Situation | Required transition/action | Successful completion? |
|---|---|---|
| T0, deadline not armed | UNARMED -> deny start; no science | No |
| Timer armed and verified | ARMED -> OPEN only with all checks | Possible |
| Normal early start | OPEN -> QUEUED -> GATED -> RUNNING; original deadline preserved | Only with verified stop/seal |
| Late start or inadequate remaining time | OPEN -> DENIED; no StartUnit | No science |
| Start queued when closure fires | OPEN/QUEUED -> CLOSED, revoke, cancel job, StopUnit; gate denies late activation | Only if termination and seal verified |
| Activation concurrent with closure | Closure serializes with gate's final exec authority; stop activating unit; no late scientific exec | Unknown race -> NOT PASS |
| Controller dies before submission | Deadline remains armed; no controller privilege to start | No science; completion requires receipts |
| Controller dies after submission, before activation | Deadline action cancels/stops; gate denies if closure; unit independent limits | Missing receipts -> NOT PASS |
| Controller dies during admission | Gate cannot rely on controller; broker serialization determines OPEN/CLOSED; no ambiguous exec | Unknown -> NOT PASS |
| Controller dies after science starts | PID 1 enforces R and deadline action closes/stops; seal may be absent | Missing timely seal -> NOT PASS |
| Broker/action failure | Fail-closed on unavailable broker; independent PID-1 workload runtime remains; unknown closure/kill -> NOT PASS | No |
| Deadline reached with surviving descendant | Stop/escalate and verify; no PASS | No |
| Restart/replay/stale job after CLOSED | Tombstone rejects; manager permissions forbid replacement; detect/reconcile | No |
| Missing/late local seal | Never PASS, even if science succeeded | No |

## Qualification obligations (no execution authorized)
Q1 Verify exact installed systemd timer trigger semantics, AccuracySec/slack, timer next-elapse and independent persistence after controller death.
Q2 Verify no workload StartUnit/RunTransientUnit/SetUnitProperties/RestartUnit privilege for controller, workload or their descendants, including alternate D-Bus and sudo paths.
Q3 Verify root-owned broker serialization, atomic durable CLOSED tombstone, restart recovery and immutable invocation binding; attempt replay and cross-invocation substitution.
Q4 Inject queued StartUnit and deadline closure simultaneously; inspect manager job ID, unit activation, cancellation, stop, cgroup emptiness and gate decision. A CancelJob acknowledgement alone is not PASS.
Q5 Inject closure during gate-to-exec race; demonstrate no scientific payload starts after CLOSED. If this cannot be demonstrated, the design is NOT ACCEPTED. Use synthetic harmless payload only.
Q6 Controller death before submit, after submit, during gate and after synthetic payload startup; verify deadline action still runs, queued/running jobs quiesce, receipts correctly classify missing evidence.
Q7 Late timer arming, delayed manager queue, late workload activation and minimum runtime rejection; verify absolute T0 budget is never reset and PID-1 workload R remains independently effective.
Q8 Verify stop/kill escalation and descendant containment, time-to-quiescence by +570s, local seal by +585s, envelope by +590s, whole invocation by +600s under qualified healthy-host scheduling.
Q9 Verify failures of timer, broker, job introspection, event receipts and evidence storage cannot yield PASS; inspect actual properties rather than relying on requested settings.

## Disposition
Documentary design specifies ownership, ordering, identity, closure and race obligations; no assertion that systemd timer and D-Bus transaction semantics have already been proven. In particular gate-to-exec atomicity and queued-start cancellation/termination require separately authorized control-only implementation qualification. EC-01 remains HOLD pending independent architecture review. EC-02–EC-05 documentary acceptance unchanged. No workflow dispatch or scientific execution.
