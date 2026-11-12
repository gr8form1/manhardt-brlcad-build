# Manhardt Audio — M1 IR-01 EC-01 Focused Resolution
Date: 2026-11-12
Status: DOCUMENTARY — EC-01 HOLD. EC-02 through EC-05 documentary acceptance preserved. No workflow dispatch, qualification probe, scientific execution, source alteration, or changed scientific thresholds/resources.

## 1. Decision
The most coherent candidate is one PID-1-managed Type=oneshot invocation-envelope service. Its TimeoutStartSec includes its entire activation phase, unlike RuntimeMaxSec, which does not apply to Type=oneshot. All invocation-specific archive acquisition, authentication, extraction, guard activation, controller startup, scientific admission, science, stopping, verification and local sealing occur during this single activation. This closes the conceptual pre-armed-timer gap in v0.2 but DOES NOT prove a strict 600-second upper bound under scheduling, kernel, storage or host failure. No successive guard layers are proposed.

## 2. Trusted enforcement boundary and exact unit types
Envelope: m1-ir01-envelope-ID.service, system-manager PID 1 owned, Type=oneshot, RemainAfterExit=no, Restart=no, TimeoutStartSec=590s, TimeoutStartFailureMode=terminate (subject to host-version verification), TimeoutStopSec=5s, KillMode=control-group, SendSIGKILL=yes, Delegate=no. One reviewed ExecStart launcher, with no invocation-related ExecStartPre/ExecStartPost/ExecCondition outside the accounted sequence. No Type=notify or timeout extensions. PID 1 owns activation timeout even if GitHub shell/controller fails. Controller runs inside envelope service cgroup.
Workload: separate PID-1-owned Type=exec service, Restart=no, RemainAfterExit=no, TimeoutStartSec=10s, TimeoutStopSec=2s, KillMode=control-group, SendSIGKILL=yes, Delegate=no, MemoryMax=1073741824, MemorySwapMax=0; retain EC-02/03 privilege, cgroup and secondary active-runtime controls. Workload process starts in its own cgroup by systemd, not the GitHub shell. Critically, killing the envelope cgroup does NOT kill this separate workload cgroup. The accepted workload unit runtime/stop policy is a necessary independent fallback, not a new timer layer. A controller death may prevent evidence sealing and forces NOT PASS.
The root/system manager and privileged host actors can modify/stop units; workload must not have that authority.

## 3. Authoritative start and ordering
Candidate T0: PID 1 begins envelope activation, evidenced by a manager activation-begin monotonic timestamp (such as InactiveExitTimestampMonotonic, after checking host-version semantics), not by controller exec or scientific start. Type=oneshot stays activating until ExecStart exits. GitHub submits only the start request for a reusable, pre-reviewed generic unit. If the GitHub start-request-to-PID-1 activation queue interval is contractually part of the invocation, this candidate does NOT cover it: no atomic enforcement begins at the GitHub request.
No invocation-specific work before T0. At T0 launcher begins its recorded sequence; authenticate source and safe-extract; activate and verify workload restrictions; admit science only if all preconditions pass and sufficient absolute time remains. No science if setup is incomplete at T0+60s. No relative deadline resets after late preparation. If a unit start partially succeeds, verify actual PID-1 unit identity and cgroup properties before science; otherwise STOP. If controller never starts, use PID-1 start-job status, journal and unit properties; never fabricate controller receipts.

## 4. Composed budget
T0 to +60s: setup, source authentication, extraction, guard activation, controller start and admission (PID-1 envelope start timeout + controller cutoff).
By T0+540s: science stops (controller plus workload service active-runtime/stop policy).
By T0+570s: escalation, all descendants stopped, unit lifecycle and cgroup verified.
By T0+585s: local evidence sealing with hashes, timestamps and fsync/atomic publication; remote delivery is later and cannot cure late sealing.
By T0+590s: envelope normally exits, else PID 1 activation timeout fires.
590–600s: nominal 10-second stop reserve, including requested TimeoutStopSec=5s; this is NOT a worst-case guaranteed bound. TimeoutStopSec is not proof that kernel scheduling, process exit, evidence flush or cleanup completes by 600s.
All target times are monotonic offsets from the same T0. A setup stall causes start timeout and no scientific admission; controller failure may leave only systemd journal evidence; workload service must independently time out. A seal missing at +585s means NOT PASS regardless of scientific outcome.

## 5. Systemd semantic verification
Official systemd.service documentation: TimeoutStartSec limits service activation; Type=oneshot defaults to no startup timeout; RuntimeMaxSec has no effect on Type=oneshot; TimeoutStopSec governs stop escalation, not hard real-time completion. Type=notify can extend timeouts and is not selected. Official systemd.timer documentation: OnActiveSec is relative to timer activation, and AccuracySec introduces tolerance; separate timer activation is not an atomic T0.
Sources: https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html ; https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html .
These are upstream documentary semantics, not verification of the runner's installed systemd version. Before implementation, confirm the exact supported properties, monotonic timestamp semantics, and stop behavior for that version. No probe is authorized now.

## 6. Reusable versus invocation-specific work
Reusable prior qualification: Python 3.12, cgroup v2, synthetic resource and termination observations, reviewed generic launcher/unit template, approved source digest. Reusable preinstalled templates must be generic and separately authorized. Invocation-specific archive fetch, digest, manifest verification, extraction, directory creation, cgroup admission, guard activation and all setup are AFTER T0. A pre-T0 invocation-specific action invalidates the claim.

## 7. Partial activation and evidence
No PID-1 activation: NOT_STARTED, report start-job failure/journal; do not invent T0. Activation begun but controller never execs: STARTUP_FAILURE, manager activation timestamp, unit Result/SubState, journal and exit status if available. Controller dies after workload admission: existing PID-1 workload timeouts remain; local seal may be absent and completion fails. Workload start uncertain: STOP, never admit science. A missing systemd receipt is UNKNOWN, not PASS. An absent cgroup without lifecycle proof is UNKNOWN. Remote upload is separate from timely local seal.

## 8. Residual impossibility and contract decision
This candidate does not prove (a) inclusion of GitHub request queue time if invocation begins at request; (b) bounded stop, descendant disappearance and storage sealing under arbitrary host/kernel/scheduler failure; or (c) guaranteed timely local evidence sealing when controller dies or storage stalls. Therefore EC-01 cannot be independently closed as an unconditional hard 600-second whole-invocation completion guarantee on this environment.
Return to founder for a contract choice: A) define the ceiling from PID-1 activation under explicit healthy-host assumptions, with successful timely seal mandatory for PASS but not guaranteed on failure; or B) retain unconditional all-failure-mode bound and use a stronger externally controlled execution environment. No choice is presumed. EC-01 HOLD. EC-02–EC-05 documentary acceptance unchanged. No scientific execution.
