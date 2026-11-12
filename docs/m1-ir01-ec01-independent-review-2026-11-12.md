# Manhardt Audio — M1 IR-01 EC-01 Independent Focused Review
Date: 2026-11-12
Disposition: SPECIFIC INCOMPATIBILITY; MINIMUM CORRECTION REQUIRED. EC-02–EC-05 documentary acceptance preserved.

## Governing interpretation
Founder selected the qualified healthy-host enforcement model already assumed by EC-05. Do not demand survival of arbitrary host failure. The 600-second envelope remains invocation-wide, including setup, guard, controller, science, stopping and timely local sealing. Missing or late receipts prohibit PASS. No dispatch, probes or scientific execution.

## Accepted elements
PID-1-owned Type=oneshot envelope with explicit TimeoutStartSec=590s accounts for invocation-specific preparation in the activation phase; RuntimeMaxSec is inapplicable to oneshot. The authoritative proposed T0 is PID-1 activation start, provided no invocation-specific preparation precedes it and the contract agrees that a bare start request is not itself invocation preparation. Scientific work runs in a separate PID-1-owned Type=exec service with MemoryMax=1 GiB, MemorySwapMax=0, KillMode=control-group, Restart=no, and verified descendant containment. Local seal is separate from remote delivery. No scientific result overrides missing cleanup or evidence.

## Remaining incompatibility EC-01-R1
Envelope timeout kills only envelope cgroup. It does not kill the independently managed workload service. The proposed separate workload RuntimeMaxSec is relative to workload activation and is not explicitly derived from the original envelope T0. A late workload activation or a controller crash can therefore allow science to persist beyond the invocation-wide stopping deadline, despite the healthy systemd/kernel assumptions. Merely retaining a static 540-second workload runtime is insufficient.

## Minimum correction
1. Fix T0 as a manager-observed monotonic envelope activation event. Require a verified manager timestamp and a monotonic-clock-compatible time calculation; absent/unverifiable T0 means no science. Specify exact property availability on installed systemd during later authorized qualification.
2. Before workload admission, compute remaining permitted runtime from the same T0, with an absolute workload kill target no later than T0+540s (and reserve for the independent stop policy). The workload unit's systemd-enforced RuntimeMaxSec must be set **before** its activation to at most the remaining interval, reduced by the maximum permitted activation delay and stop/escalation reserve; read back and authenticate the effective value and unit identity before science. If a conservative bound for activation delay cannot be established, the unit must not be admitted; do not reset the 540s allowance at activation.
3. Ensure the workload unit is already under PID-1 enforcement before the controller can signal successful admission. A controller crash must not remove or extend the workload timeout. A PID-1 workload timeout/stop receipt, final cgroup emptiness (or unit lifecycle evidence explaining cgroup removal), and timely local seal are mandatory for PASS. If controller death prevents seal, FAIL/UNKNOWN, not PASS.
4. Resolve the separate issue of any invocation-specific preparation occurring before PID-1 envelope activation: a generic pre-reviewed unit can be installed before T0, but source acquisition, per-invocation unit instantiation and other unique setup cannot. State explicitly whether the bare GitHub start request is excluded from the contract; if not, this architecture cannot cover the request-to-activation interval.
5. Specify the actual systemd start/stop unit properties and timing offsets, including TimeoutStartSec=590s for oneshot, TimeoutStopSec=5s, Type=exec workload TimeoutStartSec=10s and TimeoutStopSec=2s, Restart=no, KillMode=control-group, SendSIGKILL=yes. Do not confuse these configured values with demonstrated deadline enforcement. A workload service with its own 10s activation timeout must account for that delay in its remaining-time calculation.

## Disposition
**Option 2:** specific remaining incompatibility, minimum correction above. EC-01 remains HOLD pending documentary correction and independent acceptance. EC-02–EC-05 remain documentarily accepted. No workflow construction, dispatch, qualification or scientific execution authorized.
