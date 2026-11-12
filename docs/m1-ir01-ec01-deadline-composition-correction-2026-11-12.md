# M1 IR-01 — EC-01 Minimum Deadline-Composition Correction
Date: 2026-11-12. Documentary only. EC-02–EC-05 and accepted healthy-host assumptions unchanged. No execution authorized.

## Focused diff to EC-01 focused resolution
REPLACE the static workload runtime assumption with a per-invocation RuntimeMaxSec assigned before activation. Workload remains PID-1 Type=exec, Restart=no, KillMode=control-group, SendSIGKILL=yes, TimeoutStartSec=10s, TimeoutStopSec=2s, MemoryMax=1073741824, MemorySwapMax=0, MemorySwapMax verified effective. The oneshot envelope retains TimeoutStartSec=590s. A workload relative runtime is never a new 540-second allowance.

ADD absolute monotonic deadlines referenced to original manager-observed envelope activation T0: science stopped by T0+540; descendant verification by T0+570; local seal by T0+585; envelope exit by T0+590; overall ceiling T0+600.

At configuration time t_cfg, define A as the enforceable maximum from configuration through manager job queue and Type=exec activation until workload RuntimeMaxSec begins; S as reserved stop/escalation time; V as verification reserve. Assign R>0 only when R <= (T0+540)-t_cfg-A-S and t_cfg+A+R+S+V <= T0+570. Reduce R as setup runs late; reject admission if R is nonpositive, below the approved scientific minimum, or insufficient time remains for cleanup and seal. No clock reset.

TimeoutStartSec=10s bounds the service start phase but is not demonstrated to bound the manager job queue. A must explicitly include and enforce queue delay. If A cannot be bounded by PID 1 or an equally independent mechanism under controller failure, do not admit science. A mere controller calculation before start is insufficient.

Scientific code MUST remain behind a fail-closed in-unit pre-exec admission gate, counted inside workload runtime. The gate verifies original T0, effective PID-1 properties, activation timestamp, containment, guard, limits and the inequality t_active+R+S <= T0+540 before exec of the unchanged reviewed scientific source. A controller post-start check is not sufficient because scientific code could already have begun. If the gate cannot authenticate any property, it exits without science. It must not extend unit runtime or create another watchdog.

PID 1 owns workload RuntimeMaxSec after controller death, but stopping the envelope does not stop the separate workload unit. A queued start surviving controller death is safe only if the in-unit gate denies late activation; to prove a hard independent deadline, the queue bound A must itself be enforced, not just observed.

## Four timing cases
1. Normal: early t_cfg; bounded A deducted; gate checks effective unit and original clock; science runs only within R; PID 1 runtime expiry and stop reserve precede T0+540; verification and local seal meet subsequent deadlines.
2. Late: t_cfg increases, R decreases one-for-one. If insufficient time remains for minimum science plus A/S/V/sealing, NO ADMISSION, seal reason if possible.
3. Activation delay/failure: queued job time counts toward A; TimeoutStartSec bounds only relevant activation; late activation must be denied by in-unit gate; unit failure and manager receipts preserved. No science on partial activation.
4. Controller death before admission: no science without in-unit gate and independent effective properties; after admission: PID 1 still enforces preconfigured R and stop policy, but missing verified cleanup or timely local seal is NOT PASS.

## Required effective readbacks and receipts
Manager-monotonic T0, t_cfg, t_active; unit ID and PID-1 ownership; RuntimeMaxSec, TimeoutStartSec, TimeoutStopSec, Restart, KillMode, SendSIGKILL, MemoryMax, MemorySwapMax, cgroup placement, guard activation, pre-exec gate decision, bounded queue evidence, stop/cgroup lifecycle and locally sealed evidence timestamp/hash. Missing or contradictory values mean NO ADMISSION or NOT PASS. Remote upload cannot cure late local sealing.

## Review disposition
Minimum correction specified, but a bounded and independently enforceable manager queue interval A remains an explicit proof obligation. The Type=exec start timeout alone does not establish it. If A is not implementable under the accepted assumptions, return that precise incompatibility; do not add general watchdogs or change environment. EC-01 HOLD pending review; EC-02–EC-05 documentary acceptance preserved.