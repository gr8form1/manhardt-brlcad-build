# Manhardt Audio — M1 IR-01 short synthetic qualification, approval candidate

Date: 2026-11-12. Status: **OFFLINE STATIC REVIEW ONLY; NOT DISPATCHED**.

## Exact identity and scope

- Public repository: `gr8form1/manhardt-brlcad-build`.
- Originating commit: `96e8722e2c2b8d79452651c2754ebebaf8db98ef`.
- Target: `.github/workflows/m1-ir01-final-synthetic-qualification.yml`.
- Git blob SHA-1 of the fetched baseline: `5598df9a8b8e8c4e94bcfd71fc771edce557da33`.
- Previously successful short mechanism test: run `43291411801`; its evidence and outcome are reused, not claimed as a complete sandbox qualification.
- Deliverable patch: `ir01-qualification.patch`. No repository edits, workflow dispatch, scientific tests, private-source upload, Lenovo action, or paid usage are authorized by preparing this document.

## Offline static verification performed

1. Baseline reconstructed byte-for-byte and its Git blob SHA-1 computed equal to the connector-returned blob SHA.
2. `git apply --check` and `git apply` passed in an isolated local directory; the patched file compared byte-identically to the proposed revised workflow.
3. YAML parsed; the outer Python 3.12-compatible code and the embedded synthetic child code both parsed with Python's AST parser. This is a **syntax** check, not runtime qualification.
4. Ambiguous `systemd-run` submission now triggers cleanup: `attempted=True` is set *before* invocation. Structured `cleanup[]` and `failures[]` records are persisted in `result.json`; cleanup commands are bounded to 5 seconds each, and post-cleanup quiescence is checked. Nonzero cleanup commands for an already absent unit are recorded and assessed against final quiescence; cleanup exceptions or unverified quiescence cause FAIL.
5. Added systemd properties are explicit, not optional. The short synthetic workload checks effective readbacks and direct negative/positive probes. Unsupported or ineffective controls fail qualification; there is no fallback or relaxation.

**Static limitations:** The actual GitHub runner has not yet executed the revised file. `journalctl` visibility, systemd property availability, effective sandboxing and complete evidence upload are runtime acceptance questions. This is exactly why one bounded synthetic dispatch is proposed. `IPAddressDeny=any` and `RestrictAddressFamilies=AF_UNIX` both apply to the test service, not the GitHub job's control process. No source archive is needed for this run.

## Runtime PASS criteria — short source-free synthetic only

- GitHub-hosted standard `ubuntu-24.04`, Python 3.12, five-minute job timeout; no packages installed or repository checkout.
- Transient unique systemd service runs under the runner's non-root UID; dedicated `/system.slice/<unit>` cgroup observed with parent and child; both ignore SIGTERM.
- `memory.max=1073741824`, `memory.swap.max=0`; effective `KillMode=control-group`, `SendSIGKILL=yes`, `RuntimeMaxUSec=3s`, `TimeoutStopUSec=1s`; process IDs and cgroup path retained.
- Effective sandbox properties read back exactly: `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `IPAddressDeny=any`, `RestrictAddressFamilies=AF_UNIX`. Empty capability bounding set requested; readback is not treated as proved unless separately observed or probed.
- Direct service probe confirms `/etc/hostname` cannot be opened for writing (no write attempted), an AF_INET socket cannot be created, and a disposable `/tmp` marker can be written and removed within the service's private temporary directory.
- Systemd runtime expiry terminates the resistant parent and child; final service state failed/inactive and cgroup absent/empty within the existing 12-second short observation window.
- `evidence/result.json`, `evidence/qualification.log` and `evidence/service-journal.txt` (on success) preserved; artifact upload succeeds with 7-day retention. If service/journal or upload is missing, no PASS may be issued.
- Any unsupported property, missing observation, ineffective restriction, uncontained process, ambiguous termination, cleanup exception or unresolved cleanup state results in FAIL, with all available evidence retained and the unique service stopped/killed/reset as appropriate. If GitHub itself terminates the job before evidence upload, that is **INDETERMINATE/FAIL for qualification**, never PASS.

## What this short test does not establish

- No actual memory exhaustion is induced; the readback and previously observed cgroup behavior do not prove an OOM-kill response. No swap-pressure test is induced.
- It does not test every descendant escape strategy, privileged process, filesystem location, network namespace or host resource.
- It does not establish the later 540/570/600-second invocation procedure or absolute cessation at 600 seconds. The amended policy is: independently initiate stop by original T0+540 s, target quiescence by T0+570 s, operational deadline T0+600 s; any overrun or incomplete evidence requires explicit disposition, not automatic scientific invalidation or a fabricated PASS.
- The later scientific authorization must separately authenticate the private archive bytes and extracted manifest, review the actual command and resource needs, prove the independent stopping path and original-T0 accounting, ensure all descendants and outputs are bounded, and preserve full scientific/regression/adversarial/frozen-reference evidence. Source SHA-256 reported: `00b7c8139a7c5a154253ce2288564e157a4bb672b903594afb574a1d3077ed4f` (64 hex digits); byte-level authentication outstanding, **not a blocker for this source-free synthetic run**.

## Billing — separate pre-dispatch gate

- GitHub published terms: standard GitHub-hosted runners in public repositories are free; `ubuntu-24.04` is a standard runner. This proposal does not request a larger runner or private repository.
- Artifact storage is separate from compute. This run retains a small evidence artifact for 7 days. A small artifact is not evidence of unused included storage.
- **No paid storage exposure authorized.** Before dispatch, owner should confirm in GitHub **Settings → Billing and licensing → Usage** the current Actions artifacts/Packages storage usage and applicable included allowance, and in **Budgets and alerts** whether a storage budget prevents overages (rather than only notifying). If paid overage is enabled and usage could exceed allowance, do not dispatch until storage exposure is disabled or separately authorized.

## Exact consolidated founder decision requested

**Approve (1) application of `ir01-qualification.patch` to the identified existing public repository workflow and filing of this qualification document; and (2) one manually dispatched, source-free synthetic qualification using the revised workflow on GitHub's standard `ubuntu-24.04` runner, capped at 5 job minutes, 3 seconds systemd runtime, 1 GiB memory, zero swap, and 7-day evidence retention, strictly conditioned on no paid storage exposure.**

This approval would NOT authorize additional runs, scientific execution, private archive transfer, paid capacity, Lenovo actions, NV31 work, a ptrace/broker architecture, or relaxation of failed controls. Founder approval is pending.