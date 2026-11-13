#!/usr/bin/env python3
"""Bounded non-scientific runner qualification for M1 IR-01.

This program MUST NOT import or execute private m1.py. It imports the independently
accepted v7 supervisor as a support library, exercises its control helpers against a
synthetic sleep/descendant fixture, and records public-safe evidence only.

BRQ-01 v3 preserves the founder-approved operational timing interpretation and distinguishes independent deadline action events:
- pre-call stop-request time;
- systemctl command return time;
- marker creation time;
- marker first-observation time.
A latched accepted-v7 guard miss or guard fallback is never a normal-deadline PASS.
For BRQ-01 qualification only, no separate numerical maximum positive stop-request
lateness is imposed; actual lateness is recorded and prominently reported. This does
not prove stop initiation occurred no later than exactly T0+540 and does not bound
scheduling or observation delay. Later scientific-execution timing semantics remain
a separate approval question.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import inspect
import json
import os
import pathlib
import secrets
import subprocess
import sys
import time
import uuid

MEM_MAX = 1073741824
STOP_S = 540.0
QUIET_S = 570.0
TIMEOUT_S = 600.0
MAX_EVIDENCE_BYTES = 1048576


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path, obj):
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


def run(args, timeout=30, check=False, env=None):
    return subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=check, env=env)


def load_supervisor(path):
    p = pathlib.Path(path).resolve(strict=True)
    sys.path.insert(0, str(p.parent))
    spec = importlib.util.spec_from_file_location("ma_m1_supervisor_v7", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def safe_summary(r):
    return {
        "returncode": r.returncode,
        "stdout_sha256": hashlib.sha256((r.stdout or "").encode()).hexdigest(),
        "stderr_sha256": hashlib.sha256((r.stderr or "").encode()).hexdigest(),
        "stdout_bytes": len((r.stdout or "").encode()),
        "stderr_bytes": len((r.stderr or "").encode()),
    }


def safe_exception(stage, exc):
    # Never serialize exception text: it can contain private paths, source excerpts,
    # command lines, or other diagnostics. The stage and exception class are enough
    # for public evidence; detailed diagnostics remain runner-private.
    return {"stage": str(stage), "error_type": type(exc).__name__}


def api_probe(python_exe, evidence_path):
    # Deliberately non-scientific: obtaining the callable and inspecting its Python
    # signature is allowed; the Helmholtz operator is NEVER called or assembled.
    code = r'''
import inspect,json,numpy as np
import bempp_cl.api as bempp
from bempp_cl.api.grid.grid import Grid
from numba import njit
@njit
def inc(x): return x+1
assert inc(41)==42
vertices=np.array([[1.,-1.,-1.,1.],[1.,-1.,1.,-1.],[1.,1.,-1.,-1.]],dtype=float)/np.sqrt(3.)
elements=np.array([[0,0,0,1],[2,1,3,2],[1,3,2,3]],dtype=np.uint32)
grid=Grid(vertices,elements)
space=bempp.function_space(grid,'P',1)
assert int(space.global_dof_count)==4
sl=bempp.operators.boundary.helmholtz.single_layer
sig=str(inspect.signature(sl))
assert callable(sl)
print(json.dumps({'status':'PASS_NONSCIENTIFIC_API','grid_dofs':int(space.global_dof_count),
                  'single_layer_signature':sig,'single_layer_called':False,
                  'operator_assembled':False,'scientific_solve_executed':False,
                  'numba_njit_result':int(inc(1))},sort_keys=True))
'''
    r = run([str(python_exe), "-c", code], timeout=60)
    if r.returncode:
        raise RuntimeError("NONSCIENTIFIC_API_PROBE_FAILED")
    obj = json.loads(r.stdout)
    if obj.get("single_layer_called") is not False or obj.get("operator_assembled") is not False or obj.get("scientific_solve_executed") is not False:
        raise RuntimeError("NONSCIENTIFIC_API_SCOPE_VIOLATION")
    write_json(evidence_path, obj)
    return obj


def fixture_source():
    return r'''from __future__ import annotations
import argparse,json,os,pathlib,signal,subprocess,time
ap=argparse.ArgumentParser()
ap.add_argument('--authorized-run-token',required=True)
ap.add_argument('--output-dir',required=True)
ap.add_argument('--level',required=True);ap.add_argument('--frequency',required=True);ap.add_argument('--phase',required=True)
a=ap.parse_args()
if not os.environ.get('MA_M1_RUN_TOKEN') or os.environ['MA_M1_RUN_TOKEN']!=a.authorized_run_token: raise SystemExit(70)
out=pathlib.Path(a.output_dir);out.mkdir(parents=True,exist_ok=True)
(out/'fixture_started.json').write_text(json.dumps({'status':'NONSCIENTIFIC_FIXTURE_STARTED','pid':os.getpid()},sort_keys=True)+'\n')
signal.signal(signal.SIGTERM,signal.SIG_IGN)
subprocess.Popen(['/usr/bin/python3.12','-c','import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(700)'])
time.sleep(700)
'''


def capture_marker_observations(markers, observed, t0_ns):
    """Record when this harness first observes each already-created marker."""
    for key in ("stop", "quiescence", "timeout"):
        if key not in observed and isinstance(markers.get(key), dict):
            now_ns = time.monotonic_ns()
            observed[key] = {
                "marker_first_observed_monotonic_ns": str(now_ns),
                "marker_first_observed_elapsed_s": (now_ns - int(t0_ns)) / 1e9,
            }


def int_field(obj, key):
    try:
        return int(obj[key])
    except (KeyError, TypeError, ValueError):
        return None


def deadline_mechanism_assessment(markers, marker_observations, guard_miss, fallback_used, first_post_540_observation, quiescence_elapsed_s, t0_ns):
    """Assess the *normal* deadline mechanism separately from fail-closed fallback.

    The accepted v7 guard is authoritative: a guard miss is latched and immediately
    disqualifies normal-mechanism PASS even if fallback containment later succeeds.
    +570 remains the quiescence target; it is not a replacement stop-request deadline.
    """
    out = {
        "normal_deadline_mechanism_qualified": False,
        "fail_closed_fallback_observed": bool(guard_miss and fallback_used),
        "governing_stop_boundary_s": STOP_S,
        "quiescence_target_s": QUIET_S,
        "timing_policy": "BRQ01_FOUNDER_OPERATIONAL_INTERPRETATION_2026-11-13",
        "separate_max_positive_stop_request_lateness_s": None,
        "pass_does_not_prove_stop_request_no_later_than_exact_t0_plus_540": True,
        "pass_does_not_bound_scheduling_or_marker_observation_delay": True,
        "scientific_execution_timing_semantics_unchanged_and_require_separate_approval": True,
        "guard_miss_latched": bool(guard_miss),
        "guard_fallback_used": bool(fallback_used),
        "first_post_540_guard_observation": first_post_540_observation,
        "stop_event_evidence": None,
        "reason_codes": [],
    }
    stop = markers.get("stop") if isinstance(markers, dict) else None
    obs = marker_observations.get("stop") if isinstance(marker_observations, dict) else None
    if not isinstance(stop, dict):
        out["reason_codes"].append("STOP_MARKER_MISSING")
        return out
    if str(stop.get("t0_monotonic_ns")) != str(t0_ns) or float(stop.get("target_s", -1)) != STOP_S or stop.get("mode") != "stop":
        out["reason_codes"].append("STOP_MARKER_IDENTITY_INVALID")
        return out
    request_ns = int_field(stop, "stop_request_pre_call_monotonic_ns")
    return_ns = int_field(stop, "stop_command_return_monotonic_ns")
    created_ns = int_field(stop, "marker_created_observed_monotonic_ns")
    observed_ns = int_field(obs or {}, "marker_first_observed_monotonic_ns")
    if None in (request_ns, return_ns, created_ns, observed_ns):
        out["reason_codes"].append("STOP_EVENT_TIMESTAMPS_INCOMPLETE")
        return out
    request_elapsed = (request_ns - int(t0_ns)) / 1e9
    return_elapsed = (return_ns - int(t0_ns)) / 1e9
    created_elapsed = (created_ns - int(t0_ns)) / 1e9
    observed_elapsed = (observed_ns - int(t0_ns)) / 1e9
    out["stop_event_evidence"] = {
        "stop_request_pre_call_elapsed_s": request_elapsed,
        "stop_command_return_elapsed_s": return_elapsed,
        "marker_created_observed_elapsed_s": created_elapsed,
        "marker_first_observed_elapsed_s": observed_elapsed,
        "stop_request_lateness_from_target_s": request_elapsed - STOP_S,
        "action_returncode": stop.get("action_returncode"),
        "registration_status": stop.get("registration_status"),
    }
    if not (request_ns <= return_ns <= created_ns <= observed_ns):
        out["reason_codes"].append("STOP_EVENT_ORDER_INVALID")
    if request_elapsed < STOP_S:
        out["reason_codes"].append("STOP_REQUEST_PREDATES_GOVERNING_BOUNDARY")
    if stop.get("registration_status") != "verified" or int(stop.get("action_returncode", -1)) != 0:
        out["reason_codes"].append("STOP_REQUEST_NOT_VERIFIED_SUCCESSFUL")
    if not isinstance(first_post_540_observation, dict) or float(first_post_540_observation.get("elapsed_s", -1)) < STOP_S:
        out["reason_codes"].append("POST_540_GUARD_OBSERVATION_MISSING")
    elif first_post_540_observation.get("stop_marker_present") is not True:
        out["reason_codes"].append("STOP_MARKER_ABSENT_AT_FIRST_POST_540_GUARD_OBSERVATION")
    if guard_miss:
        out["reason_codes"].append("V7_DEADLINE_GUARD_MISS_LATCHED")
    if fallback_used:
        out["reason_codes"].append("V7_GUARD_FALLBACK_USED")
    if quiescence_elapsed_s is None or float(quiescence_elapsed_s) > QUIET_S:
        out["reason_codes"].append("QUIESCENCE_TARGET_NOT_MET")
    out["normal_deadline_mechanism_qualified"] = not out["reason_codes"]
    return out


def _direct_cgroup_cleanup_readback(control_group, cgroup):
    """Independently distinguish removed, readable-empty, and unreadable boundaries.

    The accepted v7 supervisor intentionally has broader runtime read helpers. Cleanup
    needs stricter evidence: if the boundary still exists, both cgroup.procs and
    cgroup.events must be independently readable here. Raw content is never serialized.
    """
    if not control_group:
        return {
            "cgroup_readback_status": "NO_CONTROL_GROUP_REPORTED",
            "cgroup_procs_readable": False,
            "cgroup_events_readable": False,
            "cgroup_process_count": None,
            "cgroup_populated": None,
        }
    if not cgroup.get("exists"):
        return {
            "cgroup_readback_status": "REMOVED",
            "cgroup_procs_readable": True,
            "cgroup_events_readable": True,
            "cgroup_process_count": 0,
            "cgroup_populated": False,
        }
    p = pathlib.Path("/sys/fs/cgroup") / control_group.lstrip("/")
    try:
        procs = [x for x in (p / "cgroup.procs").read_text().splitlines() if x.strip()]
        procs_readable = True
    except OSError:
        procs = None
        procs_readable = False
    try:
        events = (p / "cgroup.events").read_text()
        fields = {}
        for line in events.splitlines():
            parts = line.split()
            if len(parts) == 2:
                fields[parts[0]] = parts[1]
        populated = (fields.get("populated") == "1") if "populated" in fields else None
        events_readable = populated is not None
    except OSError:
        populated = None
        events_readable = False
    return {
        "cgroup_readback_status": "READABLE" if procs_readable and events_readable else "UNREADABLE",
        "cgroup_procs_readable": procs_readable,
        "cgroup_events_readable": events_readable,
        "cgroup_process_count": len(procs) if procs is not None else None,
        "cgroup_populated": populated,
    }


def unit_snapshot(sup, unit, control_group_hint=""):
    rc, fields, _ = sup.service_show(unit)
    control_group = fields.get("ControlGroup", "") if rc == 0 else ""
    control_group = control_group or control_group_hint
    cgroup = sup.read_cgroup(control_group)
    direct = _direct_cgroup_cleanup_readback(control_group, cgroup)
    return {
        "service_show_rc": rc,
        "active_state": fields.get("ActiveState") if rc == 0 else None,
        "sub_state": fields.get("SubState") if rc == 0 else None,
        "control_group": control_group,
        "cgroup_exists": bool(cgroup.get("exists")),
        **direct,
    }


def snapshot_quiescent(snapshot):
    """General workload quiescence observation; not sufficient for cleanup success."""
    return snapshot.get("cgroup_readback_status") == "REMOVED" or (
        snapshot.get("cgroup_readback_status") == "READABLE"
        and snapshot.get("cgroup_process_count") == 0
        and snapshot.get("cgroup_populated") is False
    )


def cleanup_snapshot_resolved(snapshot):
    """R4a cleanup predicate: terminated service AND empty/removed containment."""
    if not isinstance(snapshot, dict) or snapshot.get("service_show_rc") != 0:
        return False
    if snapshot.get("active_state") not in {"inactive", "failed"}:
        return False
    status = snapshot.get("cgroup_readback_status")
    if status in {"REMOVED", "NO_CONTROL_GROUP_REPORTED"}:
        return True
    if status != "READABLE":
        return False
    return snapshot.get("cgroup_process_count") == 0 and snapshot.get("cgroup_populated") is False


def bounded_unit_cleanup(sup, unit, control_group_hint, proc, deadline_dir, registration_installed):
    """Bounded teardown with readback before registration removal.

    Cleanup failure remains an explicit unresolved exposure. We do not rely on eventual
    GitHub-runner destruction and we never serialize raw command output.
    """
    record = {
        "unit": unit,
        "attempts": [],
        "control_process": {"known": proc is not None, "resolved": proc is None},
        "registration_removed": False,
        "registration_preserved_due_to_unresolved_cleanup": False,
        "cleanup_status_established": False,
        "cleanup_unresolved_exposure": False,
    }
    if not unit:
        record["cleanup_status_established"] = True
        record["final"] = {"no_unit_registered": True}
        return record

    try:
        rr = run(["sudo", "-n", "systemctl", "stop", "--no-block", unit], timeout=8)
        record["attempts"].append({"action": "stop_no_block", **safe_summary(rr)})
    except BaseException as exc:
        record["attempts"].append({"action": "stop_no_block", "error_type": type(exc).__name__})

    deadline = time.monotonic() + 3.0
    snap = None
    while time.monotonic() < deadline:
        try:
            snap = unit_snapshot(sup, unit, control_group_hint)
            if cleanup_snapshot_resolved(snap):
                break
        except BaseException:
            snap = None
        time.sleep(0.1)

    if snap is None or not cleanup_snapshot_resolved(snap):
        try:
            rr = run(["sudo", "-n", "systemctl", "kill", "--kill-who=all", "--signal=SIGKILL", unit], timeout=8)
            record["attempts"].append({"action": "kill_all_sigkill", **safe_summary(rr)})
        except BaseException as exc:
            record["attempts"].append({"action": "kill_all_sigkill", "error_type": type(exc).__name__})
        deadline = time.monotonic() + 4.0
        while time.monotonic() < deadline:
            try:
                snap = unit_snapshot(sup, unit, control_group_hint)
                if cleanup_snapshot_resolved(snap):
                    break
            except BaseException:
                snap = None
            time.sleep(0.1)

    # Reconcile the local systemd-run --wait --pipe control process separately from
    # workload/cgroup quiescence. Raw stdout/stderr never enter public evidence.
    if proc is not None:
        if proc.poll() is None:
            try:
                out, err = proc.communicate(timeout=2)
                record["control_process"] = {"known": True, "resolved": True, "returncode": proc.returncode,
                                             "stdout_sha256": hashlib.sha256((out or "").encode()).hexdigest(),
                                             "stderr_sha256": hashlib.sha256((err or "").encode()).hexdigest()}
            except subprocess.TimeoutExpired:
                try:
                    proc.terminate()
                    out, err = proc.communicate(timeout=1)
                    record["control_process"] = {"known": True, "resolved": True, "terminated": True, "returncode": proc.returncode,
                                                 "stdout_sha256": hashlib.sha256((out or "").encode()).hexdigest(),
                                                 "stderr_sha256": hashlib.sha256((err or "").encode()).hexdigest()}
                except subprocess.TimeoutExpired:
                    try:
                        proc.kill()
                        out, err = proc.communicate(timeout=1)
                        record["control_process"] = {"known": True, "resolved": True, "killed": True, "returncode": proc.returncode,
                                                     "stdout_sha256": hashlib.sha256((out or "").encode()).hexdigest(),
                                                     "stderr_sha256": hashlib.sha256((err or "").encode()).hexdigest()}
                    except BaseException as exc:
                        record["control_process"] = {"known": True, "resolved": False, "error_type": type(exc).__name__}
        else:
            try:
                out, err = proc.communicate(timeout=1)
            except BaseException:
                out, err = "", ""
            record["control_process"] = {"known": True, "resolved": True, "returncode": proc.returncode,
                                         "stdout_sha256": hashlib.sha256((out or "").encode()).hexdigest(),
                                         "stderr_sha256": hashlib.sha256((err or "").encode()).hexdigest()}

    try:
        final = unit_snapshot(sup, unit, (snap or {}).get("control_group", control_group_hint))
    except BaseException as exc:
        final = {"readback_error_type": type(exc).__name__}
    record["final"] = final
    workload_resolved = bool(final and "readback_error_type" not in final and cleanup_snapshot_resolved(final))
    control_resolved = bool(record["control_process"].get("resolved"))
    record["cleanup_status_established"] = True
    record["cleanup_unresolved_exposure"] = not (workload_resolved and control_resolved)

    # Only after the cleanup status is established do we discard registration state.
    if registration_installed and not record["cleanup_unresolved_exposure"]:
        try:
            rr = sup.remove_unit_registration(deadline_dir)
            record["registration_removed"] = rr.get("returncode") == 0
            record["registration_remove_result"] = rr
        except BaseException as exc:
            record["registration_remove_result"] = {"error_type": type(exc).__name__}
            record["cleanup_unresolved_exposure"] = True
    elif registration_installed:
        record["registration_preserved_due_to_unresolved_cleanup"] = True

    if not record["cleanup_unresolved_exposure"]:
        try:
            rr = run(["sudo", "-n", "systemctl", "reset-failed", unit], timeout=8)
            record["attempts"].append({"action": "reset_failed_after_readback", **safe_summary(rr)})
        except BaseException as exc:
            record["attempts"].append({"action": "reset_failed_after_readback", "error_type": type(exc).__name__})
    return record


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--supervisor", required=True)
    ap.add_argument("--gate", required=True)
    ap.add_argument("--source-dir", required=True)
    ap.add_argument("--source-admission-receipt", required=True)
    ap.add_argument("--python", required=True)
    ap.add_argument("--bempp-checkout", required=True)
    ap.add_argument("--t0-monotonic-ns", required=True)
    ap.add_argument("--deadline-control-dir", required=True)
    ap.add_argument("--gate-control-dir", required=True)
    ap.add_argument("--evidence-root", required=True)
    a = ap.parse_args()

    evidence = pathlib.Path(a.evidence_root).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    t0_ns = int(a.t0_monotonic_ns)
    t0 = t0_ns / 1e9
    stage = "initialization"
    sup = None
    deadline_dir = None
    gate_dir = None
    gate = None
    source = None
    fixture = None
    fifo = None
    cap_file = None
    proc = None
    unit = None
    control_group = ""
    registration_installed = False
    workload_started = False
    failures = []
    marker_observations = {}
    observations = []
    guard_miss = False
    fallback_used = False
    fallback_evidence = None
    quiescence = None
    first_post_540_observation = None
    result = {
        "schema": "MA-M1-NONSCIENTIFIC-RUNNER-QUAL-v2",
        "status": "INCOMPLETE",
        "scientific_solver_executed": False,
        "private_m1_imported_or_executed": False,
        "acoustic_operator_called_or_assembled": False,
        "t0_monotonic_ns": str(t0_ns),
    }

    try:
        stage = "load_accepted_support"
        sup = load_supervisor(a.supervisor)
        source = pathlib.Path(a.source_dir).resolve(strict=True)
        gate = pathlib.Path(a.gate).resolve(strict=True)
        gate_dir = pathlib.Path(a.gate_control_dir).resolve(strict=True)
        deadline_dir = pathlib.Path(a.deadline_control_dir).resolve(strict=True)

        stage = "source_admission_receipt"
        admission = json.loads(pathlib.Path(a.source_admission_receipt).read_text())
        if admission.get("state") != "ADMITTED_PRIVATE_SOURCE":
            raise RuntimeError("SOURCE_NOT_ADMITTED")
        if float(admission.get("admission_timing", {}).get("completed_elapsed_s", 1e99)) >= 60.0:
            raise RuntimeError("SOURCE_ADMISSION_LATE")
        # The private source is authenticated but m1.py is never imported or executed.
        if not (source / "m1.py").is_file():
            raise RuntimeError("PRIVATE_M1_EXPECTED_BUT_NOT_EXECUTED")

        stage = "deadline_preflight"
        arm = sup.load_deadline_arm(deadline_dir, t0_ns)
        preflight = sup.deadline_preflight(arm, t0, deadline_dir)

        stage = "dependency_probe"
        deps = sup.dep_probe(pathlib.Path(a.python).resolve(strict=True), json.loads((source / "dependency.lock").read_text()), pathlib.Path(a.bempp_checkout).resolve(strict=True))
        write_json(evidence / "dependency-observed.json", deps)

        stage = "non_scientific_api_probe"
        api = api_probe(pathlib.Path(a.python).resolve(strict=True), evidence / "api-probe.json")
        if time.monotonic() - t0 >= STOP_S:
            raise RuntimeError("QUALIFICATION_PREPARATION_REACHED_T0_PLUS_540")

        stage = "fixture_setup"
        fixture = gate_dir / "m1_non_scientific_fixture.py"
        fixture.write_text(fixture_source())
        fixture.chmod(0o500)
        fixture_sha = sha(fixture)
        unit_name = f"ma-m1-{os.environ['GITHUB_RUN_ID']}-{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}-{uuid.uuid4().hex[:8]}"
        unit = unit_name + ".service"
        work = evidence / "fixture-work"
        work.mkdir(mode=0o700)
        payload = work / "payload"
        fifo = gate_dir / (unit_name + ".fifo")
        os.mkfifo(fifo, 0o600)
        cap_file = gate_dir / (unit_name + ".env")
        capability = secrets.token_urlsafe(32)
        fd = os.open(cap_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("MA_M1_RUN_CAPABILITY=" + capability + "\n")
        cap_sha = hashlib.sha256(capability.encode()).hexdigest()

        stage = "unit_registration"
        gh = {k: os.environ.get(k, "") for k in ("GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA", "GITHUB_WORKFLOW_REF")}
        reg = sup.install_unit_registration(deadline_dir, gate_dir, unit, gh)
        registration_installed = True
        snap = sup.fresh_deadline_snapshot(t0, deadline_dir)
        capture_marker_observations(snap["markers"], marker_observations, t0_ns)
        if snap["elapsed_s"] >= STOP_S or snap["markers"]["stop"] or snap["markers"]["timeout"]:
            raise RuntimeError("STOP_BOUNDARY_BEFORE_FIXTURE")
        runtime = max(1.0, STOP_S - snap["elapsed_s"])
        gate_argv = [
            sys.executable, str(gate), "--release-fifo", str(fifo), "--t0-monotonic-ns", str(t0_ns), "--release-cutoff-s", "540.0",
            "--python", str(pathlib.Path(a.python).resolve()), "--m1", str(fixture), "--output-dir", str(payload),
            "--level", "2", "--frequency", "500.0", "--phase", "real",
        ]
        cmd = [
            "sudo", "-n", "systemd-run", "--wait", "--pipe", "--unit=" + unit,
            "--property=User=" + str(os.getuid()), "--property=MemoryAccounting=yes", "--property=MemoryMax=" + str(MEM_MAX),
            "--property=MemorySwapMax=0", "--property=TasksMax=256", "--property=RuntimeMaxSec=" + f"{runtime:.3f}s",
            "--property=KillMode=control-group", "--property=SendSIGKILL=yes", "--property=TimeoutStopSec=30s",
            "--property=NoNewPrivileges=yes", "--property=ProtectSystem=strict", "--property=ProtectHome=read-only", "--property=PrivateTmp=yes",
            "--property=RestrictAddressFamilies=AF_UNIX", "--property=IPAddressDeny=any", "--property=CapabilityBoundingSet=",
            "--property=ReadOnlyPaths=" + str(source), "--property=ReadWritePaths=" + str(work), "--property=EnvironmentFile=" + str(cap_file), "--", *gate_argv,
        ]
        result.update({
            "support": {"supervisor_sha256": sha(a.supervisor), "gate_sha256": sha(gate), "fixture_sha256": fixture_sha},
            "source_admission_receipt_sha256": sha(a.source_admission_receipt),
            "private_source_archive_sha256": admission.get("archive_sha256"),
            "dependency_probe": deps,
            "api_probe": api,
            "deadline_preflight": preflight,
            "fixture_capability_sha256": cap_sha,
            "unit": unit,
            "unit_registration": reg,
        })

        stage = "start_fixture_service"
        proc = subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        workload_started = True
        deadline = min(t0 + STOP_S, time.monotonic() + 30)
        controls = False
        while time.monotonic() < deadline:
            rc, fields, _ = sup.service_show(unit)
            cg = fields.get("ControlGroup", "") if rc == 0 else ""
            cgs = sup.read_cgroup(cg)
            runtime_obs = sup.parse_systemd_timespan(fields.get("RuntimeMaxUSec")) if rc == 0 else None
            stop_timeout = sup.parse_systemd_timespan(fields.get("TimeoutStopUSec")) if rc == 0 else None
            if cg and cgs["exists"] and sup.cgroup_populated(cgs) is True and cgs["memory_max"] == str(MEM_MAX) and cgs["swap_max"] == "0" and fields.get("KillMode") == "control-group" and fields.get("SendSIGKILL") == "yes" and stop_timeout is not None and stop_timeout <= 30.5 and runtime_obs is not None:
                control_group = cg
                controls = True
                break
            if proc.poll() is not None:
                break
            time.sleep(0.2)
        if not controls:
            raise RuntimeError("CONTROL_READBACK_FAILED")

        stage = "sandbox_readback"
        props = ["NoNewPrivileges", "ProtectSystem", "ProtectHome", "PrivateTmp", "RestrictAddressFamilies", "IPAddressDeny", "CapabilityBoundingSet"]
        pr = run(["sudo", "-n", "systemctl", "show", unit, *sum((["-p", p] for p in props), [])], timeout=8)
        if pr.returncode:
            raise RuntimeError("SANDBOX_READBACK_FAILED")
        pmap = sup.parse_show(pr.stdout)
        if pmap.get("NoNewPrivileges") != "yes" or pmap.get("ProtectSystem") != "strict" or pmap.get("ProtectHome") != "read-only" or pmap.get("PrivateTmp") != "yes" or pmap.get("RestrictAddressFamilies", "").strip() != "AF_UNIX" or pmap.get("IPAddressDeny") not in ("any", "::/0 0.0.0.0/0", "0.0.0.0/0 ::/0"):
            raise RuntimeError("SANDBOX_PROPERTY_MISMATCH")
        if (payload / "fixture_started.json").exists():
            raise RuntimeError("FIXTURE_STARTED_BEFORE_RELEASE")

        stage = "gate_release"
        cap_file.unlink(missing_ok=True)
        sup.deadline_preflight(arm, t0, deadline_dir)
        sup.release_gate(fifo, min(t0 + STOP_S, time.monotonic() + 5.0))
        started_deadline = time.monotonic() + 10
        while time.monotonic() < started_deadline:
            cgs = sup.read_cgroup(control_group)
            procs = cgs.get("procs") or []
            if (payload / "fixture_started.json").is_file() and len(procs) >= 2:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("FIXTURE_OR_DESCENDANT_NOT_OBSERVED")
        result["control_readback"] = {"control_group": control_group, "memory_max": cgs.get("memory_max"), "swap_max": cgs.get("swap_max"), "process_count": len(procs), "sandbox": pmap}
        if cgs.get("memory_max") != str(MEM_MAX) or cgs.get("swap_max") != "0" or len(procs) < 2:
            raise RuntimeError("CGROUP_ENFORCEMENT_MISMATCH")

        stage = "deadline_observation"
        end = t0 + 610.0
        while time.monotonic() < end:
            rc, fields, _ = sup.service_show(unit)
            cg = fields.get("ControlGroup", control_group) if rc == 0 else control_group
            cgs = sup.read_cgroup(cg)
            ds = sup.fresh_deadline_snapshot(t0, deadline_dir)
            elapsed = ds["elapsed_s"]
            capture_marker_observations(ds["markers"], marker_observations, t0_ns)
            quiescent = proc.poll() is not None and (not cgs.get("exists") or sup.cgroup_populated(cgs) is False) and not (cgs.get("procs") or [])
            if elapsed >= STOP_S and first_post_540_observation is None:
                first_post_540_observation = {"elapsed_s": elapsed, "stop_marker_present": ds["markers"]["stop"] is not None}
            decision = sup.adjudicate_monitor_observation(elapsed, ds["markers"]["stop"] is not None, quiescent, guard_miss)
            guard_miss = decision["deadline_guard_miss"]
            if decision["issue_fallback_stop"] and not fallback_used:
                req_ns = time.monotonic_ns()
                rr = run(["sudo", "-n", "systemctl", "stop", "--no-block", unit], timeout=8)
                ret_ns = time.monotonic_ns()
                fallback_evidence = {
                    "fallback_stop_request_pre_call_monotonic_ns": str(req_ns),
                    "fallback_stop_command_return_monotonic_ns": str(ret_ns),
                    "command": safe_summary(rr),
                }
                fallback_used = True
            if quiescent and quiescence is None:
                quiescence = elapsed
            if len(observations) < 1200:
                observations.append({
                    "elapsed_s": round(elapsed, 6), "active": fields.get("ActiveState"), "pids": len(cgs.get("procs") or []),
                    "stop_marker": ds["markers"]["stop"] is not None, "quiescence_marker": ds["markers"]["quiescence"] is not None,
                    "timeout_marker": ds["markers"]["timeout"] is not None, "guard_miss": guard_miss,
                })
            if elapsed >= 605 and ds["markers"]["stop"] is not None and ds["markers"]["quiescence"] is not None and ds["markers"]["timeout"] is not None:
                break
            time.sleep(0.25)

        final = sup.fresh_deadline_snapshot(t0, deadline_dir)
        capture_marker_observations(final["markers"], marker_observations, t0_ns)
        markers = final["markers"]
        if not all(markers.get(k) for k in ("stop", "quiescence", "timeout")):
            failures.append("DEADLINE_MARKER_SET_INCOMPLETE")
        for key, target in (("quiescence", QUIET_S), ("timeout", TIMEOUT_S)):
            marker = markers.get(key)
            if not isinstance(marker, dict) or float(marker.get("target_s", -1)) != target or str(marker.get("t0_monotonic_ns")) != str(t0_ns):
                failures.append("INVALID_" + key.upper() + "_MARKER")
                continue
            created_ns = int_field(marker, "marker_created_observed_monotonic_ns")
            if created_ns is None:
                failures.append(key.upper() + "_MARKER_CREATION_TIME_MISSING")
            elif (created_ns - t0_ns) / 1e9 < target:
                failures.append(key.upper() + "_MARKER_PREDATES_TARGET")
        if quiescence is None or quiescence > QUIET_S:
            failures.append("QUIESCENCE_NOT_OBSERVED_BY_T0_PLUS_570")

        assessment = deadline_mechanism_assessment(markers, marker_observations, guard_miss, fallback_used, first_post_540_observation, quiescence, t0_ns)
        if not assessment["normal_deadline_mechanism_qualified"]:
            failures.append("NORMAL_DEADLINE_MECHANISM_NOT_QUALIFIED")
        result.update({
            "deadline_markers": markers,
            "marker_first_observations": marker_observations,
            "deadline_guard_miss": guard_miss,
            "fallback_stop_used": fallback_used,
            "fallback_stop_evidence": fallback_evidence,
            "deadline_mechanism_assessment": assessment,
            "quiescence_first_observed_elapsed_s": quiescence,
            "t0_plus_570_quiescence_target_met": bool(quiescence is not None and quiescence <= QUIET_S),
            "observations": observations,
        })

    except BaseException as exc:
        failures.append("EXCEPTIONAL_QUALIFICATION_EXIT")
        result["sanitized_exception"] = safe_exception(stage, exc)
    finally:
        cleanup = None
        if sup is not None and deadline_dir is not None:
            try:
                cleanup = bounded_unit_cleanup(sup, unit, control_group, proc, deadline_dir, registration_installed)
            except BaseException as exc:
                cleanup = {"cleanup_status_established": False, "cleanup_unresolved_exposure": True, "error_type": type(exc).__name__}
        else:
            cleanup = {"cleanup_status_established": True, "cleanup_unresolved_exposure": False, "no_runtime_unit_possible": True}
        if cleanup.get("cleanup_unresolved_exposure"):
            failures.append("CLEANUP_UNRESOLVED_EXPOSURE")

        # Delete runner-private fixture material only after workload/control cleanup is
        # positively established. On unresolved cleanup it remains runner-private for
        # forensic inspection and is never placed in the public evidence tree.
        if not cleanup.get("cleanup_unresolved_exposure"):
            for p in (cap_file, fifo, fixture):
                if p is not None:
                    try:
                        pathlib.Path(p).unlink(missing_ok=True)
                    except OSError:
                        failures.append("PRIVATE_FIXTURE_CLEANUP_FAILED")

        result["cleanup"] = cleanup
        result["failures"] = sorted(set(failures))
        normal_ok = bool(result.get("deadline_mechanism_assessment", {}).get("normal_deadline_mechanism_qualified"))
        result["fail_closed_fallback_containment_demonstrated"] = bool(
            result.get("deadline_guard_miss") and result.get("fallback_stop_used") and quiescence is not None and quiescence <= QUIET_S and not cleanup.get("cleanup_unresolved_exposure")
        )
        result["status"] = "PASS_NONSCIENTIFIC_RUNNER_QUALIFICATION" if not result["failures"] and normal_ok else "FAIL_NONSCIENTIFIC_RUNNER_QUALIFICATION"
        write_json(evidence / "qualification.json", result)
        total = sum(p.stat().st_size for p in evidence.rglob("*") if p.is_file())
        if total > MAX_EVIDENCE_BYTES:
            # The workflow's independent evidence validator will suppress upload.
            result["status"] = "FAIL_NONSCIENTIFIC_RUNNER_QUALIFICATION"
            result["failures"] = sorted(set(result["failures"] + ["PUBLIC_EVIDENCE_SIZE_CAP_EXCEEDED"]))
            result["evidence_size_bytes"] = total
            write_json(evidence / "qualification.json", result)

    print(json.dumps({
        "status": result["status"],
        "normal_deadline_mechanism_qualified": bool(result.get("deadline_mechanism_assessment", {}).get("normal_deadline_mechanism_qualified")),
        "fail_closed_fallback_containment_demonstrated": bool(result.get("fail_closed_fallback_containment_demonstrated")),
        "cleanup_unresolved_exposure": bool(result.get("cleanup", {}).get("cleanup_unresolved_exposure")),
        "failure_count": len(result.get("failures", [])),
    }, sort_keys=True))
    return 0 if result["status"] == "PASS_NONSCIENTIFIC_RUNNER_QUALIFICATION" else 1


if __name__ == "__main__":
    try:
        _rc = main()
    except BaseException as _fatal:
        # Last-resort public-log safety: never allow Python to emit a raw traceback.
        print(json.dumps({"status":"FAIL_HARNESS_FATAL","error_type":type(_fatal).__name__},sort_keys=True),file=sys.stderr)
        _rc = 2
    raise SystemExit(_rc)
