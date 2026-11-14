#!/usr/bin/env python3
"""Source-free M1 BRQ timer diagnostic. PROPOSED; NEVER AUTORUN.

The two reviewed readback functions are imported from exactly hash-verified,
unchanged implementation files. This module contains no alternative verifier.
Failures are represented by fixed codes; no subprocess output is published.
"""
from __future__ import annotations

import hashlib
import types
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ARM_SHA = '839cbb827afe2663ee7e987c9a3ac56c7ddc617390c7e81a93959b91c56aad30'
SUPERVISOR_SHA = '09ddf1f5e9d6e6b7d4c1c662bff54607e494119265b6c669928aa6954211c380'
CUSTODY_SHA = '28e858d9ec14b6bec642938db8afbf257f19a2108d36892abf9cdf06468f1ab6'
TARGET_S = 540
ARM_LEAD_S = 2
MAX_SETUP_AND_READBACK_S = 45
MAX_PREARM_ELAPSED_S = 80
CLEANUP_BUDGET_S = 12
MAX_TIMER_COMMAND_S = 5
MAX_TEARDOWN_COMMAND_S = 3
SCHEMA = 'MA-M1-BRQ-SOURCEFREE-DIAG-v3.1'

class DiagnosticFailure(Exception):
    """Only a fixed code may propagate beyond the process."""


def _fail(code):
    raise DiagnosticFailure(code)


def exact_unit_identity():
    run_id = os.environ.get('GITHUB_RUN_ID', '')
    attempt = os.environ.get('GITHUB_RUN_ATTEMPT', '')
    if (re.fullmatch(r'[0-9]{1,20}', run_id, re.ASCII) is None
            or re.fullmatch(r'[0-9]{1,10}', attempt, re.ASCII) is None):
        _fail('INVALID_INVOCATION_IDENTITY')
    base = f'ma-m1-t0-stop-{run_id}-{attempt}'
    return base, base + '.timer', base + '.service'


def code_root():
    # Exact accepted bytes are staged in this dedicated diagnostic namespace.
    # Do NOT replace the existing public BRQ support/supervisor.py: that public
    # commit still pins the predecessor source and must remain unchanged.
    support = Path(__file__).resolve().parent
    return support, support / 'accepted_initial_arm_source.py'


def authenticated_source_bytes(path, expected_sha):
    """Read, authenticate, then compile THESE bytes (never an importlib pycache)."""
    try:
        if not path.is_file() or path.is_symlink():
            _fail('IMPLEMENTATION_IDENTITY_MISMATCH')
        source = path.read_bytes()
        if hashlib.sha256(source).hexdigest() != expected_sha:
            _fail('IMPLEMENTATION_IDENTITY_MISMATCH')
        return source
    except OSError:
        _fail('IMPLEMENTATION_IDENTITY_MISMATCH')


def auth_bytes(path, expected_sha):
    authenticated_source_bytes(path, expected_sha)


def _execute_authenticated(module_name, path, source_bytes):
    mod = types.ModuleType(module_name)
    mod.__file__ = str(path)
    mod.__package__ = ''
    exec(compile(source_bytes, str(path), 'exec', dont_inherit=True), mod.__dict__)
    return mod


def load_exact_sources():
    support, arm_file = code_root()
    supervisor_file = support / 'supervisor.py'
    custody_file = support / 'custody.py'
    # Read and hash the exact source that is executed, before T0 or timer creation.
    arm_bytes = authenticated_source_bytes(arm_file, ARM_SHA)
    supervisor_bytes = authenticated_source_bytes(supervisor_file, SUPERVISOR_SHA)
    custody_bytes = authenticated_source_bytes(custody_file, CUSTODY_SHA)
    # An existing 'custody' cache entry (even with a forged __file__) is not trusted.
    if 'custody' in sys.modules:
        _fail('IMPLEMENTATION_IMPORT_IDENTITY_MISMATCH')
    try:
        arm = _execute_authenticated('m1_reviewed_initial_arm', arm_file, arm_bytes)
        custody = _execute_authenticated('custody', custody_file, custody_bytes)
        # The unchanged supervisor contains `from custody import ...`. Bind that
        # absolute import to the freshly compiled, authenticated source object.
        sys.modules['custody'] = custody
        try:
            supervisor = _execute_authenticated('m1_reviewed_supervisor', supervisor_file,
                                                supervisor_bytes)
            if sys.modules.get('custody') is not custody:
                _fail('IMPLEMENTATION_IMPORT_IDENTITY_MISMATCH')
            for name in ('open_dir_nofollow', 'create_child_dir', 'write_exclusive'):
                bound = getattr(supervisor, name, None)
                trusted = getattr(custody, name, None)
                if (bound is not trusted or not isinstance(bound, types.FunctionType)
                        or bound.__globals__ is not custody.__dict__):
                    _fail('IMPLEMENTATION_IMPORT_IDENTITY_MISMATCH')
            # The imported names now resolve to verified function *objects*,
            # not a module that happens to advertise a matching pathname.
        finally:
            if sys.modules.get('custody') is custody:
                del sys.modules['custody']
        auth_bytes(arm_file, ARM_SHA)
        auth_bytes(supervisor_file, SUPERVISOR_SHA)
        auth_bytes(custody_file, CUSTODY_SHA)
    except DiagnosticFailure:
        raise
    except Exception:
        _fail('IMPLEMENTATION_IMPORT_UNAVAILABLE')
    return arm, supervisor


def prearm_budget_gate():
    """Fail before T0 if checkout/auth consumed the reserved setup window."""
    stamp = Path(os.environ.get('RUNNER_TEMP', '/nonexistent')) / 'm1_sourcefree_job_epoch_ns'
    try:
        value = stamp.read_text(encoding='ascii').strip()
        if not re.fullmatch(r'[0-9]{1,22}', value, re.ASCII):
            _fail('PREARM_BUDGET_UNVERIFIABLE')
        now = time.monotonic_ns()
        if now < int(value) or now - int(value) >= MAX_PREARM_ELAPSED_S * 1_000_000_000:
            _fail('PREARM_BUDGET_EXCEEDED')
    except OSError:
        _fail('PREARM_BUDGET_UNVERIFIABLE')


def bounded(argv, timeout_s, *, allow_nonzero=False, observation=None):
    # Optional fixed-category observation only; argv, timeout and return semantics
    # remain identical to accepted v2. Never retain stdout/stderr in evidence.
    try:
        r = subprocess.run(argv, text=True, capture_output=True, check=False, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        if observation is not None: observation['result'] = 'TIMEOUT'
        return None
    except (OSError, ValueError):
        if observation is not None: observation['result'] = 'UNAVAILABLE'
        return None
    if observation is not None:
        observation['result'] = 'SUCCESS' if r.returncode == 0 else 'NONZERO'
    if not allow_nonzero and r.returncode != 0:
        return None
    return r

def present_timer(timer):
    r = bounded(['sudo', '-n', 'systemctl', 'is-active', '--quiet', timer], 4)
    return r is not None and r.returncode == 0


def arm_one_timer(base, t0_ns):
    now_ns = time.monotonic_ns()
    delay = TARGET_S - ARM_LEAD_S - (now_ns - t0_ns) / 1_000_000_000
    if delay <= 0 or now_ns < t0_ns or now_ns - t0_ns >= MAX_SETUP_AND_READBACK_S * 1_000_000_000:
        _fail('ORIGINAL_T0_SETUP_TOO_LATE')
    # EXACT reviewed unit-name, on-active creation form and AccuracySec=1ms.
    # /usr/bin/true is the only harmless diagnostic action; no source or solver.
    argv = ['sudo', '-n', 'systemd-run', '--quiet', '--unit=' + base,
            '--on-active=' + f'{delay:.6f}s', '--timer-property=AccuracySec=1ms', '/usr/bin/true']
    if bounded(argv, MAX_TIMER_COMMAND_S) is None:
        _fail('TIMER_CREATION_FAILED')


def new_stage_provenance():
    return {'source_authenticated': False, 'prearm_passed': False,
            'timer_active_entered': False, 'timer_active_passed': False, 'initial_arm_entered': False,
            'initial_arm_returned': False, 'initial_arm_record_checked': False,
            'supervisor_entered': False, 'supervisor_value_verified': False,
            'comparison_state': 'NOT_REACHED', 'post_readback_passed': False}


def verified_deadline_equality(arm, supervisor, timer, t0_ns, observations=None):
    # Only the diagnostic observations are new. Accepted verifiers, ordering,
    # rejection conditions, arithmetic and clock sampling are unchanged.
    obs = observations if observations is not None else {}
    stages = obs.setdefault('stages', new_stage_provenance())
    stages['initial_arm_entered'] = True
    try:
        arm_record = arm.verify_timer_schedule(unit=timer, t0_ns=t0_ns,
                                                target_s=540, lead_s=2)
    except Exception:
        _fail('INITIAL_ARM_READBACK_REJECTED')
    stages['initial_arm_returned'] = True
    if (not isinstance(arm_record, dict) or arm_record.get('timer_unit') != timer
            or arm_record.get('key') != 'stop' or arm_record.get('target_s') != 540
            or arm_record.get('arm_lead_s') != 2
            or arm_record.get('verified_not_late') is not True):
        _fail('INITIAL_ARM_RECORD_INVALID')

    # Retain only a positive, target-bound number from a returned accepted
    # record, even if the later supervisor call fails or cleanup is unverified.
    candidate = arm_record.get('next_elapse_monotonic_usec')
    target = t0_ns // 1000 + TARGET_S * 1_000_000
    if (type(candidate) is int and candidate > 0
            and type(arm_record.get('target_monotonic_usec')) is int
            and arm_record['target_monotonic_usec'] == target):
        obs['initial_arm_deadline_monotonic_usec'] = candidate

    stages['supervisor_entered'] = True
    try:
        next_us = supervisor.timer_next_elapse_usec(timer)
    except Exception:
        _fail('SUPERVISOR_READBACK_REJECTED')
    if type(next_us) is not int or next_us <= 0:
        _fail('SUPERVISOR_READBACK_REJECTED')
    stages['supervisor_value_verified'] = True
    obs['supervisor_deadline_monotonic_usec'] = next_us
    observed = arm_record.get('next_elapse_monotonic_usec')
    if (type(observed) is not int or type(arm_record.get('target_monotonic_usec')) is not int
            or arm_record['target_monotonic_usec'] != target):
        _fail('INITIAL_ARM_RECORD_INVALID')
    stages['initial_arm_record_checked'] = True
    stages['comparison_state'] = 'MISMATCH' if observed != next_us else 'MATCH'
    if observed != next_us:
        _fail('INDEPENDENT_DEADLINE_MISMATCH')
    obs['deadline_monotonic_usec'] = next_us
    post_ns = time.monotonic_ns()
    if post_ns >= t0_ns:
        obs['readback_elapsed_ms'] = (post_ns - t0_ns) // 1_000_000
    if post_ns < t0_ns or post_ns >= t0_ns + TARGET_S * 1_000_000_000:
        _fail('ORIGINAL_STOP_BOUNDARY_REACHED')
    if post_ns - t0_ns > MAX_SETUP_AND_READBACK_S * 1_000_000_000:
        _fail('DIAGNOSTIC_READBACK_BUDGET_EXCEEDED')
    stages['post_readback_passed'] = True
    return next_us, (post_ns - t0_ns) // 1_000_000, observed

def _unit_inactive(unit, observation=None):
    command = {}
    r = bounded(['sudo', '-n', 'systemctl', 'show', unit,
                 '-p', 'ActiveState', '-p', 'ControlGroup', '-p', 'Job', '-p', 'LoadState'],
                MAX_TEARDOWN_COMMAND_S, observation=command)
    if r is None:
        if observation is not None:
            observation['result'] = (command.get('result')
                                     if command.get('result') in ('TIMEOUT','NONZERO')
                                     else 'UNAVAILABLE')
        return False
    if not isinstance(r.stdout, str) or len(r.stdout) > 1024:
        if observation is not None: observation['result'] = 'MALFORMED'
        return False
    lines = r.stdout.splitlines()
    if len(lines) != 4 or any(line.count('=') != 1 for line in lines):
        if observation is not None: observation['result'] = 'MALFORMED'
        return False
    props = dict(line.split('=', 1) for line in lines)
    if set(props) != {'ActiveState', 'ControlGroup', 'Job', 'LoadState'}:
        if observation is not None: observation['result'] = 'MALFORMED'
        return False
    # Exact accepted v2 inactivity predicate, no extra query or relaxation.
    positive = (props['ActiveState'] in ('inactive', 'failed')
                and props['ControlGroup'] == ''
                and props['Job'] in ('', '0')
                and props['LoadState'] in ('loaded', 'not-found', 'masked'))
    if observation is not None:
        observation['result'] = 'VERIFIED_INACTIVE' if positive else 'NOT_INACTIVE'
        observation['predicates'] = {
            'ActiveState': 'PASS' if props['ActiveState'] in ('inactive', 'failed') else 'FAIL',
            'ControlGroup': 'PASS' if props['ControlGroup'] == '' else 'FAIL',
            'Job': 'PASS' if props['Job'] in ('', '0') else 'FAIL',
            'LoadState': 'PASS' if props['LoadState'] in ('loaded', 'not-found', 'masked') else 'FAIL',
        }
    return positive

def teardown(base, timer, service, *, registration_uncertainty_unresolved=False):
    # Same stop commands, polling, reset, and positive predicate as v2.
    stop_timer_obs, stop_service_obs = {}, {}
    stop_timer = bounded(['sudo', '-n', 'systemctl', 'stop', timer], MAX_TEARDOWN_COMMAND_S,
                         allow_nonzero=True, observation=stop_timer_obs)
    stop_service = bounded(['sudo', '-n', 'systemctl', 'stop', service], MAX_TEARDOWN_COMMAND_S,
                           allow_nonzero=True, observation=stop_service_obs)
    stop_commands_returned = stop_timer is not None and stop_service is not None
    stop_commands_succeeded = (stop_commands_returned and stop_timer.returncode == 0
                               and stop_service.returncode == 0)
    def stop_class(result, category):
        if result is not None:
            return 'SUCCESS' if result.returncode == 0 else 'NONZERO'
        return category.get('result', 'UNAVAILABLE')
    t_stop, s_stop = stop_class(stop_timer, stop_timer_obs), stop_class(stop_service, stop_service_obs)
    t_state, s_state = {'result':'NOT_REACHED'}, {'result':'NOT_REACHED'}
    def observed_inactive(unit, state):
        result = _unit_inactive(unit, observation=state)
        # Supports offline instrumentation; production always populates state.
        if state.get('result') == 'NOT_REACHED':
            state['result'] = 'VERIFIED_INACTIVE' if result else 'UNAVAILABLE'
        return result
    start = time.monotonic()
    verified = False
    while time.monotonic() - start < CLEANUP_BUDGET_S:
        # One paired evaluation: never mix an earlier service observation with
        # a later timer observation when Python's original AND short-circuits.
        t_state, s_state = {'result':'NOT_REACHED'}, {'result':'NOT_REACHED'}
        if observed_inactive(timer, t_state) and observed_inactive(service, s_state):
            verified = True
            break
        time.sleep(0.1)
    if verified:
        bounded(['sudo', '-n', 'systemctl', 'reset-failed', timer, service],
                MAX_TEARDOWN_COMMAND_S, allow_nonzero=True)
        # Reset/recheck is the terminal observation; retain no earlier pair.
        t_state, s_state = {'result':'NOT_REACHED'}, {'result':'NOT_REACHED'}
        verified = observed_inactive(timer, t_state) and observed_inactive(service, s_state)
    def predicates(state):
        return state.get('predicates', {key: 'NOT_OBSERVED' for key in
               ('ActiveState', 'ControlGroup', 'Job', 'LoadState')})
    return {'stop_commands_returned': bool(stop_commands_returned),
            'stop_commands_succeeded': bool(stop_commands_succeeded),
            'timer_and_service_inactive_verified': bool(verified),
            'registration_uncertainty_unresolved': bool(registration_uncertainty_unresolved),
            'teardown_verified': bool(verified and stop_commands_returned
                                      and not registration_uncertainty_unresolved),
            'timer_stop_result': t_stop, 'service_stop_result': s_stop,
            'timer_state_readback': t_state['result'],
            'service_state_readback': s_state['result'],
            'timer_property_predicates': predicates(t_state),
            'service_property_predicates': predicates(s_state)}


def empty_cleanup(*, uncertainty=True):
    return {'stop_commands_returned': False, 'stop_commands_succeeded': False,
            'timer_and_service_inactive_verified': False,
            'registration_uncertainty_unresolved': bool(uncertainty),
            'teardown_verified': False,
            'timer_stop_result': 'NOT_REACHED', 'service_stop_result': 'NOT_REACHED',
            'timer_state_readback': 'NOT_REACHED', 'service_state_readback': 'NOT_REACHED',
            'timer_property_predicates': {k: 'NOT_OBSERVED' for k in
                ('ActiveState','ControlGroup','Job','LoadState')},
            'service_property_predicates': {k: 'NOT_OBSERVED' for k in
                ('ActiveState','ControlGroup','Job','LoadState')}}

def _update_status_for_final_cleanup(evidence, final_verified):
    """Finalize only the overall outcome and final failure domain.

    Neither primary failure, initial-teardown failure, stage history nor any
    observed deadline may be rewritten by the independent cleanup step.
    """
    p = evidence / 'DIAGNOSTIC_STATUS.json'
    if not p.is_file() or p.is_symlink():
        return False
    record = json.loads(p.read_text(encoding='utf-8'))
    if record.get('schema') != SCHEMA or record.get('outcome') not in ('HOLD', 'PENDING_FINAL_CLEANUP'):
        return False
    record['final_teardown_failure_code'] = ('NONE' if final_verified
                                             else 'FINAL_TEARDOWN_UNVERIFIED')
    initial_ok = record.get('initial_teardown_failure_code') == 'NONE'
    stages = record.get('stage_provenance', {})
    required_stages = ('source_authenticated','prearm_passed','timer_active_entered','timer_active_passed',
                       'initial_arm_entered','initial_arm_returned','initial_arm_record_checked',
                       'supervisor_entered','supervisor_value_verified','post_readback_passed')
    initial_us = record.get('initial_arm_deadline_monotonic_usec')
    supervisor_us = record.get('supervisor_deadline_monotonic_usec')
    elapsed_ms = record.get('readback_elapsed_ms')
    diagnostic_ok = (
        record.get('primary_diagnostic_failure_code') == 'NONE'
        and record.get('initial_source_authenticated') is True
        and record.get('timer_creation_completed') is True
        and record.get('original_t0_captured') is True
        and type(record.get('original_t0_monotonic_ns')) is int
        and record['original_t0_monotonic_ns'] > 0
        and isinstance(stages, dict)
        and all(stages.get(key) is True for key in required_stages)
        and stages.get('comparison_state') == 'MATCH'
        and record.get('deadline_comparison_state') == 'MATCH'
        and type(initial_us) is int and initial_us > 0
        and type(supervisor_us) is int and supervisor_us == initial_us
        and record.get('deadline_monotonic_usec') == initial_us
        and type(elapsed_ms) is int and 0 <= elapsed_ms <= 45_000)
    combined = initial_ok and final_verified
    record['outcome'] = 'PASS' if diagnostic_ok and combined else 'HOLD'
    record['teardown_verified'] = combined
    tmp = evidence / 'DIAGNOSTIC_STATUS.json.finalizing'
    safe_json(tmp, record)
    os.replace(tmp, p)
    return True

def safe_json(path, content):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as f:
        json.dump(content, f, sort_keys=True, separators=(',', ':'))
        f.write('\n')


def main_run(evidence):
    base, timer, service = exact_unit_identity()
    outcome = 'HOLD'
    primary_code = 'UNEXPECTED_FAILURE'
    t0_ns = None
    created = False
    observations = {'stages': new_stage_provenance(),
                    'initial_arm_deadline_monotonic_usec': None,
                    'supervisor_deadline_monotonic_usec': None,
                    'deadline_monotonic_usec': None, 'readback_elapsed_ms': None}
    cleanup = empty_cleanup()
    verified_source = False
    try:
        arm, supervisor = load_exact_sources()
        verified_source = True
        observations['stages']['source_authenticated'] = True
        prearm_budget_gate()
        observations['stages']['prearm_passed'] = True
        t0_ns = time.monotonic_ns()
        arm_one_timer(base, t0_ns)
        created = True
        observations['stages']['timer_active_entered'] = True
        if not present_timer(timer):
            _fail('TIMER_NOT_ACTIVE')
        observations['stages']['timer_active_passed'] = True
        # Observations are captured as the accepted functions execute; cleanup
        # may later change HOLD/PASS but never erase these authenticated values.
        verified_deadline_equality(arm, supervisor, timer, t0_ns, observations)
        outcome, primary_code = 'PENDING_FINAL_CLEANUP', 'NONE'
    except DiagnosticFailure as ex:
        primary_code = str(ex) if str(ex) in FAILURE_CODES else 'UNEXPECTED_FAILURE'
    except Exception:
        primary_code = 'UNEXPECTED_FAILURE'
    finally:
        try:
            cleanup = teardown(base, timer, service,
                               registration_uncertainty_unresolved=not created)
        except Exception:
            cleanup = empty_cleanup(uncertainty=not created)
        initial_teardown_code = 'NONE' if cleanup['teardown_verified'] else 'TEARDOWN_UNVERIFIED'
        if not cleanup['teardown_verified']:
            outcome = 'HOLD'
        stages = observations['stages']
        rec = {'schema': SCHEMA, 'outcome': outcome,
               'primary_diagnostic_failure_code': primary_code,
               'initial_teardown_failure_code': initial_teardown_code,
               'final_teardown_failure_code': 'NOT_RECORDED',
               'run_id': os.environ['GITHUB_RUN_ID'], 'attempt': os.environ['GITHUB_RUN_ATTEMPT'],
               'initial_source_authenticated': verified_source,
               'stage_provenance': stages,
               'timer_creation_completed': created, 'original_t0_captured': t0_ns is not None,
               'target_s': TARGET_S, 'arm_lead_s': ARM_LEAD_S,
               'original_t0_monotonic_ns': t0_ns,
               'initial_arm_deadline_monotonic_usec': observations['initial_arm_deadline_monotonic_usec'],
               'supervisor_deadline_monotonic_usec': observations['supervisor_deadline_monotonic_usec'],
               'deadline_comparison_state': stages['comparison_state'],
               'deadline_monotonic_usec': observations['deadline_monotonic_usec'],
               'readback_elapsed_ms': observations['readback_elapsed_ms'],
               'teardown_verified': cleanup['teardown_verified'],
               'brq_qualification_established': False, 'scientific_execution': False}
        safe_json(evidence / 'DIAGNOSTIC_STATUS.json', rec)
        safe_json(evidence / 'TEARDOWN_STATUS.json', dict(schema=SCHEMA,
                  run_id=os.environ['GITHUB_RUN_ID'], attempt=os.environ['GITHUB_RUN_ATTEMPT'],
                  **cleanup))
        safe_json(evidence / 'SOURCE_IDENTITIES.json', dict(schema=SCHEMA,
                  initial_arm_sha256=ARM_SHA, supervisor_sha256=SUPERVISOR_SHA,
                  custody_sha256=CUSTODY_SHA, source_authentication_passed=verified_source))
    print('M1_SOURCEFREE_INITIAL=' + ('PROVISIONAL' if outcome == 'PENDING_FINAL_CLEANUP' else 'HOLD'))
    return 0 if outcome == 'PENDING_FINAL_CLEANUP' else 2

def main_cleanup(evidence):
    base, timer, service = exact_unit_identity()
    prior = None
    try:
        candidate = evidence / 'DIAGNOSTIC_STATUS.json'
        if candidate.is_file() and not candidate.is_symlink():
            prior = json.loads(candidate.read_text(encoding='utf-8'))
    except (OSError, ValueError, UnicodeError, TypeError):
        prior = None
    # Missing/invalid initial record or interrupted creation is unresolved,
    # even when both unit state snapshots happen to report inactive.
    known_created = (isinstance(prior, dict) and prior.get('schema') == SCHEMA
                     and prior.get('timer_creation_completed') is True)
    try:
        result = teardown(base, timer, service,
                          registration_uncertainty_unresolved=not known_created)
    except Exception:
        result = empty_cleanup(uncertainty=not known_created)
    safe_json(evidence / 'FINAL_TEARDOWN_STATUS.json', dict(schema=SCHEMA,
              run_id=os.environ['GITHUB_RUN_ID'], attempt=os.environ['GITHUB_RUN_ATTEMPT'], **result))
    finalized = _update_status_for_final_cleanup(evidence, result['teardown_verified'])
    print('M1_SOURCEFREE_FINAL_CLEANUP=' + ('VERIFIED' if result['teardown_verified']
                                             else 'UNRESOLVED'))
    return 0 if (result['teardown_verified'] and finalized) else 2


FAILURE_CODES = frozenset({
    'NONE', 'INVALID_INVOCATION_IDENTITY', 'IMPLEMENTATION_IDENTITY_MISMATCH',
    'IMPLEMENTATION_IMPORT_UNAVAILABLE', 'IMPLEMENTATION_IMPORT_IDENTITY_MISMATCH',
    'ORIGINAL_T0_SETUP_TOO_LATE', 'TIMER_CREATION_FAILED', 'TIMER_NOT_ACTIVE',
    'INITIAL_ARM_READBACK_REJECTED', 'INITIAL_ARM_RECORD_INVALID',
    'SUPERVISOR_READBACK_REJECTED', 'INDEPENDENT_DEADLINE_MISMATCH',
    'ORIGINAL_STOP_BOUNDARY_REACHED', 'DIAGNOSTIC_READBACK_BUDGET_EXCEEDED',
    'TEARDOWN_UNVERIFIED', 'FINAL_TEARDOWN_UNVERIFIED',
    'PREARM_BUDGET_EXCEEDED', 'PREARM_BUDGET_UNVERIFIABLE', 'UNEXPECTED_FAILURE',
})

if __name__ == '__main__':
    # Inputs: operation plus a workflow-local evidence root only.
    if len(sys.argv) != 3 or sys.argv[1] not in ('run', 'cleanup'):
        print('M1_SOURCEFREE_DIAGNOSTIC=INVALID_ARGUMENTS')
        raise SystemExit(2)
    root = Path(sys.argv[2]).resolve()
    allowed_parent = Path(os.environ.get('RUNNER_TEMP', '/nonexistent')).resolve()
    if root != allowed_parent / 'm1_sourcefree_diagnostic_evidence':
        print('M1_SOURCEFREE_DIAGNOSTIC=BAD_EVIDENCE_ROOT')
        raise SystemExit(2)
    raise SystemExit(main_run(root) if sys.argv[1] == 'run' else main_cleanup(root))
