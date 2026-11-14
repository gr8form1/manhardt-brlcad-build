#!/usr/bin/env python3
"""Strict public-safe allowlist for the proposed source-free M1 diagnostic."""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import sys

SCHEMA = 'MA-M1-BRQ-SOURCEFREE-DIAG-v2'
CAP = 32768
KNOWN = {'DIAGNOSTIC_STATUS.json', 'TEARDOWN_STATUS.json', 'FINAL_TEARDOWN_STATUS.json',
         'SOURCE_IDENTITIES.json', 'PUBLIC_EVIDENCE_VALIDATION.json', 'EVIDENCE_MEMBERS.txt'}
REQUIRED = {'FINAL_TEARDOWN_STATUS.json'}
FAILURE_CODES = {
    'NONE', 'INVALID_INVOCATION_IDENTITY', 'IMPLEMENTATION_IDENTITY_MISMATCH',
    'IMPLEMENTATION_IMPORT_UNAVAILABLE', 'IMPLEMENTATION_IMPORT_IDENTITY_MISMATCH',
    'ORIGINAL_T0_SETUP_TOO_LATE', 'TIMER_CREATION_FAILED', 'TIMER_NOT_ACTIVE',
    'INITIAL_ARM_READBACK_REJECTED', 'INITIAL_ARM_RECORD_INVALID',
    'SUPERVISOR_READBACK_REJECTED', 'INDEPENDENT_DEADLINE_MISMATCH',
    'ORIGINAL_STOP_BOUNDARY_REACHED', 'DIAGNOSTIC_READBACK_BUDGET_EXCEEDED',
    'TEARDOWN_UNVERIFIED', 'FINAL_TEARDOWN_UNVERIFIED',
    'PREARM_BUDGET_EXCEEDED', 'PREARM_BUDGET_UNVERIFIABLE', 'UNEXPECTED_FAILURE',
}
SHA = re.compile('[0-9a-f]{64}', re.ASCII)
DIGITS = re.compile('[0-9]{1,20}', re.ASCII)


def exact(obj, fields):
    if not isinstance(obj, dict) or set(obj) != fields: raise ValueError('SCHEMA')
    if obj['schema'] != SCHEMA: raise ValueError('SCHEMA')
    return obj


def is_bool(obj, *fields):
    if any(type(obj[k]) is not bool for k in fields): raise ValueError('BOOLEAN')


def run_id(obj):
    if not isinstance(obj['run_id'], str) or not DIGITS.fullmatch(obj['run_id']): raise ValueError('RUN_ID')
    if not isinstance(obj['attempt'], str) or not DIGITS.fullmatch(obj['attempt']): raise ValueError('ATTEMPT')
    if obj['run_id'] != os.environ.get('GITHUB_RUN_ID') or obj['attempt'] != os.environ.get('GITHUB_RUN_ATTEMPT'):
        raise ValueError('IDENTITY')


def check_json(name, o):
    common = {'schema', 'run_id', 'attempt'}
    if name == 'DIAGNOSTIC_STATUS.json':
        exact(o, common | {'outcome','failure_code','initial_source_authenticated',
              'timer_creation_completed','original_t0_captured','target_s','arm_lead_s',
              'readbacks_equal','deadline_monotonic_usec','readback_elapsed_ms',
              'teardown_verified','brq_qualification_established','scientific_execution',
              'original_t0_monotonic_ns','initial_arm_deadline_monotonic_usec',
              'supervisor_deadline_monotonic_usec'})
        run_id(o)
        if o['outcome'] not in ('PASS','HOLD') or o['failure_code'] not in FAILURE_CODES: raise ValueError('RESULT')
        if type(o['target_s']) is not int or o['target_s'] != 540 or type(o['arm_lead_s']) is not int or o['arm_lead_s'] != 2:
            raise ValueError('TARGET')
        is_bool(o,'initial_source_authenticated','timer_creation_completed','original_t0_captured',
                'readbacks_equal','teardown_verified','brq_qualification_established','scientific_execution')
        if o['brq_qualification_established'] or o['scientific_execution']: raise ValueError('SCOPE')
        if o['original_t0_monotonic_ns'] is not None and (type(o['original_t0_monotonic_ns']) is not int or o['original_t0_monotonic_ns'] <= 0):
            raise ValueError('T0')
        if o['outcome'] == 'PASS':
            if (o['failure_code'] != 'NONE' or not o['readbacks_equal'] or not o['teardown_verified']
                    or not o['timer_creation_completed'] or not o['initial_source_authenticated']):
                raise ValueError('UNSUPPORTED_PASS')
            if (type(o['deadline_monotonic_usec']) is not int or o['deadline_monotonic_usec'] <= 0
                    or o['original_t0_monotonic_ns'] is None
                    or type(o['initial_arm_deadline_monotonic_usec']) is not int
                    or type(o['supervisor_deadline_monotonic_usec']) is not int
                    or not (o['deadline_monotonic_usec'] == o['initial_arm_deadline_monotonic_usec']
                            == o['supervisor_deadline_monotonic_usec'])):
                raise ValueError('DEADLINE')
            if type(o['readback_elapsed_ms']) is not int or not (0 <= o['readback_elapsed_ms'] <= 45000):
                raise ValueError('DURATION')
        else:
            if o['failure_code'] == 'NONE': raise ValueError('UNSUPPORTED_HOLD')
            if (o['readbacks_equal'] or o['deadline_monotonic_usec'] is not None
                    or o['initial_arm_deadline_monotonic_usec'] is not None
                    or o['supervisor_deadline_monotonic_usec'] is not None
                    or o['readback_elapsed_ms'] is not None):
                raise ValueError('UNSUPPORTED_HOLD')
    elif name in ('TEARDOWN_STATUS.json', 'FINAL_TEARDOWN_STATUS.json'):
        exact(o, common | {'stop_commands_returned','stop_commands_succeeded',
                            'timer_and_service_inactive_verified','registration_uncertainty_unresolved',
                            'teardown_verified'})
        run_id(o)
        is_bool(o,'stop_commands_returned','stop_commands_succeeded',
                'timer_and_service_inactive_verified','registration_uncertainty_unresolved',
                'teardown_verified')
        if (o['stop_commands_succeeded'] and not o['stop_commands_returned']
                or o['teardown_verified'] != (o['stop_commands_returned']
                    and o['timer_and_service_inactive_verified']
                    and not o['registration_uncertainty_unresolved'])):
            raise ValueError('CLEANUP')
    elif name == 'SOURCE_IDENTITIES.json':
        exact(o, {'schema','initial_arm_sha256','supervisor_sha256','custody_sha256','source_authentication_passed'})
        if (o['initial_arm_sha256'] != '839cbb827afe2663ee7e987c9a3ac56c7ddc617390c7e81a93959b91c56aad30'
            or o['supervisor_sha256'] != '09ddf1f5e9d6e6b7d4c1c662bff54607e494119265b6c669928aa6954211c380'
            or o['custody_sha256'] != '28e858d9ec14b6bec642938db8afbf257f19a2108d36892abf9cdf06468f1ab6'):
            raise ValueError('SOURCE_IDENTITY')
        is_bool(o,'source_authentication_passed')


def cross_record_disposition(records):
    """Only the independent FINAL observation may enable overall PASS.

    A crash before the driver writes its normal record may leave only FINAL.
    In that case delayed creation cannot be excluded; FINAL must remain HOLD.
    Incomplete/provisional, contradictory, or unsupported PASS is rejected.
    """
    final = records['FINAL_TEARDOWN_STATUS.json']
    diag = records.get('DIAGNOSTIC_STATUS.json')
    initial = records.get('TEARDOWN_STATUS.json')
    sources = records.get('SOURCE_IDENTITIES.json')
    if diag is None:
        if initial is not None or sources is not None:
            raise ValueError('ORPHANED_DIAGNOSTIC_RECORD')
        if final['teardown_verified'] or not final['registration_uncertainty_unresolved']:
            raise ValueError('FINAL_ONLY_CANNOT_PROVE_CLEANUP')
        return 'HOLD'
    if initial is None or sources is None:
        raise ValueError('INCOMPLETE_DIAGNOSTIC_RECORD')
    if (diag['run_id'] != initial['run_id'] or diag['attempt'] != initial['attempt']
            or diag['run_id'] != final['run_id'] or diag['attempt'] != final['attempt']):
        raise ValueError('CROSS_RECORD_RUN_ID')
    if diag['initial_source_authenticated'] != sources['source_authentication_passed']:
        raise ValueError('CROSS_RECORD_SOURCE_IDENTITY')
    # The diagnostic field is *combined* cleanup after finalization, not a
    # stale initial snapshot masquerading as a final cleanup success.
    combined = initial['teardown_verified'] and final['teardown_verified']
    if diag['teardown_verified'] != combined:
        raise ValueError('CONTRADICTORY_CLEANUP_RECORDS')
    if diag['timer_creation_completed'] is False:
        if not initial['registration_uncertainty_unresolved'] or not final['registration_uncertainty_unresolved']:
            raise ValueError('UNCERTAIN_CREATION_NOT_RETAINED')
    if diag['outcome'] == 'PASS':
        if (not combined or initial['registration_uncertainty_unresolved']
                or final['registration_uncertainty_unresolved']):
            raise ValueError('FINAL_TEARDOWN_NOT_VERIFIED')
        return 'PASS'
    # A final failure must be reflected in the overall failure code; a
    # later successful FINAL state cannot revise an earlier readback failure.
    if not final['teardown_verified'] and diag['failure_code'] != 'FINAL_TEARDOWN_UNVERIFIED':
        raise ValueError('FINAL_FAILURE_NOT_RECONCILED')
    return 'HOLD'


def validate(root):
    if not root.is_dir() or root.is_symlink(): raise ValueError('MISSING_EVIDENCE')
    paths = list(root.iterdir())
    if not paths or any(p.is_symlink() or not p.is_file() or p.name not in KNOWN for p in paths):
        raise ValueError('NONALLOWLISTED_MEMBER')
    if not REQUIRED.issubset({p.name for p in paths}): raise ValueError('MISSING_CLEANUP_EVIDENCE')
    records = {}
    for p in paths:
        if p.name in ('PUBLIC_EVIDENCE_VALIDATION.json','EVIDENCE_MEMBERS.txt'):
            raise ValueError('STALE_VALIDATOR_OUTPUT')
        if p.stat().st_size > 8192: raise ValueError('OVERSIZED_MEMBER')
        o = json.loads(p.read_text(encoding='utf-8'))
        check_json(p.name, o)
        records[p.name] = o
    disposition = cross_record_disposition(records)
    # The validator's own complete-tree metadata is included in the final cap.
    with (root/'PUBLIC_EVIDENCE_VALIDATION.json').open('x',encoding='utf-8') as f:
        json.dump({'schema':SCHEMA,'status':'PUBLIC_ALLOWLIST_PASS',
                   'diagnostic_disposition':disposition,
                   'brq_qualification_established':False,
                   'complete_tree_size_cap_bytes':CAP,'raw_dbus_output_published':False,
                   'credentials_published':False,'scientific_source_published':False},f,sort_keys=True)
        f.write('\n')
    members = sorted([p.name for p in root.iterdir()] + ['EVIDENCE_MEMBERS.txt'])
    (root/'EVIDENCE_MEMBERS.txt').write_text('\n'.join(members)+'\n', encoding='utf-8')
    count = 0
    for p in root.iterdir():
        if p.is_symlink() or not p.is_file() or p.name not in KNOWN: raise ValueError('NONALLOWLISTED_MEMBER')
        b = p.read_bytes(); count += len(b)
        if b'\x00' in b: raise ValueError('BINARY')
        txt = b.decode('utf-8')
        if re.search(r'(?i)github_pat_|gh[pousr]_[A-Za-z0-9]|Traceback \(most recent call last\)|M1_PRIVATE_ARTIFACT_READ_TOKEN|M1_PRIVATE_SOURCE_B64|/m1_admitted/|private_source_inbox',txt):
            raise ValueError('CONFIDENTIALITY')
    if count > CAP: raise ValueError('COMPLETE_TREE_TOO_LARGE')
    return count, members


if __name__=='__main__':
    if len(sys.argv)!=2:
        print('PUBLIC_EVIDENCE=INVALID_ARGUMENTS')
        raise SystemExit(2)
    root=Path(sys.argv[1]).resolve()
    if root != Path(os.environ.get('RUNNER_TEMP','/nonexistent')).resolve()/'m1_sourcefree_diagnostic_evidence':
        print('PUBLIC_EVIDENCE=INVALID_ROOT')
        raise SystemExit(2)
    try:
        total,members=validate(root)
    except (ValueError,OSError,UnicodeError,KeyError,TypeError,json.JSONDecodeError):
        print('PUBLIC_EVIDENCE=REJECTED')
        raise SystemExit(2)
    print('PUBLIC_EVIDENCE=PASS; MEMBERS='+str(len(members))+'; BYTES='+str(total))
