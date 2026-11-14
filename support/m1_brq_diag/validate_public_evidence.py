#!/usr/bin/env python3
"""Source-free M1 public evidence v3: bounded provenance, strict cross-record gate.

No raw command output, exception strings or environment values are serialized.
This is evidence validation only, not a second timer/supervisor verifier.
"""
from __future__ import annotations
import json, os, re, sys
from pathlib import Path

SCHEMA = 'MA-M1-BRQ-SOURCEFREE-DIAG-v4'
CAP = 32768
KNOWN = {'DIAGNOSTIC_STATUS.json', 'TEARDOWN_STATUS.json', 'FINAL_TEARDOWN_STATUS.json',
         'SOURCE_IDENTITIES.json', 'PUBLIC_EVIDENCE_VALIDATION.json', 'EVIDENCE_MEMBERS.txt'}
REQUIRED = {'FINAL_TEARDOWN_STATUS.json'}
PRIMARY_CODES = frozenset({
    'NONE','INVALID_INVOCATION_IDENTITY','IMPLEMENTATION_IDENTITY_MISMATCH',
    'IMPLEMENTATION_IMPORT_UNAVAILABLE','IMPLEMENTATION_IMPORT_IDENTITY_MISMATCH',
    'ORIGINAL_T0_SETUP_TOO_LATE','TIMER_CREATION_FAILED','TIMER_NOT_ACTIVE',
    'INITIAL_ARM_READBACK_REJECTED','INITIAL_ARM_RECORD_INVALID',
    'SUPERVISOR_READBACK_REJECTED','INDEPENDENT_DEADLINE_MISMATCH',
    'ORIGINAL_STOP_BOUNDARY_REACHED','DIAGNOSTIC_READBACK_BUDGET_EXCEEDED',
    'PREARM_BUDGET_EXCEEDED','PREARM_BUDGET_UNVERIFIABLE','UNEXPECTED_FAILURE',
})
STAGE_FIELDS = frozenset({'source_authenticated','prearm_passed','timer_active_entered','timer_active_passed',
                          'initial_arm_entered','initial_arm_returned',
                          'initial_arm_record_checked','supervisor_entered',
                          'supervisor_value_verified','comparison_state',
                          'post_readback_passed'})
PROPERTY_NAMES = frozenset({'ActiveState','ControlGroup','Job','LoadState'})
PROPERTY_CLASS = frozenset({'NOT_OBSERVED','PASS','FAIL'})
STOP = frozenset({'NOT_REACHED','SUCCESS','NONZERO','TIMEOUT','UNAVAILABLE'})
STATE = frozenset({'NOT_REACHED','VERIFIED_INACTIVE','NOT_INACTIVE','MALFORMED','TIMEOUT','NONZERO','UNAVAILABLE'})
REJECTION = frozenset({
    'NOT_REACHED', 'NONE', 'COMMAND_TIMEOUT', 'COMMAND_NONZERO',
    'COMMAND_UNAVAILABLE', 'OUTPUT_INVALID', 'OUTPUT_OVERSIZED',
    'MALFORMED_SYNTAX', 'DUPLICATE_PROPERTY', 'UNEXPECTED_PROPERTY',
    'MISSING_PROPERTY', 'WRONG_LINE_COUNT',
})
TERMINAL_ORIGIN = frozenset({'NOT_REACHED','POLLING','POST_RESET_RECHECK'})
PARSE_REJECTIONS = REJECTION - {
    'NOT_REACHED','NONE','COMMAND_TIMEOUT','COMMAND_NONZERO','COMMAND_UNAVAILABLE'
}
CMP = frozenset({'NOT_REACHED','MATCH','MISMATCH'})
SHA = re.compile(r'[0-9a-f]{64}',re.ASCII)
DIGITS = re.compile(r'[0-9]{1,20}',re.ASCII)


def exact(o,keys):
    if not isinstance(o,dict) or set(o)!=keys or o.get('schema')!=SCHEMA:
        raise ValueError('SCHEMA')
    return o


def boolean(o,*fields):
    if any(type(o[k]) is not bool for k in fields): raise ValueError('BOOLEAN')


def run_identity(o):
    for k in ('run_id','attempt'):
        if type(o[k]) is not str or DIGITS.fullmatch(o[k]) is None:
            raise ValueError('INVOCATION_IDENTITY')
    if (o['run_id'] != os.environ.get('GITHUB_RUN_ID')
            or o['attempt'] != os.environ.get('GITHUB_RUN_ATTEMPT')):
        raise ValueError('INVOCATION_IDENTITY')


def positive_or_null(value, field):
    if value is not None and (type(value) is not int or not 0<value<2**64):
        raise ValueError('INVALID_'+field)


def check_stages(o):
    st=o['stage_provenance']
    if not isinstance(st,dict) or set(st)!=STAGE_FIELDS: raise ValueError('STAGE_SCHEMA')
    if st['comparison_state'] not in CMP or type(st['comparison_state']) is not str:
        raise ValueError('STAGE_COMPARISON')
    boolean(st,*(STAGE_FIELDS-{'comparison_state'}))
    prerequisites=[
        ('prearm_passed','source_authenticated'),
        ('timer_active_entered','prearm_passed'),
        ('timer_active_passed','timer_active_entered'),
        ('initial_arm_entered','timer_active_passed'),
        ('initial_arm_returned','initial_arm_entered'),
        ('supervisor_entered','initial_arm_returned'),
        ('supervisor_value_verified','supervisor_entered'),
        ('initial_arm_record_checked','supervisor_value_verified'),
        ('post_readback_passed','initial_arm_record_checked'),
    ]
    for flag,prior in prerequisites:
        if st[flag] and not st[prior]: raise ValueError('STAGE_ORDER')
    if st['source_authenticated']!=o['initial_source_authenticated']:
        raise ValueError('STAGE_SOURCE_MISMATCH')
    if st['timer_active_entered'] and not o['timer_creation_completed']:
        raise ValueError('STAGE_ACTIVE_ENTRY_CREATION_MISMATCH')
    if st['timer_active_passed'] and not o['timer_creation_completed']:
        raise ValueError('STAGE_CREATION_MISMATCH')
    if o['timer_creation_completed'] and not o['original_t0_captured']:
        raise ValueError('STAGE_T0_MISMATCH')
    if o['original_t0_captured'] and not st['prearm_passed']:
        raise ValueError('STAGE_PREARM_MISMATCH')
    if (o['primary_diagnostic_failure_code']=='TIMER_NOT_ACTIVE'
            and (not st['timer_active_entered'] or st['timer_active_passed'])):
        raise ValueError('TIMER_ACTIVE_REJECTION_PROVENANCE')
    if (st['timer_active_entered'] and not st['timer_active_passed']
            and o['primary_diagnostic_failure_code'] not in ('TIMER_NOT_ACTIVE','UNEXPECTED_FAILURE')):
        raise ValueError('TIMER_ACTIVE_ENTRY_FAILURE_CODE')
    if st['comparison_state']!='NOT_REACHED' and not st['initial_arm_record_checked']:
        raise ValueError('STAGE_COMPARISON_NOT_REACHED')
    if st['post_readback_passed'] and st['comparison_state']!='MATCH':
        raise ValueError('STAGE_POST_REQUIRES_MATCH')
    if o['deadline_comparison_state']!=st['comparison_state']:
        raise ValueError('COMPARISON_PROVENANCE_MISMATCH')


def check_diagnostic(o):
    common={'schema','run_id','attempt'}
    exact(o,common|{
        'outcome','primary_diagnostic_failure_code','initial_teardown_failure_code',
        'final_teardown_failure_code','initial_source_authenticated','stage_provenance',
        'timer_creation_completed','original_t0_captured','target_s','arm_lead_s',
        'original_t0_monotonic_ns','initial_arm_deadline_monotonic_usec',
        'supervisor_deadline_monotonic_usec','deadline_comparison_state',
        'deadline_monotonic_usec','readback_elapsed_ms','teardown_verified',
        'brq_qualification_established','scientific_execution'})
    run_identity(o)
    if o['outcome'] not in {'HOLD','PASS'}: raise ValueError('OUTCOME')
    if o['primary_diagnostic_failure_code'] not in PRIMARY_CODES:
        raise ValueError('PRIMARY_FAILURE_CODE')
    if o['initial_teardown_failure_code'] not in ('NONE','TEARDOWN_UNVERIFIED'):
        raise ValueError('INITIAL_FAILURE_CODE')
    if o['final_teardown_failure_code'] not in ('NONE','FINAL_TEARDOWN_UNVERIFIED'):
        raise ValueError('FINAL_FAILURE_CODE')
    if type(o['target_s']) is not int or o['target_s']!=540 or type(o['arm_lead_s']) is not int or o['arm_lead_s']!=2:
        raise ValueError('TIMING_CONTRACT')
    boolean(o,'initial_source_authenticated','timer_creation_completed','original_t0_captured',
            'teardown_verified','brq_qualification_established','scientific_execution')
    if o['brq_qualification_established'] or o['scientific_execution']:
        raise ValueError('SCOPE')
    check_stages(o)
    t0=o['original_t0_monotonic_ns']
    if t0 is None:
        if o['original_t0_captured']:raise ValueError('MISSING_T0')
    elif type(t0) is not int or t0<=0 or not o['original_t0_captured']:
        raise ValueError('T0')
    initial=o['initial_arm_deadline_monotonic_usec']
    sup=o['supervisor_deadline_monotonic_usec']
    matched=o['deadline_monotonic_usec']
    for field,value in [('INITIAL',initial),('SUPERVISOR',sup),('MATCHED',matched)]:
        positive_or_null(value,field)
    st=o['stage_provenance']
    if initial is not None:
        if not st['initial_arm_returned'] or t0 is None:
            raise ValueError('UNOBSERVED_INITIAL')
        if not (t0//1000+537_000_000<=initial<=t0//1000+540_000_000):
            raise ValueError('INITIAL_TARGET_WINDOW')
    if st['initial_arm_record_checked'] and initial is None:
        raise ValueError('MISSING_VERIFIED_INITIAL')
    if (sup is not None)!=st['supervisor_value_verified']:
        raise ValueError('SUPERVISOR_PROVENANCE')
    state=st['comparison_state']
    if state=='NOT_REACHED':
        if matched is not None or o['readback_elapsed_ms'] is not None:
            raise ValueError('COMPARISON_NOT_REACHED_VALUES')
    elif initial is None or sup is None:
        raise ValueError('MISSING_COMPARISON_VALUES')
    elif state=='MATCH':
        if initial!=sup or matched!=initial:
            raise ValueError('CONTRADICTORY_MATCH')
    elif state=='MISMATCH':
        if initial==sup or matched is not None or o['readback_elapsed_ms'] is not None:
            raise ValueError('CONTRADICTORY_MISMATCH')
        if o['primary_diagnostic_failure_code']!='INDEPENDENT_DEADLINE_MISMATCH':
            raise ValueError('MISMATCH_FAILURE_CODE')
    elapsed=o['readback_elapsed_ms']
    if elapsed is not None:
        if state!='MATCH' or type(elapsed) is not int or not 0<=elapsed<1_000_000:
            raise ValueError('ELAPSED')
    if st['post_readback_passed']:
        if (elapsed is None or elapsed>45000 or state!='MATCH'):
            raise ValueError('POSTCHECK')
    good_diag = (st['source_authenticated'] and st['prearm_passed']
                 and o['timer_creation_completed'] and st['timer_active_entered'] and st['timer_active_passed']
                 and st['initial_arm_entered'] and st['initial_arm_returned']
                 and st['initial_arm_record_checked'] and st['supervisor_entered']
                 and st['supervisor_value_verified'] and state=='MATCH'
                 and st['post_readback_passed'] and initial is not None and sup is not None
                 and elapsed is not None and o['original_t0_captured'])
    if (o['primary_diagnostic_failure_code']=='NONE') != bool(good_diag):
        raise ValueError('PRIMARY_STATUS_CONTRADICTION')
    return good_diag


def check_teardown(o):
    common={'schema','run_id','attempt'}
    exact(o,common|{'stop_commands_returned','stop_commands_succeeded',
                    'timer_and_service_inactive_verified','registration_uncertainty_unresolved',
                    'teardown_verified','timer_stop_result','service_stop_result',
                    'timer_state_readback','service_state_readback',
                    'timer_property_predicates','service_property_predicates',
                    'timer_state_rejection_code','service_state_rejection_code',
                    'timer_property_presence_mask','service_property_presence_mask',
                    'timer_state_line_count_capped','service_state_line_count_capped',
                    'terminal_evaluation_origin'})
    run_identity(o)
    boolean(o,'stop_commands_returned','stop_commands_succeeded',
            'timer_and_service_inactive_verified','registration_uncertainty_unresolved',
            'teardown_verified')
    t,s=o['timer_stop_result'],o['service_stop_result']
    ti,si=o['timer_state_readback'],o['service_state_readback']
    if any(type(x) is not str for x in (t,s,ti,si)) or t not in STOP or s not in STOP or ti not in STATE or si not in STATE:
        raise ValueError('TEARDOWN_ENUM')
    origin=o['terminal_evaluation_origin']
    if type(origin) is not str or origin not in TERMINAL_ORIGIN:
        raise ValueError('TERMINAL_ORIGIN_ENUM')
    for unit in ('timer','service'):
        state = o[unit+'_state_readback']
        predicates = o[unit+'_property_predicates']
        rejection = o[unit+'_state_rejection_code']
        mask = o[unit+'_property_presence_mask']
        count = o[unit+'_state_line_count_capped']
        if not isinstance(predicates,dict) or set(predicates)!=PROPERTY_NAMES:
            raise ValueError('PROPERTY_PREDICATE_SCHEMA')
        if any(type(value) is not str or value not in PROPERTY_CLASS
               for value in predicates.values()):
            raise ValueError('PROPERTY_PREDICATE_ENUM')
        if type(rejection) is not str or rejection not in REJECTION:
            raise ValueError('REJECTION_ENUM')
        if mask is not None and (type(mask) is not int or not 0<=mask<=15):
            raise ValueError('PRESENCE_MASK')
        if count is not None and (type(count) is not int or not 0<=count<=9):
            raise ValueError('LINE_COUNT')
        values=list(predicates.values())
        if state=='VERIFIED_INACTIVE' and not all(x=='PASS' for x in values):
            raise ValueError('PROPERTY_VERIFIED_CONTRADICTION')
        if state=='NOT_INACTIVE' and (any(x=='NOT_OBSERVED' for x in values)
                                       or not any(x=='FAIL' for x in values)):
            raise ValueError('PROPERTY_NEGATIVE_CONTRADICTION')
        if state not in ('VERIFIED_INACTIVE','NOT_INACTIVE') and any(
                x!='NOT_OBSERVED' for x in values):
            raise ValueError('PROPERTY_UNAVAILABLE_CONTRADICTION')
        if state in ('NOT_REACHED','TIMEOUT','NONZERO','UNAVAILABLE'):
            correct={'NOT_REACHED':'NOT_REACHED','TIMEOUT':'COMMAND_TIMEOUT',
                     'NONZERO':'COMMAND_NONZERO','UNAVAILABLE':'COMMAND_UNAVAILABLE'}[state]
            if rejection!=correct or mask is not None or count is not None:
                raise ValueError('UNAVAILABLE_REJECTION_CONTRADICTION')
        elif state in ('VERIFIED_INACTIVE','NOT_INACTIVE'):
            if rejection!='NONE' or mask!=15 or count!=4:
                raise ValueError('PARSED_REJECTION_CONTRADICTION')
        elif state=='MALFORMED':
            if rejection not in PARSE_REJECTIONS:
                raise ValueError('MALFORMED_REJECTION_CONTRADICTION')
            if rejection in ('OUTPUT_INVALID','OUTPUT_OVERSIZED'):
                if mask is not None or count is not None:
                    raise ValueError('UNPARSEABLE_OUTPUT_METADATA')
            else:
                if mask is None or count is None:
                    raise ValueError('PARSE_METADATA_MISSING')
                # The four-bit mask counts distinct recognized property names.
                # Each requires its own input line. The retained line count is
                # min(actual_lines, 9), so these lower bounds remain valid when
                # the count has saturated at nine; nine is NOT an exact count.
                distinct_names = mask.bit_count()
                if distinct_names > count:
                    raise ValueError('PRESENCE_EXCEEDS_LINE_COUNT')
                # A syntactically malformed nonblank line, a duplicate recognized
                # property, or an unexpected property necessarily occupies at
                # least one line beyond the distinct recognized property lines.
                if (rejection in ('MALFORMED_SYNTAX','DUPLICATE_PROPERTY',
                                  'UNEXPECTED_PROPERTY')
                        and count <= distinct_names):
                    raise ValueError('REJECTION_EXTRA_LINE_MISSING')
                if rejection=='MALFORMED_SYNTAX' and count==0:
                    raise ValueError('MALFORMED_EMPTY_COUNT')
                if rejection=='DUPLICATE_PROPERTY' and (count<2 or mask==0):
                    raise ValueError('DUPLICATE_METADATA')
                if rejection=='UNEXPECTED_PROPERTY' and count==0:
                    raise ValueError('UNEXPECTED_METADATA')
                if rejection=='MISSING_PROPERTY' and mask==15:
                    raise ValueError('MISSING_PROPERTY_MASK')
                if rejection=='WRONG_LINE_COUNT' and (mask!=15 or count<=4):
                    raise ValueError('WRONG_LINE_COUNT_METADATA')
    # Origin applies to the terminal *paired* observation only. Do not join
    # predicates from different polling attempts or reset/recheck snapshots.
    if origin=='NOT_REACHED':
        if ti!='NOT_REACHED' or si!='NOT_REACHED':
            raise ValueError('UNREACHED_TERMINAL_PAIR')
    else:
        if ti=='NOT_REACHED':
            raise ValueError('TERMINAL_TIMER_NOT_QUERIED')
        if si!='NOT_REACHED' and ti!='VERIFIED_INACTIVE':
            raise ValueError('SERVICE_SHORT_CIRCUIT_VIOLATION')
        # A positive polling pair can reach reset/recheck even when an earlier
        # stop call timed out or was unavailable. Origin describes which paired
        # observations were retained, not whether stop commands returned. The
        # accepted teardown predicate below independently requires both stops.
    returned=(t in ('SUCCESS','NONZERO') and s in ('SUCCESS','NONZERO'))
    succeeded=t=='SUCCESS' and s=='SUCCESS'
    inactive=ti=='VERIFIED_INACTIVE' and si=='VERIFIED_INACTIVE'
    if (o['stop_commands_returned']!=returned or o['stop_commands_succeeded']!=succeeded
            or o['timer_and_service_inactive_verified']!=inactive):
        raise ValueError('TEARDOWN_OBSERVATIONS')
    # Both commands must RETURN; they need not both EXIT ZERO, as originally
    # accepted. Positive unit state, not exit status, proves inactivity.
    if o['teardown_verified'] != (returned and inactive and not o['registration_uncertainty_unresolved']):
        raise ValueError('TEARDOWN_PREDICATE')


def check_json(name,obj):
    if name=='DIAGNOSTIC_STATUS.json': return check_diagnostic(obj)
    if name in ('TEARDOWN_STATUS.json','FINAL_TEARDOWN_STATUS.json'):
        return check_teardown(obj)
    if name=='SOURCE_IDENTITIES.json':
        exact(obj,{'schema','initial_arm_sha256','supervisor_sha256','custody_sha256',
                   'source_authentication_passed'})
        if (obj['initial_arm_sha256']!='839cbb827afe2663ee7e987c9a3ac56c7ddc617390c7e81a93959b91c56aad30'
            or obj['supervisor_sha256']!='09ddf1f5e9d6e6b7d4c1c662bff54607e494119265b6c669928aa6954211c380'
            or obj['custody_sha256']!='28e858d9ec14b6bec642938db8afbf257f19a2108d36892abf9cdf06468f1ab6'):
            raise ValueError('SOURCE_IDENTITY')
        boolean(obj,'source_authentication_passed')


def cross_record_disposition(records):
    final=records['FINAL_TEARDOWN_STATUS.json']
    diag=records.get('DIAGNOSTIC_STATUS.json')
    initial=records.get('TEARDOWN_STATUS.json')
    sources=records.get('SOURCE_IDENTITIES.json')
    if diag is None:
        if initial is not None or sources is not None:
            raise ValueError('ORPHANED_DIAGNOSTIC_RECORD')
        if final['teardown_verified'] or not final['registration_uncertainty_unresolved']:
            raise ValueError('FINAL_ONLY_CANNOT_PROVE_CLEANUP')
        return 'HOLD'
    if initial is None or sources is None:
        raise ValueError('INCOMPLETE_DIAGNOSTIC_RECORD')
    if (diag['run_id']!=initial['run_id'] or diag['attempt']!=initial['attempt']
            or diag['run_id']!=final['run_id'] or diag['attempt']!=final['attempt']):
        raise ValueError('CROSS_RECORD_RUN_ID')
    if (diag['initial_source_authenticated'] != sources['source_authentication_passed']):
        raise ValueError('SOURCE_CROSS_RECORD')
    initial_failure='NONE' if initial['teardown_verified'] else 'TEARDOWN_UNVERIFIED'
    final_failure='NONE' if final['teardown_verified'] else 'FINAL_TEARDOWN_UNVERIFIED'
    if (diag['initial_teardown_failure_code']!=initial_failure
            or diag['final_teardown_failure_code']!=final_failure):
        raise ValueError('FAILURE_DOMAIN_MISMATCH')
    if diag['teardown_verified']!=(initial['teardown_verified'] and final['teardown_verified']):
        raise ValueError('CONTRADICTORY_TEARDOWN')
    if not diag['timer_creation_completed']:
        if not initial['registration_uncertainty_unresolved'] or not final['registration_uncertainty_unresolved']:
            raise ValueError('UNCERTAIN_CREATION_NOT_RETAINED')
    good=check_diagnostic(diag)
    positive=(good and initial['teardown_verified'] and final['teardown_verified']
              and not initial['registration_uncertainty_unresolved']
              and not final['registration_uncertainty_unresolved'])
    if diag['outcome']!=('PASS' if positive else 'HOLD'):
        raise ValueError('OVERALL_DISPOSITION_CONTRADICTION')
    return diag['outcome']


def validate(root):
    if not root.is_dir() or root.is_symlink(): raise ValueError('MISSING_EVIDENCE')
    paths=list(root.iterdir())
    if not paths or any(p.is_symlink() or not p.is_file() or p.name not in KNOWN for p in paths):
        raise ValueError('NONALLOWLISTED_MEMBER')
    if not REQUIRED.issubset({p.name for p in paths}): raise ValueError('MISSING_CLEANUP_EVIDENCE')
    records={}
    for p in paths:
        if p.name in ('PUBLIC_EVIDENCE_VALIDATION.json','EVIDENCE_MEMBERS.txt'):
            raise ValueError('STALE_VALIDATOR_OUTPUT')
        if p.stat().st_size>8192: raise ValueError('OVERSIZED_MEMBER')
        obj=json.loads(p.read_text(encoding='utf-8'))
        check_json(p.name,obj)
        records[p.name]=obj
    outcome=cross_record_disposition(records)
    # Final complete-tree validation includes the validator's two own products.
    with (root/'PUBLIC_EVIDENCE_VALIDATION.json').open('x',encoding='utf-8') as f:
        json.dump({'schema':SCHEMA,'status':'PUBLIC_ALLOWLIST_PASS',
                   'diagnostic_disposition':outcome,
                   'brq_qualification_established':False,
                   'complete_tree_size_cap_bytes':CAP,'raw_dbus_output_published':False,
                   'credentials_published':False,'scientific_source_published':False},f,sort_keys=True)
        f.write('\n')
    members=sorted([p.name for p in root.iterdir()]+['EVIDENCE_MEMBERS.txt'])
    (root/'EVIDENCE_MEMBERS.txt').write_text('\n'.join(members)+'\n',encoding='utf-8')
    total=0
    for p in root.iterdir():
        if p.is_symlink() or not p.is_file() or p.name not in KNOWN:
            raise ValueError('NONALLOWLISTED_MEMBER')
        data=p.read_bytes(); total+=len(data)
        if b'\x00' in data: raise ValueError('BINARY')
        txt=data.decode('utf-8')
        if re.search(r'(?i)github_pat_|gh[pousr]_[A-Za-z0-9]|Traceback \(most recent call last\)|M1_PRIVATE_ARTIFACT_READ_TOKEN|M1_PRIVATE_SOURCE_B64|/m1_admitted/|private_source_inbox',txt):
            raise ValueError('CONFIDENTIALITY')
    if total>CAP: raise ValueError('COMPLETE_TREE_TOO_LARGE')
    return total,members

if __name__=='__main__':
    if len(sys.argv)!=2:
        print('PUBLIC_EVIDENCE=INVALID_ARGUMENTS');raise SystemExit(2)
    root=Path(sys.argv[1]).resolve()
    if root != Path(os.environ.get('RUNNER_TEMP','/nonexistent')).resolve()/'m1_sourcefree_diagnostic_evidence':
        print('PUBLIC_EVIDENCE=INVALID_ROOT');raise SystemExit(2)
    try:
        total,members=validate(root)
    except (ValueError,OSError,UnicodeError,KeyError,TypeError,json.JSONDecodeError):
        print('PUBLIC_EVIDENCE=REJECTED');raise SystemExit(2)
    print('PUBLIC_EVIDENCE=PASS; MEMBERS='+str(len(members))+'; BYTES='+str(total))
