"""Prepared external M1 IR-01 runner supervisor. NO scientific execution on import.

Option-B v6 timing/control semantics:
- original monotonic T0 is armed by PID-1-owned systemd timers before checkout/acquisition;
- T0+540 independently initiates stop if a scientific unit is registered/active;
- T0+570 independently attempts whole-unit kill if it is not quiescent;
- T0+600 writes an operational-timeout disposition. It is not an absolute cessation guarantee;
- scientific code cannot start until this supervisor verifies the final unit's cgroup/systemd
  controls and releases a one-shot non-scientific gate;
- unresolved timing, admission, exit, cgroup, cleanup, or evidence state is nonpositive.

The secret one-use run capability is separate from the nonsecret authorization identity.
It is inherited through a private EnvironmentFile, consumed by gate.py, and never serialized
in public evidence.
"""
from __future__ import annotations
import argparse, errno, hashlib, json, os, platform, re, stat, subprocess, sys, time, uuid
from pathlib import Path
from custody import open_dir_nofollow, create_child_dir, write_exclusive

MEM_MAX=1073741824
SWAP_MAX=0
SOURCE_ADMISSION_DEADLINE_S=60.0
STOP_INITIATE_S=540.0
QUIESCENCE_TARGET_S=570.0
OPERATIONAL_TIMEOUT_S=600.0
SUPERVISOR_ID='MA-M1-IR01-systemd-supervisor-v7'
DEADLINE_SCHEMA='MA-M1-ORIGINAL-T0-DEADLINE-v2'


def sha(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()


def sha_bytes(b): return hashlib.sha256(b).hexdigest()


def run(args,timeout=10,check=False,env=None):
    return subprocess.run(args,text=True,capture_output=True,timeout=timeout,check=check,env=env)


def command_summary(r):
    return {'returncode':r.returncode,'stdout_sha256':sha_bytes((r.stdout or '').encode()),
            'stderr_sha256':sha_bytes((r.stderr or '').encode()),
            'stdout_bytes':len((r.stdout or '').encode()),'stderr_bytes':len((r.stderr or '').encode())}


def parse_show(text): return dict(line.split('=',1) for line in text.splitlines() if '=' in line)


def service_show(unit):
    props=['ActiveState','SubState','Result','ExecMainCode','ExecMainStatus','ControlGroup','MemoryPeak','MemoryCurrent','MemorySwapCurrent','RuntimeMaxUSec','TimeoutStopUSec','KillMode','SendSIGKILL']
    r=run(['sudo','-n','systemctl','show',unit,*sum((['-p',p] for p in props),[])],timeout=8)
    return (r.returncode,parse_show(r.stdout),r.stderr)


def timer_active(timer_unit):
    r=run(['sudo','-n','systemctl','is-active',timer_unit],timeout=4)
    return r.returncode==0 and r.stdout.strip()=='active'


def timer_next_elapse_usec(timer_unit):
    r=run(['sudo','-n','systemctl','show',timer_unit,'-p','NextElapseUSecMonotonic','--value'],timeout=4)
    if r.returncode:return None
    value=(r.stdout or '').strip()
    if not value.isdigit():return None
    out=int(value)
    return out if out>0 else None


def read_cgroup(control_group):
    out={'control_group':control_group,'exists':False,'procs':None,'memory_max':None,'memory_peak':None,'swap_max':None,'swap_peak':None,'swap_current':None,'events':None}
    if not control_group:return out
    p=Path('/sys/fs/cgroup')/control_group.lstrip('/')
    if not p.exists():return out
    out['exists']=True
    def txt(name):
        q=p/name
        try:return q.read_text().strip()
        except OSError:return None
    out.update(procs=(txt('cgroup.procs') or '').split(),memory_max=txt('memory.max'),memory_peak=txt('memory.peak'),swap_max=txt('memory.swap.max'),swap_peak=txt('memory.swap.peak'),swap_current=txt('memory.swap.current'),events=txt('cgroup.events'))
    return out


def cgroup_populated(cg):
    if not cg.get('exists'):return False
    events=cg.get('events')
    if not events:return None
    fields={}
    for line in events.splitlines():
        parts=line.split()
        if len(parts)==2:fields[parts[0]]=parts[1]
    return fields.get('populated')=='1' if 'populated' in fields else None


def parse_systemd_timespan(text):
    if text is None:return None
    t=str(text).strip().lower()
    if not t or t in ('infinity','infinite'):return None
    units={'us':1e-6,'ms':1e-3,'s':1.0,'min':60.0,'h':3600.0,'d':86400.0}
    parts=re.findall(r'([0-9]+(?:\.[0-9]+)?)\s*(us|ms|s|min|h|d)',t)
    if not parts:
        try:return float(t)
        except ValueError:return None
    return sum(float(n)*units[u] for n,u in parts)


def dep_probe(python_exe,lock,bempp_checkout):
    head=run(['git','-C',str(bempp_checkout),'rev-parse','HEAD'],timeout=8)
    if head.returncode or head.stdout.strip()!=lock['bempp_cl']['commit']:
        raise RuntimeError('BEMPP_COMMIT_MISMATCH')
    names=['numpy','scipy','numba','llvmlite','meshio','mpmath','bempp-cl','pip','setuptools','wheel','packaging']
    code=("import importlib.metadata,json,sys,sysconfig,bempp_cl;"
          "print(json.dumps({'python':sys.version.split()[0],'executable':sys.executable,'implementation':sys.implementation.name,"
          "'platform_tag':sysconfig.get_platform(),'bempp_file':bempp_cl.__file__,"
          "'versions':{n:importlib.metadata.version(n) for n in %r}},sort_keys=True))"%names)
    r=run([str(python_exe),'-c',code],timeout=30)
    if r.returncode:raise RuntimeError('DEPENDENCY_IMPORT_PROBE_FAILED')
    observed=json.loads(r.stdout)
    if '.'.join(observed['python'].split('.')[:2])!=lock['python']['required_major_minor']:
        raise RuntimeError('PYTHON_VERSION_MISMATCH')
    for n,v in lock['runtime_packages'].items():
        if observed['versions'].get(n)!=v:raise RuntimeError('DEPENDENCY_VERSION_MISMATCH:'+n)
    for n,v in lock['build_tools'].items():
        if observed['versions'].get(n)!=v:raise RuntimeError('BUILD_TOOL_VERSION_MISMATCH:'+n)
    if observed['versions'].get('bempp-cl')!=lock['bempp_cl']['project_version']:
        raise RuntimeError('BEMPP_VERSION_MISMATCH')
    freeze=run([str(python_exe),'-m','pip','freeze','--all'],timeout=30)
    if freeze.returncode:raise RuntimeError('PIP_FREEZE_FAILED')
    observed['pip_freeze']=sorted(x.strip() for x in freeze.stdout.splitlines() if x.strip())
    observed['bempp_checkout_head']=lock['bempp_cl']['commit']
    return observed


def integer_or_none(x):
    try:return int(x)
    except (TypeError,ValueError):return None


def load_deadline_arm(control_dir,t0_ns):
    root=Path(control_dir)
    try:rst=os.lstat(root)
    except OSError as ex:raise RuntimeError('DEADLINE_CONTROL_DIR_MISSING') from ex
    if stat.S_ISLNK(rst.st_mode) or not stat.S_ISDIR(rst.st_mode) or rst.st_uid!=0 or (stat.S_IMODE(rst.st_mode)&0o022):
        raise RuntimeError('DEADLINE_CONTROL_DIR_OWNERSHIP_INVALID')
    p=root/'DEADLINE_ARMED.json'
    if not p.is_file() or p.is_symlink():raise RuntimeError('DEADLINE_ARM_RECORD_MISSING')
    pst=os.lstat(p)
    if pst.st_uid!=0 or (stat.S_IMODE(pst.st_mode)&0o022):raise RuntimeError('DEADLINE_ARM_RECORD_OWNERSHIP_INVALID')
    obj=json.loads(p.read_text())
    if obj.get('schema')!=DEADLINE_SCHEMA or str(obj.get('t0_monotonic_ns'))!=str(t0_ns):
        raise RuntimeError('DEADLINE_ARM_RECORD_MISMATCH')
    if obj.get('targets_s')!={'stop':STOP_INITIATE_S,'quiescence':QUIESCENCE_TARGET_S,'timeout':OPERATIONAL_TIMEOUT_S}:
        raise RuntimeError('DEADLINE_TARGET_MISMATCH')
    action=obj.get('deadline_action') if isinstance(obj.get('deadline_action'),dict) else {}
    action_path=Path(str(action.get('path','')))
    try:ast=os.lstat(action_path)
    except OSError as ex:raise RuntimeError('DEADLINE_ACTION_MISSING') from ex
    if action_path.parent.resolve()!=root.resolve() or stat.S_ISLNK(ast.st_mode) or not stat.S_ISREG(ast.st_mode) or ast.st_uid!=0 or ast.st_gid!=0 or (stat.S_IMODE(ast.st_mode)&0o022):
        raise RuntimeError('DEADLINE_ACTION_OWNERSHIP_INVALID')
    if action.get('sha256')!=sha(action_path):raise RuntimeError('DEADLINE_ACTION_IDENTITY_MISMATCH')
    timers=obj.get('timer_units');schedules=obj.get('timer_schedules')
    if not isinstance(timers,dict) or set(timers)!={'stop','quiescence','timeout'} or not all(isinstance(v,str) and v.endswith('.timer') for v in timers.values()):
        raise RuntimeError('DEADLINE_TIMER_IDENTITY_INVALID')
    if not isinstance(schedules,dict) or set(schedules)!=set(timers):raise RuntimeError('DEADLINE_TIMER_SCHEDULE_RECORD_MISSING')
    t0_us=t0_ns//1000
    expected={'stop':STOP_INITIATE_S,'quiescence':QUIESCENCE_TARGET_S,'timeout':OPERATIONAL_TIMEOUT_S}
    for key,target_s in expected.items():
        rec=schedules.get(key) if isinstance(schedules.get(key),dict) else {}
        target_us=t0_us+int(target_s*1_000_000)
        observed=rec.get('next_elapse_monotonic_usec')
        if rec.get('timer_unit')!=timers[key] or float(rec.get('target_s',-1))!=target_s or rec.get('target_monotonic_usec')!=target_us:
            raise RuntimeError('DEADLINE_TIMER_SCHEDULE_IDENTITY_MISMATCH:'+key)
        if not isinstance(observed,int) or observed<=0 or observed>target_us or rec.get('verified_not_late') is not True:
            raise RuntimeError('DEADLINE_TIMER_SCHEDULE_NOT_FAIL_CLOSED:'+key)
    return obj

def deadline_markers(control_dir):
    root=Path(control_dir)
    names={'stop':'STOP_INITIATED.json','quiescence':'QUIESCENCE_TARGET.json','timeout':'OPERATIONAL_TIMEOUT.json'}
    out={}
    for key,name in names.items():
        p=root/name
        if p.exists():
            try:out[key]=json.loads(p.read_text())
            except Exception:out[key]={'invalid_marker':True}
        else:out[key]=None
    return out


def fresh_deadline_snapshot(t0,control_dir):
    # Every call samples the clock AFTER any caller's potentially blocking observation.
    return {'elapsed_s':time.monotonic()-t0,'markers':deadline_markers(control_dir)}


def deadline_preflight(arm,t0,control_dir):
    snap=fresh_deadline_snapshot(t0,control_dir)
    if snap['elapsed_s']>=STOP_INITIATE_S or snap['markers']['stop'] or snap['markers']['timeout']:
        raise RuntimeError('ORIGINAL_T0_TOO_LATE_FOR_SCIENCE')
    schedules=arm.get('timer_schedules') if isinstance(arm.get('timer_schedules'),dict) else {}
    verified={}
    for key,unit in arm['timer_units'].items():
        if not timer_active(unit):raise RuntimeError('DEADLINE_TIMER_NOT_ACTIVE:'+key)
        observed=timer_next_elapse_usec(unit)
        rec=schedules.get(key) if isinstance(schedules.get(key),dict) else {}
        if observed is None or observed!=rec.get('next_elapse_monotonic_usec') or observed>rec.get('target_monotonic_usec',-1):
            raise RuntimeError('DEADLINE_TIMER_EFFECTIVE_SCHEDULE_UNVERIFIED:'+key)
        verified[key]=observed
    # Re-sample after all systemd calls: a delayed readback cannot inherit an earlier timely sample.
    final=fresh_deadline_snapshot(t0,control_dir)
    if final['elapsed_s']>=STOP_INITIATE_S or final['markers']['stop'] or final['markers']['timeout']:
        raise RuntimeError('ORIGINAL_T0_TOO_LATE_AFTER_TIMER_READBACK')
    return {'elapsed_s':final['elapsed_s'],'timer_units':arm['timer_units'],'next_elapse_monotonic_usec':verified}

def write_private(path,data,mode=0o600):
    p=Path(path)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),mode)
    with os.fdopen(fd,'wb') as f:
        f.write(data);f.flush();os.fsync(f.fileno())


def valid_scientific_unit_identity(unit,github_origin):
    run_id=str(github_origin.get('GITHUB_RUN_ID',''));run_attempt=str(github_origin.get('GITHUB_RUN_ATTEMPT',''))
    if not run_id or not run_attempt:return False
    pattern=rf'^ma-m1-{re.escape(run_id)}-{re.escape(run_attempt)}-[0-9a-f]{{8}}\.service$'
    return re.fullmatch(pattern,unit) is not None


def install_unit_registration(control_dir,gate_dir,unit,github_origin):
    run_id=str(github_origin.get('GITHUB_RUN_ID',''));run_attempt=str(github_origin.get('GITHUB_RUN_ATTEMPT',''))
    if not valid_scientific_unit_identity(unit,github_origin):raise RuntimeError('SCIENTIFIC_UNIT_IDENTITY_INVALID')
    obj={'schema':'MA-M1-SCIENTIFIC-UNIT-REGISTRATION-v1','run_id':run_id,'run_attempt':run_attempt,
         'execution_repository':github_origin.get('GITHUB_REPOSITORY'),'unit':unit}
    tmp=Path(gate_dir)/('registration-'+uuid.uuid4().hex+'.json')
    write_private(tmp,(json.dumps(obj,sort_keys=True)+'\n').encode(),0o600)
    target=Path(control_dir)/'scientific_unit.json'
    try:
        r=run(['sudo','-n','install','-o','root','-g','root','-m','0444',str(tmp),str(target)],timeout=8)
        if r.returncode:raise RuntimeError('SCIENTIFIC_UNIT_REGISTRATION_INSTALL_FAILED')
    finally:tmp.unlink(missing_ok=True)
    st=os.lstat(target)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_gid!=0 or (stat.S_IMODE(st.st_mode)&0o222):
        raise RuntimeError('SCIENTIFIC_UNIT_REGISTRATION_OWNERSHIP_INVALID')
    observed=json.loads(target.read_text())
    if observed!=obj:raise RuntimeError('SCIENTIFIC_UNIT_REGISTRATION_READBACK_MISMATCH')
    return {'path':str(target),'sha256':sha(target),'owner_uid':st.st_uid,'group_gid':st.st_gid,'mode':oct(stat.S_IMODE(st.st_mode))}


def remove_unit_registration(control_dir):
    target=Path(control_dir)/'scientific_unit.json'
    r=run(['sudo','-n','rm','-f','--',str(target)],timeout=8)
    return command_summary(r)


def release_gate(fifo,deadline_monotonic):
    payload=b'RELEASE\n'
    while time.monotonic()<deadline_monotonic:
        try:
            fd=os.open(fifo,os.O_WRONLY|os.O_NONBLOCK|getattr(os,'O_NOFOLLOW',0))
        except OSError as ex:
            if ex.errno in (errno.ENXIO,errno.ENOENT):time.sleep(.02);continue
            raise
        try:
            # Fresh check after FIFO writer acquisition: a delayed open cannot inherit an earlier timely sample.
            if time.monotonic()>=deadline_monotonic:raise RuntimeError('GATE_RELEASE_CUTOFF_REACHED_AFTER_OPEN')
            n=os.write(fd,payload)
            if n!=len(payload):raise RuntimeError('GATE_RELEASE_PARTIAL')
            return
        finally:os.close(fd)
    raise RuntimeError('GATE_RELEASE_TIMEOUT')

def process_diagnostics(stdout,stderr,capability,source_root):
    # Public evidence contains no raw process output. Hash/length/flags permit
    # correlation without source lines, traceback frames, private paths, or capability bytes.
    sb=(stdout or '').encode(); eb=(stderr or '').encode(); cap=capability.encode()
    source_text=str(source_root)
    return {
      'schema':'MA-M1-PROCESS-DIAGNOSTICS-v1',
      'stdout_sha256':sha_bytes(sb),'stdout_bytes':len(sb),
      'stderr_sha256':sha_bytes(eb),'stderr_bytes':len(eb),
      'traceback_observed':('Traceback (most recent call last)' in (stderr or '')),
      'private_source_path_observed':(source_text in (stdout or '') or source_text in (stderr or '')),
      'capability_material_observed':(bool(cap) and (cap in sb or cap in eb)),
      'raw_output_serialized':False,
    }


def adjudicate_monitor_observation(elapsed, stop_marker_present, quiescent, guard_miss_seen=False):
    """Pure fail-closed ordering for one fresh post-observation monitor sample.

    A quiescent workload can be accepted as timely only when first observed before T0+540.
    At/after +540, missing independently generated stop evidence is a control failure even if
    the workload has naturally exited.  A later stop marker does not erase an earlier miss.
    """
    guard_miss=bool(guard_miss_seen)
    issue_fallback_stop=False
    if elapsed>=STOP_INITIATE_S and not stop_marker_present and not guard_miss:
        guard_miss=True
        issue_fallback_stop=True
    return {
      'deadline_guard_miss':guard_miss,
      'stop_initiated':bool(stop_marker_present or guard_miss),
      'issue_fallback_stop':issue_fallback_stop,
      'quiescent':bool(quiescent),
      'quiescence_observed_elapsed_s':float(elapsed) if quiescent else None,
      'quiescence_target_met':bool(quiescent and elapsed<=QUIESCENCE_TARGET_S),
    }


def quiescence_timing_fields(quiescence_observed_elapsed_s):
    observed=(float(quiescence_observed_elapsed_s) if isinstance(quiescence_observed_elapsed_s,(int,float)) and quiescence_observed_elapsed_s>=0 else None)
    return {'quiescence_first_observed_elapsed_s':observed,
            't0_plus_570_quiescence_target_met':bool(observed is not None and observed<=QUIESCENCE_TARGET_S)}


def positive_execution(reason,stop_initiated,elapsed,systemd_rc,exec_code,exec_status,result_field,has_result,has_stop,post_cg,peak,swap,controls_verified,gate_released,deadline_timeout_seen,deadline_guard_miss,quiescence_observed_elapsed_s):
    timely_quiescence=(isinstance(quiescence_observed_elapsed_s,(int,float)) and
                       0<=float(quiescence_observed_elapsed_s)<STOP_INITIATE_S)
    return (reason=='INCOMPLETE' and not stop_initiated and not deadline_guard_miss and timely_quiescence and
            elapsed<OPERATIONAL_TIMEOUT_S and controls_verified and gate_released and not deadline_timeout_seen and
            systemd_rc==0 and exec_code in (1,None) and exec_status in (0,None) and result_field in ('success','') and has_result and not has_stop and
            (not post_cg.get('exists') or (not post_cg.get('procs') and cgroup_populated(post_cg) is False)) and
            peak is not None and peak<=MEM_MAX and swap is not None and swap<=SWAP_MAX)


def safe_reason(ex):return 'STOP:'+type(ex).__name__


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--source-dir',required=True);ap.add_argument('--source-admission-receipt',required=True)
    ap.add_argument('--t0-monotonic-ns',required=True);ap.add_argument('--deadline-control-dir',required=True);ap.add_argument('--gate-control-dir',required=True)
    ap.add_argument('--python',required=True);ap.add_argument('--bempp-checkout',required=True);ap.add_argument('--gate-script',required=True)
    ap.add_argument('--evidence-root',required=True);ap.add_argument('--authorization-id',required=True)
    ap.add_argument('--level',type=int,required=True);ap.add_argument('--frequency',type=float,required=True);ap.add_argument('--phase',choices=['real','rotated'],required=True)
    ap.add_argument('--expected-execution-repository',default='gr8form1/manhardt-brlcad-build')
    a=ap.parse_args()
    try:t0_ns=int(a.t0_monotonic_ns)
    except (TypeError,ValueError):raise SystemExit('STOP: invalid original T0')
    now_ns=time.monotonic_ns()
    if t0_ns<=0 or t0_ns>now_ns:raise SystemExit('STOP: invalid original T0')
    t0=t0_ns/1_000_000_000.0
    source=Path(a.source_dir).resolve(strict=True);evidence_root=Path(a.evidence_root).resolve(strict=True);deadline_dir=Path(a.deadline_control_dir).resolve(strict=True);gate_dir=Path(a.gate_control_dir).resolve(strict=True)
    gate_script=Path(a.gate_script).resolve(strict=True)
    gst=os.lstat(gate_dir)
    if stat.S_ISLNK(gst.st_mode) or not stat.S_ISDIR(gst.st_mode) or gst.st_uid!=os.getuid() or (stat.S_IMODE(gst.st_mode)&0o077):raise SystemExit('STOP: gate control directory permissions invalid')
    arm=load_deadline_arm(deadline_dir,t0_ns)
    admission=json.loads(Path(a.source_admission_receipt).read_text())
    if admission.get('state')!='ADMITTED_PRIVATE_SOURCE' or admission.get('source_repository')!='gr8form1/manhardt-numerical' or admission.get('source_repository_id')!='1434752390':raise SystemExit('STOP: invalid source admission receipt')
    timing=admission.get('admission_timing') if isinstance(admission.get('admission_timing'),dict) else {}
    if str(timing.get('t0_monotonic_ns',''))!=str(t0_ns) or timing.get('completed_before_deadline') is not True or float(timing.get('deadline_s',-1))!=SOURCE_ADMISSION_DEADLINE_S or float(timing.get('completed_elapsed_s',1e99))>=SOURCE_ADMISSION_DEADLINE_S:
        raise SystemExit('STOP: source admission timing not bound to original T0/T0+60')
    gh={k:os.environ.get(k,'') for k in ('GITHUB_REPOSITORY','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_SHA','GITHUB_WORKFLOW_REF')}
    if gh['GITHUB_REPOSITORY']!=a.expected_execution_repository or not all(gh.values()):raise SystemExit('STOP: execution origin environment unresolved')
    capability=os.environ.get('MA_M1_RUN_CAPABILITY','')
    if not capability or capability==a.authorization_id:raise SystemExit('STOP: secret capability absent or not separated from authorization identity')
    capability_sha256=sha_bytes(capability.encode())
    manifest=json.loads((source/'acceptance.json').read_text());dep_lock=json.loads((source/'dependency.lock').read_text())
    phase_vec=[1,0] if a.phase=='real' else [0,1]
    if a.level not in manifest['geometry']['levels'] or a.frequency not in manifest['frequencies_hz'] or phase_vec not in manifest['source_velocities_m_s_manhardt']:raise SystemExit('STOP: unfrozen fixture')
    if admission.get('m1_sha256')!=sha(source/'m1.py') or admission.get('acceptance_sha256')!=sha(source/'acceptance.json'):raise SystemExit('STOP: source admission identity mismatch')
    observed_deps=dep_probe(Path(a.python).resolve(strict=True),dep_lock,Path(a.bempp_checkout).resolve(strict=True))
    preflight=deadline_preflight(arm,t0,deadline_dir)

    unit_name=f"ma-m1-{gh['GITHUB_RUN_ID']}-{gh['GITHUB_RUN_ATTEMPT']}-{uuid.uuid4().hex[:8]}";unit=unit_name+'.service'
    rootfd=open_dir_nofollow(evidence_root);unitfd=create_child_dir(rootfd,unit_name,0o700);os.close(rootfd)
    unit_dir=evidence_root/unit_name;workload_dir=unit_dir/'workload';workload_dir.mkdir(mode=0o700);payload=workload_dir/'payload'
    admission_bytes=Path(a.source_admission_receipt).read_bytes();write_exclusive(unitfd,'SOURCE_ADMISSION_RECEIPT.json',admission_bytes)
    write_exclusive(unitfd,'DEADLINE_ARMED.json',(deadline_dir/'DEADLINE_ARMED.json').read_bytes())
    support_identity={'supervisor_sha256':sha(Path(__file__).resolve()),'gate_sha256':sha(gate_script),'custody_sha256':sha(Path(__file__).resolve().with_name('custody.py')),'admission_tool_sha256':admission.get('admission_tool_sha256'),'execution_repository':a.expected_execution_repository,'execution_commit':gh['GITHUB_SHA'],'workflow_ref':gh['GITHUB_WORKFLOW_REF']}
    events=[];snapshots=[];cleanup=[];submitted=False;stop_initiated=False;deadline_guard_miss=False;quiescence_observed_elapsed_s=None;gate_released=False;controls_verified=False;runner_proc=None;control_group='';final_show={};final_cg={};reason='INCOMPLETE';state='UNRESOLVED_EXECUTION';stdout=stderr=''
    cap_file=gate_dir/(unit_name+'.capability.env');fifo=gate_dir/(unit_name+'.release.fifo');unit_registration=deadline_dir/'scientific_unit.json';registration_info=None
    def ev(name,**kw):events.append({'event':name,'elapsed_s':round(time.monotonic()-t0,6),**kw})
    scientific_argv_redacted=[str(Path(a.python).resolve()),'<PRIVATE_SOURCE>/m1.py','--authorized-run-token','<CAPABILITY_FROM_SECRET>','--output-dir','<WORKLOAD>/payload','--level',str(a.level),'--frequency',str(a.frequency),'--phase',a.phase]
    try:
        write_private(cap_file,('MA_M1_RUN_CAPABILITY='+capability+'\n').encode())
        os.mkfifo(fifo,0o600)
        registration_info=install_unit_registration(deadline_dir,gate_dir,unit,gh)
        # Close the race between unit registration and T0+540: if the independent
        # stop timer fired or the fresh clock crossed +540, science is never submitted.
        registered_snap=fresh_deadline_snapshot(t0,deadline_dir)
        if registered_snap['elapsed_s']>=STOP_INITIATE_S or registered_snap['markers']['stop'] or registered_snap['markers']['timeout']:
            raise RuntimeError('ORIGINAL_T0_STOP_BOUNDARY_REACHED_BEFORE_SUBMISSION')
        runtime_max_s=max(1.0,STOP_INITIATE_S-registered_snap['elapsed_s'])  # defense in depth only; not the original-T0 proof.
        gate_argv=[sys.executable,str(gate_script),'--release-fifo',str(fifo),'--t0-monotonic-ns',str(t0_ns),'--release-cutoff-s',str(STOP_INITIATE_S),'--python',str(Path(a.python).resolve()),'--m1',str(source/'m1.py'),'--output-dir',str(payload),'--level',str(a.level),'--frequency',str(a.frequency),'--phase',a.phase]
        systemd=['sudo','-n','systemd-run','--wait','--pipe','--unit='+unit,
          '--property=User='+str(os.getuid()),'--property=MemoryAccounting=yes','--property=MemoryMax='+str(MEM_MAX),'--property=MemorySwapMax=0','--property=TasksMax=256',
          '--property=RuntimeMaxSec='+f'{runtime_max_s:.3f}s','--property=KillMode=control-group','--property=SendSIGKILL=yes','--property=TimeoutStopSec=30s',
          '--property=NoNewPrivileges=yes','--property=ProtectSystem=strict','--property=ProtectHome=read-only','--property=PrivateTmp=yes','--property=RestrictAddressFamilies=AF_UNIX','--property=IPAddressDeny=any','--property=CapabilityBoundingSet=',
          '--property=ReadOnlyPaths='+str(source),'--property=ReadWritePaths='+str(workload_dir),'--property=EnvironmentFile='+str(cap_file),'--',*gate_argv]
        ev('ORIGINAL_T0_DEADLINE_BOUND',t0_monotonic_ns=str(t0_ns),deadline_preflight=preflight,source_admission_sha256=sha(a.source_admission_receipt),source_admission_timing=timing,support_identity=support_identity,dependency_lock_sha256=sha(source/'dependency.lock'),dependencies=observed_deps,runtime_max_defense_in_depth_s=runtime_max_s,authorization_id=a.authorization_id,capability_sha256=capability_sha256,unit_registration=registration_info)
        runner_proc=subprocess.Popen(systemd,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE);submitted=True;ev('SYSTEMD_GATE_SUBMISSION_STARTED',unit=unit)
        admission_deadline=min(time.monotonic()+30.0,t0+STOP_INITIATE_S)
        while time.monotonic()<admission_deadline:
            rc,fields,_=service_show(unit);cg=fields.get('ControlGroup','') if rc==0 else '';cgs=read_cgroup(cg)
            snapshots.append({'elapsed_s':time.monotonic()-t0,'show':fields,'cgroup':cgs})
            runtime_observed=parse_systemd_timespan(fields.get('RuntimeMaxUSec')) if rc==0 else None;stop_timeout=parse_systemd_timespan(fields.get('TimeoutStopUSec')) if rc==0 else None
            runtime_ok=runtime_observed is not None and runtime_observed<=runtime_max_s+1.0 and runtime_observed>=max(0.0,runtime_max_s-1.0)
            lifecycle_ok=fields.get('KillMode')=='control-group' and fields.get('SendSIGKILL')=='yes' and stop_timeout is not None and stop_timeout<=30.5
            if cg and cgs['exists'] and cgroup_populated(cgs) is True and cgs['memory_max']==str(MEM_MAX) and cgs['swap_max']=='0' and runtime_ok and lifecycle_ok:
                # Re-check independently owned timers AFTER potentially blocking systemd readback.
                deadline_preflight(arm,t0,deadline_dir)
                control_group=cg;controls_verified=True;ev('NONSCIENTIFIC_GATE_CONTROLS_VERIFIED',control_group=cg,runtime_max_observed_s=runtime_observed,timeout_stop_observed_s=stop_timeout);break
            if runner_proc.poll() is not None:break
            time.sleep(.2)
        if not controls_verified:raise RuntimeError('CONTROL_ADMISSION_UNVERIFIED')
        # EnvironmentFile has been consumed because the gate is running; remove capability bytes before release.
        cap_file.unlink(missing_ok=True)
        snap=fresh_deadline_snapshot(t0,deadline_dir)
        if snap['elapsed_s']>=STOP_INITIATE_S or snap['markers']['stop'] or snap['markers']['timeout']:raise RuntimeError('DEADLINE_REACHED_BEFORE_GATE_RELEASE')
        release_gate(fifo,min(t0+STOP_INITIATE_S,time.monotonic()+5.0));gate_released=True;ev('SCIENTIFIC_GATE_RELEASED',authorization_id=a.authorization_id,capability_sha256=capability_sha256)
        while True:
            rc,fields,_=service_show(unit);cg=fields.get('ControlGroup',control_group) if rc==0 else control_group;cgs=read_cgroup(cg)
            # Fresh sample AFTER systemctl/read_cgroup, so a blocked monitor call cannot defer deadline logic on stale time.
            ds=fresh_deadline_snapshot(t0,deadline_dir);elapsed=ds['elapsed_s'];snapshots.append({'elapsed_s':elapsed,'show':fields,'cgroup':cgs,'deadline_markers':ds['markers']})
            quiescent=(runner_proc.poll() is not None and (not cgs['exists'] or not cgs['procs']))
            adjudication=adjudicate_monitor_observation(elapsed,ds['markers']['stop'] is not None,quiescent,deadline_guard_miss)
            deadline_guard_miss=adjudication['deadline_guard_miss']
            if adjudication['stop_initiated']:stop_initiated=True
            if adjudication['issue_fallback_stop']:
                # The independently owned +540 action was not evidenced at the first fresh
                # observation at/after the boundary.  Natural completion cannot erase this miss.
                reason='DEADLINE_GUARD_STOP_MARKER_MISSING'
                r=run(['sudo','-n','systemctl','stop','--no-block',unit],timeout=8);cleanup.append({'action':'fallback_stop',**command_summary(r)});ev('FALLBACK_STOP_AFTER_DEADLINE_GUARD_MISS',quiescent_at_guard=quiescent)
            if quiescent:
                if quiescence_observed_elapsed_s is None:quiescence_observed_elapsed_s=elapsed
                final_show=fields;final_cg=cgs;ev('OBSERVED_QUIESCENT_EXIT',systemd_run_rc=runner_proc.returncode,quiescence_observed_elapsed_s=quiescence_observed_elapsed_s,deadline_guard_miss=deadline_guard_miss);break
            if elapsed>=QUIESCENCE_TARGET_S and cgs.get('procs'):
                r=run(['sudo','-n','systemctl','kill','--kill-who=all','--signal=SIGKILL',unit],timeout=8);cleanup.append({'action':'fallback_kill_after_quiescence_target',**command_summary(r)})
            if elapsed>=OPERATIONAL_TIMEOUT_S or ds['markers']['timeout'] is not None:
                final_show=fields;final_cg=cgs;reason='OPERATIONAL_TIMEOUT_T0_PLUS_600';ev('TIMEOUT_DISPOSITION_T0_PLUS_600',remaining_pids=cgs.get('procs'));break
            time.sleep(.25)
        if runner_proc.poll() is None:
            try:stdout,stderr=runner_proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:stdout='';stderr='systemd-run control process unresolved after operational timeout'
        else:stdout,stderr=runner_proc.communicate(timeout=2)
        if submitted:
            for action,cmd in [('kill',['sudo','-n','systemctl','kill','--kill-who=all','--signal=SIGKILL',unit]),('reset_failed',['sudo','-n','systemctl','reset-failed',unit])]:
                r=run(cmd,timeout=8);cleanup.append({'action':action,**command_summary(r)})
        rc,fields,_=service_show(unit);post_cg=read_cgroup(fields.get('ControlGroup',control_group) if rc==0 else control_group);ev('POST_CLEANUP_CHECK',active_state=fields.get('ActiveState','UNAVAILABLE'),remaining_pids=post_cg.get('procs'),cgroup_exists=post_cg.get('exists'))
        diagnostics=process_diagnostics(stdout,stderr,capability,source);write_exclusive(unitfd,'PROCESS_DIAGNOSTICS.json',(json.dumps(diagnostics,indent=2,sort_keys=True)+'\n').encode())
        elapsed=time.monotonic()-t0;result_path=payload/'result.json';stop_path=payload/'STOP.json';systemd_rc=runner_proc.returncode if runner_proc and runner_proc.returncode is not None else None
        exec_code=integer_or_none(final_show.get('ExecMainCode'));exec_status=integer_or_none(final_show.get('ExecMainStatus'));result_field=final_show.get('Result','')
        peak_vals=[];swap_vals=[];swap_max_verified=True;swap_current_vals=[]
        for s in snapshots:
            for key,dst in [('memory_peak',peak_vals),('swap_peak',swap_vals)]:
                v=s['cgroup'].get(key)
                if v and v not in ('max','infinity'):
                    try:dst.append(int(v))
                    except ValueError:pass
            if s['cgroup'].get('exists'):
                if s['cgroup'].get('swap_max')!='0':swap_max_verified=False
                sv=s['cgroup'].get('swap_current')
                if sv is not None:
                    try:swap_current_vals.append(int(sv))
                    except ValueError:pass
        systemd_peak=integer_or_none(final_show.get('MemoryPeak'))
        if systemd_peak is not None:peak_vals.append(systemd_peak)
        peak=max(peak_vals) if peak_vals else None;systemd_swap=integer_or_none(final_show.get('MemorySwapCurrent'))
        if systemd_swap is not None:swap_current_vals.append(systemd_swap)
        if swap_vals:swap=max(swap_vals)
        elif swap_max_verified and (not swap_current_vals or max(swap_current_vals)==0):swap=0
        else:swap=None
        deadline_final=fresh_deadline_snapshot(t0,deadline_dir)
        positive=positive_execution(reason,stop_initiated,elapsed,systemd_rc,exec_code,exec_status,result_field,result_path.is_file(),stop_path.exists(),post_cg,peak,swap,controls_verified,gate_released,deadline_final['markers']['timeout'] is not None,deadline_guard_miss,quiescence_observed_elapsed_s)
        if positive:
            result_bytes=result_path.read_bytes();write_exclusive(unitfd,'result.json',result_bytes)
            rr=run([str(Path(a.python).resolve()),str(source/'emit_reference.py'),str(result_path),str(source/'acceptance.json')],timeout=60)
            if rr.returncode:raise RuntimeError('REFERENCE_EVIDENCE_GENERATION_FAILED')
            rv=json.loads(rr.stdout);write_exclusive(unitfd,'REFERENCE_VALIDATION.json',(json.dumps(rv,indent=2,sort_keys=True)+'\n').encode())
            result_obj=json.loads(result_bytes);write_exclusive(unitfd,'dependency.lock',(source/'dependency.lock').read_bytes());write_exclusive(unitfd,'dependency-observed.json',(json.dumps(observed_deps,indent=2,sort_keys=True)+'\n').encode())
            receipt={'state':'SEALED_EXTERNAL_SUPERVISOR','supervisor_identity':SUPERVISOR_ID,'unit_level_frequency_phase':[a.level,a.frequency,phase_vec],'execution_authorization_id':a.authorization_id,'capability_sha256':capability_sha256,'scientific_argv_redacted':scientific_argv_redacted,'result_sha256':sha(unit_dir/'result.json'),'source_file_sha256':sha(source/'m1.py'),'acceptance_manifest_sha256':sha(source/'acceptance.json'),'dependency_lockfile_sha256':sha(source/'dependency.lock'),'supervisor_log_sha256':'PENDING','process_diagnostics_sha256':sha(unit_dir/'PROCESS_DIAGNOSTICS.json'),'exit_code':0,'entire_invocation_wall_seconds':elapsed,'cgroup_peak_bytes':peak,'swap_peak_bytes':swap,'completed_before_operational_timeout':True,'memory_limit_enforced':True,'swap_limit_enforced':True,'cleanup_resolved':True,'gate_controls_verified_before_release':True,'exit_status_reconciliation':{'systemd_run_returncode':systemd_rc,'exec_main_code':exec_code,'exec_main_status':exec_status,'systemd_result':result_field,'result_json_present':True,'stop_json_present':False},'operational_timing':{'original_t0_monotonic_ns':str(t0_ns),'source_admission_completed_elapsed_s':timing.get('completed_elapsed_s'),'independent_deadline_arm_sha256':sha(unit_dir/'DEADLINE_ARMED.json'),'t0_plus_540_stop_initiation':False,'t0_plus_540_stop_guard_miss':deadline_guard_miss,**quiescence_timing_fields(quiescence_observed_elapsed_s),'t0_plus_600_timeout_disposition':False,'absolute_stop_guarantee':False},'github_execution_origin':gh,'trusted_support_identity':support_identity,'source_admission_receipt_sha256':sha(unit_dir/'SOURCE_ADMISSION_RECEIPT.json'),'private_source_origin':{k:admission[k] for k in ('source_repository','source_repository_id','artifact_name','artifact_id','source_run_id','archive_sha256')}}
            prov={'state':'SEALED_EXECUTED','unit_level_frequency_phase':[a.level,a.frequency,phase_vec],'source_file_sha256':sha(source/'m1.py'),'acceptance_manifest_sha256':sha(source/'acceptance.json'),'upstream_commit':manifest['upstream_commit'],'result_sha256':receipt['result_sha256'],'reference_validation_sha256':sha(unit_dir/'REFERENCE_VALIDATION.json'),'dependency_lockfile_sha256':sha(unit_dir/'dependency.lock'),'dependency_observed_sha256':sha(unit_dir/'dependency-observed.json'),'dependency_versions':observed_deps,'execution_authorization_id':a.authorization_id,'capability_sha256':capability_sha256,'host':platform.node(),'os':platform.platform(),'process_diagnostics_sha256':receipt['process_diagnostics_sha256'],'scientific_argv_redacted':scientific_argv_redacted,'exit_code':0,'process_peak_rss_bytes':result_obj['peak_rss_bytes'],'external_wall_seconds':elapsed,'cgroup_peak_bytes':peak,'swap_bytes':swap,'github_execution_origin':gh,'trusted_support_identity':support_identity,'source_admission_receipt_sha256':receipt['source_admission_receipt_sha256'],'private_source_origin':receipt['private_source_origin']}
            log_obj={'supervisor_identity':SUPERVISOR_ID,'events':events,'snapshots':snapshots,'cleanup':cleanup,'final_show':final_show,'post_cleanup_cgroup':post_cg,'deadline_arm_sha256':sha(unit_dir/'DEADLINE_ARMED.json')}
            write_exclusive(unitfd,'supervisor.log',(json.dumps(log_obj,indent=2,sort_keys=True)+'\n').encode());receipt['supervisor_log_sha256']=sha(unit_dir/'supervisor.log')
            write_exclusive(unitfd,'RESOURCE_RECEIPT.json',(json.dumps(receipt,indent=2,sort_keys=True)+'\n').encode());write_exclusive(unitfd,'PROVENANCE.json',(json.dumps(prov,indent=2,sort_keys=True)+'\n').encode())
            state='SEALED_EXTERNAL_SUPERVISOR';reason='SUCCESSFULLY_COMPLETED_BEFORE_OPERATIONAL_TIMEOUT'
        else:
            state='UNRESOLVED_EXECUTION'
            if reason=='INCOMPLETE':reason='EXECUTION_OR_CONTROL_RECONCILIATION_FAILED'
    except Exception as ex:
        reason=safe_reason(ex);state='STOP'
        try:
            if submitted:run(['sudo','-n','systemctl','kill','--kill-who=all','--signal=SIGKILL',unit],timeout=8)
        except Exception:pass
    finally:
        for p in (cap_file,fifo):
            try:Path(p).unlink(missing_ok=True)
            except Exception:pass
        try:
            cleanup.append({'action':'remove_root_owned_unit_registration',**remove_unit_registration(deadline_dir)})
        except Exception:pass
        summary={'state':state,'reason':reason,'supervisor_identity':SUPERVISOR_ID,'events':events,'cleanup':cleanup,'unit':unit,'authorization_id':a.authorization_id,'capability_sha256':capability_sha256,'control_observations':{'deadline_guard_miss':deadline_guard_miss,**quiescence_timing_fields(quiescence_observed_elapsed_s)},'operational_timeout_semantics':{'original_t0_monotonic_ns':str(t0_ns),'source_admission_deadline_s':SOURCE_ADMISSION_DEADLINE_S,'stop_initiation_s':STOP_INITIATE_S,'quiescence_target_s':QUIESCENCE_TARGET_S,'timeout_disposition_s':OPERATIONAL_TIMEOUT_S,'absolute_stop_guarantee':False}}
        try:write_exclusive(unitfd,'SUPERVISOR_DECISION.json',(json.dumps(summary,indent=2,sort_keys=True)+'\n').encode())
        except Exception:pass
        try:os.close(unitfd)
        except Exception:pass
    print(json.dumps({'state':state,'reason':reason,'unit_dir':str(unit_dir)},sort_keys=True))
    return 0 if state=='SEALED_EXTERNAL_SUPERVISOR' else 1


if __name__=='__main__':raise SystemExit(main())
