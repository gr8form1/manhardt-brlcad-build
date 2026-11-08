"""ADR-001 P2: strict verification of Docker security evidence; stdlib only.

Policies are fail-closed; no unknown config value, marker omission, truncation,
extra mount, or unobserved timeout can produce PASS. This module never executes CAD.
"""
import json, re

MEM=1073741824
PIDS=32
TMPFS_SIZE=67108864
IMAGE='docker.io/library/ubuntu@sha256:2e863c44b718727c860746568e1d54afd13b2fa71b160f5cd9058fc436217b30'
NS_PATTERN=re.compile(r'\Anet:\[(\d+)\]\Z')
MARK_PATTERN=re.compile(r'^NETNS_MARKER:(net:\[\d+\])$',re.M)

class GateError(RuntimeError):
    pass

def must(ok, reason):
    if not ok: raise GateError(reason)

def network_evidence(output, host_ns):
    markers=MARK_PATTERN.findall(output)
    # Detect malformed or duplicated marker lines, not just valid matches.
    candidates=[line for line in output.splitlines() if 'NETNS_MARKER' in line]
    must(len(candidates)==1 and len(markers)==1,'Network namespace marker missing, malformed or duplicated')
    must(NS_PATTERN.fullmatch(host_ns) is not None,'Host namespace identifier malformed')
    must(markers[0]!=host_ns,'Container network namespace equals host')
    must(output.splitlines().count('ROUTES_EMPTY:yes')==1 and len([l for l in output.splitlines() if l.startswith('ROUTES_EMPTY:')])==1,'No-route evidence missing')
    must(output.splitlines().count('IPV6_ROUTES_EMPTY:yes')==1 and len([l for l in output.splitlines() if l.startswith('IPV6_ROUTES_EMPTY:')])==1,'IPv6 no-route evidence missing')
    must(output.count('ONLY_LOOPBACK:yes')==1 and output.count('ONLY_LOOPBACK:')==1,'Interface isolation evidence missing')
    must(output.count('NET_CONNECT_DENIED:yes')==1 and output.count('NET_CONNECT_DENIED:')==1,'Connect-denial evidence missing')
    return {'host':host_ns,'payload':markers[0], 'distinct':True,'routes_empty':True,'ipv6_routes_empty':True,'only_loopback':True,'connect_denied':True}

def _norm_tmpfs(s):
    return set(s.split(',')) if isinstance(s,str) else set()

def verify_hostconfig(cfg, runtime, fixtures, image_id):
    must(isinstance(cfg,dict),'No HostConfig')
    for key,want in [('ReadonlyRootfs',True),('NetworkMode','none'),('IpcMode','none'),('Memory',MEM),('MemorySwap',MEM),('MemorySwappiness',0),('PidsLimit',PIDS),('NanoCpus',1000000000),('CgroupnsMode','private')]:
        must(type(cfg.get(key)) is type(want) and cfg.get(key)==want,'HostConfig '+key+' mismatch/unknown')
    must('ALL' in [str(x).upper() for x in cfg.get('CapDrop') or []], 'ALL capabilities not dropped')
    must('no-new-privileges:true' in cfg.get('SecurityOpt',[]) or 'no-new-privileges' in cfg.get('SecurityOpt',[]),'no-new-privileges missing')
    must(cfg.get('Privileged') is False,'Privileged setting unknown/enabled')
    must(cfg.get('ReadonlyPaths') is not None,'ReadonlyPaths missing')
    must(cfg.get('Devices')==[],'Explicit device mappings present/unknown')
    must(cfg.get('DeviceRequests') in (None,[]),'Device requests present')
    must(cfg.get('CapAdd') in (None,[]),'Capabilities added')
    must(cfg.get('PidMode') in ('',None),'Host/shared PID namespace enabled')
    must(cfg.get('UsernsMode') in ('',None),'Unexpected UsernsMode')
    must(cfg.get('NetworkMode')=='none','Network enabled')
    must(cfg.get('Binds') in (None,[]),'Legacy Docker binds present')
    must(cfg.get('VolumesFrom') in (None,[]),'Inherited volumes present')
    must(cfg.get('Links') in (None,[]),'Container links present')
    ul=cfg.get('Ulimits')
    must(isinstance(ul,list) and len(ul)==2,'Ulimits missing or extra')
    actual={(x.get('Name'),x.get('Soft'),x.get('Hard')) for x in ul if isinstance(x,dict)}
    must(actual=={('core',0,0),('fsize',8388608,8388608)},'Ulimits mismatch')
    must(cfg.get('Tmpfs') and len(cfg['Tmpfs'])==1 and '/scratch' in cfg['Tmpfs'],'Tmpfs entry mismatch')
    tf=_norm_tmpfs(cfg['Tmpfs']['/scratch'])
    must({'rw','nosuid','nodev','noexec','mode=1777',f'size={TMPFS_SIZE}'}<=tf,'Scratch tmpfs policy mismatch')
    must(not ({'exec','suid','dev'} & tf),'Contradictory tmpfs privileges')
    must(len([s for s in tf if s.startswith('size=')])==1,'Conflicting scratch sizes')
    must(cfg.get('ShmSize') is not None,'ShmSize unknown')
    mounts=cfg.get('Mounts')
    must(isinstance(mounts,list) and len(mounts)==2,'Bind mount config count mismatch')
    expected={(str(runtime),'/runtime'),(str(fixtures),'/fixtures')}
    seen=set()
    for m in mounts:
        must(isinstance(m,dict),'Invalid mount config')
        must(m.get('Type')=='bind' and m.get('ReadOnly') is True,'Non-readonly or nonbind runtime/fixture')
        must(m.get('BindOptions',{}) in ({},None),'Unexpected bind options')
        seen.add((m.get('Source'),m.get('Target')))
    must(seen==expected,'Mounted paths incorrect')
    return {'hostconfig_checked':True,'mount_destinations':sorted(t for _,t in seen)}

def verify_container_inspect(observed, runtime, fixtures, image_id):
    must(isinstance(observed,dict),'Full container inspect missing')
    must(observed.get('Image')==image_id,'Container image ID mismatch')
    must((observed.get('Config') or {}).get('Image')==IMAGE,'Container requested image digest mismatch')
    config=observed.get('Config') or {}
    must(config.get('User')=='65534:65534','Effective requested UID/GID mismatch')
    must(config.get('WorkingDir') in ('','/'),'Unexpected working dir')
    must(config.get('Entrypoint') in (None,[]),'Unexpected image entrypoint')
    must(config.get('Env') is not None,'Environment unavailable')
    must(set(['HOME=/scratch','TMPDIR=/scratch']) <= set(config['Env']),'Required scratch env missing')
    must(all('GH_TOKEN' not in str(s) and 'GITHUB_TOKEN' not in str(s) for s in config['Env']),'Credential leaked to payload')
    out=verify_hostconfig(observed.get('HostConfig'),runtime,fixtures,image_id)
    mi=observed.get('Mounts')
    must(isinstance(mi,list) and len(mi)==2,'Effective mounts incomplete/extra')
    for m in mi:
        must(m.get('Type')=='bind' and m.get('RW') is False,'Effective bind writable')
        must((m.get('Source'),m.get('Destination')) in {(str(runtime),'/runtime'),(str(fixtures),'/fixtures')}, 'Effective bind source/destination mismatch')
    return out

def _unescape_mount(v):
    return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m.group(1),8)),v)

def parse_mountinfo(text):
    must(isinstance(text,str) and 0<len(text)<1_000_000,'Mountinfo missing/over cap')
    mounts=[]
    for row in text.splitlines():
        left,sep,right=row.partition(' - ')
        must(bool(sep),'Malformed mountinfo row')
        p=left.split();q=right.split()
        must(len(p)>=6 and len(q)>=3,'Incomplete mountinfo row')
        mounts.append({'point':_unescape_mount(p[4]),'opts':set(p[5].split(',')) | set(q[2].split(',')),'fstype':q[0],'src':q[1]})
    must(bool(mounts),'No mount entries')
    return mounts

def verify_mountinfo(text):
    mounts=parse_mountinfo(text)
    by={m['point']:m for m in mounts}
    for p in ['/','/runtime','/fixtures','/scratch']:
        must(p in by, 'Required mount absent '+p)
    for p in ['/','/runtime','/fixtures']:
        must('ro' in by[p]['opts'] and 'rw' not in by[p]['opts'],'Required mount not read-only '+p)
    sc=by['/scratch'];must(sc['fstype']=='tmpfs' and 'rw' in sc['opts'] and {'nosuid','nodev','noexec'}<=sc['opts'],'Scratch mount incorrect')
    must(any(opt in sc['opts'] for opt in ('size=65536k','size=67108864','size=64m')),'Scratch effective size not 64MiB')
    # Docker's kernel-managed pseudo mounts are not ordinary writable storage.
    # Accept only explicitly named API/device mounts, with negative write canaries.
    pseudo={'/proc','/dev','/dev/pts','/sys','/sys/fs/cgroup','/dev/mqueue'}
    for m in mounts:
        p=m['point'];opts=m['opts']
        if 'rw' in opts:
            must(p=='/scratch' or (p in pseudo and m['fstype'] in {'proc','sysfs','cgroup2','devpts','tmpfs','mqueue'}), 'Unexpected writable mount: '+p)
    must('/dev/shm' not in by or 'ro' in by['/dev/shm']['opts'],'Writable /dev/shm present')
    return {'mount_count':len(mounts),'writable_mounts':sorted(m['point'] for m in mounts if 'rw' in m['opts']),'scratch':sc['fstype']}

def verify_cgroups(text):
    rec={}
    for key in ['memory.max','memory.swap.max','pids.max','memory.current','memory.swap.current','pids.current','memory.events','memory.swap.events','pids.events']:
        found=re.findall(r'^'+re.escape(key)+r':(.*)$',text,re.M)
        must(len(found)==1,'Missing/duplicate cgroup marker '+key)
        rec[key]=found[0]
    for k,v in [('memory.max',MEM),('memory.swap.max',0),('pids.max',PIDS)]:
        must(rec[k]==str(v),'Effective cgroup '+k+' mismatch')
    for k in ['memory.current','memory.swap.current','pids.current']:
        must(rec[k].isdigit(),'Non-numeric '+k)
    must(int(rec['memory.current'])<=MEM,'Observed memory exceeds cgroup maximum')
    must(int(rec['memory.swap.current'])==0,'Observed swap usage not zero')
    must(int(rec['pids.current'])<=PIDS,'Observed PID use exceeds cap')
    for k in ['memory.events','memory.swap.events','pids.events']:
        try: obj=json.loads(rec[k])
        except Exception as exc:raise GateError('Unparseable '+k) from exc
        must(isinstance(obj,dict) and all(isinstance(x,int) and x>=0 for x in obj.values()),'Invalid '+k)
        rec[k]=obj
    must(rec['memory.swap.events'].get('fail',0)==0,'Swap usage denial events')
    must(rec['memory.events'].get('oom',0)==0 and rec['memory.events'].get('oom_kill',0)==0,'OOM event')
    must(rec['pids.events'].get('max',0)==0,'PID limit event')
    return rec

def verify_canary(output,host_ns,mountinfo):
    rec=network_evidence(output,host_ns)
    must(output.count('SCRATCH_WRITE_PASS:yes')==1,'Scratch write unproven')
    for name in ['etc','runtime','fixtures','dev','dev_shm','proc','sys','root','tmp','var_tmp']:
        marker='DENY_'+name.upper()+':yes'
        must(output.count(marker)==1,'Non-scratch write denial not proven '+name)
    must(output.count('UID_GID:65534:65534')==1,'Effective UID/GID not demonstrated')
    must(output.count('NO_NEW_PRIVS:1')==1,'NoNewPrivs unset')
    must(output.count('CAP_EFF:0000000000000000')==1,'Effective capabilities not zero')
    must(output.count('FROZEN_PASS:yes')==1,'Security canary did not complete')
    rec['cgroup']=verify_cgroups(output)
    rec['mounts']=verify_mountinfo(mountinfo)
    return rec

def bounded_complete_streams(stdout_path,stderr_path,maximum):
    for p in [stdout_path,stderr_path]:
        must(p.exists() and p.stat().st_size<=maximum,'Raw stream exceeded explicit cap or absent '+str(p))
    return True

def extract_observed_sleep_tree(top_text):
    """Require distinct real host PIDs and a sleep child of the shell, not command-text substring."""
    must(isinstance(top_text,str) and len(top_text)<200000,'Docker top missing or oversized')
    records=[]
    for row in top_text.splitlines()[1:]:
        parts=row.strip().split(None,2)
        if len(parts)!=3 or not parts[0].isdigit() or not parts[1].isdigit():
            raise GateError('Malformed docker top output')
        records.append({'pid':int(parts[0]),'ppid':int(parts[1]),'cmd':parts[2]})
    must(len(records)>=2,'Process-tree canary child not observed')
    sleepers=[r for r in records if re.fullmatch(r'(?:/usr/bin/|/bin/)?sleep\s+180',r['cmd'])]
    must(len(sleepers)==1,'Exactly one genuine sleep child required')
    child=sleepers[0]
    parents=[r for r in records if r['pid']==child['ppid'] and r['pid']!=child['pid']]
    must(len(parents)==1 and ('sh' in parents[0]['cmd']),'Child not attached to expected shell')
    return {'child_pid':child['pid'],'shell_pid':parents[0]['pid'],
            'observed_pids':sorted({r['pid'] for r in records})}


def verify_cleanup_observed(rm_code,inspect_code,remaining_ids,observed_pids):
    must(rm_code==0,'Docker forced removal failed')
    must(inspect_code!=0,'Removed Docker container remains inspectable')
    must(isinstance(remaining_ids,list) and not remaining_ids,'Labeled Docker container remains')
    must(isinstance(observed_pids,dict) and all(v is False for v in observed_pids.values()),'Old container process still observable')
    return True
