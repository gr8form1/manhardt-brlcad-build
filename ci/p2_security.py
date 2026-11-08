"""ADR-001 P3: strict verification of Docker security evidence; stdlib only.

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

def verify_docker_cgroup_v2(info):
    """Positive host observation; a requested Docker setting alone is not enforcement.

    The Docker daemon is outside the payload cgroup. This check only establishes
    that the observed daemon reports Linux and cgroup v2. Effective zero-swap
    capacity is qualified separately from actual running-container cgroup files.
    """
    must(isinstance(info,dict) and info.get('OSType')=='linux'
         and type(info.get('CgroupVersion')) is str
         and info.get('CgroupVersion')=='2',
         'Positive Docker Linux/cgroup-v2 evidence unavailable')
    return {'observed_ostype':'linux','observed_cgroup_version':'2'}

def _norm_tmpfs(s):
    return set(s.split(',')) if isinstance(s,str) else set()

def verify_hostconfig(cfg, runtime, fixtures, image_id, docker_info):
    verify_docker_cgroup_v2(docker_info)
    must(isinstance(cfg,dict),'No HostConfig')
    for key,want in [('ReadonlyRootfs',True),('NetworkMode','none'),('IpcMode','none'),('Memory',MEM),('MemorySwap',MEM),('PidsLimit',PIDS),('NanoCpus',1000000000),('CgroupnsMode','private')]:
        must(type(cfg.get(key)) is type(want) and cfg.get(key)==want,'HostConfig '+key+' mismatch/unknown')
    # On the positively verified cgroup-v2 runner, Docker 28.0.4 reports
    # MemorySwappiness:null even with --memory-swappiness 0. Null is a
    # compatibility result only, NEVER evidence of swap prohibition.
    must('MemorySwappiness' in cfg,'HostConfig MemorySwappiness missing')
    swappiness=cfg['MemorySwappiness']
    must(swappiness is None or (type(swappiness) is int and swappiness==0),
         'HostConfig MemorySwappiness unsafe/unknown')
    # This observation cannot yield a full PASS until verify_cgroups verifies
    # memory.max, memory.swap.max, memory.swap.current and pids.max in-container.
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

def verify_container_inspect(observed, runtime, fixtures, image_id, docker_info):
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
    out=verify_hostconfig(observed.get('HostConfig'),runtime,fixtures,image_id,docker_info)
    mi=observed.get('Mounts')
    must(isinstance(mi,list) and len(mi)==2,'Effective mounts incomplete/extra')
    for m in mi:
        must(m.get('Type')=='bind' and m.get('RW') is False,'Effective bind writable')
        must((m.get('Source'),m.get('Destination')) in {(str(runtime),'/runtime'),(str(fixtures),'/fixtures')}, 'Effective bind source/destination mismatch')
    return out

def _unescape_mount(v):
    return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m.group(1),8)),v)

# The only writable Docker-masked /proc mounts qualified by this campaign.
# Their provenance must be established from the SAME container's Docker inspect
# HostConfig.MaskedPaths, and their mountinfo source must be the /dev tmpfs's
# /null mount root. This is not a general /proc or tmpfs write exception.
MASKED_NULL_PATHS=frozenset({
    '/proc/interrupts', '/proc/kcore', '/proc/keys',
    '/proc/latency_stats', '/proc/timer_list',
})
SYSTEM_RO_PATHS=frozenset({'/etc/hosts','/etc/hostname','/etc/resolv.conf'})
REQUIRED_RO_PATHS=frozenset({'/','/runtime','/fixtures'}) | SYSTEM_RO_PATHS
PSEUDO_FILESYSTEMS={
    '/proc':'proc', '/dev':'tmpfs', '/dev/pts':'devpts',
    '/sys':'sysfs', '/sys/fs/cgroup':'cgroup2', '/dev/mqueue':'mqueue',
}


def _option_set(raw,where):
    must(bool(raw) and isinstance(raw,str), 'Empty mount options: '+where)
    result=raw.split(',')
    must(all(result) and len(result)==len(set(result)),
         'Empty or duplicate mount option: '+where)
    return set(result)


def _single_readwrite_mode(opts,where):
    must(('ro' in opts) != ('rw' in opts),
         'Missing or contradictory ro/rw mount mode: '+where)


def parse_mountinfo(text):
    """Parse /proc/self/mountinfo preserving VFS vs superblock semantics.

    VFS options are field 6 BEFORE ` - `; superblock options are field 3
    AFTER ` - `. Never union them: a read-only bind can legitimately have
    VFS ro with a writable superblock.
    """
    must(isinstance(text,str) and 0<len(text)<1_000_000,
         'Mountinfo missing/over cap')
    mounts=[];ids=set();points=set()
    for row in text.splitlines():
        left,sep,right=row.partition(' - ')
        must(bool(sep) and right.count(' - ')==0,'Malformed mountinfo separator')
        p=left.split();q=right.split()
        must(len(p)>=6 and len(q)>=3,'Incomplete mountinfo row')
        must(p[0].isdigit() and p[1].isdigit() and
             re.fullmatch(r'\d+:\d+',p[2]) is not None,
             'Invalid mount identity/device')
        mid=int(p[0]);parent=int(p[1])
        point=_unescape_mount(p[4]);mount_root=_unescape_mount(p[3])
        must(point.startswith('/') and mount_root.startswith('/'),
             'Mountpoint/root not absolute')
        must(mid not in ids and point not in points,
             'Duplicated mount ID or mountpoint: '+point)
        ids.add(mid);points.add(point)
        vfs=_option_set(p[5],'VFS '+point)
        super_opts=_option_set(q[2],'superblock '+point)
        _single_readwrite_mode(vfs,'VFS '+point)
        _single_readwrite_mode(super_opts,'superblock '+point)
        must(q[0] and q[1],'Missing filesystem type/source')
        mounts.append({'id':mid,'parent':parent,'devno':p[2],
                       'root':mount_root,'point':point,
                       'mount_opts':vfs,'super_opts':super_opts,
                       'fstype':q[0],'src':_unescape_mount(q[1])})
    must(bool(mounts),'No mount entries')
    return mounts


def verify_mountinfo(text,masked_paths=None):
    mounts=parse_mountinfo(text)
    by={m['point']:m for m in mounts}
    must(REQUIRED_RO_PATHS <= set(by),
         'Missing required root/input/Docker system read-only mounts: '+
         ','.join(sorted(REQUIRED_RO_PATHS-set(by))))
    for path in sorted(REQUIRED_RO_PATHS):
        must('ro' in by[path]['mount_opts'] and
             'rw' not in by[path]['mount_opts'],
             'Required VFS mount not read-only '+path)

    must('/sys/fs/cgroup' in by and by['/sys/fs/cgroup']['fstype']=='cgroup2',
         'In-container cgroup2 filesystem mount absent or wrong type')
    must('/scratch' in by,'Scratch mount missing')
    sc=by['/scratch']
    must(sc['fstype']=='tmpfs' and sc['src']=='tmpfs' and
         'rw' in sc['mount_opts'] and
         {'nosuid','nodev','noexec'} <= sc['mount_opts'],
         'Scratch VFS mount missing security flags or wrong type')
    sizes=[x for x in sc['super_opts'] if x.startswith('size=')]
    must(len(sizes)==1 and sizes[0] in ('size=65536k','size=67108864','size=64m'),
         'Scratch superblock size not exactly 64 MiB')

    # P3.2.1 positive evidence completeness: this pinned runner MUST expose
    # all five independently authenticated /dev/null masks, even when none
    # would otherwise be counted as an observed writable mount.
    must(isinstance(masked_paths,list) and
         all(isinstance(x,str) for x in masked_paths) and
         len(set(masked_paths))==len(masked_paths),
         'Docker masked-path evidence missing, malformed or duplicated')
    masked_set=set(masked_paths)
    observed_null=set(by)&MASKED_NULL_PATHS
    must(observed_null==MASKED_NULL_PATHS,
         'Incomplete /dev/null masked mount set')
    must(MASKED_NULL_PATHS<=masked_set,
         'Docker HostConfig.MaskedPaths does not authenticate five masks')
    dev=by.get('/dev');proc=by.get('/proc')
    for path in sorted(observed_null):
        m=by[path]
        must(dev is not None and proc is not None and
             dev['fstype']=='tmpfs' and dev['src']=='tmpfs' and
             m['fstype']=='tmpfs' and m['src']=='tmpfs' and
             m['root']=='/null' and m['devno']==dev['devno'] and
             m['parent']==proc['id'] and 'rw' in m['mount_opts'] and
             'nosuid' in m['mount_opts'],
             'Unqualified masked /dev/null mount: '+path)

    # No wildcard pseudo-filesystem exception: exact path/fstype pairing only.
    for m in mounts:
        p=m['point']
        if 'rw' in m['mount_opts']:
            must(p=='/scratch' or p in observed_null or
                 (p in PSEUDO_FILESYSTEMS and
                  m['fstype']==PSEUDO_FILESYSTEMS[p]),
                 'Unexpected writable VFS mount: '+p)
    must('/dev/shm' not in by or 'ro' in by['/dev/shm']['mount_opts'],
         'Writable /dev/shm present')
    return {'mount_count':len(mounts),
            'writable_mounts':sorted(m['point'] for m in mounts
                                      if 'rw' in m['mount_opts']),
            'root_vfs_ro':True,
            'system_ro_mounts':sorted(SYSTEM_RO_PATHS),
            'masked_null_mounts':sorted(observed_null),
            'scratch':sc['fstype'],
            'scratch_size_super_opts':sizes[0],
            'separate_vfs_and_super_opts':True}

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

def verify_canary(output,host_ns,mountinfo,masked_paths=None):
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
    rec['mounts']=verify_mountinfo(mountinfo,masked_paths=masked_paths)
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
