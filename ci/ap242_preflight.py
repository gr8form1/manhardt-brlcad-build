#!/usr/bin/env python3
"""ADR-001 preflight only. No STEP parser/converter execution.

stdlib-only host controller. Fail closed: every runtime, fixture, image and
security precondition must be observed before preflight PASS is recorded.
"""
import argparse, base64, hashlib, io, json, os, pathlib, resource, shutil, stat
import subprocess, sys, tarfile, time, urllib.request, urllib.error, urllib.parse, zipfile

REPO = 'gr8form1/manhardt-brlcad-build'
ARTIFACT_ID = 13624376032
ZIP_SHA = '437fd42a8044c836d255fdde4b318a4d7ca92cbd3cbc073e8397ee9e3e86ec65'
TAR_SHA = '4447f9cc8ede6f0386a4a289c963d5b04df93aad25016e60d960d23e8cdece0c'
# An immutable ubuntu:24.04 manifest digest documented by Docker.
# Its availability/architecture/provider ABI must be independently confirmed on the runner.
IMAGE = 'docker.io/library/ubuntu@sha256:2e863c44b718727c860746568e1d54afd13b2fa71b160f5cd9058fc436217b30'
MEM = 1073741824
PID_MAX = 32
FIXTURES = [
  ('base_attachment.step','TheRobotStudio','SO-ARM100','6f22fbd94cd0b656aa8797a8c1a34b389bc5eff6',
   'bf0ab4c59e4a3a1305ea1ebca012af0d8eb3f0a9a70e2b19587b6a7d13ad8b1b'),
  ('M015.stp','zellyn','dodgy-step-files','32a98830de2c0c4bffab9142ffd1f68ef463cfbe',
   'ee2760196c738fcc9c7f7ce12a7ebdf700cdfb50639d73699fe2482fce8d766a')
]

def hash_bytes(b): return hashlib.sha256(b).hexdigest()
def hash_file(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for part in iter(lambda:f.read(1024*1024), b''): h.update(part)
    return h.hexdigest()

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None

def build_artifact_download(max_bytes):
    url=f'https://api.github.com/repos/{REPO}/actions/artifacts/{ARTIFACT_ID}/zip'
    req=urllib.request.Request(url,headers={'Authorization':'Bearer '+os.environ['GH_TOKEN'],
                  'Accept':'application/vnd.github+json','User-Agent':'Manhardt-ADR001-preflight'})
    try:
        urllib.request.build_opener(NoRedirect()).open(req,timeout=35)
        raise RuntimeError('GitHub artifact did not produce expected 302 redirect')
    except urllib.error.HTTPError as e:
        if e.code not in (302, 307): raise
        location=e.headers.get('Location','')
    u=urllib.parse.urlsplit(location)
    host=(u.hostname or '').lower()
    allowed=host.endswith('.githubusercontent.com') or host.endswith('.blob.core.windows.net')
    if u.scheme!='https' or not allowed or u.username or u.password:
        raise RuntimeError('Untrusted GitHub artifact redirect host')
    # Critical: do not forward GITHUB_TOKEN to the signed third-party download URL.
    return bounded_http(location,max_bytes,auth=False)

def bounded_http(url, max_bytes, auth=True):
    headers={'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'Manhardt-ADR001-public-preflight'}
    if auth: headers['Authorization']='Bearer '+os.environ['GH_TOKEN']
    req=urllib.request.Request(url,headers=headers)
    with urllib.request.urlopen(req,timeout=35) as f:
        b=f.read(max_bytes+1)
    if len(b)>max_bytes: raise RuntimeError('HTTP response exceeded byte cap')
    return b

def command(args, timeout=30, env=None, evidence=None, label=None, byte_cap=4_000_000):
    """Full bounded raw files; any overflow or timeout fails closed."""
    import signal
    started=time.monotonic()
    if evidence is None or label is None:
        raise ValueError('Evidence directory and stable command label required')
    evidence=pathlib.Path(evidence);evidence.mkdir(parents=True,exist_ok=True)
    stdout=evidence/(label+'.stdout.bin');stderr=evidence/(label+'.stderr.bin')
    if stdout.exists() or stderr.exists():raise RuntimeError('Refuse evidence overwrite: '+label)
    status={'argv':args,'stdout_file':stdout.name,'stderr_file':stderr.name,
            'stdout_cap':byte_cap,'stderr_cap':byte_cap,'timed_out':False}
    from p2_security import GateError
    with open(stdout,'xb') as so,open(stderr,'xb') as se:
        try:
            proc=subprocess.Popen(args,stdout=so,stderr=se,env=env,start_new_session=True,
                preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_FSIZE,(byte_cap,byte_cap)))
        except FileNotFoundError:
            status['rc']=127
        else:
            try:status['rc']=proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                status['timed_out']=True
                try:os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                proc.wait(timeout=10)
                status['rc']=124
    status['seconds']=round(time.monotonic()-started,4)
    status['stdout_bytes']=stdout.stat().st_size;status['stderr_bytes']=stderr.stat().st_size
    status['stdout_sha256']=hash_file(stdout);status['stderr_sha256']=hash_file(stderr)
    if status['stdout_bytes']>=byte_cap or status['stderr_bytes']>=byte_cap:
        raise GateError('Evidence stream overflow: '+label)
    return status

def require_success(r):
    if r['rc']!=0 or r['timed_out']:
        raise RuntimeError('Command failed: '+str(r['argv'][:3]))

def stdout_text(r,evidence):
    return (pathlib.Path(evidence)/r['stdout_file']).read_text(encoding='utf-8',errors='strict')

def docker_json(r,evidence):
    require_success(r)
    return json.loads(stdout_text(r,evidence))

def safe_extract_runtime(tarpath, dest):
    # Authenticated but still defensive: no links, absolute paths, traversal, devices or alternate PAX extraction.
    count=0; total=0; root='brlcad-runtime/'
    with tarfile.open(tarpath,'r:gz') as tf:
        for m in tf:
            if not m.isfile() or not m.name.startswith(root):
                raise RuntimeError('Unexpected nonregular runtime member '+m.name)
            rel=m.name[len(root):]
            parts=pathlib.PurePosixPath(rel).parts
            if not rel or any(s in ('','.','..') for s in parts) or rel.startswith('/'):
                raise RuntimeError('Unsafe runtime member name')
            if len(parts)>12 or len(rel)>240 or any(ord(c)>127 for c in rel):
                raise RuntimeError('Unsafe member path')
            count+=1; total+=m.size
            if count>2500 or total>350_000_000:raise RuntimeError('Runtime expansion cap exceeded')
            target=dest.joinpath(*parts);target.parent.mkdir(parents=True,exist_ok=True)
            with open(target,'xb') as out:
                source=tf.extractfile(m)
                for part in iter(lambda:source.read(1024*1024),b''):out.write(part)
            target.chmod(0o755 if rel=='bin/step-g' else 0o644)
    if count!=2410: raise RuntimeError('Runtime member count not 2410: '+str(count))
    checks={}
    for line in (dest/'SHA256SUMS').read_text().splitlines():
        digest,rel=line[:64],line[66:]
        if not rel or rel in checks:raise RuntimeError('Duplicated checksum entry')
        checks[rel]=digest
    if len(checks)!=2409:raise RuntimeError('Unexpected runtime SHA256SUMS record count')
    for rel,digest in checks.items():
        if hash_file(dest/rel)!=digest:raise RuntimeError('Runtime checksum mismatch '+rel)
    manifest=json.loads((dest/'MANIFEST.json').read_text())
    # Critical outer census and recorded identities are checked. No edits to runtime.
    entries=manifest.get('files') if isinstance(manifest,dict) else None
    if not isinstance(entries,list) or len(entries)!=2408:
        raise RuntimeError('Runtime MANIFEST records unexpected')
    paths=set()
    for e in entries:
        rel=e['path']
        if rel in paths:raise RuntimeError('Duplicate manifest path')
        paths.add(rel)
        p=dest/rel
        if not p.is_file() or p.stat().st_size!=e['size'] or hash_file(p)!=e['sha256']:
            raise RuntimeError('Runtime MANIFEST verification failed '+rel)
    if manifest.get('source_commit')!='bc130e1e7a9f179fe95fb42cde1a7d3becb512df':
        raise RuntimeError('Runtime BRL-CAD source pin mismatch')
    return {'files_extracted':count,'expanded_bytes':total,'sha256sums_records':len(checks),
            'manifest_records_verified':len(entries),
            'manifest_sha256':hash_file(dest/'MANIFEST.json'),
            'step_g_sha256':hash_file(dest/'bin/step-g'),
            'plugin_sha256':hash_file(dest/'libexec/step/libstep-schema-ap242e2.so'),
            'manifest_top_level_keys':list(manifest) if isinstance(manifest,dict) else []}

def write_json(path,obj):path.write_text(json.dumps(obj,sort_keys=True,indent=2)+'\n')

def main():
    import signal
    from p2_security import (IMAGE,MEM,PIDS,GateError,verify_container_inspect,
        verify_canary,bounded_complete_streams,network_evidence,extract_observed_sleep_tree,verify_cleanup_observed,verify_docker_cgroup_v2)
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True)
    args=parser.parse_args();out=pathlib.Path(args.output).resolve();out.mkdir(parents=True,exist_ok=True)
    evidence=out/'raw'; evidence.mkdir(exist_ok=True)
    started=time.monotonic()
    rec={'status':'HOLD','phase':'preflight-only','runner_enforcement':'UNOBSERVED',
         'runtime_source_run':42485097796,'artifact_id':ARTIFACT_ID,
         'no_geometry_conversion':True,'commands':{},'containers':[]}
    scratch=pathlib.Path(os.environ.get('RUNNER_TEMP','/tmp'))/('adr001-preflight-p2-'+str(os.getpid()))
    scratch.mkdir(mode=0o700)
    label='adr001-ap242-p2-'+str(os.getpid())
    image_id=None
    active=[]
    def cmd(tag,argv,timeout=30,cap=4_000_000):
        if time.monotonic()-started>550: raise GateError('Campaign deadline exhausted')
        c=command(argv,timeout=timeout,evidence=evidence,label=tag,byte_cap=cap)
        rec['commands'][tag]=c
        return c
    def cleanup_one(name,tag,expected_host_pids=None):
        # Verify normal and timeout cleanup from outside the container.
        rm=cmd('cleanup_'+tag,['docker','rm','-f',name],25)
        inspect=cmd('cleanup_inspect_'+tag,['docker','inspect',name],15)
        remaining=container_ids('after_cleanup_'+tag)
        observed_pids={str(pid):os.path.exists('/proc/'+str(pid)) for pid in (expected_host_pids or [])}
        verify_cleanup_observed(rm['rc'],inspect['rc'],remaining,observed_pids)
        if name in active:active.remove(name)
        return True
    def container_ids(tag):
        p=cmd('ps_'+tag,['docker','ps','-aq','--no-trunc','--filter','label=adr001.p2=public-ap242-preflight'],20)
        require_success(p)
        return stdout_text(p,evidence).splitlines()
    try:
        if not os.environ.get('GH_TOKEN'):raise GateError('GH_TOKEN absent')
        if os.uname().machine!='x86_64':raise GateError('Host not x86-64')
        # Explicitly record supervisor and payload resource-domain separation.
        rec['supervisory_boundary']='GH download, Docker CLI/daemon, Python and runner outside container cgroup'
        rec['host_netns']=os.readlink('/proc/self/ns/net')
        zbytes=build_artifact_download(260_000_000)
        rec['build_zip']={'size':len(zbytes),'sha256':hash_bytes(zbytes)}
        if rec['build_zip']['sha256']!=ZIP_SHA:raise GateError('Build #5 ZIP SHA mismatch')
        with zipfile.ZipFile(io.BytesIO(zbytes)) as z:
            if z.testzip() is not None:raise GateError('Build ZIP CRC failed')
            tbytes=z.read('brlcad-runtime.tar.gz')
        if hash_bytes(tbytes)!=TAR_SHA:raise GateError('Runtime SHA mismatch')
        tp=scratch/'runtime.tar.gz';tp.write_bytes(tbytes)
        runtime=scratch/'runtime';runtime.mkdir()
        rec['runtime']=safe_extract_runtime(tp,runtime)
        fixture_dir=scratch/'fixtures';fixture_dir.mkdir()
        rec['fixtures']=[]
        for name,owner,repo,blob,sha in FIXTURES:
            api=f'https://api.github.com/repos/{owner}/{repo}/git/blobs/{blob}'
            metadata=json.loads(bounded_http(api,100_000))
            if metadata.get('sha')!=blob or metadata.get('encoding')!='base64':raise GateError('Fixture blob mismatch '+name)
            b=base64.b64decode(metadata['content'],validate=False)
            if len(b)>100000 or not b.startswith(b'ISO-10303-21;'):raise GateError('Fixture size/schema mismatch '+name)
            check=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
            if check!=blob or hash_bytes(b)!=sha:raise GateError('Fixture identity mismatch '+name)
            (fixture_dir/name).write_bytes(b)
            rec['fixtures'].append({'name':name,'sha256':sha,'blob':blob,'bytes':len(b)})
        if shutil.which('docker') is None:raise GateError('Docker client unavailable')
        rec['host']={'uname':os.uname().release,'python':sys.version,
                     'docker_sha256':hash_file(shutil.which('docker')),
                     'host_netns':rec['host_netns']}
        info=docker_json(cmd('docker_info',['docker','info','--format','{{json .}}'],25),evidence)
        rec['docker_cgroup_v2']=verify_docker_cgroup_v2(info)
        rec['docker_version']=stdout_text(cmd('docker_version',['docker','version','--format','{{.Server.Version}}'],20),evidence).strip()
        require_success(cmd('image_pull',['docker','pull','--platform','linux/amd64',IMAGE],120,4_000_000))
        im=docker_json(cmd('image_inspect',['docker','image','inspect',IMAGE,'--format','{{json .}}'],25),evidence)
        image_id=im.get('Id')
        if im.get('Architecture')!='amd64' or not image_id or not any(IMAGE.split('@')[1] in d for d in im.get('RepoDigests') or []):
            raise GateError('Pinned image identity mismatch')
        rec['image']={'ref':IMAGE,'Id':image_id,'RepoDigests':im.get('RepoDigests')}
        # Execute separate normal and forced-timeout canaries, no STEP command.
        scripts=[('normal','fixture_canary.sh'),('timeout','process_tree_canary.sh')]
        for idx,(kind,source) in enumerate(scripts):
            name=label+'-'+kind
            content=(pathlib.Path(__file__).parent/source).read_text()
            rec['containers'].append({'name':name,'kind':kind,'script_sha256':hash_bytes(content.encode())})
            argv=['docker','create','--name',name,'--label','adr001.p2=public-ap242-preflight',
                  '--platform','linux/amd64','--read-only','--network','none','--ipc','none','--cgroupns','private',
                  '--cap-drop','ALL','--security-opt','no-new-privileges:true','--user','65534:65534',
                  '--pids-limit',str(PIDS),'--memory',str(MEM),'--memory-swap',str(MEM),
                  '--memory-swappiness','0','--cpus','1',
                  '--ulimit','core=0:0','--ulimit','fsize=8388608:8388608',
                  '--tmpfs','/scratch:rw,nosuid,nodev,noexec,size=67108864,mode=1777',
                  '--mount',f'type=bind,src={runtime},dst=/runtime,readonly',
                  '--mount',f'type=bind,src={fixture_dir},dst=/fixtures,readonly',
                  '-e','HOME=/scratch','-e','TMPDIR=/scratch',IMAGE,'/bin/sh','-ec',content]
            cr=cmd('create_'+kind,argv,35);require_success(cr);active.append(name)
            observed=docker_json(cmd('inspect_'+kind,['docker','inspect',name,'--format','{{json .}}'],25),evidence)
            verify_container_inspect(observed,str(runtime),str(fixture_dir),image_id,info)
            # First verify static settings, then execute the normal/timeout canaries.
            if kind=='normal':
                run=cmd('start_normal',['docker','start','-a',name],50)
                bounded_complete_streams(evidence/run['stdout_file'],evidence/run['stderr_file'],4_000_000)
                out_text=stdout_text(run,evidence)
                require_success(run)
                a=out_text.split('MOUNTINFO_BEGIN\n')
                if len(a)!=2:raise GateError('Missing/duplicate mountinfo section')
                b=a[1].split('MOUNTINFO_END\n')
                if len(b)!=2:raise GateError('Incomplete mountinfo section')
                mountinfo=b[0]
                rec['normal_evidence']=verify_canary(out_text,rec['host_netns'],mountinfo,
                     masked_paths=(observed.get('HostConfig') or {}).get('MaskedPaths'))
                rec['normal_evidence']['effective_cgroup_limits_verified_in_running_payload']=True
                rec['normal_evidence']['mountinfo_sha256']=hash_bytes(mountinfo.encode())
                cleanup_one(name,kind)
            else:
                # Deliberately start a shell + sleep child, observe both, then
                # trigger an independent short host watchdog and force removal.
                require_success(cmd('start_timeout',['docker','start',name],20))
                top=cmd('top_timeout',['docker','top',name,'-eo','pid,ppid,args'],15)
                require_success(top)
                top_data=stdout_text(top,evidence)
                tree=extract_observed_sleep_tree(top_data)
                observed_run=docker_json(cmd('running_timeout',['docker','inspect',name,'--format','{{json .State}}'],20),evidence)
                host_pid=observed_run.get('Pid')
                if observed_run.get('Running') is not True or not isinstance(host_pid,int) or host_pid<=1:
                    raise GateError('Watchdog container not running')
                # docker wait would block ~180s without termination; the
                # 3-second independent watchdog MUST time out.
                wait=cmd('watchdog_timeout',['docker','wait',name],3)
                if wait['rc']!=124 or wait['timed_out'] is not True:
                    raise GateError('Host watchdog failed to bound docker wait')
                if host_pid!=tree['shell_pid']:
                    raise GateError('Docker inspector PID differs from observed shell PID')
                cleanup_one(name,kind,tree['observed_pids'])
                rec['timeout_evidence']={'watchdog_fired':True,
                    'container_was_running':True,'host_pid_before_kill':host_pid,
                    'two_or_more_tree_processes_observed':True,
                    'observed_tree':tree,
                    'docker_top_sha256':top['stdout_sha256'],
                    'removed_and_host_pid_absent':True}
        if container_ids('finished'):raise GateError('P2-labeled containers remain')
        rec['runner_enforcement']='OBSERVED_FOR_PREFLIGHT_ONLY'
        rec['status']='PASS_SECURITY_PREFLIGHT_ONLY'
    except Exception as e:
        rec['error']=repr(e)
        print('P2 PREFLIGHT HOLD:',e,file=sys.stderr)
    finally:
        # All previously created containers must be forcibly removed even after failure.
        for k,name in enumerate(list(active)):
            try:cleanup_one(name,'finally_'+str(k))
            except Exception as e:rec.setdefault('cleanup_errors',[]).append(repr(e))
        if rec.get('cleanup_errors'):rec['status']='HOLD'
        rec['seconds']=round(time.monotonic()-started,3)
        rec['peak_parent_rss_kib']=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        rec['host_aggregate_cgroup_enforced']=False
        try:shutil.rmtree(scratch)
        except Exception as e:rec['status']='HOLD';rec['scratch_cleanup_error']=repr(e)
        # Verify evidence set bounded, hash all raw streams, and write an immutable manifest.
        try:
            evidence_bytes=sum(p.stat().st_size for p in evidence.iterdir() if p.is_file())
            if evidence_bytes>60_000_000:raise GateError('Total raw evidence exceeded explicit 60 MB budget')
            rec['raw_evidence_bytes']=evidence_bytes
            write_json(out/'SECURITY_PREFLIGHT.json',rec)
            manifest=[]
            for p in sorted(out.rglob('*')):
                if p.is_file() and p.name!='SHA256SUMS.txt':manifest.append(f'{hash_file(p)}  {p.relative_to(out).as_posix()}')
            (out/'SHA256SUMS.txt').write_text('\n'.join(manifest)+'\n')
        except Exception as e:
            print('Evidence sealing failure:',e,file=sys.stderr)
            return 1
    return 0 if rec['status']=='PASS_SECURITY_PREFLIGHT_ONLY' else 1

if __name__=='__main__':sys.exit(main())
