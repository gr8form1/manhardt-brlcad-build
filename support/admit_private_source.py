"""Authenticate and safely extract one private M1 source archive. No network access."""
import argparse,hashlib,json,os,shutil,stat,sys,time,zipfile
from pathlib import Path,PurePosixPath

ADMISSION_DEADLINE_S=60.0

def sha_bytes(b): return hashlib.sha256(b).hexdigest()
def sha_file(p):
    h=hashlib.sha256()
    with open(p,'rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()

def safe_member(info):
    p=PurePosixPath(info.filename)
    mode=(info.external_attr>>16)&0xffff
    return (not p.is_absolute() and '..' not in p.parts and not stat.S_ISLNK(mode))

def elapsed_from_t0_ns(t0_ns):
    try:t0_ns=int(t0_ns)
    except (TypeError,ValueError): raise ValueError('invalid original T0')
    now=time.monotonic_ns()
    if t0_ns<=0 or t0_ns>now: raise ValueError('invalid original T0')
    return (now-t0_ns)/1_000_000_000.0

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--archive',required=True); ap.add_argument('--expected-sha256',required=True)
    ap.add_argument('--destination',required=True); ap.add_argument('--receipt',required=True)
    ap.add_argument('--source-repository',required=True); ap.add_argument('--source-repository-id',required=True); ap.add_argument('--artifact-name',required=True)
    ap.add_argument('--artifact-id',required=True); ap.add_argument('--source-run-id',required=True)
    ap.add_argument('--t0-monotonic-ns',required=True,help='Original runner monotonic T0 armed before source acquisition')
    a=ap.parse_args(); src=Path(a.archive).resolve(strict=True); dst=Path(a.destination); receipt=Path(a.receipt)
    try: initial_elapsed=elapsed_from_t0_ns(a.t0_monotonic_ns)
    except ValueError as e: sys.exit('STOP: '+str(e))
    if initial_elapsed>=ADMISSION_DEADLINE_S: sys.exit('STOP: source admission started after T0+60')
    if src.is_symlink() or not src.is_file() or dst.exists() or receipt.exists(): sys.exit('STOP: invalid admission paths')
    if sha_file(src)!=a.expected_sha256: sys.exit('STOP: source archive SHA-256 mismatch')
    with zipfile.ZipFile(src) as z:
        infos=z.infolist()
        if not infos or any(not safe_member(i) for i in infos): sys.exit('STOP: unsafe ZIP member')
        names={i.filename for i in infos if not i.is_dir()}
        if 'PACKAGE_MANIFEST.json' not in names or 'M1/m1.py' not in names or 'M1/acceptance.json' not in names:
            sys.exit('STOP: required source members missing')
        manifest=json.loads(z.read('PACKAGE_MANIFEST.json'))
        files=manifest.get('files') if isinstance(manifest,dict) else None
        if not isinstance(files,dict): sys.exit('STOP: invalid package manifest')
        for name,expected in files.items():
            if name not in names or sha_bytes(z.read(name))!=expected: sys.exit('STOP: internal package hash mismatch: '+name)
        if names-set(files)-{'PACKAGE_MANIFEST.json'}: sys.exit('STOP: unlisted package member')
        dst.mkdir(mode=0o700,parents=False)
        try:
            for info in infos:
                p=PurePosixPath(info.filename)
                target=dst.joinpath(*p.parts)
                if info.is_dir(): target.mkdir(mode=0o700,parents=True,exist_ok=True); continue
                target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                data=z.read(info); fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
                with os.fdopen(fd,'wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
            admitted_elapsed=elapsed_from_t0_ns(a.t0_monotonic_ns)
            if admitted_elapsed>=ADMISSION_DEADLINE_S:
                raise TimeoutError('source admission not complete before T0+60')
        except TimeoutError as exc:
            shutil.rmtree(dst,ignore_errors=True); sys.exit('STOP: '+str(exc))
        except Exception:
            shutil.rmtree(dst,ignore_errors=True); raise
    rec={
      'state':'ADMITTED_PRIVATE_SOURCE','archive_sha256':a.expected_sha256,
      'source_repository':a.source_repository,'source_repository_id':str(a.source_repository_id),'artifact_name':a.artifact_name,'artifact_id':str(a.artifact_id),
      'source_run_id':str(a.source_run_id),'m1_sha256':sha_file(dst/'M1/m1.py'),
      'acceptance_sha256':sha_file(dst/'M1/acceptance.json'),'package_manifest_sha256':sha_file(dst/'PACKAGE_MANIFEST.json'),'admission_tool_sha256':sha_file(Path(__file__).resolve()),
      'admission_timing':{'t0_monotonic_ns':str(a.t0_monotonic_ns),'deadline_s':ADMISSION_DEADLINE_S,'completed_elapsed_s':admitted_elapsed,'completed_before_deadline':True}}
    receipt.write_text(json.dumps(rec,indent=2,sort_keys=True)+'\n'); receipt.chmod(0o600)
    print(json.dumps(rec,sort_keys=True))
if __name__=='__main__': main()
