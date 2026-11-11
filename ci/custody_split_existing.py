#!/usr/bin/env python3
"""Archive existing authenticated GitHub P1 native-build artifact without recompilation.
Hard-coded source identity; no manufacturer CAD; read-only input.
All segment artifacts are below the 512 MB connector cap.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
import urllib.request

REPO = 'gr8form1/manhardt-brlcad-build'
RUN_ID = 42897744666
HEAD_SHA = '78856c27dbf6e17b2f660e455d2bd7d431a8dabd'
ARTIFACT_ID = 13815662301
ARTIFACT_NAME = 'manhardt-geometry-tools-42897744666-1'
SOURCE_GITHUB_DIGEST = 'sha256:f79c820ee8ff18bc2f2328b090f4525dfe73fea311b174b770ec3c1ac5f75e47'
SOURCE_GITHUB_BYTES = 825200137
CHUNK_SIZE = 240000000
MAX_CHUNKS = 20

def insist(value, explanation):
    if not value:
        raise RuntimeError(explanation)

def checksum(path):
    h = hashlib.sha256()
    with open(path, 'rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def get_api(path):
    token = os.environ['GITHUB_TOKEN']
    req = urllib.request.Request('https://api.github.com/repos/' + REPO + path, headers={
       'Authorization': 'Bearer ' + token,
       'Accept': 'application/vnd.github+json',
       'X-GitHub-Api-Version': '2022-11-28'
    })
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)

def main():
    insist(os.environ.get('GITHUB_REPOSITORY') == REPO, 'Unexpected repository')
    insist(os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'Only manual dispatch')
    insist(os.environ.get('GITHUB_RUN_ATTEMPT') == '1', 'Only initial invocation authorized')
    insist(os.environ.get('GITHUB_REF') == 'refs/heads/feature/p1-run42897744666-custody', 'Wrong branch')
    run = get_api('/actions/runs/' + str(RUN_ID))
    insist(run['head_sha'] == HEAD_SHA and run['status'] == 'completed' and run['conclusion'] == 'success'
           and run['head_branch'] == 'feature/step-export-p1-native-candidate'
           and run['event'] == 'workflow_dispatch', 'P1 source run identity/status mismatch')
    source_artifact = get_api('/actions/artifacts/' + str(ARTIFACT_ID))
    insist(source_artifact['digest'] == SOURCE_GITHUB_DIGEST and
           source_artifact['size_in_bytes'] == SOURCE_GITHUB_BYTES,
           'P1 GitHub artifact digest/byte-count mismatch')
    insist(source_artifact['name'] == ARTIFACT_NAME and not source_artifact['expired']
           and source_artifact['workflow_run']['id'] == RUN_ID,
           'P1 source artifact ID/name/run mismatch or expired')
    root = Path('source-artifact').resolve()
    insist(root.is_dir() and not root.is_symlink(), 'Missing downloaded source artifact')
    insist((root / 'RESULT.json').is_file()
           and (root / 'SHA256SUMS').is_file(), 'Missing required original evidence files')
    source_result = json.loads((root / 'RESULT.json').read_text())
    insist(source_result.get('run', {}).get('GITHUB_REPOSITORY') == REPO and
           source_result.get('run', {}).get('GITHUB_SHA') == HEAD_SHA and
           source_result.get('run', {}).get('GITHUB_RUN_ID') == str(RUN_ID) and
           source_result.get('run', {}).get('GITHUB_RUN_ATTEMPT') == '1' and
           source_result.get('disposition') == 'GEOMETRY_TOOLKIT_CANDIDATE',
           'P1 source RESULT identity/disposition mismatch')
    paths = sorted(root.rglob('*'))
    members = []
    for p in paths:
        insist(p.resolve().is_relative_to(root) and not p.is_symlink(),
               'Symlink or escape in source artifact: ' + str(p))
        if p.is_file():
            insist(stat.S_ISREG(p.lstat().st_mode), 'Unexpected file member')
            members.append({'path': p.relative_to(root).as_posix(),
                            'size': p.stat().st_size,
                            'sha256': checksum(p)})
        else:
            insist(p.is_dir(), 'Unexpected non-directory member')
    insist(len(members) >= 5, 'Suspiciously small P1 output')
    out = Path('custody')
    out.mkdir(exist_ok=False)
    master = out / 'p1-source-artifact.tar'
    with tarfile.open(master, 'w', format=tarfile.PAX_FORMAT) as archive:
        for p in paths:
            archive.add(p, arcname='source-artifact/' + p.relative_to(root).as_posix(), recursive=False)
    master_hash = checksum(master)
    chunks = []
    with master.open('rb') as reader:
        for index in range(MAX_CHUNKS + 1):
            block = reader.read(CHUNK_SIZE)
            if not block:
                break
            insist(index < MAX_CHUNKS,
                   'Unanticipated >4.8 GB source artifact: avoid incomplete custody')
            path = out / ('p1-part-%03d.bin' % index)
            path.write_bytes(block)
            chunks.append({'part': index, 'name': path.name,
                           'size': len(block), 'sha256': checksum(path)})
    insist(chunks and sum(x['size'] for x in chunks) == master.stat().st_size,
           'Chunk coverage incomplete')
    h = hashlib.sha256()
    for piece in chunks:
        with (out/piece['name']).open('rb') as f:
            for b in iter(lambda:f.read(1048576),b''):
                h.update(b)
    insist(h.hexdigest() == master_hash, 'Chunk reconstruction hash mismatch')
    receipt = {
       'format': 'MANHARDT_GITHUB_P1_CUSTODY_SEGMENTS/1',
       'source_repository': REPO, 'source_run': RUN_ID,
       'source_commit': HEAD_SHA,
       'source_artifact_id': ARTIFACT_ID,
       'source_artifact_name': ARTIFACT_NAME,
       'source_github_digest': source_artifact.get('digest'),
       'source_artifact_reported_bytes': source_artifact['size_in_bytes'],
       'repack_workflow_run': os.environ['GITHUB_RUN_ID'],
       'repack_workflow_sha': os.environ['GITHUB_SHA'],
       'method': 'Source GitHub artifact downloaded through actions/download-artifact, expanded; rewrapped uncompressed as PAX TAR; split without changing files',
       'tar_sha256': master_hash, 'tar_bytes': master.stat().st_size,
       'chunk_bytes': CHUNK_SIZE,
       'chunks': chunks, 'files': members
    }
    (out/'CUSTODY_MANIFEST.json').write_text(json.dumps(receipt, indent=2, sort_keys=True)+'\n')
    (out/'README.txt').write_text(
      'Retrieve every p1-custody-part-NNN artifact, verify CUSTODY_MANIFEST.json SHA-256s, '
      'concatenate files in numeric order, check tar_sha256, extract; then independently validate '
      'RESULT.json, SHA256SUMS and every runtime/component hash. Workflow success is not geometry qualification.\n')
    with open(os.environ['GITHUB_OUTPUT'],'a') as f:
        f.write('count='+str(len(chunks))+'\n')
        f.write('master_sha256='+master_hash+'\n')
        f.write('master_bytes='+str(master.stat().st_size)+'\n')
    # upload artifacts only hold segments, not duplicate full TAR.
    master.unlink()
    print('SUCCESS: source run',RUN_ID,'parts',len(chunks),'bytes',receipt['tar_bytes'],'sha256',master_hash,flush=True)

if __name__=='__main__':
    main()
