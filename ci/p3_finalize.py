#!/usr/bin/env python3
"""ADR-001 P3: post-cleanup evidence seal. Never invokes Docker or STEP.

Intentionally runs AFTER the GitHub Actions always() cleanup step. The
controller's earlier SHA256SUMS.txt remains untouched and is itself covered
by the final inventory. FINAL_SHA256SUMS.txt is the sole self-excluded member.
"""
import argparse
import hashlib
import json
from pathlib import Path

MAX_OUTPUT_BYTES = 80_000_000
FINAL = 'FINAL_SHA256SUMS.txt'
RECEIPT = 'FINAL_EVIDENCE_STATUS.json'


def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def seal(root):
    root=Path(root).resolve(strict=True)
    if not root.is_dir():raise RuntimeError('Evidence root missing')
    if (root/FINAL).exists() or (root/RECEIPT).exists():
        raise RuntimeError('Final seal already exists; refusing overwrite')
    cleanup={n:(root/n).is_file() and not (root/n).is_symlink()
             for n in ('cleanup_before.txt','cleanup_after.txt')}
    before=root/'cleanup_before.txt'; after=root/'cleanup_after.txt'
    after_empty=cleanup['cleanup_after.txt'] and after.stat().st_size==0
    controller_manifest=root/'SHA256SUMS.txt'
    controller_receipt=root/'SECURITY_PREFLIGHT.json'
    clean_failure=root/'cleanup_failure.txt'
    status='PASS_EVIDENCE_SEAL_ONLY' if (all(cleanup.values()) and after_empty and
         not clean_failure.exists() and controller_manifest.is_file() and
         controller_receipt.is_file()) else 'HOLD_INCOMPLETE_CLEANUP_EVIDENCE'
    receipt={
        'status':status,
        'scope':'P3 final evidence inventory, not runner security qualification',
        'controller_manifest_present':controller_manifest.is_file(),
        'controller_receipt_present':controller_receipt.is_file(),
        'cleanup_files_present':cleanup,
        'cleanup_after_empty':after_empty,
        'cleanup_failure_file_present':clean_failure.exists(),
        'cleanup_sha256':{n:sha(root/n) for n,present in cleanup.items() if present},
        'missing_cleanup_evidence':[n for n,present in cleanup.items() if not present],
        'sole_intentional_inventory_exclusion':FINAL,
        'inventories_are_not_self_hashing':True,
        'no_geometry_execution':True,
    }
    (root/RECEIPT).write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n',encoding='utf-8')
    files=[];size=0
    for p in sorted(root.rglob('*')):
        if p.is_symlink():raise RuntimeError('Symlink in evidence: '+str(p.relative_to(root)))
        if p.is_dir():continue
        if not p.is_file():raise RuntimeError('Unexpected nonregular evidence')
        rel=p.relative_to(root).as_posix()
        if '\n' in rel or '\r' in rel:raise RuntimeError('Unsafe evidence filename')
        if rel==FINAL:raise RuntimeError('Unexpected self-reference')
        size+=p.stat().st_size
        if size>MAX_OUTPUT_BYTES:raise RuntimeError('Evidence inventory exceeds explicit size cap')
        files.append((rel,sha(p)))
    if not files:raise RuntimeError('Empty evidence inventory')
    (root/FINAL).write_text(''.join(f'{digest}  {rel}\n' for rel,digest in files),encoding='utf-8')
    return {'status':status,'inventoried_files':len(files),
            'inventoried_bytes':size,'final_sha256sums_sha256':sha(root/FINAL),
            'cleanup_sha256':receipt['cleanup_sha256']}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True)
    args=parser.parse_args()
    try:
        result=seal(args.output)
        print(json.dumps(result,sort_keys=True))
        return 0 if result['status']=='PASS_EVIDENCE_SEAL_ONLY' else 1
    except Exception as exc:
        print('P3 FINAL EVIDENCE HOLD:',repr(exc),file=__import__('sys').stderr)
        return 1

if __name__=='__main__':raise SystemExit(main())
