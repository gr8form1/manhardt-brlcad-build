"""Bext dependency checkpoint: same-workflow, pinned-host, hash-authenticated handoff."""
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import tarfile

from common import sha256, write_json

SCHEMA = 'MANHARDT_BEXT_SAME_WORKFLOW_PREFIX/1'
ARCHIVE = 'bext-output.tar.gz'
RECEIPT = 'bext-output-receipt.json'


def insist(value, reason):
    if not value:
        raise RuntimeError(reason)


def fingerprint(pins, cmake, attempt):
    """Bind build stages to pinned commits, host compiler, CMake, OS, and path."""
    import shutil
    insist(platform.machine() == 'x86_64', 'Pinned x86_64 runner required')
    cc = shutil.which('gcc-13')
    cxx = shutil.which('g++-13')
    insist(cc is not None and cxx is not None, 'Pinned compilers missing')
    return {
        'brlcad_commit': pins['brlcad_commit'],
        'bext_commit': pins['bext_commit'],
        'bext_gitlinks_sha256': hashlib.sha256(json.dumps(
            pins['bext_gitlinks'], sort_keys=True).encode()).hexdigest(),
        'cmake_sha256': sha256(cmake),
        'gcc13_sha256': sha256(Path(cc).resolve()),
        'gxx13_sha256': sha256(Path(cxx).resolve()),
        'machine': platform.machine(),
        'runner_image_os': os.environ.get('ImageOS'),
        'runner_image_version': os.environ.get('ImageVersion'),
        'absolute_attempt': str(Path(attempt).resolve()),
    }


def inventory(root):
    """Hash all regular members, reject escaping or absolute symlinks."""
    root = Path(root)
    insist(root.is_dir() and not root.is_symlink(), 'Missing legitimate bext prefix')
    root = root.resolve()
    result = []
    for path in sorted(root.rglob('*')):
        rel = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if stat.S_ISLNK(mode):
            target = os.readlink(path)
            insist(not os.path.isabs(target), f'Absolute dependency symlink: {rel}')
            resolved = path.resolve(strict=True)
            insist(resolved.is_relative_to(root),
                   f'Escaping dependency symlink: {rel}')
            result.append({'path': rel, 'type': 'symlink', 'target': target})
        elif stat.S_ISREG(mode):
            result.append({'path': rel, 'type': 'file',
                           'size': path.stat().st_size,
                           'sha256': sha256(path), 'mode': mode & 0o777})
        else:
            raise RuntimeError(f'Nonregular dependency member refused: {rel}')
    insist(result, 'Empty dependency prefix')
    return result


def create_checkpoint(prefix, out, pins, cmake, attempt):
    prefix, out = Path(prefix), Path(out)
    insist((prefix/'install').is_dir() and (prefix/'noinstall').is_dir(),
           'Incomplete pinned dependency prefix')
    insist((prefix/'bext-install-manifest.json').is_file(),
           'Missing dependency installation manifest')
    members = inventory(prefix)
    out.mkdir(parents=True, exist_ok=True)
    archive = out/ARCHIVE
    insist(not archive.exists(), 'Refusing checkpoint overwrite')
    with tarfile.open(archive, 'w:gz', compresslevel=3,
                      format=tarfile.PAX_FORMAT) as tf:
        tf.add(prefix, arcname='bext-output', recursive=False)
        for member in sorted(prefix.rglob('*')):
            tf.add(member, arcname='bext-output/'+member.relative_to(prefix).as_posix(),
                   recursive=False)
    # Refuse oversized artifacts; a failed custody handoff is NOT a build PASS.
    insist(archive.stat().st_size < 1800000000,
           'Bext stage archive exceeds 1.8 GB cautious custody ceiling')
    receipt = {'schema': SCHEMA, 'prefix': str(prefix.resolve()),
               'fingerprint': fingerprint(pins, cmake, attempt),
               'members': members, 'member_count': len(members),
               'archive_sha256': sha256(archive),
               'archive_bytes': archive.stat().st_size}
    write_json(out/RECEIPT, receipt)
    return {k: receipt[k] for k in
            ('schema', 'member_count', 'archive_sha256', 'archive_bytes')}


def restore_checkpoint(stage, prefix, pins, cmake, attempt):
    stage, prefix = Path(stage), Path(prefix)
    receipt = json.loads((stage/RECEIPT).read_text())
    insist(receipt.get('schema') == SCHEMA, 'Wrong checkpoint schema')
    insist(receipt.get('prefix') == str(prefix.resolve()),
           'Dependency output path differs between stages')
    insist(receipt.get('fingerprint') == fingerprint(pins, cmake, attempt),
           'Runner, source pins, or compiler mismatch')
    archive = stage/ARCHIVE
    insist(archive.is_file() and sha256(archive) == receipt.get('archive_sha256')
           and archive.stat().st_size == receipt.get('archive_bytes'),
           'Bext checkpoint archive integrity failure')
    insist(not prefix.exists(), 'Refusing replacement of dependency prefix')
    with tarfile.open(archive, 'r:gz') as tf:
        names = [m.name for m in tf.getmembers()]
        insist(len(names) == len(set(names)), 'Duplicate tar entries')
        insist(all(n == 'bext-output' or n.startswith('bext-output/')
                   for n in names), 'Unexpected archive root')
        insist(all(m.isfile() or m.isdir() or m.issym() for m in tf.getmembers()),
               'Unsupported tar member type')
        tf.extractall(path=prefix.parent, filter='data')
    insist(prefix.is_dir(), 'Bext output not restored')
    rows = inventory(prefix)
    insist(rows == receipt.get('members') and len(rows) == receipt.get('member_count'),
           'Restored dependency content differs from producer')
    insist((prefix/'install').is_dir() and (prefix/'noinstall').is_dir()
           and (prefix/'bext-install-manifest.json').is_file(),
           'Restored dependency prefix incomplete')
    return {'schema': SCHEMA, 'archive_sha256': receipt['archive_sha256'],
            'member_count': len(rows), 'status': 'SAME_RUN_CHECKPOINT_VERIFIED'}
