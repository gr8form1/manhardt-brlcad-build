"""Collect and relocate trusted, freshly built public-source ELFs for review.

Called only by the GitHub build driver. No Work qualification or CAD import.
"""
import contextlib
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile

from common import elf_code_sections, ldd_map, needed_from_readelf, sha256, write_json

BASELINE = {'libc.so.6', 'libm.so.6', 'libdl.so.2', 'libpthread.so.0', 'librt.so.1',
            'libresolv.so.2', 'libgcc_s.so.1', 'libstdc++.so.6', 'ld-linux-x86-64.so.2'}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def semantics(rec, path):
    dynamic = rec.run(['readelf', '-dW', path])
    program = rec.run(['readelf', '-lW', path])
    soname = re.findall(r'\(SONAME\).*Library soname: \[([^\]]+)\]', dynamic)
    interpreter = re.findall(r'Requesting program interpreter: ([^\]]+)', program)
    needed = needed_from_readelf(dynamic)
    require(all('/' not in x and re.fullmatch(r'[A-Za-z0-9_.+\-]+', x) for x in needed),
            f'Absolute or unsupported DT_NEEDED: {path}')
    return {'needed': needed, 'soname': soname, 'interpreter': interpreter,
            'code_sections': elf_code_sections(path)}


def collect_runtime(rec, seeds):
    queue = list(seeds);seen = set();providers = {};baseline = {}
    while queue:
        path = Path(queue.pop()).resolve()
        if path in seen:
            continue
        seen.add(path)
        semantic = semantics(rec, path)
        resolved = ldd_map(rec.run(['ldd', path]))
        require(all(name in resolved for name in semantic['needed']), f'Incomplete loader map: {path}')
        for name, real in resolved.items():
            real = Path(real)
            row = {'source_path': str(real), 'sha256': sha256(real)}
            bucket = baseline if name in BASELINE else providers
            require(name not in bucket or bucket[name]['sha256'] == row['sha256'],
                    f'Conflicting providers for {name}')
            bucket[name] = row
            if name not in BASELINE:
                queue.append(real)
    return providers, baseline


def copy_regular(source, target, mode=0o644):
    target = Path(target);target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(Path(source).resolve(), target);target.chmod(mode)


def licenses(rec, runtime, brl, ext_output, providers):
    target = runtime / 'licenses';target.mkdir()
    require((brl / 'COPYING').is_file(), 'BRL-CAD COPYING absent')
    copy_regular(brl / 'COPYING', target / 'BRL-CAD-COPYING')
    brl_legal = brl / 'doc/legal'
    if brl_legal.is_dir():
        for file in brl_legal.rglob('*'):
            if file.is_file():
                copy_regular(file, target / 'brlcad-legal' / file.relative_to(brl_legal))
    legal = ext_output / 'install/share/doc/legal/other'
    require(legal.is_dir(), 'Pinned dependency license directory absent')
    for file in legal.rglob('*'):
        if file.is_file():
            copy_regular(file, target / 'bext' / file.relative_to(legal))
    # Include copyright/license notices for bundled system-provided libraries.
    inventory = []
    for name, row in providers.items():
        path = row['source_path']
        if not path.startswith(('/usr/lib/', '/lib/')):
            continue
        owners = rec.run(['dpkg-query', '-S', path], allow_failure=True)
        if not owners.strip() and path.startswith('/usr/lib/'):
            owners = rec.run(['dpkg-query', '-S', path.replace('/usr/lib/', '/lib/', 1)], allow_failure=True)
        matches = [x.split(': ', 1)[0] for x in owners.splitlines() if ': ' in x]
        require(matches, f'Cannot attribute bundled system library: {name}')
        for package in sorted(set(matches)):
            base = package.split(':', 1)[0]
            notice = Path('/usr/share/doc') / base / 'copyright'
            require(notice.is_file(), f'Copyright notice missing for {package}')
            copy_regular(notice, target / 'system' / re.sub(r'[^A-Za-z0-9_.-]', '_', package) / 'copyright')
            inventory.append({'library': name, 'package': package,
                              'package_record': rec.run(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\n', package])})
    return inventory


@contextlib.contextmanager
def hidden_build_trees(roots):
    moved = []
    try:
        for root in roots:
            hidden = root.with_name(root.name + '.hidden-for-relocation-test')
            require(root.is_dir() and not hidden.exists(), 'Cannot hide original build tree')
            root.rename(hidden);moved.append((root, hidden))
        yield
    finally:
        for original, hidden in reversed(moved):
            hidden.rename(original)


def verify_loader_map(rec, runtime, baseline):
    maps = {}
    for path in sorted(runtime.rglob('*')):
        if not path.is_file() or path.read_bytes()[:4] != b'\x7fELF':
            continue
        mapping = ldd_map(rec.run(['ldd', path]))
        for name, source in mapping.items():
            resolved = Path(source).resolve()
            if name in BASELINE:
                require(name in baseline and sha256(resolved) == baseline[name]['sha256'],
                        f'Baseline provider changed: {name}')
            else:
                require(resolved.is_relative_to(runtime.resolve()),
                        f'Library escaped relocated bundle: {name} => {resolved}')
        maps[str(path.relative_to(runtime))] = mapping
    return maps


def make_tar(runtime, destination, source_commit):
    require(not (runtime / 'MANIFEST.json').exists() and not (runtime / 'SHA256SUMS').exists(),
            'Refusing to reuse a previously sealed runtime tree')
    files = sorted(p for p in runtime.rglob('*') if p.is_file())
    rows = []
    for f in files:
        rel = f.relative_to(runtime).as_posix()
        role = ('executable' if rel == 'bin/step-g' else
                'ap242e2-plugin' if rel.startswith('libexec/step/') else
                'library' if rel.startswith('lib/') else
                'license' if rel.startswith('licenses/') else 'evidence')
        rows.append({'path': rel, 'sha256': sha256(f), 'size': f.stat().st_size,
                     'mode': f.stat().st_mode & 0o777, 'role': role})
    write_json(runtime / 'MANIFEST.json', {'schema': 'ADR001_RUNTIME_CONTENTS/2',
                                         'source_commit': source_commit, 'files': rows})
    files = sorted(p for p in runtime.rglob('*') if p.is_file())
    (runtime / 'SHA256SUMS').write_text(''.join(f'{sha256(p)}  {p.relative_to(runtime).as_posix()}\n' for p in files))
    files.append(runtime / 'SHA256SUMS')
    with destination.open('wb') as out, gzip.GzipFile(filename='', fileobj=out, mode='wb', mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w', format=tarfile.USTAR_FORMAT) as tf:
            for f in sorted(files):
                info = tf.gettarinfo(str(f), arcname='brlcad-runtime/' + f.relative_to(runtime).as_posix())
                require(info.isfile(), 'Runtime tar accepts regular files only')
                info.uid = info.gid = 0;info.uname = info.gname = '';info.mtime = 0
                with f.open('rb') as stream:
                    tf.addfile(info, stream)
    return {'sha256': sha256(destination), 'bytes': destination.stat().st_size,
            'payload_files': len(files)}



def preserve_compiled_checkpoint(rec, out, targets, run):
    """Seal public-source ELFs before relocation; not a runnable or qualified bundle.

    A later recovery procedure must independently authenticate this artifact,
    its provider map, the toolchain and compatible host libraries.
    """
    executable = targets['step-g'][0]
    plugin = targets['step-schema-ap242e2'][0]
    require(executable.is_file() and plugin.is_file(), 'Checkpoint targets missing')
    providers, baseline = collect_runtime(rec, [executable, plugin])
    root = out / 'compiled-checkpoint'
    require(not root.exists(), 'Checkpoint already exists')
    root.mkdir()
    copy_regular(executable, root / 'bin/step-g', 0o755)
    copy_regular(plugin, root / 'libexec/step' / plugin.name)
    for name, provider in sorted(providers.items()):
        require(name not in {'step-g', plugin.name}, 'Checkpoint name collision')
        copy_regular(provider['source_path'], root / 'lib' / name)
    rows = []
    for f in sorted(root.rglob('*')):
        if f.is_file():
            rows.append({'path': f.relative_to(root).as_posix(),
                         'sha256': sha256(f), 'size': f.stat().st_size})
    write_json(root / 'CHECKPOINT.json', {
        'schema': 'ADR001_COMPILED_CHECKPOINT/1',
        'status': 'UNRELOCATED_UNQUALIFIED',
        'run': run, 'files': rows,
        'bundled_providers': providers, 'host_baseline': baseline,
        'source_pins': json.loads((out / 'evidence/source-pins.json').read_text())})
    destination = out / 'compiled-checkpoint.tar.gz'
    with destination.open('wb') as stream, gzip.GzipFile(filename='', fileobj=stream,
                                                        mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for f in sorted(p for p in root.rglob('*') if p.is_file()):
                info = archive.gettarinfo(str(f), arcname='compiled-checkpoint/' + f.relative_to(root).as_posix())
                require(info.isfile(), 'Checkpoint expects regular files only')
                info.uid = info.gid = 0
                info.uname = info.gname = ''
                info.mtime = 0
                with f.open('rb') as source:
                    archive.addfile(info, source)
    write_json(out / 'evidence/compiled-checkpoint.json', {
        'status': 'UNRELOCATED_UNQUALIFIED',
        'sha256': sha256(destination), 'bytes': destination.stat().st_size,
        'payload_files': len(rows), 'source_commit': run.get('GITHUB_SHA')})
    shutil.rmtree(root)

def package_runtime(rec, attempt, out, brl, bext, build, ext_build, ext_output, targets, run):
    metadata = out / 'evidence'
    executable = targets['step-g'][0]
    plugin = targets['step-schema-ap242e2'][0]
    require(executable.is_file() and plugin.is_file(), 'Required build output missing')
    providers, baseline = collect_runtime(rec, [executable, plugin])
    runtime = attempt / 'package/brlcad-runtime';runtime.mkdir(parents=True)
    copy_regular(executable, runtime / 'bin/step-g', 0o755)
    copy_regular(plugin, runtime / 'libexec/step' / plugin.name)
    for name, row in providers.items():
        copy_regular(row['source_path'], runtime / 'lib' / name)
    write_json(metadata / 'runtime-providers.json', {'bundled': providers, 'host_baseline': baseline})
    write_json(metadata / 'bundled-system-license-records.json', licenses(rec, runtime, brl, ext_output, providers))
    relocation = []
    for path in sorted(runtime.rglob('*')):
        if not path.is_file() or path.read_bytes()[:4] != b'\x7fELF':
            continue
        rel = path.relative_to(runtime).as_posix()
        rpath = '$ORIGIN/../lib' if rel == 'bin/step-g' else '$ORIGIN/../../lib' if rel.startswith('libexec/step/') else '$ORIGIN'
        before_hash = sha256(path);before = semantics(rec, path)
        rec.run(['patchelf', '--set-rpath', rpath, path])
        after = semantics(rec, path)
        require(before == after, f'RPATH change altered code/NEEDED/SONAME/interpreter: {rel}')
        require(rec.run(['patchelf', '--print-rpath', path]).strip() == rpath, f'RPATH mismatch: {rel}')
        rec.run(['readelf', '--version-info', path]);rec.run(['readelf', '-nW', path])
        relocation.append({'path': rel, 'original_sha256': before_hash, 'runtime_sha256': sha256(path),
                           'RUNPATH': rpath, 'semantic_checks': after})
    write_json(metadata / 'relocation.json', relocation)
    other = attempt / 'second-prefix/different-layout/brlcad-runtime'
    other.parent.mkdir(parents=True);shutil.copytree(runtime, other)
    maps = {}
    with hidden_build_trees([build, ext_build, ext_output]):
        for number, root in enumerate([runtime, other], 1):
            maps[str(number)] = verify_loader_map(rec, root, baseline)
            help_text = rec.run([root / 'bin/step-g', '--help'], cwd=root)
            help_text += (rec.output / f'{len(rec.records):04d}.stderr').read_text(errors='replace')
            require(all(option in help_text for option in ['--strict', '--exact', '--repair', '--report', '--jobs']),
                    'Required CLI controls absent')
            bu = [p for p in (root / 'lib').glob('libbu.so*') if p.is_file()]
            require(len(bu) == 1, 'Ambiguous/missing bundled libbu')
            query = ('import ctypes,sys; x=ctypes.CDLL(sys.argv[1]); '
                     'x.bu_version.argtypes=[]; x.bu_version.restype=ctypes.c_char_p; '
                     'print(x.bu_version().decode())')
            version = rec.run(['/usr/bin/python3', '-c', query, bu[0]], cwd=root)
            require('7.47.0' in version, 'Compiled libbu version/source mismatch')
    write_json(metadata / 'two-prefix-loader-maps.json', maps)
    write_json(metadata / 'runtime-profile.json', {
        'run': run, 'profile': 'step-g plus AP242e2 only', 'other_compiled_schema_modules': 'not bundled',
        'native_step_g_version_option': 'not provided by pinned CLI',
        'version_evidence': 'bundled libbu bu_version output and binary/source identities',
        'smoke_checks': 'help, compiled-library version and loader maps at two prefixes, original build trees hidden',
        'geometry_controls': 'NOT RUN', 'actual_AP242e2_import': 'NOT TESTED',
        'Work_qualification': 'PENDING', 'Lenovo_qualification': 'PENDING'})
    # All metadata is public runner/build material. No workspace-wide upload.
    shutil.copytree(metadata, runtime / 'metadata')
    for f in (runtime / 'metadata').rglob('*'):
        if f.is_file(): f.chmod(0o644)
    pins = json.loads((metadata / 'source-pins.json').read_text())
    temporary = attempt / 'brlcad-runtime.tar.gz.partial'
    receipt = make_tar(runtime, temporary, pins['brlcad_commit'])
    shutil.move(temporary, out / 'brlcad-runtime.tar.gz')
    (out / 'brlcad-runtime.tar.gz.sha256').write_text(receipt['sha256'] + '\n')
    write_json(metadata / 'runtime-archive.json', receipt)
    return receipt
