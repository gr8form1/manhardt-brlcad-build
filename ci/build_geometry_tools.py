"""Manual public-source GitHub build. Importing this module starts no build."""
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time
import traceback

from common import Recorder, clean_environment, sha256, write_json
from geometry_profile import BUILD_TARGETS, EXECUTABLES, SCHEMAS, cmake_source_components_arg

ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = 'conv:libtclcad:libged:libgcv:libdm:libicv:libanalyze:libwdb:liboptical:librt:libbrep:libnmg:libbv:libbg:libbn:libbu:libpkg'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def checkout(rec, directory, url, commit):
    rec.run(['git', 'init', directory])
    rec.run(['git', '-C', directory, 'remote', 'add', 'origin', url])
    rec.run(['git', '-C', directory, 'fetch', '--depth', '1', 'origin', commit])
    rec.run(['git', '-C', directory, 'checkout', '--detach', commit])
    actual = rec.run(['git', '-C', directory, 'rev-parse', 'HEAD']).strip()
    require(actual == commit, f'Wrong source HEAD: {directory}')


def verify_submodules(rec, bext, pins, required=True):
    text = rec.run(['git', '-C', bext, 'submodule', 'status', '--recursive'])
    require(not any(line.startswith(('+', 'U')) for line in text.splitlines()),
            'Submodule differs from its recorded gitlink')
    if required:
        for rel, expected in [('stepcode/stepcode', 'ed686ee1d9cb8bf763ab8d61ef6d417c3b45c146'),
                              ('opennurbs/opennurbs', '23fc677ba06e49212296ca75fab7fb6c2851b4ce')]:
            head = rec.run(['git', '-C', bext / rel, 'rev-parse', 'HEAD']).strip()
            require(head == expected, 'STEPcode/openNURBS pin mismatch')


def snapshot(rec, brl, bext, metadata):
    for label, repo in [('brlcad', brl), ('bext', bext)]:
        if not (repo / '.git').exists():
            continue
        record = {}
        for key, args in [('head', ['rev-parse', 'HEAD']), ('tree', ['rev-parse', 'HEAD^{tree}']),
                          ('status', ['status', '--porcelain=v1', '--untracked-files=no']),
                          ('diff', ['diff', '--binary']),
                          ('submodules', ['submodule', 'status', '--recursive'])]:
            record[key] = rec.run(['git', '-C', repo] + args, allow_failure=True)
        write_json(metadata / f'{label}-source.json', record)
    if (bext / '.git').exists():
        names = rec.run(['git', '-C', bext, 'ls-files']).splitlines()
        patch_rows = []
        for name in names:
            if name.endswith('.patch') and (bext / name).is_file():
                dest = metadata / 'pinned-bext-patches' / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(bext / name, dest)
                patch_rows.append({'path': name, 'sha256': sha256(dest)})
        write_json(metadata / 'patch-inventory.json', patch_rows)


def target_artifacts(build):
    reply = build / '.cmake/api/v1/reply'
    index = json.loads(sorted(reply.glob('index-*.json'))[-1].read_text())
    codemodel_file = next(x['jsonFile'] for x in index['objects'] if x['kind'] == 'codemodel')
    model = json.loads((reply / codemodel_file).read_text())
    configuration = model['configurations'][0]
    targets = {}
    for row in configuration['targets']:
        obj = json.loads((reply / row['jsonFile']).read_text())
        paths = []
        for artifact in obj.get('artifacts', []):
            path = Path(artifact['path'])
            paths.append(path if path.is_absolute() else build / path)
        targets[row['name']] = paths
    return targets


def collect_build_evidence(attempt, metadata):
    """Retain existing stock configure/provider/ExternalProject logs, even on failure."""
    rows = []
    for label in ['bext', 'brlcad']:
        root = attempt / 'build' / label
        if not root.is_dir():
            continue
        for file in sorted(root.rglob('*')):
            if not file.is_file() or file.is_symlink():
                continue
            rel = file.relative_to(root)
            wanted = (file.name in {'CMakeCache.txt', 'CMakeConfigureLog.yaml',
                                    'TargetDirectories.txt', 'compile_commands.json'}
                      or file.name.endswith(('-out.log', '-err.log'))
                      or ('.cmake/api/v1/reply/' in file.as_posix() and file.suffix == '.json'))
            if not wanted:
                continue
            # upload-artifact excludes hidden paths.  Preserve the source
            # .cmake file-API record under a visible evidence-only path so
            # SHA256SUMS describes exactly what GitHub actually uploads.
            evidence_rel = (Path('cmake-file-api', *rel.parts[1:])
                            if rel.parts[0] == '.cmake' else rel)
            destination = metadata / 'stock-build-records' / label / evidence_rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(file, destination)
            rows.append({'build': label, 'path': rel.as_posix(),
                         'evidence_path': evidence_rel.as_posix(),
                         'sha256': sha256(destination)})
    write_json(metadata / 'stock-build-records.json', rows)


def main():
    # An accidental local invocation must not begin source acquisition.
    require(os.environ.get('GITHUB_ACTIONS') == 'true', 'GitHub execution only')
    require(os.environ.get('GITHUB_REPOSITORY') == 'gr8form1/manhardt-brlcad-build', 'Wrong repository')
    require(os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and os.environ.get('GITHUB_RUN_ATTEMPT') == '1', 'Wrong event/attempt')
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    require(event.get('repository', {}).get('private') is False, 'Public-source repository required')
    require(platform.machine() == 'x86_64', 'x64 runner required')
    out = ROOT / 'out';out.mkdir(exist_ok=False)
    metadata = out / 'evidence';metadata.mkdir()
    started = time.monotonic()
    attempt = Path(os.environ['RUNNER_TEMP']) / 'adr001-brlcad-geometry-attempt'
    attempt.mkdir(exist_ok=False)
    for name in ['home', 'tmp', 'src', 'build', 'private', 'tools']:
        (attempt / name).mkdir()
    env = clean_environment(attempt / 'home', attempt / 'tmp')
    rec = Recorder(metadata / 'commands', env)
    pins = json.loads((ROOT / 'pins/sources.json').read_text())
    brl, bext = attempt / 'src/brlcad', attempt / 'src/bext'
    result = {'schema': 'ADR001_GEOMETRY_BUILD_ATTEMPT/1', 'disposition': 'BUILD_ATTEMPT_FAILED',
              'scientific_qualification': 'NOT_PERFORMED',
              'run': {key: os.environ.get(key) for key in
                      ['GITHUB_REPOSITORY', 'GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT',
                       'ImageOS', 'ImageVersion']}}
    try:
        for program in ['git', 'curl', 'make', 'patch', 'readelf', 'ldd', 'patchelf',
                        '/usr/bin/gcc-13', '/usr/bin/g++-13', '/usr/bin/time']:
            require(shutil.which(program, path=env['PATH']) is not None, f'Missing tool: {program}')
        tool_receipts = {}
        for program, argv in [('gcc-13', ['gcc-13', '--version']), ('g++-13', ['g++-13', '--version']),
                              ('ld', ['ld', '--version']), ('patchelf', ['patchelf', '--version']),
                              ('python3', ['python3', '--version']), ('git', ['git', '--version']),
                              ('make', ['make', '--version'])]:
            path = Path(shutil.which(program, path=env['PATH'])).resolve()
            tool_receipts[program] = {'path': str(path), 'sha256': sha256(path),
                                      'version_output': rec.run(argv)}
        write_json(metadata / 'host-tools.json', tool_receipts)
        rec.run(['uname', '-a']);rec.run(['getconf', 'GNU_LIBC_VERSION'])
        rec.run(['df', '-B1', str(attempt)]);rec.run(['free', '-b'])
        rec.run(['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\n'])
        write_json(metadata / 'source-pins.json', pins)
        controls = []
        for rel in ['.github/workflows/build-brlcad.yml', 'ci/build_geometry_tools.py',
                    'ci/geometry_bundle.py', 'ci/geometry_profile.py', 'ci/native_geometry_smoke.py',
                    'ci/bundle.py', 'ci/common.py', 'pins/sources.json']:
            # Avoid hidden output paths, which upload-artifact intentionally omits.
            stored = 'workflow/build-brlcad.yml' if rel.startswith('.github/') else rel
            dest = metadata / 'control-source' / stored
            dest.parent.mkdir(parents=True, exist_ok=True);shutil.copyfile(ROOT / rel, dest)
            controls.append({'repository_path': rel, 'evidence_path': stored, 'sha256': sha256(dest)})
        write_json(metadata / 'control-source-inventory.json', controls)
        archive = attempt / 'tools/cmake.tar.gz'
        rec.run(['curl', '--fail', '--location', '--proto', '=https', '--tlsv1.2',
                 '--retry', '3', '--retry-delay', '5', '--retry-max-time', '180',
                 '--max-time', '600', '--output', archive, pins['cmake_url']])
        require(archive.stat().st_size == pins['cmake_size_bytes']
                and sha256(archive) == pins['cmake_sha256'], 'CMake archive identity mismatch')
        with tarfile.open(archive, 'r:gz') as tf:
            tf.extractall(attempt / 'tools', filter='data')
        cmake = attempt / 'tools/cmake-3.31.10-linux-x86_64/bin/cmake'
        write_json(metadata / 'cmake.json', {'sha256': sha256(cmake), 'version': rec.run([cmake, '--version'])})
        checkout(rec, brl, 'https://github.com/BRL-CAD/brlcad.git', pins['brlcad_commit'])
        checkout(rec, bext, 'https://github.com/BRL-CAD/bext.git', pins['bext_commit'])
        modules = rec.run(['git', '-C', bext, 'config', '--file', '.gitmodules', '--get-regexp', 'submodule.*.url'])
        require(all(line.split()[-1].startswith('https://github.com/BRL-CAD/')
                    for line in modules.splitlines()), 'Non-public/unapproved root dependency URL')
        tree = rec.run(['git', '-C', bext, 'ls-tree', '-r', 'HEAD'])
        for row in pins['bext_gitlinks']:
            require(f"160000 commit {row['commit']}\t{row['path']}" in tree, 'bext gitlink lock mismatch')
        rec.run(['git', '-C', bext, 'submodule', 'update', '--init', '--depth', '1', '--',
                 'stepcode/stepcode', 'opennurbs/opennurbs'])
        verify_submodules(rec, bext, pins)
        snapshot(rec, brl, bext, metadata)
        ext_build, ext_output = attempt / 'build/bext', attempt / 'private/bext-output'
        rec.run([cmake, '-S', bext, '-B', ext_build, '-G', 'Unix Makefiles',
                 '-DCMAKE_BUILD_TYPE=Release', f'-DCMAKE_INSTALL_PREFIX={ext_output}',
                 f'-DBRLCAD_COMPONENTS={COMPONENTS}', '-DENABLE_ALL=OFF', '-DUSE_BRLCAD=ON',
                 '-DUSE_BRLCAD_EXTRA=ON', '-DUSE_GDAL=OFF', '-DUSE_QT=OFF', '-DUSE_TCL=OFF',
                 '-DUSE_APPLESEED=OFF', '-DUSE_OSPRAY=OFF'])
        shutil.copyfile(ext_build / 'CMakeCache.txt', metadata / 'bext-CMakeCache.txt')
        verify_submodules(rec, bext, pins)
        rec.run(['/usr/bin/time', '-v', '-o', metadata / 'bext-build-rusage.txt',
                 cmake, '--build', ext_build, '--parallel', '1'])
        require((ext_output / 'install').is_dir() and (ext_output / 'noinstall').is_dir(),
                'Missing private dependency output')
        require((ext_output / 'bext-install-manifest.json').is_file(), 'Dependency install manifest absent')
        shutil.copyfile(ext_output / 'bext-install-manifest.json', metadata / 'bext-install-manifest.json')
        build = attempt / 'build/brlcad'
        query = build / '.cmake/api/v1/query';query.mkdir(parents=True)
        (query / 'codemodel-v2').touch()
        rec.run([cmake, '-S', brl, '-B', build, '-G', 'Unix Makefiles',
                 '-DCMAKE_BUILD_TYPE=Release', f'-DCMAKE_INSTALL_PREFIX={attempt / "private/unused-prefix"}',
                 f'-DBRLCAD_EXT_DIR={ext_output}', f'-DBRLCAD_EXT_SOURCE_DIR={bext}',
                 '-DBRLCAD_EXT_PARALLEL=1', cmake_source_components_arg(), '-DBRLCAD_BUNDLED_LIBS=AUTO',
                 '-DBRLCAD_ENABLE_STEP=ON', '-DBRLCAD_ENABLE_MINIMAL=ON', '-DBRLCAD_ENABLE_TCL=OFF',
                 '-DBRLCAD_ENABLE_TK=OFF', '-DBRLCAD_ENABLE_QT=OFF', '-DBRLCAD_ENABLE_OPENGL=OFF',
                 '-DBRLCAD_ENABLE_X11=OFF', '-DBRLCAD_ENABLE_GDAL=OFF', '-DBRLCAD_ENABLE_BULLET=OFF',
                 '-DBRLCAD_ENABLE_ASSETIMPORT=OFF', '-DBRLCAD_ENABLE_OPENVDB=OFF',
                 '-DBRLCAD_EXTRADOCS=OFF', '-DBRLCAD_INSTALL_DOCS=OFF',
                 '-DBRLCAD_INSTALL_EXAMPLE_GEOMETRY=OFF', '-DBUILD_TESTING=ON',
                 '-DBRLCAD_ENABLE_STRICT=OFF', '-DBRLCAD_WARNINGS=ON',
                 '-DBUILD_SHARED_LIBS=ON', '-DBUILD_STATIC_LIBS=OFF', '-DBRLCAD_ENABLE_UNITY_BUILD=OFF',
                 '-DBRLCAD_LTO_MODE=OFF', '-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF',
                 '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'])
        shutil.copyfile(build / 'CMakeCache.txt', metadata / 'brlcad-CMakeCache.txt')
        if (build / 'compile_commands.json').exists():
            shutil.copyfile(build / 'compile_commands.json', metadata / 'compile_commands.json')
        targets = target_artifacts(build)
        require(all(name in targets for name in BUILD_TARGETS), 'Required geometry-tool target absent')
        rec.run(['/usr/bin/time', '-v', '-o', metadata / 'step-g-build-rusage.txt',
                 cmake, '--build', build, '--target', *BUILD_TARGETS, '--parallel', '1'])
        targets = target_artifacts(build)
        write_json(metadata / 'target-artifacts.json', {k: [str(p) for p in v]
                                                       for k, v in targets.items() if v})
        plugin_targets = ['step-schema-' + schema for schema in SCHEMAS]
        require(all(name in targets and len(targets[name]) == 1 and targets[name][0].is_file()
                    for name in plugin_targets),
                'Required STEP schema edition missing or ambiguous')
        verify_submodules(rec, bext, pins)
        snapshot(rec, brl, bext, metadata)
        rec.run(['df', '-B1', str(attempt)]);rec.run(['free', '-b'])
        collect_build_evidence(attempt, metadata)
        from geometry_bundle import package_runtime, preserve_compiled_checkpoint
        preserve_compiled_checkpoint(rec, out, targets, result['run'], build)
        bundle = package_runtime(rec, attempt, out, brl, bext, build, ext_build, ext_output, targets, result['run'])
        result.update({'disposition': 'GEOMETRY_TOOLKIT_CANDIDATE', 'bundle': bundle,
                       'work_qualification': 'PENDING_INDEPENDENT_ACCEPTANCE',
                       'lenovo_release': 'NOT_QUALIFIED_NOT_AUTHORIZED'})
        return_code = 0
    except Exception as exc:
        result['error'] = f'{type(exc).__name__}: {exc}'
        (metadata / 'failure-traceback.txt').write_text(traceback.format_exc())
        return_code = 1
    finally:
        result['elapsed_seconds'] = time.monotonic() - started
        try:
            snapshot(rec, brl, bext, metadata)
            collect_build_evidence(attempt, metadata)
        except Exception as exc:
            result['final_snapshot_error'] = str(exc)
            if result['disposition'] == 'GEOMETRY_TOOLKIT_CANDIDATE':
                result['disposition'] = 'BUILD_ATTEMPT_FAILED';return_code = 1
        write_json(out / 'RESULT.json', result)
        census = []
        for f in sorted(out.rglob('*')):
            if f.is_file() and f != out / 'SHA256SUMS':
                census.append(f"{sha256(f)}  {f.relative_to(out).as_posix()}\n")
        (out / 'SHA256SUMS').write_text(''.join(census))
    return return_code


if __name__ == '__main__':
    raise SystemExit(main())
