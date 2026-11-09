"""Package the reusable CLI toolkit; frozen Build #5 packaging is unchanged."""
import gzip
import os
from pathlib import Path
import shutil
import tarfile

import bundle
from common import sha256, write_json
from geometry_profile import EXECUTABLES, SCHEMAS, runtime_layout, runpath, manifest_role
from native_geometry_smoke import run_smoke


def _copy_layout(layout, root):
    for rel, source in layout.items():
        executable = rel.startswith(('bin/', 'libexec/ged_exec/'))
        bundle.copy_regular(source, root/rel, 0o755 if executable else 0o644)


def preserve_compiled_checkpoint(rec, out, targets, run, build):
    layout = runtime_layout(build, targets)
    providers, baseline = bundle.collect_runtime(rec, layout.values())
    root = out/'geometry-compiled-checkpoint'; root.mkdir(exist_ok=False)
    _copy_layout(layout, root)
    for name, row in providers.items():
        bundle.copy_regular(row['source_path'], root/'lib'/name)
    rows = [{'path': f.relative_to(root).as_posix(), 'sha256': sha256(f),
             'size': f.stat().st_size} for f in sorted(root.rglob('*')) if f.is_file()]
    write_json(root/'CHECKPOINT.json', {'schema':'ADR001_GEOMETRY_COMPILED_CHECKPOINT/1',
        'status':'UNRELOCATED_UNQUALIFIED', 'run':run, 'files':rows,
        'bundled_providers':providers, 'host_baseline':baseline,
        'source_pins':__import__('json').loads((out/'evidence/source-pins.json').read_text())})
    destination = out/'geometry-compiled-checkpoint.tar.gz'
    with destination.open('wb') as stream, gzip.GzipFile(filename='', fileobj=stream,
            mode='wb', mtime=0) as compressed, tarfile.open(fileobj=compressed,
            mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for f in sorted(p for p in root.rglob('*') if p.is_file()):
            info=archive.gettarinfo(str(f),arcname='geometry-compiled-checkpoint/'+f.relative_to(root).as_posix())
            bundle.require(info.isfile(), 'Checkpoint requires regular files')
            info.uid=info.gid=0; info.uname=info.gname=''; info.mtime=0
            with f.open('rb') as source: archive.addfile(info,source)
    write_json(out/'evidence/geometry-compiled-checkpoint.json',
               {'sha256':sha256(destination),'bytes':destination.stat().st_size,
                'status':'UNRELOCATED_UNQUALIFIED','files':len(rows)})
    shutil.rmtree(root)


def package_runtime(rec, attempt, out, brl, bext, build, ext_build, ext_output, targets, run):
    metadata=out/'evidence'
    layout=runtime_layout(build,targets)
    providers,baseline=bundle.collect_runtime(rec,layout.values())
    runtime=attempt/'package/brlcad-geometry-tools'; runtime.mkdir(parents=True)
    _copy_layout(layout,runtime)
    for name,row in providers.items(): bundle.copy_regular(row['source_path'],runtime/'lib'/name)
    # libged/libdm may consume configured public data (for example fonts).
    # Keep the configured relative layout, not runner home or source directories.
    data=build/'share'
    if data.is_dir():
        for source in sorted(data.rglob('*')):
            if source.is_file(): bundle.copy_regular(source,runtime/'share'/source.relative_to(data))
    write_json(metadata/'geometry-runtime-providers.json',{'bundled':providers,'host_baseline':baseline})
    write_json(metadata/'geometry-license-records.json',
               bundle.licenses(rec,runtime,brl,ext_output,providers))
    relocations=[]
    for path in sorted(runtime.rglob('*')):
        if not path.is_file(): continue
        with path.open('rb') as f: elf=f.read(4)==b'\x7fELF'
        if not elf: continue
        rel=path.relative_to(runtime).as_posix(); before=bundle.semantics(rec,path)
        original_hash=sha256(path); rpath=runpath(rel)
        rec.run(['patchelf','--set-rpath',rpath,path])
        bundle.require(bundle.semantics(rec,path)==before,f'ELF semantics changed: {rel}')
        bundle.require(rec.run(['patchelf','--print-rpath',path]).strip()==rpath,
                       f'RUNPATH differs: {rel}')
        relocations.append({'path':rel,'before_sha256':original_hash,
                            'after_sha256':sha256(path),'runpath':rpath})
    write_json(metadata/'geometry-relocation.json',relocations)
    second=attempt/'second-prefix/other-layout/brlcad-geometry-tools'
    second.parent.mkdir(parents=True);shutil.copytree(runtime,second)
    results={}
    with bundle.hidden_build_trees([build,ext_build,ext_output]):
        for number,root in enumerate((runtime,second),1):
            loader=bundle.verify_loader_map(rec,root,baseline)
            env=dict(rec.env,BRLCAD_ROOT=str(root.resolve()))
            for name in EXECUTABLES:
                # gqa's documented help path intentionally exits 1.
                rec.run(['timeout','-k','5s','20s',root/'bin'/name,'--help'],
                        cwd=root,env=env,allow_failure=(name=='gqa'))
                command=rec.records[-1]
                text=(rec.output/command['stdout']).read_text(errors='replace')
                text+=(rec.output/command['stderr']).read_text(errors='replace')
                bundle.require(command['exit_status'] in ((0,1) if name=='gqa' else (0,))
                               and ('Usage:' in text or 'usage:' in text),f'Invalid help result: {name}')
            version=rec.run([root/'bin/gsh','--version'],cwd=root,env=env)
            bundle.require('7.47.0' in version,'Compiled toolkit version differs from source pin')
            native=run_smoke(rec,root,brl,metadata/f'geometry-native-prefix-{number}')
            results[str(number)]={'loader_maps':loader,'native_public_fixture':native}
    write_json(metadata/'geometry-two-prefix-native-results.json',results)
    write_json(metadata/'geometry-runtime-profile.json',{
        'run':run,'executables':EXECUTABLES,'schemas':SCHEMAS,
        'scope':'Reusable CLI candidate; public tetrahedron I/O verification only',
        'SPK16_fidelity':'HOLD; repair inflation and curved geometry require separate measurement',
        'acoustic_qualification':'NOT_PERFORMED','Lenovo_installation':'NOT_PERFORMED'})
    shutil.copytree(metadata,runtime/'metadata')
    for f in (runtime/'metadata').rglob('*'):
        if f.is_file(): f.chmod(0o644)
    # Retain the same top-level directory as Build #5 for known portable layout;
    # users extract this new candidate separately and never overwrite Build #5.
    temporary=attempt/'brlcad-geometry-tools.tar.gz.partial'
    pins=__import__('json').loads((metadata/'source-pins.json').read_text())
    receipt=bundle.make_tar(runtime,temporary,pins['brlcad_commit'],role_for_path=manifest_role)
    shutil.move(temporary,out/'brlcad-geometry-tools.tar.gz')
    (out/'brlcad-geometry-tools.tar.gz.sha256').write_text(receipt['sha256']+'\n')
    write_json(metadata/'geometry-runtime-archive.json',receipt)
    return receipt
