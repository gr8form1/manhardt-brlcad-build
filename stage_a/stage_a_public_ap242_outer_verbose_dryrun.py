#!/usr/bin/env python3
"""ADR-001 Stage A PUBLIC ONLY. EXECUTION REQUIRES LATER FOUNDER APPROVAL.

Use only an independently approved isolated runner and reviewed original Build #5
acquisition route. No fallback, private CAD, output .g, retry or second experiment.
"""
import argparse
import base64
import datetime as dt
import hashlib
import io
import json
import os
import pathlib
import re
import secrets
import stat
import sys
import tempfile
import time
import zipfile

BUILD_BYTES = 224_909_478
BUILD_SHA = '437fd42a8044c836d255fdde4b318a4d7ca92cbd3cbc073e8397ee9e3e86ec65'
TAR_SHA = '4447f9cc8ede6f0386a4a289c963d5b04df93aad25016e60d960d23e8cdece0c'
BIN_SHA = '5cb3c20ac53827be697e1dcd6fe153586a9b13bab537166f9e27e8ead5f01e73'
PLUGIN_SHA = '0580fe3e551387a21fca7661c4b369ff8a07292b8daaba789ce4171442367bfa'
FIXTURE_SHA = '6e1133bb17c870ac04e677b52722c6115e52ca8685fcd628f58d8cb686306828'
FIXTURE_GIT_BLOB = 'de19c98aba9b097d3dd442cb565815ce7a433db5'
FIXTURE_SOURCE_PATH = 'stage_a/fixtures/adr001_public_ap242_planar_box_explicit_outer.step'
FIXTURE_BYTES = 15487
FIXTURE_SCHEMA = 'AP242_MANAGED_MODEL_BASED_3D_ENGINEERING_MIM_LF {1 0 10303 442 1 1 4 }'
INVENTORY_SHA = '9320bf0eef074584460f901e0cc2d76dfe956a7874ad27929c8ebb0f3c33488c'
IMAGE_ID = 'sha256:35a88802559dd2077e584394471ddaa1a2c5bfd16893b829ea57619301eb3908'
EXPIRY = dt.datetime(2026, 11, 9, 15, 56, 29, tzinfo=dt.timezone.utc)


def demand(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def source_guard(root, inventory):
    # Before importing project helpers, authenticate the *entire* source tree.
    # The inventory is a separate pinned input and is not an allowed tree member.
    demand(sha_file(inventory) == INVENTORY_SHA, 'P4.3.5 source inventory identity mismatch')
    entries = json.loads(inventory.read_text())['entries']
    demand(len(entries) == 14 and len({x['path'] for x in entries}) == 14,
           'Expected exactly fourteen approved public source identities')
    demand(stat.S_ISDIR(root.lstat().st_mode), 'Source root not an ordinary directory')
    approved_files, approved_dirs = set(), set()
    for x in entries:
        rel = pathlib.PurePosixPath(x['path'])
        demand(not rel.is_absolute() and '..' not in rel.parts and
               all(part not in ('', '.') for part in rel.parts) and
               rel.as_posix() == x['path'], 'Invalid approved source pathname')
        approved_files.add(rel.as_posix())
        approved_dirs.update(parent.as_posix() for parent in rel.parents if parent.as_posix() != '.')
        path = root.joinpath(*rel.parts)
        meta = path.lstat()  # never follow symlinks
        demand(stat.S_ISREG(meta.st_mode) and meta.st_size == x['bytes'] and
               sha_file(path) == x['sha256'],
               'Approved source byte identity mismatch: ' + x['path'])
        data = path.read_bytes()
        blob = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
        demand(blob == x['git_blob_sha1'], 'Approved source Git blob mismatch: ' + x['path'])
    found_files, found_dirs = set(), set()
    for path in root.rglob('*'):
        rel = path.relative_to(root).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISREG(mode):
            found_files.add(rel)
        elif stat.S_ISDIR(mode):
            found_dirs.add(rel)
        else:
            raise RuntimeError('Unapproved source symlink or special entry: ' + rel)
    demand(found_files == approved_files and found_dirs == approved_dirs,
           'Unapproved or missing source file/directory in exact tree census')


def scratch_census(raw):
    """Validate exact NUL-framed find records; never split filenames on whitespace."""
    demand(isinstance(raw, bytes) and 0 < len(raw) <= 4096 and raw.endswith(b'\0'),
           'Scratch census missing, oversized or unterminated')
    fields = raw[:-1].split(b'\0')
    demand(len(fields) % 3 == 0, 'Scratch census malformed field triples')
    allowed = {'adr001-write-test', 'adr001_public_ap242_planar_box_explicit_outer.dryrun.json'}
    found = {}
    for i in range(0, len(fields), 3):
        name = fields[i].decode('utf-8', 'strict')
        kind = fields[i + 1].decode('ascii', 'strict')
        size_text = fields[i + 2].decode('ascii', 'strict')
        demand(name in allowed and name not in found and kind == 'f' and
               bool(re.fullmatch(r'[0-9]+', size_text)),
               'Scratch contains unexpected, duplicated or nonregular entry')
        size = int(size_text)
        demand(0 <= size < 8_388_608 and
               (name != 'adr001_public_ap242_planar_box_explicit_outer.dryrun.json' or size > 0),
               'Scratch entry size invalid or report empty')
        found[name] = {'type': kind, 'bytes': size}
    demand(set(found) == allowed, 'Expected exact two regular scratch files')
    return found


def schema_header(data):
    # Header inspection only; no STEP geometry parsing in this preparation gate.
    head = data[:min(len(data), 16000)]
    matches = re.findall(rb"FILE_SCHEMA\s*\(\s*\(\s*'([^']+)'\s*\)\s*\)\s*;", head)
    demand(len(matches) == 1, 'Missing/ambiguous public STEP FILE_SCHEMA')
    schema = matches[0].decode('ascii', 'strict')
    demand(schema == FIXTURE_SCHEMA, 'Expected exact source-authenticated AP242 common-subset FILE_SCHEMA')
    return schema


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--source-root', type=pathlib.Path, required=True)
    ap.add_argument('--evidence-dir', type=pathlib.Path, required=True)
    ap.add_argument('--acquisition', choices=('github', 'archived'), required=True)
    ap.add_argument('--original-archive', type=pathlib.Path)
    ap.add_argument('--archived-acquisition-independently-approved', action='store_true')
    args = ap.parse_args()
    os.umask(0o077)
    started = time.monotonic()
    demand(not args.source_root.is_symlink(), 'Symlinked source root forbidden')
    source = args.source_root.resolve(strict=True)
    inventory = pathlib.Path(__file__).with_name('P435_EXACT_PROPOSED_PUBLICATION_INVENTORY.json')
    out = args.evidence_dir.absolute()
    demand(not os.path.lexists(out), 'Evidence output already exists; refuse overwrite')
    out.mkdir(parents=True, mode=0o700)
    raw = out/'raw'; raw.mkdir(mode=0o700)
    rec = {'status':'HOLD', 'experiment':'ONE_PUBLIC_STEP_DRY_RUN_ONLY',
           'original_build5_sha256': BUILD_SHA, 'source_acquisition':args.acquisition,
           'pinned_public_fixture_sha256': FIXTURE_SHA, 'commands':{},
           'no_output_database_authorized':True}
    scratch = None; name = None; created = False
    try:
        source_guard(source, inventory)
        sys.path.insert(0, str(source/'ci'))  # after verifying approved exact sources
        import ap242_preflight as pre
        import p4_abi_controller as p4
        from p2_security import (verify_docker_cgroup_v2, verify_container_inspect,
                                 verify_canary)
        demand(pre.ARTIFACT_ID == 13624376032 and pre.ZIP_SHA == BUILD_SHA and
               pre.TAR_SHA == TAR_SHA and p4.BINARY_SHA == BIN_SHA and
               p4.PLUGIN_SHA == PLUGIN_SHA and p4.EXPECTED_IMAGE_ID == IMAGE_ID,
               'Frozen controlling constants mismatch')
        rec['frozen_p3_controls'] = p4.verify_control_source(source)
        rec['source_inventory_sha256'] = INVENTORY_SHA
        demand(os.uname().machine == 'x86_64', 'x86_64 runner required')
        demand(time.monotonic() - started < 420, 'Host preparation deadline passed')
        runner_temp = pathlib.Path(os.environ.get('RUNNER_TEMP','/tmp')).resolve()
        scratch = pathlib.Path(tempfile.mkdtemp(prefix='adr001-stage-a-', dir=runner_temp))
        demand((scratch.stat().st_mode & 0o777) == 0o700, 'Private host scratch must remain 0700')
        host_ns = os.readlink('/proc/self/ns/net')

        def command(label, argv, seconds=25, cap=4_000_000):
            demand(time.monotonic() - started < 420, 'Stage A controller deadline exceeded')
            result = pre.command(argv, timeout=seconds, evidence=raw, label=label, byte_cap=cap)
            rec['commands'][label] = result
            return result

        def require(label, argv, seconds=25):
            result = command(label, argv, seconds)
            pre.require_success(result)
            return (raw/result['stdout_file']).read_text(errors='strict')

        if args.acquisition == 'github':
            demand(dt.datetime.now(dt.timezone.utc) < EXPIRY,
                   'Original GitHub artifact expiration boundary reached')
            demand(bool(os.environ.get('GH_TOKEN')), 'GH_TOKEN needed for original GitHub acquisition')
            metadata = json.loads(pre.bounded_http(
                'https://api.github.com/repos/gr8form1/manhardt-brlcad-build/actions/artifacts/13624376032',
                200_000))
            demand(metadata.get('id') == 13624376032 and metadata.get('expired') is False and
                   metadata.get('size_in_bytes') == BUILD_BYTES and
                   metadata.get('digest') == 'sha256:'+BUILD_SHA,
                   'Original GitHub artifact metadata missing/expired/mismatched')
            whole = pre.build_artifact_download(260_000_000)
            rec['original_artifact_provenance'] = 'ORIGINAL_GITHUB_ARTIFACT_ENDPOINT'
        else:
            demand(args.archived_acquisition_independently_approved,
                   'Archive route requires separately documented independent + founder approval')
            demand(args.original_archive is not None and args.original_archive.is_file() and
                   not args.original_archive.is_symlink(), 'Exact independently approved archive path required')
            whole = args.original_archive.read_bytes()
            rec['original_artifact_provenance'] = 'ARCHIVED_ORIGINAL_EXPLICITLY_APPROVED_SOURCE_CHANGE'
            rec['approved_archive_path'] = str(args.original_archive.resolve())
        demand(len(whole) == BUILD_BYTES and sha_bytes(whole) == BUILD_SHA,
               'Original Build #5 outer ZIP size/hash mismatch')
        rec['original_artifact_bytes'] = len(whole)
        with zipfile.ZipFile(io.BytesIO(whole)) as archive:
            demand(archive.testzip() is None, 'Original ZIP CRC failure')
            demand(archive.namelist().count('brlcad-runtime.tar.gz') == 1,
                   'Runtime tar absent or duplicated')
            tarball = archive.read('brlcad-runtime.tar.gz')
        del whole
        demand(sha_bytes(tarball) == TAR_SHA, 'Original Build #5 runtime tar mismatch')
        tar_path = scratch/'runtime.tar.gz'; tar_path.write_bytes(tarball)
        del tarball
        runtime = scratch/'runtime'; runtime.mkdir(mode=0o700)
        extracted = pre.safe_extract_runtime(tar_path, runtime)
        demand(extracted['step_g_sha256'] == BIN_SHA and
               extracted['plugin_sha256'] == PLUGIN_SHA,
               'Frozen runtime executable/module byte identity mismatch')
        rec['runtime_manifest'] = extracted
        rec['runtime_permissions'] = p4._public_tree_manifest(runtime,
            p4._authenticated_runtime_public_files(runtime, extracted), executable=('bin/step-g',))
        # Minimal *public-only* AP242 planar solid generated with OCCT AP242DIS.
        # This is AP242 common-subset geometry, not a claim of Edition 2 authorship.
        # Exact blob and bytes are pinned in the approved commit and checked here.
        checked_fixture = pathlib.Path(__file__).resolve().parent / 'fixtures' / 'adr001_public_ap242_planar_box_explicit_outer.step'
        demand(stat.S_ISDIR(checked_fixture.parent.lstat().st_mode) and
               stat.S_ISREG(checked_fixture.lstat().st_mode) and not checked_fixture.is_symlink(),
               'Public fixture must be an ordinary pinned source file')
        public_bytes = checked_fixture.read_bytes()
        demand(len(public_bytes) == FIXTURE_BYTES and sha_bytes(public_bytes) == FIXTURE_SHA and
               public_bytes.startswith(b'ISO-10303-21;'), 'Pinned public planar-box STEP mismatch')
        git_blob = hashlib.sha1(b'blob ' + str(len(public_bytes)).encode()+b'\0'+public_bytes).hexdigest()
        demand(git_blob == FIXTURE_GIT_BLOB, 'Pinned public fixture Git blob mismatch')
        rec['public_fixture_source'] = {'repository': 'gr8form1/manhardt-brlcad-build',
            'path': FIXTURE_SOURCE_PATH, 'git_blob_sha1': git_blob,
            'sha256': FIXTURE_SHA, 'bytes':len(public_bytes),
            'origin':'public OCCT AP242DIS planar 15x20x25 mm box; common subset'}
        rec['observed_file_schema_header'] = schema_header(public_bytes)
        rec['schema_override'] = 'EXPLICIT_AP242E2_FROZEN_PLUGIN_ONLY'
        rec['diagnostic_mode'] = 'ONE_SHOT_VERBOSE_SOLIDNESS_AUDIT_ONLY'
        fixtures = scratch/'fixtures';fixtures.mkdir(mode=0o700)
        (fixtures/'adr001_public_ap242_planar_box_explicit_outer.step').write_bytes(public_bytes)
        rec['fixture_permissions'] = p4._public_tree_manifest(fixtures,
            {'adr001_public_ap242_planar_box_explicit_outer.step': FIXTURE_SHA})
        del public_bytes

        info = json.loads(require('docker_info',['docker','info','--format','{{json .}}']))
        rec['docker_cgroups'] = verify_docker_cgroup_v2(info)
        require('image_pull',['docker','pull','--platform','linux/amd64',pre.IMAGE],120)
        image = json.loads(require('image_inspect',['docker','image','inspect',pre.IMAGE,'--format','{{json .}}']))
        demand(image.get('Architecture')=='amd64' and image.get('Id')==IMAGE_ID and
               any(pre.IMAGE.split('@')[1] in x for x in image.get('RepoDigests',[])),
               'Pinned Ubuntu image identity mismatch')
        rec['pinned_image_id'] = image['Id']
        # This exact frozen canary executes first. The same container stays alive
        # for independently gated --help and exactly ONE geometry dry-run command.
        canary = (source/'ci/fixture_canary.sh').read_text()
        script = canary + "\nprintf 'STAGE_A_CANARY_READY:yes\\n'\nsleep 420\n"
        name = 'adr001-stage-a-'+secrets.token_hex(8)
        create = ['docker','create','--name',name,
                  '--label','adr001.stage=public-step-dryrun', '--platform','linux/amd64',
                  '--read-only','--network','none','--ipc','none','--cgroupns','private',
                  '--cap-drop','ALL','--security-opt','no-new-privileges:true',
                  '--user','65534:65534','--pids-limit','32','--memory','1073741824',
                  '--memory-swap','1073741824','--memory-swappiness','0',
                  '--cpus','1','--ulimit','core=0:0','--ulimit','fsize=8388608:8388608',
                  '--tmpfs','/scratch:rw,nosuid,nodev,noexec,size=67108864,mode=1777',
                  '--mount',f'type=bind,src={runtime},dst=/runtime,readonly',
                  '--mount',f'type=bind,src={fixtures},dst=/fixtures,readonly',
                  '-e','HOME=/scratch','-e','TMPDIR=/scratch',pre.IMAGE,
                  '/bin/sh','-ec',script]
        # Random single-use name avoids touching any pre-existing container.
        name_check=command('container_name_absent',['docker','inspect',name],10)
        demand(name_check['rc']!=0, 'Container name already exists')
        created = True  # ensure cleanup even if create returns ambiguous failure
        require('docker_create',create,35)
        inspected = json.loads(require('docker_inspect',['docker','inspect',name,'--format','{{json .}}']))
        verify_container_inspect(inspected, str(runtime), str(fixtures), IMAGE_ID, info)
        require('docker_start',['docker','start',name],20)
        canary_raw = None
        for n in range(12):
            record = command('canary_logs_'+str(n),['docker','logs',name],10)
            pre.require_success(record)
            output = (raw/record['stdout_file']).read_bytes()
            if output.endswith(b'FROZEN_PASS:yes\nSTAGE_A_CANARY_READY:yes\n'):
                canary_raw = output[:-len(b'STAGE_A_CANARY_READY:yes\n')]
                demand((raw/record['stderr_file']).stat().st_size == 0,
                       'Unexpected security canary stderr')
                break
            time.sleep(1)
        demand(canary_raw is not None, 'Same-container canary did not finish')
        mountinfo = p4._canary_stdout_mountinfo(canary_raw)
        rec['same_container_security'] = verify_canary(canary_raw.decode(),host_ns,mountinfo,
                          masked_paths=(inspected.get('HostConfig') or {}).get('MaskedPaths'))
        # Exactly one non-conversion help invocation: unsupported syntax => HOLD.
        help_record=command('step_g_help',['docker','exec','--user','65534:65534',name,
                                          '/runtime/bin/step-g','--help'],20)
        pre.require_success(help_record)
        help_text=((raw/help_record['stdout_file']).read_bytes()+b'\n'+
                   (raw/help_record['stderr_file']).read_bytes()).decode('utf-8','strict')
        demand(all(re.search(re.escape(opt)+r'\b',help_text) for opt in
                   ('-D','-v','--strict','--exact','--repair','--jobs','--report','--schema')),
               'Frozen step-g help does not document all proposed options')
        rec['frozen_cli_options_observed'] = ['-D','-v','--strict','--exact','--repair','--jobs','--report','--schema']
        # No fallback/retry/option change. GNU timeout 119s + 1s grace caps
        # the one authorized dry-run at <=120s inside the one-CPU cgroup.
        command_line = ('test -r /runtime/bin/step-g && '
                        'test -r /fixtures/adr001_public_ap242_planar_box_explicit_outer.step && '
                        'exec timeout -s TERM -k 1s 119s '
                        '/runtime/bin/step-g -D -v --strict --exact --repair none --jobs 1 --schema ap242e2 '
                        '--report /scratch/adr001_public_ap242_planar_box_explicit_outer.dryrun.json '
                        '/fixtures/adr001_public_ap242_planar_box_explicit_outer.step')
        stage = command('stage_a_dryrun',['docker','exec','--user','65534:65534',name,
                                        '/bin/sh','-ec',command_line],125)
        rec['dryrun_exit_code']=stage['rc']
        rec['dryrun_timed_out']=stage['timed_out']
        # Copy report BEFORE stopping container: /scratch is a tmpfs.
        scratch_ls = command('container_scratch_census', ['docker','exec','--user','65534:65534',name,
                        '/bin/sh','-ec',"find /scratch -mindepth 1 -maxdepth 1 -printf '%f\\0%y\\0%s\\0'"],15)
        pre.require_success(scratch_ls)
        census = scratch_census((raw/scratch_ls['stdout_file']).read_bytes())
        rec['container_scratch_census'] = census
        # The exact report is present and typed. Copy it *before* removing PID 1.
        # docker cp cannot reliably access the live tmpfs on the GitHub Docker host.
        # Stream the original report from the running container as UID 65534.
        # Preserve raw bytes, length, SHA-256 and return code independently.
        copy_status = command('copy_report_stream',[
            'docker','exec','--user','65534:65534',name,
            '/bin/cat','/scratch/adr001_public_ap242_planar_box_explicit_outer.dryrun.json'],15,8_388_608)
        pre.require_success(copy_status)
        report_source = raw/copy_status['stdout_file']
        demand(copy_status['stdout_bytes'] == census['adr001_public_ap242_planar_box_explicit_outer.dryrun.json']['bytes'],
               'Copied report byte count differs from container census')
        report = out/'adr001_public_ap242_planar_box_explicit_outer.dryrun.json'
        with report.open('xb') as dest,report_source.open('rb') as origin:
            while True:
                chunk=origin.read(1024*1024)
                if not chunk:break
                dest.write(chunk)
        demand(sha_file(report)==copy_status['stdout_sha256'],
               'Report readback SHA-256 mismatch')
        rec['report_retrieval'] = 'BOUND_UID65534_STREAM_FROM_LIVE_TMPFS'
        demand(stage['rc'] == 0 and stage['timed_out'] is False,
               'Dry-run failed or timed out; no retry or option change')
        demand(report.is_file() and not report.is_symlink() and
               0 < report.stat().st_size < 8_388_608,
               'Complete nonempty JSON report absent or oversized')
        parsed = json.loads(report.read_text(encoding='utf8'))
        demand(isinstance(parsed,dict) and len(parsed)>0, 'JSON report structurally empty')
        rec['report_sha256'] = sha_file(report)
        rec['report_bytes'] = report.stat().st_size
        # Do not infer semantic PASS from unknown report field names. Independent
        # review must establish complete coverage, zero repair/inference and schema.
        rec['status'] = 'CAPTURE_COMPLETE_PENDING_INDEPENDENT_REPORT_ASSESSMENT'
    except Exception as exc:
        rec['error'] = repr(exc)
        rec['status'] = 'HOLD'
    finally:
        # Always attempt forced removal, then verify absence; never silently skip.
        if created:
            try:
                from ap242_preflight import command as accepted_command
                def final_cmd(label, argv):
                    result=accepted_command(argv,timeout=25,evidence=raw,label=label,byte_cap=4_000_000)
                    rec['commands'][label]=result
                    return result
                rm=final_cmd('docker_remove_force',['docker','rm','-f',name])
                ins=final_cmd('docker_inspect_after',['docker','inspect',name])
                remaining=final_cmd('docker_labeled_after',['docker','ps','-aq',
                                     '--filter','label=adr001.stage=public-step-dryrun'])
                left=(raw/remaining['stdout_file']).read_text().strip()
                demand(rm['rc']==0 and ins['rc']!=0 and remaining['rc']==0 and not left,
                       'Container removal not verified')
                rec['container_cleanup']='VERIFIED'
            except Exception as exc:
                rec['container_cleanup']='HOLD '+repr(exc)
                rec['status']='HOLD'
        else:
            rec['container_cleanup']='NO_CONTAINER_CREATED'
        if scratch is not None:
            try:
                import p4_abi_controller as p4
                receipt=p4.cleanup_scratch(scratch)
                rec['host_scratch_cleanup']=receipt
                if receipt['status']!='VERIFIED':
                    rec['status']='HOLD'
            except Exception as exc:
                rec['host_scratch_cleanup']='HOLD '+repr(exc)
                rec['status']='HOLD'
        rec['elapsed_seconds']=round(time.monotonic()-started,3)
        for path in sorted(out.rglob('*')):
            if path.is_symlink():
                rec['status']='HOLD'
                rec['evidence_symlink_violation']=str(path)
        (out/'STAGE_A_RECEIPT.json').write_text(json.dumps(rec,indent=2,sort_keys=True)+'\n')
        sums=[]
        for path in sorted(out.rglob('*')):
            if path.is_file() and not path.is_symlink() and path.name!='SHA256SUMS.txt':
                sums.append(sha_file(path)+'  '+path.relative_to(out).as_posix()+'\n')
        (out/'SHA256SUMS.txt').write_text(''.join(sums))
    # Exit 2 is deliberately NOT success: independently review report semantics.
    return 2 if rec['status']=='CAPTURE_COMPLETE_PENDING_INDEPENDENT_REPORT_ASSESSMENT' and rec.get('container_cleanup')=='VERIFIED' and rec.get('host_scratch_cleanup',{}).get('status')=='VERIFIED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
