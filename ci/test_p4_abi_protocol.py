"""Offline P4 protocol tests; no Docker, network, native executable or CAD import."""
import hashlib, json, os, pathlib, subprocess, sys, tempfile, unittest
from unittest import mock
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
import p4_abi_controller as p
R=pathlib.Path(__file__).resolve().parents[1]

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def synthetic_loader_capture():
    """Synthetic *full manifest-closure* framing; never provider ABI proof."""
    manifest=json.loads((R/'reference/P4_Build5_Static_ELF_Manifest.json').read_text())
    provider_paths={
        'ld-linux-x86-64.so.2':'/lib64/ld-linux-x86-64.so.2',
        'libc.so.6':'/lib/x86_64-linux-gnu/libc.so.6',
        'libstdc++.so.6':'/usr/lib/x86_64-linux-gnu/libstdc++.so.6',
        'libgcc_s.so.1':'/lib/x86_64-linux-gnu/libgcc_s.so.1',
        'libm.so.6':'/lib/x86_64-linux-gnu/libm.so.6'}
    def resolved(closure):
        return {name:('/runtime/'+closure['bundled'][name]
                      if name in closure['bundled'] else provider_paths[name])
                for name in closure['needed']}
    def deps(key):
        c=p._manifest_closure(manifest,key)
        paths=resolved(c)
        return [f'{name} => {paths[name]} (0x00007fffff000000)'
                for name in sorted(paths)]
    def trace(key):
        c=p._manifest_closure(manifest,key)
        paths=resolved(c)
        lines=[]
        for name in sorted(c['needed']-{'ld-linux-x86-64.so.2'}):
            lines.extend(['      221: find library='+name+' [0]; searching',
                          '      221:   trying file='+paths[name]])
        for object_path in sorted(c['objects']):
            item=manifest['files'][object_path]
            for family, versions in item['required_symbol_versions'].items():
                provider=provider_paths[p.FAMILY_PROVIDER[family]]
                for v in versions:
                    lines.append("      221: checking for version `"+family+'_'+v+
                                 "' in file "+provider+
                                 ' [0] required by file /runtime/'+object_path+' [0]')
        return lines
    stdout=['P4_ABI_BEGIN','P4_BINARIES_REHASHED:yes',
            'ld.so (Ubuntu GLIBC 2.39) stable release version 2.39.',
            'P4_LOADER_LIST_EXEC_BEGIN']+deps('bin/step-g')+[
            'P4_LOADER_LIST_EXEC_END','P4_LOADER_LIST_PLUGIN_BEGIN']+deps(
            'libexec/step/libstep-schema-ap242e2.so')+[
            'P4_LOADER_LIST_PLUGIN_END'] + [
            ('%064x'%i)+'  '+path for i,path in enumerate(p.PROVIDER_PATHS,1)] + [
            'P4_PROVIDER_FILES_HASHED:yes','P4_ABI_END']
    stderr=['P4_LD_DEBUG_EXEC_BEGIN']+trace('bin/step-g')+[
            'P4_LD_DEBUG_EXEC_END','P4_LD_DEBUG_PLUGIN_BEGIN']+trace(
            'libexec/step/libstep-schema-ap242e2.so')+[
            'P4_LD_DEBUG_PLUGIN_END']
    return ('\n'.join(stdout)+'\n').encode(), ('\n'.join(stderr)+'\n').encode()


def synthetic_status(out, err, **changes):
    st={'rc':0,'timed_out':False,
        'stdout_cap':4_000_000,'stderr_cap':4_000_000,
        'stdout_bytes':len(out),'stderr_bytes':len(err),
        'stdout_sha256':hashlib.sha256(out).hexdigest(),
        'stderr_sha256':hashlib.sha256(err).hexdigest()}
    st.update(changes)
    return st


def structurally_accepted(out=None, err=None, status=None):
    default_out,default_err=synthetic_loader_capture()
    out = default_out if out is None else out
    err = default_err if err is None else err
    return p.check_abi_markers(out,err,status if status is not None else synthetic_status(out,err))

class P4Protocol(unittest.TestCase):
    def test_all_frozen_p321_controls_exact(self):
        self.assertEqual(len(p.verify_control_source(R)),10)
    def test_original_build5_and_image_identity_pins(self):
        self.assertEqual(p.CONTROL_COMMIT,'e25c46a1967fbca64948449d3fe027b657472f15')
        self.assertEqual(p.ZIP_SHA,'437fd42a8044c836d255fdde4b318a4d7ca92cbd3cbc073e8397ee9e3e86ec65')
        self.assertEqual(p.TAR_SHA,'4447f9cc8ede6f0386a4a289c963d5b04df93aad25016e60d960d23e8cdece0c')
        self.assertEqual(p.IMAGE,'docker.io/library/ubuntu@sha256:2e863c44b718727c860746568e1d54afd13b2fa71b160f5cd9058fc436217b30')
        self.assertEqual(p.BINARY_SHA,'5cb3c20ac53827be697e1dcd6fe153586a9b13bab537166f9e27e8ead5f01e73')
        self.assertEqual(p.PLUGIN_SHA,'0580fe3e551387a21fca7661c4b369ff8a07292b8daaba789ce4171442367bfa')
    def test_static_elf_manifest_is_consistent_and_not_overclaimed(self):
        manifest=json.loads((R/'reference/P4_Build5_Static_ELF_Manifest.json').read_text())
        self.assertEqual(manifest['control_commit'],p.CONTROL_COMMIT)
        self.assertEqual(manifest['max_required_symbol_versions'],{'GLIBC':'2.38','GLIBCXX':'3.4.32','CXXABI':'1.3.13'})
        self.assertEqual(manifest['files']['bin/step-g']['sha256'],p.BINARY_SHA)
        self.assertEqual(manifest['files']['libexec/step/libstep-schema-ap242e2.so']['sha256'],p.PLUGIN_SHA)
        self.assertEqual(manifest['files']['bin/step-g']['interpreter'],['/lib64/ld-linux-x86-64.so.2'])
        self.assertTrue(manifest['plugin_exports_step_plugin_info'])
        self.assertFalse(manifest['bundle_contains_mged_or_db_inspector'])
        self.assertTrue(manifest['image_provider_abi_not_yet_observed'])
    def test_abi_loader_script_never_invokes_entrypoint_or_geometry(self):
        s=p.ABI_SHELL
        self.assertIn('--list /runtime/bin/step-g',s)
        self.assertIn('--list /runtime/libexec/step/libstep-schema-ap242e2.so',s)
        self.assertNotIn('--schema',s)
        self.assertNotIn('--dry-run',s)
        self.assertNotIn('--strict',s)
        self.assertNotIn(' --output ',s)
        self.assertNotIn(' step-g /',s)
        self.assertNotIn('mged',s)
        self.assertNotIn('g-step',s)
    def test_loader_markers_reject_absence_and_duplicates(self):
        out,err=synthetic_loader_capture()
        result=structurally_accepted(out,err)
        self.assertTrue(result['loader_dependency_listing_complete'])
        self.assertEqual(result['provider_version_acceptance'],'INDEPENDENT_REVIEW_HOLD')
        for key in p.ABI_MARKERS:
            with self.subTest(missing=key),self.assertRaises(p.GateError):
                structurally_accepted(out.replace((key+'\n').encode(),b''),err)
            with self.subTest(duplicate=key),self.assertRaises(p.GateError):
                structurally_accepted(out+(key+'\n').encode(),err)
    def test_publication_workflow_manual_abi_only_and_gated(self):
        s=(R/'.github/workflows/adr001-public-ap242-p4-abi-proposal.yml').read_text()
        self.assertIn('workflow_dispatch:',s)
        self.assertNotIn('schedule:',s)
        self.assertNotIn('push:',s)
        self.assertIn('ADR001_P4_APPROVED_COMMIT',s)
        self.assertIn('inputs.confirmation == \'ABI_ONLY\'',s)
        self.assertIn('github.run_attempt == 1',s)
        self.assertIn('600s bash',s)
        self.assertIn('ci/ap242_preflight.py --output out/security',s)
        self.assertIn('ci/p4_abi_controller.py --output out/abi',s)
        self.assertIn('ci/p3_finalize.py --output out/security',s)
        self.assertIn('ci/p3_finalize.py --output out/abi',s)
        self.assertNotIn('step-g --schema',s)
    def test_control_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            # A sparse source-only layout cannot pass control identity verification.
            with self.assertRaises(p.GateError):p.verify_control_source(pathlib.Path(d))
    def test_no_token_executes_nothing_outside_filesystem(self):
        with tempfile.TemporaryDirectory() as d:
            env={'PATH':__import__('os').environ.get('PATH','/usr/bin:/bin'),
                 'RUNNER_TEMP':d,'PYTHONDONTWRITEBYTECODE':'1'}
            proc=subprocess.run([sys.executable,'-B',str(R/'ci/p4_abi_controller.py'),
                       '--output',str(pathlib.Path(d)/'evidence')],env=env,capture_output=True,text=True,timeout=12)
            self.assertNotEqual(proc.returncode,0)
            rec=json.loads((pathlib.Path(d)/'evidence/SECURITY_PREFLIGHT.json').read_text())
            self.assertEqual(rec['status'],'HOLD')
            self.assertIn('GH_TOKEN absent',rec['error'])
            self.assertFalse((pathlib.Path(d)/'evidence/raw').joinpath('docker_info.stdout.bin').exists())

class P41AdversarialEvidence(unittest.TestCase):
    def test_synthetic_valid_evidence_remains_structural_only(self):
        result=structurally_accepted()
        self.assertTrue(result['loader_dependency_listing_complete'])
        self.assertEqual(result['explicit_plugin_dispatch'],'NOT_TESTED')
        self.assertEqual(result['provider_version_acceptance'],'INDEPENDENT_REVIEW_HOLD')
        self.assertFalse(result['entrypoint_step_g_invoked'])
    def test_marker_only_forgery_rejected(self):
        markers=('\n'.join(p.ABI_MARKERS)+'\n').encode()
        with self.assertRaises(p.GateError):structurally_accepted(markers,b'forged\n')
    def test_empty_exec_listing_rejected(self):
        out,err=synthetic_loader_capture()
        a=out.index(b'P4_LOADER_LIST_EXEC_BEGIN\n')+len(b'P4_LOADER_LIST_EXEC_BEGIN\n')
        b=out.index(b'P4_LOADER_LIST_EXEC_END\n')
        with self.assertRaises(p.GateError):structurally_accepted(out[:a]+out[b:],err)
    def test_empty_plugin_listing_rejected(self):
        out,err=synthetic_loader_capture()
        a=out.index(b'P4_LOADER_LIST_PLUGIN_BEGIN\n')+len(b'P4_LOADER_LIST_PLUGIN_BEGIN\n')
        b=out.index(b'P4_LOADER_LIST_PLUGIN_END\n')
        with self.assertRaises(p.GateError):structurally_accepted(out[:a]+out[b:],err)
    def test_missing_or_corrupted_dependency_record_rejected(self):
        out,err=synthetic_loader_capture()
        row=b'libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fffff000000)\n'
        self.assertIn(row,out)
        for change in (out.replace(row,b''),out.replace(row,b'libc.so.6 => not found\n'),
                       out.replace(row,b'garbled-loader-record\n'),
                       out.replace(row,row+row),
                       out.replace(row,row.replace(b'/lib/x86_64-linux-gnu/libc.so.6',b'/lib/x86_64-linux-gnu/fake.so.6'))):
            with self.subTest(change=len(change)),self.assertRaises(p.GateError):
                structurally_accepted(change,err)
    def test_reordered_stdout_markers_rejected(self):
        out,err=synthetic_loader_capture()
        out=out.replace(b'P4_LOADER_LIST_EXEC_BEGIN',b'placeholder').replace(
            b'P4_LOADER_LIST_EXEC_END',b'P4_LOADER_LIST_EXEC_BEGIN').replace(
            b'placeholder',b'P4_LOADER_LIST_EXEC_END')
        with self.assertRaises(p.GateError):structurally_accepted(out,err)
    def test_stdout_truncated_or_extra_after_end_rejected(self):
        out,err=synthetic_loader_capture()
        for broken in (out[:-1],out[:-20],out+b'unattributed\n'):
            with self.subTest(length=len(broken)),self.assertRaises(p.GateError):
                structurally_accepted(broken,err)
    def test_absent_suppressed_or_unframed_ld_debug_rejected(self):
        out,err=synthetic_loader_capture()
        for broken in (b'',b'no diagnostics\n',
                       err.replace(b'P4_LD_DEBUG_PLUGIN_BEGIN\n',b''),
                       err+b'outside diagnostics\n'):
            with self.subTest(length=len(broken)),self.assertRaises(p.GateError):
                structurally_accepted(out,broken)
    def test_incomplete_version_resolution_rejected(self):
        out,err=synthetic_loader_capture()
        row=next(x for x in err.splitlines(keepends=True) if b'GLIBC_2.38' in x)
        with self.assertRaises(p.GateError):structurally_accepted(out,err.replace(row,b''))
    def test_wrong_debug_target_or_malformed_version_rejected(self):
        out,err=synthetic_loader_capture()
        for broken in (err.replace(p.PLUGIN_TARGET.encode(),b'/wrong/target'),
                       err.replace(b'GLIBC_2.38',b'GLIBC_x.38'),
                       err.replace(b'find library=libstdc++.so.6',b'find library=unknown')):
            with self.subTest(length=len(broken)),self.assertRaises(p.GateError):
                structurally_accepted(out,broken)
    def test_reordered_or_duplicated_debug_markers_rejected(self):
        out,err=synthetic_loader_capture()
        order=err.replace(b'P4_LD_DEBUG_EXEC_END',b'placeholder').replace(
            b'P4_LD_DEBUG_PLUGIN_BEGIN',b'P4_LD_DEBUG_EXEC_END').replace(
            b'placeholder',b'P4_LD_DEBUG_PLUGIN_BEGIN')
        for broken in (order,err+b'P4_LD_DEBUG_EXEC_BEGIN\n'):
            with self.assertRaises(p.GateError):structurally_accepted(out,broken)
    def test_raw_stream_hash_length_cap_and_exit_mismatch_rejected(self):
        out,err=synthetic_loader_capture()
        for updates in ({'stdout_bytes':len(out)-1},
                        {'stderr_sha256':'0'*64}, {'stdout_cap':len(out)},
                        {'stderr_cap':len(err)}, {'rc':1},
                        {'timed_out':True}):
            with self.subTest(updates=updates),self.assertRaises(p.GateError):
                structurally_accepted(out,err,synthetic_status(out,err,**updates))
    def test_invalid_utf8_and_embedded_markers_rejected(self):
        out,err=synthetic_loader_capture()
        with self.assertRaises(p.GateError):structurally_accepted(out.replace(b'ld.so',b'\xffd.so'),err)
        with self.assertRaises(p.GateError):
            structurally_accepted(out.replace(b'P4_ABI_END',b'not P4_ABI_END'),err)
    def test_provider_hash_and_loader_version_missing_rejected(self):
        out,err=synthetic_loader_capture()
        for broken in (out.replace(b'ld.so (Ubuntu GLIBC 2.39) stable release version 2.39.\n',b''),
                       out.replace(b'/lib64/ld-linux-x86-64.so.2',b'/wrong/loader')):
            with self.assertRaises(p.GateError):structurally_accepted(broken,err)
    def test_explicit_stderr_markers_wrap_each_loader_command(self):
        shell=p.ABI_SHELL
        self.assertLess(shell.index('P4_LD_DEBUG_EXEC_BEGIN'),shell.index('LD_DEBUG=libs,versions'))
        self.assertLess(shell.index('P4_LD_DEBUG_EXEC_END'),shell.index('P4_LD_DEBUG_PLUGIN_BEGIN'))
        self.assertEqual(shell.count('LD_DEBUG=libs,versions'),2)
    def test_scratch_deletion_error_forces_hold_and_nonzero(self):
        with tempfile.TemporaryDirectory() as d:
            scratch=pathlib.Path(d)/'created';scratch.mkdir()
            rec={'status':'PASS_RAW_ABI_LOADER_EVIDENCE_ONLY_NOT_PROVIDER_ACCEPTANCE',
                 'controller_cleanup':'VERIFIED'}
            def fail(path):raise PermissionError('injected deletion refusal')
            p.record_scratch_cleanup(rec,scratch,remover=fail)
            self.assertEqual(rec['status'],'HOLD')
            self.assertIn('injected deletion refusal',rec['host_scratch_cleanup']['deletion_error'])
            self.assertTrue(rec['host_scratch_cleanup']['surviving_path'])
            self.assertEqual(p.controller_exit_code(rec),1)
    def test_scratch_survivor_after_silent_remover_forces_hold(self):
        with tempfile.TemporaryDirectory() as d:
            scratch=pathlib.Path(d)/'created';scratch.mkdir()
            rec={'status':'PASS_RAW_ABI_LOADER_EVIDENCE_ONLY_NOT_PROVIDER_ACCEPTANCE',
                 'controller_cleanup':'VERIFIED'}
            p.record_scratch_cleanup(rec,scratch,remover=lambda path:None)
            self.assertEqual(rec['status'],'HOLD')
            self.assertEqual(rec['host_scratch_cleanup']['status'],'HOLD')
            self.assertTrue(rec['host_scratch_cleanup']['surviving_path'])
            self.assertEqual(p.controller_exit_code(rec),1)
    def test_scratch_success_requires_absence_and_can_return_pass(self):
        with tempfile.TemporaryDirectory() as d:
            scratch=pathlib.Path(d)/'created';scratch.mkdir()
            rec={'status':'PASS_RAW_ABI_LOADER_EVIDENCE_ONLY_NOT_PROVIDER_ACCEPTANCE',
                 'controller_cleanup':'VERIFIED'}
            p.record_scratch_cleanup(rec,scratch)
            self.assertEqual(rec['host_scratch_cleanup']['status'],'VERIFIED')
            self.assertFalse(os.path.lexists(scratch))
            self.assertEqual(p.controller_exit_code(rec),0)
    def test_missing_or_replaced_scratch_never_passes(self):
        with tempfile.TemporaryDirectory() as d:
            scratch=pathlib.Path(d)/'missing'
            rec={'status':'PASS_RAW_ABI_LOADER_EVIDENCE_ONLY_NOT_PROVIDER_ACCEPTANCE',
                 'controller_cleanup':'VERIFIED'}
            p.record_scratch_cleanup(rec,scratch)
            self.assertEqual(rec['status'],'HOLD')
            self.assertEqual(p.controller_exit_code(rec),1)
            target=pathlib.Path(d)/'not_in_scope';target.mkdir()
            scratch.symlink_to(target,target_is_directory=True)
            rec['status']='PASS_RAW_ABI_LOADER_EVIDENCE_ONLY_NOT_PROVIDER_ACCEPTANCE'
            p.record_scratch_cleanup(rec,scratch)
            self.assertEqual(rec['status'],'HOLD')
            self.assertTrue(target.exists())
            self.assertTrue(scratch.is_symlink())
    def test_failure_receipt_is_preserved_and_sha_sealed(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d)
            evidence=root/'evidence';evidence.mkdir()
            (evidence/'raw').mkdir()
            (evidence/'raw'/'existing.stdout.bin').write_bytes(b'original forensic evidence\n')
            scratch=root/'scratch';scratch.mkdir()
            rec={'status':'PASS_RAW_ABI_LOADER_EVIDENCE_ONLY_NOT_PROVIDER_ACCEPTANCE',
                 'controller_cleanup':'VERIFIED'}
            def fail(path):raise OSError('injected read-only filesystem')
            exitcode=p.seal_controller_evidence(evidence,rec,scratch,remover=fail)
            saved=json.loads((evidence/'SECURITY_PREFLIGHT.json').read_text())
            self.assertEqual(exitcode,1)
            self.assertEqual(saved['status'],'HOLD')
            self.assertIn('injected read-only filesystem',saved['host_scratch_cleanup']['deletion_error'])
            self.assertTrue(saved['host_scratch_cleanup']['surviving_path'])
            manifest=(evidence/'SHA256SUMS.txt').read_text()
            self.assertIn('SECURITY_PREFLIGHT.json',manifest)
            self.assertIn('raw/existing.stdout.bin',manifest)
            for line in manifest.splitlines():
                digest,rel=line.split('  ',1)
                self.assertEqual(digest,sha(evidence/rel))
    def test_survivor_receipt_is_preserved_and_sha_sealed(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d)
            evidence=root/'evidence';evidence.mkdir()
            scratch=root/'scratch';scratch.mkdir()
            rec={'status':'PASS_RAW_ABI_LOADER_EVIDENCE_ONLY_NOT_PROVIDER_ACCEPTANCE',
                 'controller_cleanup':'VERIFIED'}
            self.assertEqual(p.seal_controller_evidence(evidence,rec,scratch,remover=lambda path:None),1)
            saved=json.loads((evidence/'SECURITY_PREFLIGHT.json').read_text())
            self.assertEqual(saved['status'],'HOLD')
            self.assertTrue(saved['host_scratch_cleanup']['surviving_path'])
            self.assertEqual(sha(evidence/'SECURITY_PREFLIGHT.json'),
                (evidence/'SHA256SUMS.txt').read_text().split()[0])

    def test_frozen_manifest_hash_and_graph_inventory_source(self):
        self.assertEqual(sha(R/'reference/P4_Build5_Static_ELF_Manifest.json'),
                         p.FROZEN_ELF_MANIFEST_SHA256)
        # The parser is not permitted to accept a substituted static manifest.
        with mock.patch.object(p,'hash_file',side_effect=lambda path:'0'*64):
            with self.assertRaises(p.GateError):structurally_accepted()
    def test_manifest_graph_matches_reviewed_direct_and_transitive_counts(self):
        manifest=json.loads((R/'reference/P4_Build5_Static_ELF_Manifest.json').read_text())
        for key,direct,total,objects in (
                ('bin/step-g',5,19,15),
                ('libexec/step/libstep-schema-ap242e2.so',17,25,21)):
            with self.subTest(key=key):
                closure=p._manifest_closure(manifest,key)
                self.assertEqual(len(manifest['files'][key]['needed']),direct)
                self.assertEqual(len(closure['needed']),total)
                self.assertEqual(len(closure['objects']),objects)
                self.assertEqual(len(closure['providers']),5)
    def test_reviewer_direct_only_positive_now_rejected(self):
        # Reproduce the P4.1 design flaw: all direct records and root versions,
        # but NO intermediate libraries and only one library-search event.
        out,err=synthetic_loader_capture()
        manifest=json.loads((R/'reference/P4_Build5_Static_ELF_Manifest.json').read_text())
        out_lines=out.decode().splitlines()
        frames=(("P4_LOADER_LIST_EXEC_BEGIN","P4_LOADER_LIST_EXEC_END","bin/step-g"),
                ("P4_LOADER_LIST_PLUGIN_BEGIN","P4_LOADER_LIST_PLUGIN_END",
                 "libexec/step/libstep-schema-ap242e2.so"))
        for begin,end,key in frames:
            start=out_lines.index(begin); stop=out_lines.index(end)
            direct=set(manifest['files'][key]['needed'])
            out_lines[start+1:stop]=[line for line in out_lines[start+1:stop]
                if line.split(' => ')[0] in direct]
        out=('\n'.join(out_lines)+'\n').encode()
        error_lines=err.decode().splitlines()
        errors=[]
        # Keep the complete root-object version checks, but only one library trace.
        for line in error_lines:
            if ('find library=' in line or 'trying file=' in line):
                if 'libstdc++.so.6' not in line:
                    continue
            if 'required by file /runtime/lib/' in line:
                continue
            errors.append(line)
        err=('\n'.join(errors)+'\n').encode()
        with self.assertRaises(p.GateError):structurally_accepted(out,err)
    def test_missing_intermediate_transitive_entries_fail_both_targets(self):
        out,err=synthetic_loader_capture()
        for begin,end in ((b'P4_LOADER_LIST_EXEC_BEGIN\n',b'P4_LOADER_LIST_EXEC_END\n'),
                          (b'P4_LOADER_LIST_PLUGIN_BEGIN\n',b'P4_LOADER_LIST_PLUGIN_END\n')):
            i=out.index(begin)+len(begin);j=out.index(end)
            listing=out[i:j]
            for lib in (b'liblmdb.so',b'libClipper2.so.1',b'libz.so.1'):
                row=next((line for line in listing.splitlines(keepends=True)
                          if line.startswith(lib+b' => ')),None)
                if row is not None:
                    with self.subTest(target=begin.decode().strip(),library=lib.decode()),self.assertRaises(p.GateError):
                        structurally_accepted(out[:i]+listing.replace(row,b'')+out[j:],err)
    def test_only_single_search_trace_with_all_versions_fails(self):
        out,err=synthetic_loader_capture()
        # Preserve every target AND transitive version check while deleting
        # other libraries' find/trying pairs, the exact residual review finding.
        lines=[line for line in err.splitlines(keepends=True) if
               not ((b'find library=' in line or b'trying file=' in line)
                    and b'libstdc++.so.6' not in line)]
        with self.assertRaises(p.GateError):structurally_accepted(out,b''.join(lines))
    def test_missing_search_for_transitive_dependency_rejected(self):
        out,err=synthetic_loader_capture()
        row=b'      221: find library=liblmdb.so [0]; searching\n'
        self.assertIn(row,err)
        with self.assertRaises(p.GateError):structurally_accepted(out,err.replace(row,b''))
    def test_search_with_wrong_resolution_attempt_rejected(self):
        out,err=synthetic_loader_capture()
        row=b'      221:   trying file=/runtime/lib/liblmdb.so\n'
        self.assertIn(row,err)
        for replacement in (b'',b'      221:   trying file=/usr/lib/liblmdb.so\n'):
            with self.subTest(replacement=replacement),self.assertRaises(p.GateError):
                structurally_accepted(out,err.replace(row,replacement))
    def test_search_and_try_must_belong_to_same_library(self):
        out,err=synthetic_loader_capture()
        # The path appears somewhere in the stream, but is now attributed to
        # the previous SONAME's search. Global set membership is insufficient.
        a=b'      221: find library=liblmdb.so [0]; searching\n'
        b=b'      221:   trying file=/runtime/lib/liblmdb.so\n'
        self.assertIn(a+b,err)
        with self.assertRaises(p.GateError):structurally_accepted(out,err.replace(a+b,b+a))
    def test_transitive_object_version_check_rejected_if_missing(self):
        out,err=synthetic_loader_capture()
        row=next(line for line in err.splitlines(keepends=True)
                 if b'required by file /runtime/lib/liblmdb.so [0]' in line)
        with self.assertRaises(p.GateError):structurally_accepted(out,err.replace(row,b''))
    def test_version_record_wrong_provider_rejected(self):
        out,err=synthetic_loader_capture()
        row=next(line for line in err.splitlines(keepends=True)
                 if b'GLIBCXX_3.4.32' in line)
        changed=row.replace(b'/usr/lib/x86_64-linux-gnu/libstdc++.so.6',
                            b'/lib/x86_64-linux-gnu/libc.so.6')
        self.assertNotEqual(row,changed)
        with self.assertRaises(p.GateError):structurally_accepted(out,err.replace(row,changed))
    def test_bundled_resolution_must_match_frozen_inventory_path(self):
        out,err=synthetic_loader_capture()
        row=b'liblmdb.so => /runtime/lib/liblmdb.so (0x00007fffff000000)\n'
        replacement=b'liblmdb.so => /usr/lib/liblmdb.so (0x00007fffff000000)\n'
        self.assertIn(row,out)
        with self.assertRaises(p.GateError):structurally_accepted(out.replace(row,replacement),err)
    def test_unmodeled_image_provider_needs_correlated_debug(self):
        out,err=synthetic_loader_capture()
        row=b'libextra.so.2 => /usr/lib/x86_64-linux-gnu/libextra.so.2 (0x00007fffff000000)\n'
        marker=b'P4_LOADER_LIST_EXEC_END\n'
        with self.assertRaises(p.GateError):structurally_accepted(out.replace(marker,row+marker),err)
    def test_extra_image_provider_records_are_audited_not_accepted_as_abi(self):
        out,err=synthetic_loader_capture()
        name='libextra.so.2'
        path='/usr/lib/x86_64-linux-gnu/'+name
        row=(name+' => '+path+' (0x00007fffff000000)\n').encode()
        out=out.replace(b'P4_LOADER_LIST_EXEC_END\n',
                        row+b'P4_LOADER_LIST_EXEC_END\n')
        trace=('      221: find library='+name+' [0]; searching\n'
               '      221:   trying file='+path+'\n').encode()
        err=err.replace(b'P4_LD_DEBUG_EXEC_END\n',trace+b'P4_LD_DEBUG_EXEC_END\n')
        result=structurally_accepted(out,err)
        self.assertEqual(result['structurally_checked']['exec']['dependencies']
                         ['extra_image_provider_names'],[name])
        self.assertEqual(result['image_provider_transitive_abi'],'INDEPENDENT_REVIEW_HOLD')
    def test_loader_direct_path_and_provider_symlink_alias_accepted(self):
        out,err=synthetic_loader_capture()
        alias=b'ld-linux-x86-64.so.2 => /lib64/ld-linux-x86-64.so.2 (0x00007fffff000000)\n'
        direct=b'/lib64/ld-linux-x86-64.so.2 (0x00007fffff000000)\n'
        self.assertIn(alias,out)
        result=structurally_accepted(out.replace(alias,direct),err)
        self.assertTrue(result['loader_dependency_listing_complete'])
        # Provider path can be an /usr/lib alias; still no provider ABI proof.
        src=b'libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fffff000000)\n'
        dst=b'libc.so.6 => /usr/lib/x86_64-linux-gnu/libc.so.6 (0x00007fffff000000)\n'
        edited=out.replace(src,dst)
        edited_err=err.replace(b'/lib/x86_64-linux-gnu/libc.so.6',
                               b'/usr/lib/x86_64-linux-gnu/libc.so.6')
        result=structurally_accepted(edited,edited_err)
        self.assertEqual(result['provider_version_acceptance'],'INDEPENDENT_REVIEW_HOLD')
    def test_reject_unreviewed_provider_path_or_loader_format(self):
        out,err=synthetic_loader_capture()
        row=b'libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fffff000000)\n'
        for replacement in (b'libc.so.6 => /scratch/libc.so.6 (0x00007fffff000000)\n',
                            b'libc.so.6 => not found\n',
                            b'libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (unknown)\n'):
            with self.subTest(replacement=replacement),self.assertRaises(p.GateError):
                structurally_accepted(out.replace(row,replacement),err)
    def test_completeness_claim_explicitly_excludes_provider_abi(self):
        result=structurally_accepted()
        self.assertEqual(result['completeness_scope'],'FROZEN_BUNDLED_ELF_TRANSITIVE_CLOSURE_ONLY')
        self.assertEqual(result['image_provider_transitive_abi'],'INDEPENDENT_REVIEW_HOLD')
        self.assertEqual(result['structurally_checked']['exec']['dependencies']['manifest_transitive_closure_count'],19)
        self.assertEqual(result['structurally_checked']['plugin']['dependencies']['manifest_transitive_closure_count'],25)
        self.assertFalse(result['step_geometry_invoked'])
    def test_exit_code_never_promotes_unverified_cleanup(self):
        rec={'status':'PASS_RAW_ABI_LOADER_EVIDENCE_ONLY_NOT_PROVIDER_ACCEPTANCE',
             'controller_cleanup':'VERIFIED',
             'host_scratch_cleanup':{'status':'HOLD'}}
        self.assertEqual(p.controller_exit_code(rec),1)
        rec['host_scratch_cleanup']={'status':'VERIFIED'}
        rec['controller_cleanup']='HOLD'
        self.assertEqual(p.controller_exit_code(rec),1)


class P43ProviderPathAndErrorRegressions(unittest.TestCase):
    """P4.2 review counterexamples: offline fabricated evidence, never G1."""

    def test_canonical_provider_policy_rejects_lexical_aliases_and_escape(self):
        accepted=('/lib/x86_64-linux-gnu/libc.so.6',
                  '/usr/lib/x86_64-linux-gnu/libc.so.6',
                  '/lib64/ld-linux-x86-64.so.2')
        for path in accepted:
            with self.subTest(accepted=path):
                self.assertTrue(p._canonical_provider_path(path))
        rejected=('/scratch/libc.so.6', '/lib/../../scratch/libc.so.6',
                  '/usr/lib/../../../scratch/libstdc++.so.6',
                  '/lib/x86_64-linux-gnu/../libc.so.6',
                  '/lib/./x86_64-linux-gnu/libc.so.6',
                  '/lib//x86_64-linux-gnu/libc.so.6',
                  '//lib/x86_64-linux-gnu/libc.so.6',
                  '/lib/x86_64-linux-gnu/libc.so.6/',
                  'lib/x86_64-linux-gnu/libc.so.6')
        for path in rejected:
            with self.subTest(rejected=path):
                self.assertFalse(p._canonical_provider_path(path))

    def test_independent_provider_path_escape_is_rejected_even_with_matching_debug(self):
        out,err=synthetic_loader_capture()
        old=b'/lib/x86_64-linux-gnu/libc.so.6'
        self.assertIn(old,out)
        for replacement in (b'/lib/../../scratch/libc.so.6',
                            b'/lib/x86_64-linux-gnu/../libc.so.6',
                            b'/lib/./x86_64-linux-gnu/libc.so.6',
                            b'/lib//x86_64-linux-gnu/libc.so.6',
                            b'//lib/x86_64-linux-gnu/libc.so.6'):
            with self.subTest(provider_path=replacement),self.assertRaises(p.GateError):
                row=b'libc.so.6 => '+old+b' (0x00007fffff000000)'
                changed_row=row.replace(old,replacement)
                structurally_accepted(out.replace(row,changed_row),
                                      err.replace(old,replacement))

    def test_usr_lib_provider_escape_rejected_with_consistent_debug(self):
        out,err=synthetic_loader_capture()
        old=b'/usr/lib/x86_64-linux-gnu/libstdc++.so.6'
        new=b'/usr/lib/../../../scratch/libstdc++.so.6'
        self.assertIn(old,out)
        with self.assertRaises(p.GateError):
            row=b'libstdc++.so.6 => '+old+b' (0x00007fffff000000)'
            structurally_accepted(out.replace(row,row.replace(old,new)),
                                  err.replace(old,new))

    def test_extra_image_provider_cannot_escape_with_matching_trace(self):
        out,err=synthetic_loader_capture()
        name='libextra.so.2'
        path='/usr/lib/../../scratch/'+name
        row=(name+' => '+path+' (0x00007fffff000000)\n').encode()
        trace=('      221: find library='+name+' [0]; searching\n'
               '      221:   trying file='+path+'\n').encode()
        out=out.replace(b'P4_LOADER_LIST_EXEC_END\n',row+b'P4_LOADER_LIST_EXEC_END\n')
        err=err.replace(b'P4_LD_DEBUG_EXEC_END\n',trace+b'P4_LD_DEBUG_EXEC_END\n')
        with self.assertRaises(p.GateError):
            structurally_accepted(out,err)

    def test_reviewer_unexpected_error_line_rejected_with_complete_positive_traces(self):
        out,err=synthetic_loader_capture()
        line=b'      221: error while loading shared libraries: omitted provider\n'
        for marker in (b'P4_LD_DEBUG_EXEC_END\n',b'P4_LD_DEBUG_PLUGIN_END\n'):
            with self.subTest(frame=marker),self.assertRaises(p.GateError):
                structurally_accepted(out,err.replace(marker,line+marker))

    def test_broader_loader_error_vocabulary_rejected_in_both_frames(self):
        out,err=synthetic_loader_capture()
        error_lines=(
            b'      221: FATAL: relocation failed\n',
            b'      221: cannot open shared object file\n',
            b'      221: version `GLIBC_9.9` not found\n',
            b'      221: symbol lookup ERROR: undefined symbol\n',
            b'      221: permission denied\n',
            b'      221: invalid ELF header\n',
            b'      221: file too short\n',
            b'      221: no such file or directory\n',
        )
        for error in error_lines:
            for marker in (b'P4_LD_DEBUG_EXEC_END\n',b'P4_LD_DEBUG_PLUGIN_END\n'):
                with self.subTest(error=error,frame=marker),self.assertRaises(p.GateError):
                    structurally_accepted(out,err.replace(marker,error+marker))

    def test_nonerror_loader_diagnostics_remain_structural_only(self):
        out,err=synthetic_loader_capture()
        benign=b'      221: search cache=/etc/ld.so.cache\n'
        result=structurally_accepted(out,err.replace(
            b'P4_LD_DEBUG_EXEC_END\n',benign+b'P4_LD_DEBUG_EXEC_END\n'))
        self.assertTrue(result['loader_dependency_listing_complete'])
        self.assertEqual(result['provider_version_acceptance'],'INDEPENDENT_REVIEW_HOLD')

    def test_provider_path_or_error_failure_cannot_promote_abi_verdict(self):
        out,err=synthetic_loader_capture()
        row=(b'libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 '
             b'(0x00007fffff000000)')
        bad_out=out.replace(row,row.replace(b'/lib/x86_64-linux-gnu/libc.so.6',
                                            b'/lib/../../scratch/libc.so.6'))
        bad_err=err.replace(b'/lib/x86_64-linux-gnu/libc.so.6',
                            b'/lib/../../scratch/libc.so.6')
        for o,e in ((bad_out,bad_err),
                    (out,err.replace(b'P4_LD_DEBUG_EXEC_END\n',
                     b'      221: error while loading shared libraries: omitted provider\n'
                     b'P4_LD_DEBUG_EXEC_END\n'))):
            with self.assertRaises(p.GateError):
                p.check_abi_markers(o,e,synthetic_status(o,e))


class P431VersionWarningRegressions(unittest.TestCase):
    """P43-R1: warning lines must never be masked by complete positive traces."""

    def _expect_anomaly_hold(self, diagnostic):
        out,err=synthetic_loader_capture()
        for end in (b'P4_LD_DEBUG_EXEC_END\n',b'P4_LD_DEBUG_PLUGIN_END\n'):
            with self.subTest(frame=end, diagnostic=diagnostic):
                altered=err.replace(end,diagnostic+end)
                st=synthetic_status(out,altered)
                self.assertEqual(st['rc'],0)
                self.assertEqual(st['stdout_sha256'],hashlib.sha256(out).hexdigest())
                self.assertEqual(st['stderr_sha256'],hashlib.sha256(altered).hexdigest())
                with self.assertRaises(p.GateError):
                    p.check_abi_markers(out,altered,st)

    def test_reviewer_exact_no_version_information_line_both_frames(self):
        self._expect_anomaly_hold(
            b'      221: /lib/x86_64-linux-gnu/libstdc++.so.6: no version information available (required by /runtime/bin/step-g)\n')

    def test_no_version_warning_realistic_prefix_and_plugin_requestor(self):
        self._expect_anomaly_hold(
            b'      957: /usr/lib/x86_64-linux-gnu/libstdc++.so.6: no version information available (required by /runtime/libexec/step/libstep-schema-ap242e2.so)\n')

    def test_no_version_warning_case_and_spacing_variants(self):
        for warning in (
            b'   9: /lib/x86_64-linux-gnu/libc.so.6: NO VERSION INFORMATION AVAILABLE (required by /runtime/bin/step-g)\n',
            b'   9: /usr/lib/libstdc++.so.6: No  Version  Information  Available (required by /runtime/bin/step-g)\n',
        ):
            self._expect_anomaly_hold(warning)

    def test_wrong_elf_class_both_frames(self):
        self._expect_anomaly_hold(
            b'      221: /lib/x86_64-linux-gnu/libc.so.6: wrong ELF class: ELFCLASS32\n')

    def test_wrong_elf_class_upper_case_both_frames(self):
        self._expect_anomaly_hold(
            b'      221: /usr/lib/libextra.so: WRONG ELF CLASS: ELFCLASS64\n')

    def test_unsupported_version_verdef_record_both_frames(self):
        self._expect_anomaly_hold(
            b'      221: /usr/lib/libstdc++.so.6: unsupported version 2 of Verdef record\n')

    def test_unsupported_version_qualifiers_both_frames(self):
        for line in (
            b'      221: /usr/lib/libstdc++.so.6: unsupported ELF version 2\n',
            b'      221: /usr/lib/libstdc++.so.6: unsupported ABI version 4\n',
            b'      221: /usr/lib/libstdc++.so.6: version is not supported\n',
        ):
            self._expect_anomaly_hold(line)

    def test_complete_positive_raw_capture_and_hold_verdict_unchanged(self):
        out,err=synthetic_loader_capture()
        status=synthetic_status(out,err)
        result=p.check_abi_markers(out,err,status)
        self.assertTrue(result['loader_dependency_listing_complete'])
        self.assertEqual(result['raw_stdout_sha256'],status['stdout_sha256'])
        self.assertEqual(result['raw_stderr_sha256'],status['stderr_sha256'])
        self.assertEqual(result['provider_version_acceptance'],'INDEPENDENT_REVIEW_HOLD')
        self.assertEqual(result['image_provider_transitive_abi'],'INDEPENDENT_REVIEW_HOLD')
        self.assertEqual(result['completeness_scope'],'FROZEN_BUNDLED_ELF_TRANSITIVE_CLOSURE_ONLY')


class P432InterframeFramingRegressions(unittest.TestCase):
    """P431-R1: every raw line must be inside an attributed frame."""

    def _reject_unframed(self, out, err, channel):
        # A real complete positive synthetic trace, retaining all required
        # dependencies and version checks. Recompute truthful raw stream fields
        # even though fabricated command exit is zero.
        status=synthetic_status(out,err)
        self.assertEqual(status['rc'],0)
        self.assertIs(status['timed_out'],False)
        self.assertEqual(status['stdout_bytes'],len(out))
        self.assertEqual(status['stderr_bytes'],len(err))
        self.assertEqual(status['stdout_sha256'],hashlib.sha256(out).hexdigest())
        self.assertEqual(status['stderr_sha256'],hashlib.sha256(err).hexdigest())
        with self.assertRaisesRegex(p.GateError, 'unattributed '+channel):
            p.check_abi_markers(out,err,status)

    def test_reviewer_glibc_version_warning_between_stderr_frames_is_hold(self):
        out,err=synthetic_loader_capture()
        marker=b'P4_LD_DEBUG_PLUGIN_BEGIN\n'
        warning=(b'      221: /lib/x86_64-linux-gnu/libstdc++.so.6: '
                 b'no version information available (required by /runtime/bin/step-g)\n')
        self.assertEqual(err.count(marker),1)
        self._reject_unframed(out,err.replace(marker,warning+marker),'stderr')

    def test_reviewer_fatal_error_between_stderr_frames_is_hold(self):
        out,err=synthetic_loader_capture()
        marker=b'P4_LD_DEBUG_PLUGIN_BEGIN\n'
        fatal=b'      221: FATAL: error while loading shared libraries: omitted provider\n'
        self.assertEqual(err.count(marker),1)
        self._reject_unframed(out,err.replace(marker,fatal+marker),'stderr')

    def test_reviewer_fatal_error_between_stdout_listings_is_hold(self):
        out,err=synthetic_loader_capture()
        marker=b'P4_LOADER_LIST_PLUGIN_BEGIN\n'
        fatal=b'error while loading shared libraries: omitted provider\n'
        self.assertEqual(out.count(marker),1)
        self._reject_unframed(out.replace(marker,fatal+marker),err,'stdout')

    def test_even_benign_or_blank_unattributed_interframe_lines_are_hold(self):
        out,err=synthetic_loader_capture()
        for extra in (b'\n',b'      221: search cache=/etc/ld.so.cache\n'):
            with self.subTest(extra=extra):
                self._reject_unframed(out,err.replace(b'P4_LD_DEBUG_PLUGIN_BEGIN\n',
                               extra+b'P4_LD_DEBUG_PLUGIN_BEGIN\n'),'stderr')
                self._reject_unframed(out.replace(b'P4_LOADER_LIST_PLUGIN_BEGIN\n',
                               extra+b'P4_LOADER_LIST_PLUGIN_BEGIN\n'),err,'stdout')

    def test_fully_framed_positive_trace_remains_structural_not_abi_acceptance(self):
        out,err=synthetic_loader_capture()
        result=p.check_abi_markers(out,err,synthetic_status(out,err))
        self.assertTrue(result['loader_dependency_listing_complete'])
        self.assertEqual(result['completeness_scope'],
                         'FROZEN_BUNDLED_ELF_TRANSITIVE_CLOSURE_ONLY')
        self.assertEqual(result['provider_version_acceptance'],'INDEPENDENT_REVIEW_HOLD')
        self.assertEqual(result['image_provider_transitive_abi'],'INDEPENDENT_REVIEW_HOLD')
        self.assertFalse(result['entrypoint_step_g_invoked'])



class P433StdoutEvidenceRegressions(unittest.TestCase):
    """P432-R1: all stdout must be framed and --version must be anomaly-free."""

    def _reject_rehashed(self, out, err, expected):
        # Preserve the entire positive dependency/LD_DEBUG trace and compute
        # truthful bytes + SHA-256 despite synthetic zero-exit metadata.
        status=synthetic_status(out,err)
        self.assertEqual(status['rc'],0)
        self.assertFalse(status['timed_out'])
        for stream, raw in (('stdout',out),('stderr',err)):
            self.assertEqual(status[stream+'_bytes'],len(raw))
            self.assertEqual(status[stream+'_sha256'],hashlib.sha256(raw).hexdigest())
        with self.assertRaisesRegex(p.GateError,expected):
            p.check_abi_markers(out,err,status)

    def test_reviewer_leading_fatal_stdout_is_hold(self):
        out,err=synthetic_loader_capture()
        self._reject_rehashed(b'FATAL: outside all loader frames\n'+out,err,
                              'unattributed leading stdout')

    def test_reviewer_leading_warning_stdout_is_hold(self):
        out,err=synthetic_loader_capture()
        warning=(b'      221: /lib/x86_64-linux-gnu/libstdc++.so.6: '
                 b'no version information available (required by /runtime/bin/step-g)\n')
        self._reject_rehashed(warning+out,err,'unattributed leading stdout')

    def test_reviewer_leading_blank_stdout_is_hold(self):
        out,err=synthetic_loader_capture()
        self._reject_rehashed(b'\n'+out,err,'unattributed leading stdout')

    def test_reviewer_fatal_before_loader_version_line_is_hold(self):
        out,err=synthetic_loader_capture()
        key=b'ld.so (Ubuntu GLIBC 2.39) stable release version 2.39.\n'
        self.assertEqual(out.count(key),1)
        changed=out.replace(key,b'FATAL: unframed synthetic input\n'+key)
        self._reject_rehashed(changed,err,'Loader --version output contains error')

    def test_reviewer_fatal_after_loader_version_line_is_hold(self):
        out,err=synthetic_loader_capture()
        key=b'ld.so (Ubuntu GLIBC 2.39) stable release version 2.39.\n'
        self.assertEqual(out.count(key),1)
        changed=out.replace(key,key+b'FATAL: unframed synthetic input\n')
        self._reject_rehashed(changed,err,'Loader --version output contains error')

    def test_loader_version_warning_is_hold_but_positive_remains_structural(self):
        out,err=synthetic_loader_capture()
        key=b'ld.so (Ubuntu GLIBC 2.39) stable release version 2.39.\n'
        self.assertEqual(out.count(key),1)
        warning=(b'      221: /lib/x86_64-linux-gnu/libstdc++.so.6: '
                 b'no version information available (required by /runtime/bin/step-g)\n')
        self._reject_rehashed(out.replace(key,key+warning),err,
                              'Loader --version output contains error')
        status=synthetic_status(out,err)
        accepted=p.check_abi_markers(out,err,status)
        self.assertTrue(accepted['loader_dependency_listing_complete'])
        self.assertEqual(accepted['raw_stdout_sha256'],status['stdout_sha256'])
        self.assertEqual(accepted['raw_stderr_sha256'],status['stderr_sha256'])
        self.assertEqual(accepted['completeness_scope'],
                         'FROZEN_BUNDLED_ELF_TRANSITIVE_CLOSURE_ONLY')
        self.assertEqual(accepted['provider_version_acceptance'],'INDEPENDENT_REVIEW_HOLD')
        self.assertEqual(accepted['image_provider_transitive_abi'],'INDEPENDENT_REVIEW_HOLD')



class P434CanaryAbiIntegration(unittest.TestCase):
    """P433-R1 full one-container canary+ABI evidence path, source-only."""

    def setUp(self):
        self.canary=(R/'reference/P31_run42518017322_native_canary_sanitized.txt').read_bytes()
        self.abi_out,self.abi_err=synthetic_loader_capture()
        self.stdout=self.canary+self.abi_out
        self.masked=['/proc/interrupts','/proc/kcore','/proc/keys',
                     '/proc/latency_stats','/proc/timer_list']
        self.host_ns='net:[100]'

    def verify(self, out=None, err=None, receipt=None, **kw):
        out=self.stdout if out is None else out
        err=self.abi_err if err is None else err
        receipt=synthetic_status(out,err) if receipt is None else receipt
        return p.check_combined_canary_abi(
            out,err,receipt,self.host_ns,masked_paths=self.masked,**kw)

    def test_complete_frozen_canary_and_full_abi_pass_structural_only(self):
        status=synthetic_status(self.stdout,self.abi_err)
        original=dict(status)
        sec,abi,source,derived=self.verify(receipt=status)
        self.assertTrue(sec['distinct'])
        self.assertTrue(abi['loader_dependency_listing_complete'])
        self.assertEqual(abi['provider_version_acceptance'],'INDEPENDENT_REVIEW_HOLD')
        self.assertEqual(abi['image_provider_transitive_abi'],'INDEPENDENT_REVIEW_HOLD')
        self.assertEqual(source['original_stdout_sha256'],original['stdout_sha256'])
        self.assertEqual(source['original_stderr_sha256'],original['stderr_sha256'])
        self.assertEqual(source['original_stdout_bytes'],len(self.stdout))
        self.assertEqual(source['abi_stdout_offset_bytes'],len(self.canary))
        self.assertEqual(source['canary_stdout_bytes'],len(self.canary))
        self.assertEqual(source['canary_stdout_sha256'],hashlib.sha256(self.canary).hexdigest())
        self.assertEqual(source['abi_stdout_bytes'],len(self.abi_out))
        self.assertEqual(source['abi_stdout_sha256'],hashlib.sha256(self.abi_out).hexdigest())
        self.assertEqual(source['abi_stderr_sha256'],original['stderr_sha256'])
        self.assertEqual(self.stdout[source['abi_stdout_offset_bytes']:],derived)
        self.assertEqual(self.canary+derived,self.stdout)
        self.assertEqual(derived,self.abi_out)
        self.assertEqual(status,original) # original command receipt never rewritten

    def test_strict_standalone_abi_boundary_not_weakened(self):
        with self.assertRaises(p.GateError):
            p.check_abi_markers(self.stdout,self.abi_err,synthetic_status(self.stdout,self.abi_err))
        self.assertTrue(structurally_accepted(self.abi_out,self.abi_err)['loader_dependency_listing_complete'])

    def test_frozen_canary_and_abi_shell_are_contiguous_source(self):
        self.assertIn("script=(src/'ci/fixture_canary.sh').read_text()+ '\\n' + ABI_SHELL",
                      (R/'ci/p4_abi_controller.py').read_text())
        self.assertTrue((R/'ci/fixture_canary.sh').read_text().endswith("printf 'FROZEN_PASS:yes\\n'\n"))
        self.assertIn("printf 'P4_ABI_BEGIN\\n'",p.ABI_SHELL)
        self.assertEqual(sha(R/'ci/fixture_canary.sh'),p.EXPECTED_CONTROL_SHA256['ci/fixture_canary.sh'])

    def test_verify_canary_runs_before_strict_abi_checker(self):
        actions=[]
        original_sec=p.verify_canary
        original_abi=p.check_abi_markers
        def sec(*args,**kwargs):
            actions.append('security');return original_sec(*args,**kwargs)
        def abi(*args,**kwargs):
            actions.append('abi');return original_abi(*args,**kwargs)
        with mock.patch.object(p,'verify_canary',side_effect=sec), mock.patch.object(p,'check_abi_markers',side_effect=abi):
            self.verify()
        self.assertEqual(actions,['security','abi'])

    def test_error_before_canary_first_marker_rejected(self):
        with self.assertRaises(p.GateError):self.verify(b'FATAL: unauthorized preamble\n'+self.stdout)

    def test_intervening_lines_after_pass_rejected(self):
        for line in (b'FATAL: wrong phase\n',b'\n',b'harmless extra\n'):
            with self.subTest(line=line),self.assertRaises(p.GateError):
                self.verify(self.canary+line+self.abi_out)

    def test_canary_pass_boundary_missing_or_duplicate(self):
        for out in (
            self.stdout.replace(b'FROZEN_PASS:yes\n',b''),
            self.stdout.replace(b'FROZEN_PASS:yes\n',b'FROZEN_PASS:yes\nFROZEN_PASS:yes\n'),
            self.stdout.replace(b'FROZEN_PASS:yes\n',b'FROZEN_PASS:no\n'),
        ):
            with self.subTest(length=len(out)),self.assertRaises(p.GateError):self.verify(out)

    def test_abi_begin_boundary_missing_duplicated_or_reordered(self):
        for out in (
            self.stdout.replace(b'P4_ABI_BEGIN\n',b''),
            self.stdout.replace(b'P4_ABI_BEGIN\n',b'P4_ABI_BEGIN\nP4_ABI_BEGIN\n'),
            self.canary.replace(b'FROZEN_PASS:yes\n',b'')+self.abi_out+b'FROZEN_PASS:yes\n',
            self.canary+b'P4_ABI_BEGIN\nFROZEN_PASS:yes\n'+self.abi_out,
        ):
            with self.subTest(length=len(out)),self.assertRaises(p.GateError):self.verify(out)

    def test_canary_prefix_truncation_rejected(self):
        for cut in (1,8,len(self.canary)//2,len(self.canary)-1):
            with self.subTest(cut=cut),self.assertRaises(p.GateError):
                self.verify(self.canary[cut:]+self.abi_out)

    def test_canary_duplicate_or_missing_security_marker_rejected(self):
        for out in (
            self.stdout.replace(b'DENY_RUNTIME:yes\n',b''),
            self.stdout.replace(b'DENY_RUNTIME:yes\n',b'DENY_RUNTIME:yes\nDENY_RUNTIME:yes\n'),
            self.stdout.replace(b'ROUTES_EMPTY:yes\n',b'ROUTES_EMPTY:no\n'),
            self.stdout.replace(b'UID_GID:65534:65534\n',b'UID_GID:0:0\n'),
        ):
            with self.subTest(length=len(out)),self.assertRaises(p.GateError):self.verify(out)

    def test_canary_reordered_security_fields_rejected(self):
        wrong=self.stdout.replace(b'ROUTES_EMPTY:yes\nIPV6_ROUTES_EMPTY:yes\n',
                 b'IPV6_ROUTES_EMPTY:yes\nROUTES_EMPTY:yes\n')
        with self.assertRaises(p.GateError):self.verify(wrong)

    def test_canary_mountinfo_truncated_or_garbage_rejected(self):
        for out in (
            self.stdout.replace(b'MOUNTINFO_END\n',b''),
            self.stdout.replace(b'MOUNTINFO_BEGIN\n',b''),
            self.stdout.replace(b'MOUNTINFO_END\n',b'not mountinfo\nMOUNTINFO_END\n'),
        ):
            with self.subTest(length=len(out)),self.assertRaises(p.GateError):self.verify(out)

    def test_complete_stream_hash_or_byte_count_corruption_rejected(self):
        correct=synthetic_status(self.stdout,self.abi_err)
        for delta in (
            {'stdout_sha256':'0'*64}, {'stdout_bytes':len(self.stdout)-1},
            {'stderr_sha256':'0'*64}, {'stderr_bytes':len(self.abi_err)-1},
            {'rc':1}, {'timed_out':True}
        ):
            with self.subTest(delta=delta),self.assertRaises(p.GateError):
                self.verify(receipt={**correct,**delta})

    def test_unmodified_abi_error_bounds_hold_in_combined_context(self):
        for out,err in (
            (self.stdout.replace(b'P4_ABI_BEGIN\n',b'P4_ABI_BEGIN\nFATAL: inserted\n'),self.abi_err),
            (self.stdout,self.abi_err.replace(b'P4_LD_DEBUG_EXEC_END\n',
                b'no version information available (required by /runtime/bin/step-g)\nP4_LD_DEBUG_EXEC_END\n')),
        ):
            with self.subTest(stderr_bytes=len(err)),self.assertRaises(p.GateError):self.verify(out,err)

    def test_canary_source_digest_gate_independent_of_stream(self):
        with mock.patch.object(p,'hash_file',return_value='0'*64):
            with self.assertRaises(p.GateError):self.verify()


class P435PublicRuntimeReadPermissions(unittest.TestCase):
    """P4.3.5: POSIX permissions only; never run Build #5 or BRL-CAD."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='adr001-p435-')
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name)
        self.scratch = self.root/'private_scratch'
        self.scratch.mkdir(mode=0o700)
        self.runtime = self.scratch/'runtime'
        self.fixtures = self.scratch/'fixtures'
        previous = os.umask(0o077)
        try:
            self.runtime.mkdir()
            (self.runtime/'bin').mkdir()
            (self.runtime/'libexec').mkdir()
            (self.runtime/'libexec/step').mkdir()
            (self.runtime/'bin/step-g').write_bytes(b'synthetic step-g DATA, never executed')
            (self.runtime/'libexec/step/libstep-schema-ap242e2.so').write_bytes(b'synthetic plugin bytes')
            (self.runtime/'share').mkdir()
            (self.runtime/'share/frozen.txt').write_bytes(b'untouched public bytes')
            self.fixtures.mkdir()
            for fn in ('base_attachment.step','M015.stp'):
                (self.fixtures/fn).write_bytes(b'ISO-10303-21; synthetic fixture')
        finally:
            os.umask(previous)
        self.runtime_files = {
            file.relative_to(self.runtime).as_posix():sha(file)
            for file in self.runtime.rglob('*') if file.is_file()}
        self.fixture_files = {
            file.name:sha(file) for file in self.fixtures.iterdir()}

    def prepare(self):
        runtime = p._public_tree_manifest(self.runtime,self.runtime_files,('bin/step-g',))
        fixtures = p._public_tree_manifest(self.fixtures,self.fixture_files)
        return runtime,fixtures

    def test_umask_077_reproduces_inaccessible_original_directories(self):
        self.assertEqual(self.runtime.stat().st_mode & 0o777,0o700)
        self.assertEqual((self.runtime/'bin').stat().st_mode & 0o777,0o700)
        self.assertEqual(self.fixtures.stat().st_mode & 0o777,0o700)
        self.assertFalse(bool(self.runtime.stat().st_mode & 0o005))
        self.assertEqual(self.scratch.stat().st_mode & 0o777,0o700)

    def test_all_runtime_and_fixture_dirs_uid65534_traversable_and_files_readable(self):
        rt,fx=self.prepare()
        self.assertEqual(rt['uid_65534_read_traversal'],'PASS_STATIC_MODE_BITS_ONLY')
        self.assertEqual(fx['uid_65534_read_traversal'],'PASS_STATIC_MODE_BITS_ONLY')
        for root in (self.runtime,self.fixtures):
            for node in [root,*root.rglob('*')]:
                mode=node.lstat().st_mode & 0o777
                if node.is_dir():
                    self.assertEqual(mode,0o755)
                    self.assertTrue(mode & 0o001)
                else:
                    self.assertIn(mode,(0o644,0o755))
                    self.assertTrue(mode & 0o004)
        self.assertEqual(self.scratch.stat().st_mode & 0o777,0o700)
        self.assertTrue(rt['bytes_unchanged'] and fx['bytes_unchanged'])
        self.assertEqual(rt['container_access_and_ABI'],'NOT_TESTED')

    def test_positive_uid65534_actual_nonexecuting_open_when_root(self):
        # The temporary container test root is public only for this optional
        # host-mode probe; the production scratch parent stays mode 0700.
        self.prepare()
        if os.geteuid() != 0:
            self.assertEqual(self.runtime.stat().st_mode & 0o777,0o755)
            return
        self.root.chmod(0o755)
        self.scratch.chmod(0o755)
        try:
            def drop_to_nobody():
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)
            source = ('import os, pathlib; '
                      'a=pathlib.Path(os.environ["TARGET_A"]); '
                      'b=pathlib.Path(os.environ["TARGET_B"]); '
                      'assert os.getuid()==65534 and os.getgid()==65534; '
                      'assert a.open("rb").read(9)==b"synthetic"; '
                      'assert b.open("rb").read(9)==b"ISO-10303"')
            env=dict(os.environ, TARGET_A=str(self.runtime/'bin/step-g'),
                     TARGET_B=str(self.fixtures/'M015.stp'))
            proc=subprocess.run([sys.executable,'-I','-B','-c',source],
                                env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                preexec_fn=drop_to_nobody,timeout=8)
            self.assertEqual(proc.returncode,0,proc.stderr.decode())
        finally:
            self.scratch.chmod(0o700)
            self.root.chmod(0o700)
        self.assertEqual(self.scratch.stat().st_mode & 0o777,0o700)

    def test_unexpected_symlink_directory_is_fail_closed(self):
        self.runtime.joinpath('libexec/step').rename(self.runtime/'libexec/step.real')
        (self.runtime/'libexec/step').symlink_to('step.real',target_is_directory=True)
        with self.assertRaises(p.GateError):
            p._public_tree_manifest(self.runtime,self.runtime_files,('bin/step-g',))

    def test_unexpected_symlink_file_is_fail_closed(self):
        original=self.fixtures/'M015.stp'
        original.rename(self.fixtures/'M015.stp.backup')
        original.symlink_to('M015.stp.backup')
        with self.assertRaises(p.GateError):p._public_tree_manifest(self.fixtures,self.fixture_files)

    def test_uninventoried_or_missing_file_is_fail_closed(self):
        (self.fixtures/'extra.step').write_bytes(b'unexpected')
        with self.assertRaises(p.GateError):p._public_tree_manifest(self.fixtures,self.fixture_files)
        (self.fixtures/'extra.step').unlink()
        (self.fixtures/'M015.stp').unlink()
        with self.assertRaises(p.GateError):p._public_tree_manifest(self.fixtures,self.fixture_files)

    def test_unexpected_directory_is_fail_closed(self):
        (self.runtime/'extra').mkdir()
        with self.assertRaises(p.GateError):
            p._public_tree_manifest(self.runtime,self.runtime_files,('bin/step-g',))

    def test_invalid_manifest_relative_paths_fail_closed(self):
        digest=next(iter(self.fixture_files.values()))
        for bad in ('../escape','/absolute','two//slashes','./x','x/../y','x\\y','x\ny',''):
            with self.subTest(bad=bad),self.assertRaises(p.GateError):
                p._public_tree_manifest(self.fixtures,{bad:digest})

    def test_incorrect_digest_is_fail_closed_before_permission_change(self):
        with self.assertRaises(p.GateError):
            p._public_tree_manifest(self.fixtures,{**self.fixture_files,'M015.stp':'0'*64})
        self.assertEqual(self.fixtures.stat().st_mode & 0o777,0o700)

    def test_chmod_error_is_fail_closed(self):
        original=pathlib.Path.chmod
        def failed(node,mode,*args,**kwargs):
            if node==self.fixtures:raise PermissionError('injected chmod failure')
            return original(node,mode,*args,**kwargs)
        with mock.patch.object(pathlib.Path,'chmod',autospec=True,side_effect=failed):
            with self.assertRaises(p.GateError):p._public_tree_manifest(self.fixtures,self.fixture_files)

    def test_silent_chmod_noop_yields_mode_mismatch_hold(self):
        with mock.patch.object(pathlib.Path,'chmod',return_value=None):
            with self.assertRaises(p.GateError):p._public_tree_manifest(self.fixtures,self.fixture_files)

    def test_post_chmod_binary_mutation_is_fail_closed(self):
        target=self.runtime/'bin/step-g'
        original=pathlib.Path.chmod
        def corrupt(node,mode,*args,**kwargs):
            result=original(node,mode,*args,**kwargs)
            if node==target:target.write_bytes(b'corrupted synthetic bytes')
            return result
        with mock.patch.object(pathlib.Path,'chmod',autospec=True,side_effect=corrupt):
            with self.assertRaises(p.GateError):
                p._public_tree_manifest(self.runtime,self.runtime_files,('bin/step-g',))

    def test_read_gate_in_unchanged_unprivileged_ABI_shell_before_hash_and_loader(self):
        s=p.ABI_SHELL
        self.assertIn('/fixtures/base_attachment.step',s)
        self.assertIn('/fixtures/M015.stp',s)
        self.assertIn('test -r "$public_file" || exit 83',s)
        self.assertLess(s.index('test -r "$public_file"'),s.index('sha256sum /runtime/bin/step-g'))
        self.assertLess(s.index('test -r "$public_file"'),s.index('LD_DEBUG=libs,versions'))
        self.assertNotIn('step-g --schema',s)
        self.assertNotIn(' --user 0',s)

    def test_exact_frozen_security_sources_remain_preserved(self):
        self.assertEqual(len(p.verify_control_source(R)),10)
        self.assertEqual(p.CONTROL_COMMIT,'e25c46a1967fbca64948449d3fe027b657472f15')

if __name__=='__main__':unittest.main()
