"""Offline helper tests. No source build, loader, patchelf or geometry execution."""
import contextlib
import gzip
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

CI = Path(__file__).resolve().parents[1] / 'ci'
sys.path.insert(0, str(CI))
import common
import bundle
import build


def synthetic_elf(path, code=b'\x90\xc3', machine=62):
    # Static parser fixture, no program headers and never executable.
    names = b'\0.shstrtab\0.text\0.rodata\0'
    ident = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    sections_offset = 128
    names_offset = sections_offset + 4 * 64
    text_offset = names_offset + len(names)
    rodata_offset = text_offset + len(code)
    eh = struct.pack('<16sHHIQQQIHHHHHH', ident, 3, machine, 1, 0, 0,
                     sections_offset, 0, 64, 0, 0, 64, 4, 1)
    headers = [b'\0' * 64,
               struct.pack('<IIQQQQIIQQ', 1, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0),
               struct.pack('<IIQQQQIIQQ', 11, 1, 6, 0, text_offset, len(code), 0, 0, 1, 0),
               struct.pack('<IIQQQQIIQQ', 17, 1, 2, 0, rodata_offset, 3, 0, 0, 1, 0)]
    path.write_bytes(eh + b'\0' * (128 - len(eh)) + b''.join(headers) + names + code + b'abc')


def payload(root):
    for rel, data, mode in [('bin/step-g', b'SYNTHETIC NOT A WORKING EXECUTABLE', 0o755),
                             ('lib/libbu.so.20', b'synthetic library', 0o644),
                             ('libexec/step/example-ap242e2.so', b'synthetic plugin', 0o644),
                             ('metadata/test.json', b'{"synthetic":true}', 0o644),
                             ('licenses/notice', b'synthetic notice', 0o644)]:
        p = root / rel;p.parent.mkdir(parents=True, exist_ok=True);p.write_bytes(data);p.chmod(mode)


class Helpers(unittest.TestCase):
    def test_01_environment_no_tokens_or_loader_overrides(self):
        env = common.clean_environment('/tmp/home', '/tmp/temp')
        self.assertEqual(env['CMAKE_BUILD_PARALLEL_LEVEL'], '1')
        self.assertEqual(env['MAKEFLAGS'], '-j1')
        self.assertFalse(any(x.startswith(('GITHUB_', 'ACTIONS_', 'LD_')) for x in env))
        self.assertNotIn('native', env['CFLAGS'])

    def test_02_needed_parser(self):
        self.assertEqual(common.needed_from_readelf(' 0x1 (NEEDED) Shared library: [libbu.so.20]\n'), ['libbu.so.20'])

    def test_03_loader_map(self):
        m = common.ldd_map(' linux-vdso.so.1 (0x1)\n libm.so.6 => /lib/libm.so.6 (0x2)\n')
        self.assertEqual(set(m), {'libm.so.6'})

    def test_04_missing_library(self):
        with self.assertRaises(ValueError): common.ldd_map(' libbad.so => not found\n')

    def test_05_unknown_loader_format(self):
        with self.assertRaises(ValueError): common.ldd_map(' libbad.so => relative/file (0x1)\n')

    def test_06_elf_code_sections(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'fixture';synthetic_elf(p)
            value = common.elf_code_sections(p)
            self.assertEqual(value['.text'], hashlib.sha256(b'\x90\xc3').hexdigest())
            self.assertEqual(value['.rodata'], hashlib.sha256(b'abc').hexdigest())

    def test_07_elf_reject_wrong_architecture(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'fixture';synthetic_elf(p, machine=183)
            with self.assertRaises(ValueError): common.elf_code_sections(p)

    def test_08_elf_reject_non_elf(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'fixture';p.write_bytes(b'not an ELF')
            with self.assertRaises(ValueError): common.elf_code_sections(p)

    def test_09_code_change_is_observable(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / 'a', Path(d) / 'b';synthetic_elf(a);synthetic_elf(b, b'\xcc\xc3')
            self.assertNotEqual(common.elf_code_sections(a), common.elf_code_sections(b))

    def test_10_tar_modes_and_census(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / 'root';root.mkdir();payload(root)
            output = Path(d) / 'runtime.tar.gz'
            result = bundle.make_tar(root, output, 'a' * 40)
            self.assertEqual(result['sha256'], common.sha256(output))
            with tarfile.open(output) as tf:
                members = tf.getmembers()
                self.assertTrue(all(x.isfile() and not x.pax_headers for x in members))
                self.assertEqual(tf.getmember('brlcad-runtime/bin/step-g').mode, 0o755)
                self.assertEqual(tf.getmember('brlcad-runtime/lib/libbu.so.20').mode, 0o644)
                manifest = json.load(tf.extractfile('brlcad-runtime/MANIFEST.json'))
                self.assertEqual(manifest['schema'], 'ADR001_RUNTIME_CONTENTS/2')
                for line in tf.extractfile('brlcad-runtime/SHA256SUMS').read().decode().splitlines():
                    h, n = line.split('  ', 1)
                    self.assertEqual(hashlib.sha256(tf.extractfile('brlcad-runtime/' + n).read()).hexdigest(), h)

    def test_11_tar_deterministic_from_equal_fresh_payloads(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / 'a', Path(d) / 'b';a.mkdir();b.mkdir();payload(a);payload(b)
            x, y = Path(d) / 'x.gz', Path(d) / 'y.gz'
            bundle.make_tar(a, x, 'a' * 40);bundle.make_tar(b, y, 'a' * 40)
            self.assertEqual(x.read_bytes(), y.read_bytes())

    def test_12_sealed_tree_is_not_reused(self):
        with tempfile.TemporaryDirectory() as d:
            r = Path(d) / 'r';r.mkdir();payload(r)
            bundle.make_tar(r, Path(d) / 'one.gz', 'a' * 40)
            with self.assertRaises(RuntimeError): bundle.make_tar(r, Path(d) / 'two.gz', 'a' * 40)

    def test_13_symlink_payload_refused(self):
        with tempfile.TemporaryDirectory() as d:
            r = Path(d) / 'r';r.mkdir();payload(r);(r / 'lib/link').symlink_to('libbu.so.20')
            with self.assertRaises(RuntimeError): bundle.make_tar(r, Path(d) / 'out.gz', 'a' * 40)

    def test_14_hidden_trees_restore_after_failure(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'build';p.mkdir()
            with self.assertRaises(ValueError):
                with bundle.hidden_build_trees([p]):
                    self.assertFalse(p.exists());raise ValueError('test failure')
            self.assertTrue(p.is_dir())

    def test_15_file_api_actual_parser(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d);reply = p / '.cmake/api/v1/reply';reply.mkdir(parents=True)
            (reply / 'index-test.json').write_text(json.dumps({'objects': [{'kind': 'codemodel', 'jsonFile': 'model.json'}]}))
            (reply / 'model.json').write_text(json.dumps({'configurations': [{'targets': [{'name': 'step-g', 'jsonFile': 'target.json'}]}]}))
            (reply / 'target.json').write_text(json.dumps({'artifacts': [{'path': 'bin/step-g'}]}))
            self.assertEqual(build.target_artifacts(p)['step-g'], [p / 'bin/step-g'])

    def test_16_command_failure_is_not_hidden_by_stdout(self):
        with tempfile.TemporaryDirectory() as d:
            r = common.Recorder(Path(d), dict(__import__('os').environ))
            with self.assertRaises(RuntimeError):
                r.run([sys.executable, '-c', "print('plausible success');raise SystemExit(7)"])
            self.assertEqual(r.records[0]['exit_status'], 7)
            self.assertIn('plausible success', (Path(d) / '0001.stdout').read_text())

    def test_17_no_local_build_from_import(self):
        self.assertTrue(callable(build.main))
        self.assertFalse((Path(__file__).resolve().parents[1] / 'out').exists())

    def test_18_stock_logs_collected_without_collecting_objects(self):
        with tempfile.TemporaryDirectory() as d:
            attempt = Path(d) / 'attempt';metadata = Path(d) / 'metadata'
            root = attempt / 'build/bext'
            root.mkdir(parents=True)
            (root / 'CMakeCache.txt').write_text('SELECTED=system')
            (root / 'dependency-build-out.log').write_text('raw output')
            (root / 'irrelevant.o').write_bytes(b'not evidence')
            build.collect_build_evidence(attempt, metadata)
            rows = json.loads((metadata / 'stock-build-records.json').read_text())
            self.assertEqual({r['path'] for r in rows},
                             {'CMakeCache.txt', 'dependency-build-out.log'})
            self.assertEqual((metadata / 'stock-build-records/bext/dependency-build-out.log').read_text(),
                             'raw output')

    def test_19_accidental_local_main_refuses_before_acquisition(self):
        with patch.dict(__import__('os').environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, 'GitHub execution only'):
                build.main()
        self.assertFalse((Path(__file__).resolve().parents[1] / 'out').exists())


if __name__ == '__main__': unittest.main(verbosity=2)
