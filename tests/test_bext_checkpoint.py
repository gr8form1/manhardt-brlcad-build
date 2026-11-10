"""Offline staged-checkpoint tests; no native build or network needed."""
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

CI = pathlib.Path(__file__).resolve().parents[1] / 'ci'
sys.path.insert(0, str(CI))
import bext_checkpoint as cp


class BextCheckpoint(unittest.TestCase):
    def fixture(self, root):
        prefix = root/'private'/'bext-output'
        (prefix/'install'/'lib').mkdir(parents=True)
        (prefix/'noinstall').mkdir()
        (prefix/'install'/'lib'/'libtest.so').write_bytes(b'known public bytes')
        (prefix/'install'/'lib'/'link.so').symlink_to('libtest.so')
        (prefix/'noinstall'/'receipt').write_text('test')
        (prefix/'bext-install-manifest.json').write_text('{"files":[]}')
        return prefix

    def test_transfer_replays_exact_file_and_symlink_inventory(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d); prefix=self.fixture(root); stage=root/'stage'
            with patch.object(cp, 'fingerprint', return_value={'runner':'locked'}):
                result=cp.create_checkpoint(prefix,stage,{},root,root)
                original=cp.inventory(prefix)
                self.assertEqual(result['member_count'],len(original))
                shutil.rmtree(prefix)
                restored=cp.restore_checkpoint(stage,prefix,{},root,root)
                self.assertEqual(restored['member_count'],len(original))
                self.assertEqual(cp.inventory(prefix),original)
                shutil.rmtree(prefix)
                with (stage/cp.ARCHIVE).open('ab') as f: f.write(b'tampered')
                with self.assertRaisesRegex(RuntimeError, 'integrity failure'):
                    cp.restore_checkpoint(stage,prefix,{},root,root)

    def test_different_runner_fingerprint_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);prefix=self.fixture(root);stage=root/'stage'
            with patch.object(cp,'fingerprint',return_value={'abi':'A'}):
                cp.create_checkpoint(prefix,stage,{},root,root)
            shutil.rmtree(prefix)
            with patch.object(cp,'fingerprint',return_value={'abi':'B'}):
                with self.assertRaisesRegex(RuntimeError,'compiler mismatch'):
                    cp.restore_checkpoint(stage,prefix,{},root,root)

    def test_absolute_and_escaping_symlinks_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);prefix=self.fixture(root)
            link=prefix/'install'/'lib'/'bad'
            link.symlink_to('/etc/passwd')
            with self.assertRaisesRegex(RuntimeError,'Absolute dependency symlink'):
                cp.inventory(prefix)
            link.unlink()
            link.symlink_to('../../../../../../etc/passwd')
            with self.assertRaisesRegex(Exception,''):
                cp.inventory(prefix)


if __name__=='__main__':
    unittest.main()
