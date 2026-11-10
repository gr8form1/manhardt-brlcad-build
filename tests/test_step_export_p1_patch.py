"""Offline unit tests for the source-locked BRL-CAD exporter P1 correction.

These test source transforms and fail-closed invariants, not native STEP fidelity.
"""
import struct
import sys
import unittest
import subprocess
import shutil
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ci'))
from step_export_p1_patch import plan_edits, PRODUCT, ASSEMBLY, IDENTITY_HELPER

PRODUCT_FIXTURE = '''    brlcad::step::SetString(prod_def_context, "life_cycle_stage", "'part definition'");
    brlcad::step::SetString(product_context, "name", "''");
'''
ASSEMBLY_FIXTURE = '''static bool
emit_representation_membership(struct directory *parent_dp,
    if (!node->tr_l.tl_mat || bn_mat_is_identity(node->tr_l.tl_mat))
\treturn Add_Shape_Representation_Relationship(sc, parent_shape,
emit_occurrence(
NEXT_ASSEMBLY_USAGE_OCCURRENCE
CONTEXT_DEPENDENT_SHAPE_REPRESENTATION
return Build_Representation_Relationship(transformation,
'''


class PatchUnitTests(unittest.TestCase):
    def test_only_membership_and_context_fields_change(self):
        files = plan_edits(PRODUCT_FIXTURE, ASSEMBLY_FIXTURE)
        self.assertEqual(set(files), {PRODUCT, ASSEMBLY})
        self.assertIn('"name", "design"', files[PRODUCT])
        self.assertIn('"discipline_type", "mechanical"', files[PRODUCT])
        self.assertIn('identity_numeric_strict(node->tr_l.tl_mat)', files[ASSEMBLY])
        self.assertIn('NEXT_ASSEMBLY_USAGE_OCCURRENCE', files[ASSEMBLY])
        self.assertIn('CONTEXT_DEPENDENT_SHAPE_REPRESENTATION', files[ASSEMBLY])
        self.assertIn('return Build_Representation_Relationship(transformation,', files[ASSEMBLY])
        self.assertNotIn('bn_mat_is_identity(node->tr_l.tl_mat)', files[ASSEMBLY])

    def test_reject_reapplying(self):
        files = plan_edits(PRODUCT_FIXTURE, ASSEMBLY_FIXTURE)
        with self.assertRaisesRegex(RuntimeError, 'anchor mismatch'):
            plan_edits(files[PRODUCT], files[ASSEMBLY])

    def test_reject_changed_source(self):
        with self.assertRaisesRegex(RuntimeError, 'anchor mismatch'):
            plan_edits(PRODUCT_FIXTURE.replace('life_cycle_stage', 'other'), ASSEMBLY_FIXTURE)
        with self.assertRaisesRegex(RuntimeError, 'anchor mismatch'):
            plan_edits(PRODUCT_FIXTURE, ASSEMBLY_FIXTURE.replace('bn_mat_is_identity', 'other'))

    def test_reject_duplicate_anchor(self):
        with self.assertRaisesRegex(RuntimeError, 'anchor mismatch'):
            plan_edits(PRODUCT_FIXTURE + PRODUCT_FIXTURE, ASSEMBLY_FIXTURE)

    def test_actual_cpp_helper_compiles_and_rejects_nonidentity(self):
        """Compile exactly the helper injected into upstream C++ source."""
        compiler = shutil.which('g++') or shutil.which('clang++')
        if compiler is None:
            self.fail('P1 preflight requires a C++ compiler for the identity gate')
        cpp = (
            '#include <cstddef>\n'
            '#include <limits>\n'
            'using matp_t = const double *;\n'
            'static const double bn_mat_identity[16] = '
            '{1,0,0,0, 0,1,0,0, 0,0,1,0, 0,0,0,1};\n'
            + IDENTITY_HELPER + '\n'
            'int main() {\n'
            '  double m[16] = {1,0,0,0, 0,1,0,0, 0,0,1,0, 0,0,0,1};\n'
            '  if (!identity_numeric_strict(m)) return 1;\n'
            '  m[1] = -0.0; m[8] = -0.0;\n'
            '  if (!identity_numeric_strict(m)) return 2;\n'
            '  m[2] = 1.0e-300;\n'
            '  if (identity_numeric_strict(m)) return 3;\n'
            '  m[2] = 0.0;\n'
            '  m[1] = std::numeric_limits<double>::quiet_NaN();\n'
            '  if (identity_numeric_strict(m)) return 4;\n'
            '  m[1] = 0.0; m[0] = std::numeric_limits<double>::infinity();\n'
            '  if (identity_numeric_strict(m)) return 5;\n'
            '  if (!identity_numeric_strict(nullptr)) return 6;\n'
            '  return 0;\n'
            '}\n')
        with tempfile.TemporaryDirectory(prefix='manhardt-p1-cpp-test-') as root:
            file = Path(root) / 'identity_test.cpp'
            binary = Path(root) / 'identity_test'
            file.write_text(cpp)
            subprocess.run([compiler, '-std=c++11', '-O2', '-Wall', '-Wextra',
                            '-Werror', '-pedantic', str(file), '-o', str(binary)],
                           check=True, capture_output=True, timeout=60)
            subprocess.run([str(binary)], check=True, capture_output=True, timeout=10)

    def test_signed_zero_is_bitwise_distinct_but_numerically_equal(self):
        self.assertNotEqual(struct.pack('=d', -0.0), struct.pack('=d', 0.0))
        self.assertEqual(-0.0, 0.0)
        self.assertNotEqual(1.0e-300, 0.0)
        self.assertNotEqual(1.0 + 1.0e-10, 1.0)


if __name__ == '__main__':
    unittest.main()
