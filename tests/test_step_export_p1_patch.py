"""Offline unit tests for the source-locked BRL-CAD exporter P1 correction.

These test source transforms and fail-closed invariants, not native STEP fidelity.
"""
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ci'))
from step_export_p1_patch import plan_edits, PRODUCT, ASSEMBLY

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

    def test_signed_zero_is_bitwise_distinct_but_numerically_equal(self):
        self.assertNotEqual(struct.pack('=d', -0.0), struct.pack('=d', 0.0))
        self.assertEqual(-0.0, 0.0)
        self.assertNotEqual(1.0e-300, 0.0)
        self.assertNotEqual(1.0 + 1.0e-10, 1.0)


if __name__ == '__main__':
    unittest.main()
