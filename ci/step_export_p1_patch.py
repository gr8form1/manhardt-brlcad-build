"""Source-locked, bounded P1 exporter correction; does not execute at import.

This alters only two files in a checkout of the pre-authorized BRL-CAD pin.
The upstream commit is not changed; the complete diff and hashes are evidence.
"""
import hashlib
from pathlib import Path
import subprocess

PIN = "bc130e1e7a9f179fe95fb42cde1a7d3becb512df"
PRODUCT = "src/conv/step/STEPProductExport.cpp"
ASSEMBLY = "src/conv/step/g-step/Assembly_Product.cpp"


def _replace_once(text, before, after, label):
    if text.count(before) != 1 or after in text:
        raise RuntimeError("P1 source anchor mismatch: " + label)
    return text.replace(before, after, 1)


def plan_edits(product_source, assembly_source):
    """Pure transformation; fail closed on unknown or previously patched source."""
    product = _replace_once(
        product_source,
        '    brlcad::step::SetString(prod_def_context, "life_cycle_stage", "\'part definition\'");',
        '    brlcad::step::SetString(prod_def_context, "life_cycle_stage", "\'part definition\'");\n'
        '    brlcad::step::SetString(prod_def_context, "name", "design");',
        "required product-definition context name")
    product = _replace_once(
        product,
        '    brlcad::step::SetString(product_context, "name", "\'\'");',
        '    brlcad::step::SetString(product_context, "name", "\'\'");\n'
        '    brlcad::step::SetString(product_context, "discipline_type", "mechanical");',
        "required product-context discipline type")
    anchor = 'static bool\nemit_representation_membership(struct directory *parent_dp,'
    helper = '''/* A source STEP placement may contain IEEE-754 negative zeros.  The
 * bytewise bn_mat_is_identity() rejects those even though -0.0 == +0.0.
 * Use exact numerical equality here: this removes signed-zero differences
 * without hiding any nonzero translation, rotation, or scale.  Do not
 * change emit_occurrence() or its legitimate NAUO/CDSR transformations. */
static bool
identity_numeric_strict(const matp_t matrix)
{
    if (!matrix) return true;
    for (size_t i = 0; i < 16; ++i)
        if (matrix[i] != bn_mat_identity[i]) return false;
    return true;
}

'''
    assembly = _replace_once(assembly_source, anchor, helper + anchor,
                             "membership-only identity comparator")
    assembly = _replace_once(
        assembly,
        '    if (!node->tr_l.tl_mat || bn_mat_is_identity(node->tr_l.tl_mat))\n'
        '\treturn Add_Shape_Representation_Relationship(sc, parent_shape,',
        '    if (identity_numeric_strict(node->tr_l.tl_mat))\n'
        '\treturn Add_Shape_Representation_Relationship(sc, parent_shape,',
        "membership-only relationship dispatch")
    # Prevent an overbroad fix from weakening assembly placement semantics.
    for token in ('emit_occurrence(', 'NEXT_ASSEMBLY_USAGE_OCCURRENCE',
                  'CONTEXT_DEPENDENT_SHAPE_REPRESENTATION',
                  'return Build_Representation_Relationship(transformation,'):
        if token not in assembly or token not in assembly_source:
            raise RuntimeError("P1 assembly guard failed: " + token)
    return {PRODUCT: product, ASSEMBLY: assembly}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def apply_source_patch(root, expected_pin=PIN):
    """Validate all targets before changing any file; report both hashes."""
    root = Path(root).resolve()

    def git(*args):
        return subprocess.check_output(
            ['git', '-C', str(root), *args], text=True).strip()

    if expected_pin != PIN or git('rev-parse', 'HEAD') != PIN:
        raise RuntimeError('P1 rejects an unapproved BRL-CAD source pin')
    if git('status', '--porcelain=v1', '--untracked-files=no'):
        raise RuntimeError('P1 rejects a dirty tracked source checkout')
    paths = (PRODUCT, ASSEMBLY)
    inputs = {p: (root / p).read_bytes() for p in paths}
    try:
        decoded = {p: inputs[p].decode('utf-8') for p in paths}
        outputs = plan_edits(decoded[PRODUCT], decoded[ASSEMBLY])
        result = {p: outputs[p].encode('utf-8') for p in paths}
    except (UnicodeDecodeError, OSError) as exc:
        raise RuntimeError('P1 source decoding failed') from exc
    for p in paths:
        if inputs[p] == result[p]:
            raise RuntimeError('P1 produced an unchanged file: ' + p)
    for p in paths:
        (root / p).write_bytes(result[p])
    changed = set(git('diff', '--name-only').splitlines())
    if changed != set(paths):
        raise RuntimeError('P1 unexpected source diff: ' + repr(sorted(changed)))
    subprocess.run(['git', '-C', str(root), 'diff', '--check'], check=True)
    return {
        'schema': 'MANHARDT_ADR001_STEP_EXPORT_P1/1',
        'disposition': 'SOURCE_PATCH_CANDIDATE_NOT_NATIVE_QUALIFIED',
        'upstream_commit': PIN,
        'changes': [{'path': p,
                     'original_sha256': sha256(inputs[p]),
                     'patched_sha256': sha256(result[p])} for p in paths],
        'nonclaims': ['OCCT readback qualification', 'assembly placement fidelity',
                      'OEM CAD fidelity', 'Lenovo release'],
    }
