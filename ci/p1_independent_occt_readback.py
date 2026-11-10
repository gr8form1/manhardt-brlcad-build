"""Independent STEP readback gate for P1 public box and cylinder fixtures.

Requires OCP 7.9.3.1, a locally supplied BRL-CAD runtime and the public
OCCT STEP fixtures. Does not run or acquire anything at import time. Never
writes input files; all conversion output is isolated in a temporary folder.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import tempfile

REQUIRED = ('box', 'cylinder')
FIXTURE_FILES = {'box': 'occt_public_box_10.step',
                 'cylinder': 'occt_public_cylinder_R5_H10.step'}
# Authenticated independent public AP214 controls, not arbitrary user STEP inputs.
FIXTURE_SHA256 = {
    'box': '060a3083dd822f274a56d77b8e9b3e5c5a2e1bf9088b679793fce4c74f07aa16',
    'cylinder': 'ab86afbd3038ee2221d16ce39cbbbfa9d3a9f23478d76d969088cce73bd17f12',
}
EXPECTED = {'box': {'faces': 6, 'volume_mm3': 1000.0,
                    'bounds_mm': (-5.0, -5.0, -5.0, 5.0, 5.0, 5.0),
                    'centroid_mm': (0.0, 0.0, 0.0)},
            'cylinder': {'faces': 3, 'volume_mm3': math.pi * 25.0 * 10.0,
                         'bounds_mm': (-5.0, -5.0, 0.0, 5.0, 5.0, 10.0),
                         'centroid_mm': (0.0, 0.0, 5.0)}}
VOLUME_RELATIVE_LIMIT = 5e-5  # 0.005%, screened public fixtures only
PLACEMENT_ABSOLUTE_LIMIT_MM = 0.001  # Bounded fixture screen, not manufacturing tolerance


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def readback(path, label):
    """Independent OCCT shape transfer and adaptive closed-volume test."""
    from OCP.STEPControl import STEPControl_Reader
    from OCP.IFSelect import IFSelect_RetDone
    from OCP.TopExp import TopExp_Explorer
    from OCP.TopAbs import TopAbs_SOLID, TopAbs_FACE
    from OCP.BRepCheck import BRepCheck_Analyzer
    from OCP.BRepGProp import BRepGProp
    from OCP.GProp import GProp_GProps
    from OCP.BRepBndLib import BRepBndLib
    from OCP.Bnd import Bnd_Box
    import OCP
    if getattr(OCP, '__version__', None) != '7.9.3.1':
        raise RuntimeError(f'{label}: OCP 7.9.3.1 required for the registered readback')

    source = Path(path)
    step_text = source.read_text(errors='replace')
    if "PRODUCT_DEFINITION_CONTEXT('design'," not in step_text:
        raise RuntimeError(f'{label}: required product-definition name absent')
    if not re.search(r"PRODUCT_CONTEXT\('[^']*',#[0-9]+,'mechanical'\)", step_text):
        raise RuntimeError(f'{label}: required product discipline absent')
    if 'REPRESENTATION_RELATIONSHIP_WITH_TRANSFORMATION' in step_text:
        raise RuntimeError(f'{label}: unqualified transforming representation relationship')

    reader = STEPControl_Reader()
    if reader.ReadFile(str(source)) != IFSelect_RetDone:
        raise RuntimeError(f'{label}: independent STEP load failed')
    transferred = reader.TransferRoots()
    if transferred != 1:
        raise RuntimeError(f'{label}: independent root-transfer count {transferred}, expected 1')
    shape = reader.OneShape()

    def count_shapes(kind):
        e = TopExp_Explorer(shape, kind)
        count = 0
        while e.More():
            count += 1
            e.Next()
        return count

    solids = count_shapes(TopAbs_SOLID)
    faces = count_shapes(TopAbs_FACE)
    if (solids, faces) != (1, EXPECTED[label]['faces']):
        raise RuntimeError(f'{label}: topology mismatch: {solids} solids, {faces} faces')
    if not BRepCheck_Analyzer(shape).IsValid():
        raise RuntimeError(f'{label}: invalid independent B-rep')
    props = GProp_GProps()
    # The EPS float overload invokes adaptive 2D Gauss integration. Do not
    # use the bool-only overload, which has different integration semantics.
    estimated_error = BRepGProp.VolumeProperties_s(shape, props, 1e-6, True, False)
    volume = props.Mass()
    relative_error = abs(volume / EXPECTED[label]['volume_mm3'] - 1.0)
    bounds = Bnd_Box()
    BRepBndLib.AddOptimal_s(shape, bounds, False, False)
    measured_bounds = tuple(bounds.Get())
    center = props.CentreOfMass()
    measured_centroid = (center.X(), center.Y(), center.Z())
    if not all(math.isfinite(v) for v in measured_bounds + measured_centroid):
        raise RuntimeError(f'{label}: nonfinite position or bounds')
    bound_deviation = max(abs(a - b) for a, b in
                          zip(measured_bounds, EXPECTED[label]['bounds_mm']))
    center_deviation = max(abs(a - b) for a, b in
                           zip(measured_centroid, EXPECTED[label]['centroid_mm']))
    if bound_deviation > PLACEMENT_ABSOLUTE_LIMIT_MM or center_deviation > PLACEMENT_ABSOLUTE_LIMIT_MM:
        raise RuntimeError(f'{label}: nonconforming placement '
                           f'(bounds {bound_deviation} mm, centroid {center_deviation} mm)')
    if not math.isfinite(volume) or relative_error > VOLUME_RELATIVE_LIMIT:
        raise RuntimeError(f'{label}: adaptive-volume mismatch: {volume} mm3, rel {relative_error}')
    return {'status': 'INDEPENDENT_OCCT_PUBLIC_READBACK_PASS',
            'occt_solids': solids, 'occt_faces': faces, 'occt_brep_valid': True,
            'adaptive_volume_mm3': volume,
            'analytic_volume_mm3': EXPECTED[label]['volume_mm3'],
            'relative_volume_difference': relative_error,
            'bounds_mm': measured_bounds, 'centroid_mm': measured_centroid,
            'max_bound_deviation_mm': bound_deviation,
            'max_centroid_deviation_mm': center_deviation,
            'adaptive_integrator_estimated_relative_error': estimated_error,
            'source_sha256': sha256(source)}


def run_gate(runtime, fixture_dir):
    runtime, fixture_dir = Path(runtime).resolve(), Path(fixture_dir).resolve()
    if not (runtime / 'bin/step-g').is_file() or not (runtime / 'bin/g-step').is_file():
        raise RuntimeError('Required native BRL-CAD runtime executables missing')
    if not all((fixture_dir / name).is_file() for name in FIXTURE_FILES.values()):
        raise RuntimeError('Required original public STEP fixture missing')
    if not (runtime / 'lib').is_dir():
        raise RuntimeError('Required native BRL-CAD runtime library directory missing')
    # Avoid accidentally loading unrelated system BRL-CAD libraries.
    env = dict(os.environ, BRLCAD_ROOT=str(runtime), LD_LIBRARY_PATH=str(runtime / 'lib'))
    result = {'schema': 'MANHARDT_ADR001_P1_INDEPENDENT_OCCT_READBACK/1',
              'status': 'HOLD_UNTIL_ALL_CONTROLS_PASS', 'fixtures': {}}
    with tempfile.TemporaryDirectory(prefix='manhardt-p1-readback-') as tmp:
        root = Path(tmp)
        for label in REQUIRED:
            input_step = fixture_dir / FIXTURE_FILES[label]
            if sha256(input_step) != FIXTURE_SHA256[label]:
                raise RuntimeError(f'{label}: public fixture source hash mismatch')
            database = root / (label + '.g')
            output_step = root / (label + '-roundtrip.step')
            imported_report = root / (label + '-import.json')
            export_report = root / (label + '-export.json')
            subprocess.run([str(runtime / 'bin/step-g'), '--strict', '--repair', 'safe',
                            '--report', str(imported_report), '-o', str(database), str(input_step)],
                           check=True, env=env, timeout=120, capture_output=True)
            data = json.loads(imported_report.read_text())
            if (data.get('exit_status') != 0 or
                    data.get('coverage', {}).get('outcome') != 'complete' or
                    data.get('coverage', {}).get('geometry_skipped') != 0 or
                    data.get('validation', {}).get('invalid_breps') != 0 or
                    data.get('validation', {}).get('output_failures') != 0):
                raise RuntimeError(f'{label}: native import coverage incomplete')
            subprocess.run([str(runtime / 'bin/g-step'), '--strict', '--schema', 'ap242e4',
                            '--output-units', 'mm', '--angle-units', 'radian',
                            '--report', str(export_report), '-o', str(output_step), str(database)],
                           check=True, env=env, timeout=120, capture_output=True)
            report = json.loads(export_report.read_text())
            if report.get('exit_status') != 0 or report.get('coverage', {}).get('outcome') != 'complete':
                raise RuntimeError(f'{label}: native export coverage incomplete')
            checked = readback(output_step, label)
            checked['original_fixture_sha256'] = sha256(input_step)
            checked['safe_import_repairs'] = data.get('validation', {}).get('repairs')
            result['fixtures'][label] = checked
    result['status'] = 'PUBLIC_OCCT_READBACK_PASS_CANDIDATE'
    result['nonclaims'] = ['transformed assemblies', 'general curved geometry',
                           'SPK16/C16 fidelity', 'Lenovo deployment', 'manufacturing']
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    verdict = run_gate(args.runtime, args.fixtures)
    result_text = json.dumps(verdict, indent=2, sort_keys=True) + '\n'
    if args.report:
        if args.report.exists():
            raise SystemExit('Refusing to overwrite an existing report')
        args.report.write_text(result_text)
    print(result_text)
