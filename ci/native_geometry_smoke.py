"""Native public tetrahedron I/O checks, never private product qualification."""
import hashlib
import json
import math
from pathlib import Path
import re

from common import sha256, write_json


def check_tetrahedron_step(path):
    """Independent numeric reader for this four-vertex, millimetre fixture only."""
    text = Path(path).read_text()
    if not re.search(r'SI_UNIT\s*\(\s*\.MILLI\.\s*,\s*\.METRE\.\s*\)', text):
        raise RuntimeError('Exported tetrahedron does not declare millimetres')
    records = {int(k): v.strip() for k, v in
               re.findall(r'#(\d+)\s*=\s*(.*?);', text, re.S)}
    count = lambda kind: sum(v.startswith(kind + '(') for v in records.values())
    for kind, expected in [('MANIFOLD_SOLID_BREP', 1), ('ADVANCED_FACE', 4),
                           ('EDGE_CURVE', 6), ('VERTEX_POINT', 4)]:
        if count(kind) != expected:
            raise RuntimeError(f'Tetrahedron {kind} count differs from {expected}')
    points = []
    for value in records.values():
        if not value.startswith('VERTEX_POINT('):
            continue
        refs = re.findall(r'#(\d+)', value)
        if len(refs) != 1:
            raise RuntimeError('Ambiguous tetrahedron vertex')
        record = records[int(refs[0])]
        match = re.fullmatch(r"CARTESIAN_POINT\('[^']*',\s*\(([^()]*)\)\)", record)
        if not match:
            raise RuntimeError('Unsupported tetrahedron point representation')
        xyz = tuple(float(v.replace('D', 'E')) for v in match[1].split(','))
        if len(xyz) != 3 or not all(math.isfinite(v) for v in xyz):
            raise RuntimeError('Non-finite tetrahedron coordinate')
        points.append(xyz)
    expected = [(0., 0., 0.), (10., 0., 0.), (0., 10., 0.), (0., 0., 10.)]
    if any(min(math.dist(a, b) for b in points) > 1e-5 for a in expected):
        raise RuntimeError('Exported tetrahedron vertices differ from analytic input')
    a, b, c = [tuple(points[i][j] - points[0][j] for j in range(3))
               for i in (1, 2, 3)]
    volume = abs(a[0]*(b[1]*c[2]-b[2]*c[1]) -
                 a[1]*(b[0]*c[2]-b[2]*c[0]) +
                 a[2]*(b[0]*c[1]-b[1]*c[0])) / 6
    if abs(volume - 1000/6) > 1e-3:
        raise RuntimeError('Exported tetrahedron volume differs from analytic input')
    return {'vertices_mm': points, 'tetrahedron_volume_mm3': volume,
            'scope': 'This public four-vertex fixture only; not curved CAD fidelity'}


def select_tetrahedron_top(output):
    """Require the one public geometry top, allowing STEP's non-drawable metadata.

    Metadata from tops -n is not suitable input for geometry/ray commands.
    """
    names = output.split()
    if len(names) != len(set(names)) or 'toolkit_tetra' not in names or \
            set(names) - {'toolkit_tetra', '_STEP_METADATA'}:
        raise RuntimeError('Unexpected native top-level geometry or metadata')
    return 'toolkit_tetra'


def check_tetrahedron_native_vertices(output):
    """Validate native B-rep vertices of the analytic four-plane tetrahedron.

    For this planar convex fixture, vertex extrema are exact geometry bounds.
    bb -e instead includes untrimmed surface extents and cannot be used as
    a one-micrometre trimmed-geometry acceptance check.
    """
    rows = re.findall(r'(?m)^m_V\[(\d+)\]:\s*([^\n]+)', output)
    if len(rows) != 4 or sorted(int(i) for i, _ in rows) != [0, 1, 2, 3]:
        raise RuntimeError('Native tetrahedron requires four indexed B-rep vertices')
    points = []
    for _index, value in rows:
        match = re.fullmatch(r'(\S+)\s+(\S+)\s+(\S+)\s+Used by\s+\d+\s+edges',
                             value.strip())
        if not match:
            raise RuntimeError('Invalid native B-rep vertex record')
        try:
            point = tuple(float(x.replace('D', 'E')) for x in match.groups())
        except ValueError as exc:
            raise RuntimeError('Nonnumeric native B-rep vertex') from exc
        if not all(math.isfinite(x) for x in point):
            raise RuntimeError('Nonfinite native B-rep vertex')
        points.append(point)
    expected = [(0., 0., 0.), (10., 0., 0.), (0., 10., 0.), (0., 0., 10.)]
    if any(sum(math.dist(point, ref) <= 1e-3 for point in points) != 1
           for ref in expected):
        raise RuntimeError('Native B-rep tetrahedron vertices differ from reference')
    a, b, c = [tuple(points[i][j] - points[0][j] for j in range(3))
               for i in (1, 2, 3)]
    volume = abs(a[0] * (b[1]*c[2] - b[2]*c[1])
                 - a[1] * (b[0]*c[2] - b[2]*c[0])
                 + a[2] * (b[0]*c[1] - b[1]*c[0])) / 6.
    if abs(volume - 1000. / 6.) > 1e-3:
        raise RuntimeError('Native B-rep tetrahedron volume differs from analytic fixture')
    bounds = [min(p[j] for p in points) for j in range(3)] + \
             [max(p[j] for p in points) for j in range(3)]
    return {'vertices_mm': points, 'vertex_aabb_mm': bounds,
            'vertex_determinant_volume_mm3': volume}


def check_tetrahedron_native_surfaces(output):
    """Reject any nonplanar surface in the public tetrahedron fixture."""
    rows = re.findall(r'(?m)^surface\[\s*(\d+)\]:\s*(\S+)', output)
    if len(rows) != 4 or sorted(int(i) for i, _ in rows) != [0, 1, 2, 3] or \
            any(kind != 'ON_PlaneSurface' for _, kind in rows):
        raise RuntimeError('Native fixture surfaces must be four planes')
    return 4



def verify_clean_tetrahedron_import_report(report, label):
    """Require a complete and unrepaired import of the public tetrahedron."""
    if (report.get('exit_status') != 0 or
            report.get('coverage', {}).get('outcome') != 'complete' or
            report.get('coverage', {}).get('geometry_written') != 1 or
            report.get('coverage', {}).get('geometry_skipped') != 0 or
            report.get('validation', {}).get('invalid_breps') != 0 or
            report.get('validation', {}).get('repairs') != 0 or
            report.get('validation', {}).get('inferred_curves') != 0):
        raise RuntimeError(f'{label}: public tetrahedron did not import completely without repair')
    return {
        'exit_status': report['exit_status'],
        'coverage': report['coverage']['outcome'],
        'geometry_written': report['coverage']['geometry_written'],
        'repairs': report['validation']['repairs'],
        'invalid_breps': report['validation']['invalid_breps'],
    }


def run_smoke(rec, runtime, brl_source, destination):
    runtime, brl_source, destination = map(Path, (runtime, brl_source, destination))
    destination.mkdir(parents=True, exist_ok=False)
    env = dict(rec.env, BRLCAD_ROOT=str(runtime.resolve()))
    template = brl_source / 'src/conv/step/tests/step_direct_advanced_brep.stp.in'
    text = template.read_text()
    substitutions = {'SCHEMA_LABEL': 'AP242e2', 'FILE_NAME': 'toolkit_tetra.step',
                     'SCHEMA': 'AP242_MANAGED_MODEL_BASED_3D_ENGINEERING_MIM_LF',
                     'SOLID_NAME': 'toolkit_tetra', 'TOLERANCE': '0.00001',
                     'APPLICATION': 'managed model based 3d engineering',
                     'PRODUCT_ID': 'toolkit_tetra', 'PRODUCT_NAME': 'toolkit_tetra',
                     'ASSOCIATION': 'SHAPE_DEFINITION_REPRESENTATION'}
    for key, value in substitutions.items():
        text = text.replace('@' + key + '@', value)
    if re.search(r'@[A-Z_]+@', text):
        raise RuntimeError('Unresolved upstream fixture template field')
    step = destination / 'tetra.step'; step.write_text(text)
    check_tetrahedron_step(step)
    database = destination / 'tetra.g'
    report = destination / 'import.json'
    def run(argv):
        return rec.run(['timeout', '-k', '5s', '90s'] + list(argv),
                       cwd=destination, env=env)
    run([runtime/'bin/step-g', '--strict', '--schema', 'ap242e2',
         '--report', report, '-o', database, step])
    r = json.loads(report.read_text())
    if r.get('exit_status') != 0 or r['coverage'].get('outcome') != 'complete' or \
            r['coverage'].get('geometry_written') != 1 or \
            r['coverage'].get('geometry_skipped') != 0 or \
            r['validation'].get('invalid_breps') != 0:
        raise RuntimeError('Native tetrahedron import did not complete cleanly')
    original_db_hash = sha256(database)
    top_text = run([runtime/'bin/gsh', database, 'tops', '-n'])
    selected_top = select_tetrahedron_top(top_text)
    primitives=run([runtime/'bin/gsh',database,'search','.','-type','brep']).split()
    if len(primitives)!=1 or not re.fullmatch(r'[A-Za-z0-9_.-]+',primitives[0]):
        raise RuntimeError('Public fixture must contain exactly one inspectable B-rep')
    validity=run([runtime/'bin/gsh',database,'brep',primitives[0],'valid'])
    if 'brep is valid' not in validity or 'NOT valid' in validity:
        raise RuntimeError('Native B-rep validation did not confirm validity')
    solidity=run([runtime/'bin/gsh',database,'brep',primitives[0],'solid'])
    if 'brep is solid' not in solidity or 'NOT solid' in solidity:
        raise RuntimeError('Native B-rep readback did not confirm solidness')
    # Validate the native B-rep's four vertices and planar surfaces.
    # bb -e is NOT a tight trimmed-B-rep AABB for this analytic fixture.
    vertices = run([runtime/'bin/gsh',database,'brep',primitives[0],'info','V'])
    native = check_tetrahedron_native_vertices(vertices)
    surfaces = run([runtime/'bin/gsh',database,'brep',primitives[0],'info','S'])
    plane_count = check_tetrahedron_native_surfaces(surfaces)
    if sha256(database) != original_db_hash:
        raise RuntimeError('Database inspection changed the input database bytes')
    exported = destination / 'roundtrip.step'
    run([runtime/'bin/g-step', '--strict', '--schema', 'ap242e2',
         '--output-units', 'mm', '--angle-units', 'radian',
         '--report', destination/'export.json', '-o', exported, database])
    independent = check_tetrahedron_step(exported)
    run([runtime/'bin/step-g', '-D', '--strict', '--schema', 'ap242e2',
         '--report', destination/'reimport.json', exported])
    rr = json.loads((destination/'reimport.json').read_text())
    if rr.get('exit_status') != 0 or rr['coverage'].get('outcome') != 'complete' or \
            rr['coverage'].get('geometry_written') != 1 or \
            rr['coverage'].get('geometry_skipped') != 0:
        raise RuntimeError('Exported tetrahedron did not reimport completely')
    result = {'status': 'PUBLIC_TETRAHEDRON_IO_PASS', 'source_template_sha256': sha256(template),
              'input_sha256': sha256(step), 'database_sha256': original_db_hash,
              'export_sha256': sha256(exported), 'native_vertex_geometry': native,
              'native_plane_surface_count':plane_count, 'native_geometric_top': selected_top,
              'native_brep_object':primitives[0], 'native_brep_valid_and_solid':True,
              'independent_export_check': independent,
              'nonclaims': ['SPK16 geometry fidelity', 'unchanged-source validity',
                           'curved-surface accuracy', 'acoustic qualification']}
    # AP242 editions share the long-form FILE_SCHEMA identifier.  This is
    # therefore a public, explicitly selected e4 converter smoke test, NOT
    # evidence that FILE_SCHEMA alone identifies the OEM file's AP242 edition.
    e4_step = destination/'tetra-ap242e4.step'
    e4_step.write_text(text.replace('AP242e2', 'AP242e4').replace(
        'toolkit_tetra.step', 'tetra-ap242e4.step'))
    check_tetrahedron_step(e4_step)
    e4_db = destination/'tetra-ap242e4.g'
    e4_import_path = destination/'ap242e4-import.json'
    run([runtime/'bin/step-g', '--strict', '--repair', 'none',
         '--schema', 'ap242e4', '--report', e4_import_path,
         '-o', e4_db, e4_step])
    e4_import = verify_clean_tetrahedron_import_report(
        json.loads(e4_import_path.read_text()), 'Explicit AP242e4 import')
    e4_breps = run([runtime/'bin/gsh', e4_db, 'search', '.', '-type', 'brep']).split()
    if len(e4_breps) != 1 or not re.fullmatch(r'[A-Za-z0-9_.-]+', e4_breps[0]):
        raise RuntimeError('AP242e4 native import lacks exactly one B-rep')
    e4_valid = run([runtime/'bin/gsh', e4_db, 'brep', e4_breps[0], 'valid'])
    e4_solid = run([runtime/'bin/gsh', e4_db, 'brep', e4_breps[0], 'solid'])
    if 'brep is valid' not in e4_valid or 'brep is solid' not in e4_solid:
        raise RuntimeError('AP242e4 native B-rep validity or solidity missing')
    e4_native = check_tetrahedron_native_vertices(
        run([runtime/'bin/gsh', e4_db, 'brep', e4_breps[0], 'info', 'V']))
    e4_planes = check_tetrahedron_native_surfaces(
        run([runtime/'bin/gsh', e4_db, 'brep', e4_breps[0], 'info', 'S']))
    e4_export = destination/'tetra-ap242e4-roundtrip.step'
    run([runtime/'bin/g-step', '--strict', '--schema', 'ap242e4',
         '--output-units', 'mm', '--angle-units', 'radian',
         '--report', destination/'ap242e4-export.json', '-o', e4_export, e4_db])
    e4_independent = check_tetrahedron_step(e4_export)
    e4_reimport_path = destination/'ap242e4-reimport.json'
    run([runtime/'bin/step-g', '-D', '--strict', '--repair', 'none',
         '--schema', 'ap242e4', '--report', e4_reimport_path, e4_export])
    e4_reimport = verify_clean_tetrahedron_import_report(
        json.loads(e4_reimport_path.read_text()), 'Explicit AP242e4 reimport')
    # Exercise automatic edition choice without asserting which edition was
    # chosen: the STEP file's standard FILE_SCHEMA token is shared by editions.
    auto_report_path = destination/'ap242e4-auto-probe.json'
    run([runtime/'bin/step-g', '-D', '--strict', '--repair', 'none',
         '--report', auto_report_path, e4_step])
    auto_probe = verify_clean_tetrahedron_import_report(
        json.loads(auto_report_path.read_text()), 'Automatic AP242 import')
    result['ap242e4_schema_smoke'] = {
        'status': 'EXPLICIT_EDITION4_PUBLIC_TETRAHEDRON_PASS',
        'schema_edition': 'ap242e4',
        'input_sha256': sha256(e4_step),
        'native_database_sha256': sha256(e4_db),
        'export_sha256': sha256(e4_export),
        'import': e4_import, 'reimport': e4_reimport,
        'native_vertices_and_volume': e4_native,
        'native_plane_count': e4_planes,
        'independent_export_check': e4_independent,
        'automatic_selection_probe': auto_probe,
        'automatic_selected_edition': 'NOT_PROVEN_BY_PUBLIC_FILE_SCHEMA',
        'nonclaims': ['OEM AP242 edition identification',
                      'SPK16 or SEAS C16 geometry fidelity',
                      'curved-surface equivalence', 'acoustic qualification']
    }

    write_json(destination/'RESULT.json', result)
    return result
