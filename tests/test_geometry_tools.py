"""Offline toolkit closure and analytic-reference checks; no native CAD claim."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

CI=Path(__file__).resolve().parents[1]/'ci';sys.path.insert(0,str(CI))
import geometry_profile as profile
import native_geometry_smoke as smoke
import build_geometry_tools


def fixture():
    points=['(0.,0.,0.)','(10.,0.,0.)','(0.,10.,0.)','(0.,0.,10.)']
    s='ISO-10303-21;DATA;\n'
    for i,p in enumerate(points,1):s+=f"#{i}=CARTESIAN_POINT('',{p});\n"
    for i in range(1,5):s+=f"#{i+4}=VERTEX_POINT('',#{i});\n"
    for i in range(6):s+=f"#{20+i}=EDGE_CURVE('',#5,#6,#1,.T.);\n"
    for i in range(4):s+=f"#{40+i}=ADVANCED_FACE('',(#1),#2,.T.);\n"
    s+="#90=MANIFOLD_SOLID_BREP('fixture',#1);\n"
    s+='#100=(LENGTH_UNIT() NAMED_UNIT(*) SI_UNIT(.MILLI.,.METRE.));\nENDSEC;'
    return s


class Toolkit(unittest.TestCase):
    def test_brlcad_source_components_are_a_cmake_list(self):
        # Regression for Run 42681819721: one colon-joined value omitted all
        # BRL-CAD libraries and failed CMake export only after bext compiled.
        self.assertEqual(profile.cmake_source_components_arg(),
                         '-DBRLCAD_COMPONENTS=conv;gtools')
        for invalid in ((), ('conv:gtools',), ('conv', 'gtools;bad'),
                        ('conv', 'conv'), ('gtools/../conv',)):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                profile.cmake_source_components_arg(invalid)

    def test_analytic_reference_and_volume(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'fixture.step';p.write_text(fixture())
            self.assertAlmostEqual(smoke.check_tetrahedron_step(p)['tetrahedron_volume_mm3'],1000/6)

    def test_reference_rejects_wrong_units_scale_missing_or_extra_geometry(self):
        bad=[fixture().replace('.MILLI.','$'),fixture().replace('10.','9.'),
             fixture().replace('#43=ADVANCED_FACE', '#43=FACE_SURFACE'),
             fixture()+"\n#200=MANIFOLD_SOLID_BREP('extra',#1);",
             fixture().replace('(10.,0.,0.)','(nan,0.,0.)')]
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'fixture.step'
            for value in bad:
                p.write_text(value)
                with self.subTest(value=value[-90:]), self.assertRaises(RuntimeError):
                    smoke.check_tetrahedron_step(p)

    def test_full_pinned_step_schema_family_is_required(self):
        # Build #8 compiled these targets but retained only three schema DSOs.
        self.assertEqual(profile.SCHEMAS,
                         ('ap203', 'ap203e2', 'ap214', 'ap242e1',
                          'ap242e2', 'ap242e3', 'ap242e4'))
        self.assertEqual(len(profile.SCHEMAS), len(set(profile.SCHEMAS)))
        self.assertIn('ap242e4', profile.SCHEMAS)

    def test_explicit_ap242e4_report_rejects_repairs_or_partial_results(self):
        valid = {
            'exit_status': 0,
            'coverage': {'outcome': 'complete', 'geometry_written': 1,
                         'geometry_skipped': 0},
            'validation': {'invalid_breps': 0, 'repairs': 0,
                           'inferred_curves': 0}
        }
        self.assertEqual(
            smoke.verify_clean_tetrahedron_import_report(valid, 'e4')['repairs'], 0)
        import copy
        changes = (
            ('exit_status', None, 3),
            ('coverage', 'outcome', 'partial'),
            ('coverage', 'geometry_written', 0),
            ('coverage', 'geometry_skipped', 1),
            ('validation', 'invalid_breps', 1),
            ('validation', 'repairs', 1),
            ('validation', 'inferred_curves', 1),
        )
        for category, field, value in changes:
            report = copy.deepcopy(valid)
            if field is None:
                report[category] = value
            else:
                report[category][field] = value
            with self.subTest(category=category, field=field):
                with self.assertRaisesRegex(RuntimeError, 'without repair'):
                    smoke.verify_clean_tetrahedron_import_report(report, 'e4')
        import inspect
        source = inspect.getsource(smoke.run_smoke)
        self.assertIn("'--schema', 'ap242e4'", source)
        self.assertIn("'--repair', 'none'", source)
        self.assertIn("ap242e4-auto-probe.json", source)
        self.assertIn("'automatic_selected_edition': 'NOT_PROVEN_BY_PUBLIC_FILE_SCHEMA'", source)

    def test_native_tetrahedron_top_selects_geometry_not_metadata(self):
        self.assertEqual(smoke.select_tetrahedron_top('_STEP_METADATA toolkit_tetra\n'),
                         'toolkit_tetra')
        self.assertEqual(smoke.select_tetrahedron_top('toolkit_tetra\n'),
                         'toolkit_tetra')
        for listing in ('', '_STEP_METADATA', 'toolkit_tetra extra_geometry',
                        'toolkit_tetra toolkit_tetra', 'wrong_tetra',
                        'toolkit_tetra _STEP_METADATA extra_metadata'):
            with self.subTest(listing=listing), self.assertRaises(RuntimeError):
                smoke.select_tetrahedron_top(listing)

    def test_native_tetrahedron_vertices_and_planar_surfaces(self):
        native = ('m_V[0]: 0 0 0  Used by 3 edges\n'
                  '   m_E[0]: 0 -> 1\n'
                  'm_V[1]: 0 10 0  Used by 3 edges\n'
                  'm_V[2]: 10 0 0  Used by 3 edges\n'
                  'm_V[3]: 0 0 10  Used by 3 edges\n')
        value = smoke.check_tetrahedron_native_vertices(native)
        self.assertEqual(value['vertex_aabb_mm'], [0., 0., 0., 10., 10., 10.])
        self.assertAlmostEqual(value['vertex_determinant_volume_mm3'], 1000./6.)
        for changed in (native.replace('0 10 0', '0 9.998 0'),
                        native.replace('m_V[3]', 'm_V[4]'),
                        native.replace('10 0 0', 'nan 0 0'),
                        native.replace('m_V[3]: 0 0 10', 'm_V[3]: 0 0 0'),
                        native.replace('Used by 3 edges', 'unknown', 1)):
            with self.subTest(changed=changed[-80:]), self.assertRaises(RuntimeError):
                smoke.check_tetrahedron_native_vertices(changed)
        planes = ''.join(f'surface[ {i}]: ON_PlaneSurface u(0, 1) v(0, 1)\n'
                         for i in range(4))
        self.assertEqual(smoke.check_tetrahedron_native_surfaces(planes), 4)
        for changed in (planes.replace('ON_PlaneSurface', 'ON_NurbsSurface', 1),
                        planes.replace('surface[ 3]', 'surface[ 4]')):
            with self.subTest(changed=changed[-80:]), self.assertRaises(RuntimeError):
                smoke.check_tetrahedron_native_surfaces(changed)

    def test_cmake_file_api_evidence_remains_upload_visible(self):
        # Build #7 SHA256SUMS listed 1,028 paths omitted by upload-artifact
        # solely because its default excludes hidden .cmake/ directories.
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            reply = root/'attempt/build/brlcad/.cmake/api/v1/reply'
            reply.mkdir(parents=True)
            (reply/'codemodel-v2-test.json').write_text('{"test":true}\n')
            metadata = root/'evidence'
            build_geometry_tools.collect_build_evidence(root/'attempt', metadata)
            retained = metadata/'stock-build-records/brlcad/cmake-file-api/api/v1/reply/codemodel-v2-test.json'
            self.assertEqual(retained.read_text(), '{"test":true}\n')
            rows = json.loads((metadata/'stock-build-records.json').read_text())
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['path'], '.cmake/api/v1/reply/codemodel-v2-test.json')
            self.assertEqual(rows[0]['evidence_path'],
                             'cmake-file-api/api/v1/reply/codemodel-v2-test.json')
            self.assertFalse(any(part.startswith('.') for item in metadata.rglob('*')
                                 if item.is_file() for part in
                                 item.relative_to(metadata).parts))

    def test_packaging_requires_each_tool_and_each_schema(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);targets={}
            for name in profile.EXECUTABLES:
                p=root/'bin'/name;p.parent.mkdir(exist_ok=True);p.write_bytes(b'fake')
                targets[name]=[p]
            for schema in profile.SCHEMAS:
                p=root/'libexec/step'/('libstep-schema-'+schema+'.so')
                p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'fake')
                targets['step-schema-'+schema]=[p]
            ged=root/'libexec/ged/libged-brep.so';ged.parent.mkdir(parents=True);ged.write_bytes(b'fake')
            helper=root/'libexec/ged_exec/ged-brep';helper.parent.mkdir(parents=True);helper.write_bytes(b'fake')
            targets['ged-brep-plugin']=[ged];targets['ged-brep-helper']=[helper]
            unrelated=root/'private/input.step';unrelated.parent.mkdir();unrelated.write_bytes(b'never package')
            targets['unrelated']=[unrelated]
            layout=profile.runtime_layout(root,targets)
            self.assertIn('bin/g-step',layout);self.assertIn('bin/gsh',layout)
            self.assertIn('libexec/ged/libged-brep.so',layout)
            self.assertIn('libexec/ged_exec/ged-brep',layout)
            self.assertNotIn('private/input.step',layout)
            for missing in profile.EXECUTABLES+tuple('step-schema-'+s for s in profile.SCHEMAS):
                reduced=dict(targets);reduced.pop(missing)
                with self.subTest(missing=missing),self.assertRaises(RuntimeError):
                    profile.runtime_layout(root,reduced)

    def test_runpaths_work_for_executables_libraries_and_nested_plugins(self):
        self.assertEqual(profile.runpath('bin/gsh'),'$ORIGIN/../lib')
        self.assertEqual(profile.runpath('lib/libbu.so.20'),'$ORIGIN/.')
        self.assertEqual(profile.runpath('libexec/ged/libbrep.so'),'$ORIGIN/../../lib')
        self.assertEqual(profile.runpath('libexec/ged_exec/ged-brep'),'$ORIGIN/../../lib')

    def test_manifest_labels_all_tools_and_plugin_types(self):
        self.assertEqual(profile.manifest_role('bin/g-step'),'executable')
        self.assertEqual(profile.manifest_role('libexec/step/libstep-schema-ap203.so'),'plugin')
        self.assertEqual(profile.manifest_role('libexec/ged_exec/ged-brep'),'executable')

    def test_accidental_local_builder_refuses_before_any_acquisition(self):
        with patch.dict(__import__('os').environ,{},clear=True):
            with self.assertRaisesRegex(RuntimeError,'GitHub execution only'):
                build_geometry_tools.main()


if __name__=='__main__': unittest.main()
