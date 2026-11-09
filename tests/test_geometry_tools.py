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
