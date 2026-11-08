"""Offline, no Docker/no network, P2-preserving P3 regression tests."""
import io, json, pathlib, sys, tarfile, tempfile, unittest
sys.path.insert(0,str(pathlib.Path(__file__).parent))
import ap242_preflight as pre
import p2_security as sec
import p3_finalize as finalizer

SOURCE_DIR=pathlib.Path(__file__).resolve().parents[1]
ACTUAL_INFO=json.loads((SOURCE_DIR/"reference/P2_run42511228612_docker_info.json").read_text())
ACTUAL_INSPECT=json.loads((SOURCE_DIR/"reference/P2_run42511228612_docker_inspect.json").read_text())

BASE={
 'ReadonlyRootfs':True,'NetworkMode':'none','IpcMode':'none','Memory':sec.MEM,
 'MemorySwap':sec.MEM,'MemorySwappiness':0,'PidsLimit':32,'NanoCpus':1000000000,
 'CgroupnsMode':'private','CapDrop':['ALL'],'CapAdd':None,'SecurityOpt':['no-new-privileges:true'],
 'Privileged':False,'ReadonlyPaths':['/proc/asound'], 'Devices':[],'DeviceRequests':None,
 'PidMode':'','UsernsMode':'','Binds':None,'Ulimits':[{'Name':'core','Soft':0,'Hard':0},{'Name':'fsize','Soft':8388608,'Hard':8388608}],
 'Tmpfs':{'/scratch':'rw,nosuid,nodev,noexec,size=67108864,mode=1777'},
 'ShmSize':67108864,
 'Mounts':[{'Type':'bind','Source':'/r','Target':'/runtime','ReadOnly':True},
           {'Type':'bind','Source':'/f','Target':'/fixtures','ReadOnly':True}]
}
MOUNTS='''1 0 0:1 / / ro,relatime - overlay overlay ro
2 1 0:2 / /runtime ro - ext4 /dev/sda ro
3 1 0:3 / /fixtures ro - ext4 /dev/sda ro
4 1 0:4 / /scratch rw,nosuid,nodev,noexec - tmpfs tmpfs rw,size=65536k
5 1 0:5 / /proc rw - proc proc rw
6 1 0:6 / /dev rw - tmpfs tmpfs rw
7 6 0:7 / /dev/pts rw - devpts devpts rw
8 1 0:8 / /sys ro - sysfs sysfs ro
9 1 0:9 / /sys/fs/cgroup ro - cgroup2 cgroup2 ro
'''
EVENTS={
 'memory.max':'1073741824','memory.swap.max':'0','pids.max':'32',
 'memory.current':'1024','memory.swap.current':'0','pids.current':'2',
 'memory.events':{'low':0,'high':0,'max':0,'oom':0,'oom_kill':0},
 'memory.swap.events':{'high':0,'max':0,'fail':0},'pids.events':{'max':0}}

def output():
    xs=['NETNS_MARKER:net:[200]','ROUTES_EMPTY:yes','IPV6_ROUTES_EMPTY:yes','ONLY_LOOPBACK:yes','NET_CONNECT_DENIED:yes',
        'SCRATCH_WRITE_PASS:yes','UID_GID:65534:65534','NO_NEW_PRIVS:1',
        'CAP_EFF:0000000000000000','FROZEN_PASS:yes']
    xs += ['DENY_'+x.upper()+':yes' for x in ['etc','runtime','fixtures','dev','dev_shm','proc','sys','root','tmp','var_tmp']]
    xs += [k+':'+(json.dumps(v,separators=(',',':')) if isinstance(v,dict) else str(v)) for k,v in EVENTS.items()]
    return '\n'.join(xs)+'\n'

class P2(unittest.TestCase):
    def test_pins(self):
        self.assertEqual(pre.ARTIFACT_ID,13624376032)
        self.assertEqual(pre.ZIP_SHA,'437fd42a8044c836d255fdde4b318a4d7ca92cbd3cbc073e8397ee9e3e86ec65')
        self.assertEqual(pre.TAR_SHA,'4447f9cc8ede6f0386a4a289c963d5b04df93aad25016e60d960d23e8cdece0c')
        self.assertEqual(pre.IMAGE,sec.IMAGE)
    def test_p31_minimized_docker_reference_hashes(self):
        import hashlib
        # Whitelisted/minimized replay of the independently accepted, full original records.
        # Complete original file identities are retained in the sealed developer evidence.
        hashes={'P2_run42511228612_docker_info.json': '87516538cbd89afb36beaddc02bae8e19ebe43c62921b18d395fd049c5903c8b', 'P2_run42511228612_docker_inspect.json': 'c24fe3d8209c4c0d226141008cbed8380afe3a050f97c071887da9240e258f77'}
        for name,want in hashes.items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((SOURCE_DIR/'reference'/name).read_bytes()).hexdigest(),want)
        self.assertEqual(ACTUAL_INFO['ServerVersion'],'28.0.4')
        self.assertEqual(ACTUAL_INFO['CgroupVersion'],'2')
        self.assertEqual(ACTUAL_INSPECT['HostConfig']['MemorySwappiness'],None)
        self.assertIs(ACTUAL_INSPECT['State']['Running'],False)
        # The clean public test fixture must not leak a live runner path or identity.
        for name in hashes:
            data=(SOURCE_DIR/'reference'/name).read_text()
            self.assertNotIn('/home/runner/',data)
            self.assertNotIn('runnervm',data)
        self.assertEqual(ACTUAL_INSPECT['HostConfig']['Mounts'][0]['Source'],'/public-fixture/runtime')
        self.assertEqual(ACTUAL_INSPECT['HostConfig']['Mounts'][1]['Source'],'/public-fixture/fixtures')
    def test_p31_derived_inspect_null_swappiness_passes_only_static_gate(self):
        cfg=ACTUAL_INSPECT
        r=sec.verify_container_inspect(cfg,cfg['HostConfig']['Mounts'][0]['Source'],
             cfg['HostConfig']['Mounts'][1]['Source'],cfg['Image'],ACTUAL_INFO)
        self.assertTrue(r['hostconfig_checked'])
        # The actual P2 container was never started. No cgroup/kernel evidence exists.
        with self.assertRaises(sec.GateError):sec.verify_canary('', 'net:[100]', MOUNTS)
    def test_p3_explicit_cgroup_v2_proof_required(self):
        self.assertEqual(sec.verify_docker_cgroup_v2(ACTUAL_INFO)['observed_cgroup_version'],'2')
        for val in ['1',None,'3',2,True,'',{},'v2']:
            info=dict(ACTUAL_INFO,CgroupVersion=val)
            with self.subTest(value=val),self.assertRaises(sec.GateError):
                sec.verify_hostconfig(dict(BASE,MemorySwappiness=None),'/r','/f','image',info)
        with self.assertRaises(sec.GateError):sec.verify_hostconfig(
            dict(BASE,MemorySwappiness=None),'/r','/f','image',dict(ACTUAL_INFO,OSType='windows'))
    def test_p3_swappiness_null_or_zero_only_with_positive_v2(self):
        for sw in (None,0):
            self.assertTrue(sec.verify_hostconfig(dict(BASE,MemorySwappiness=sw),
                '/r','/f','image',ACTUAL_INFO)['hostconfig_checked'])
        for sw in (1,-1,10,100,False,True,'0','null',0.0,[],{}):
            with self.subTest(sw=sw),self.assertRaises(sec.GateError):
                sec.verify_hostconfig(dict(BASE,MemorySwappiness=sw),'/r','/f','image',ACTUAL_INFO)
        cfg=BASE.copy();cfg.pop('MemorySwappiness')
        with self.assertRaises(sec.GateError):sec.verify_hostconfig(cfg,'/r','/f','image',ACTUAL_INFO)
    def test_p31_derived_inspect_rejects_unsafe_resource_mutations(self):
        import copy
        runtime=ACTUAL_INSPECT['HostConfig']['Mounts'][0]['Source']
        fixtures=ACTUAL_INSPECT['HostConfig']['Mounts'][1]['Source']
        for key,val in [('Memory',sec.MEM-1),('MemorySwap',sec.MEM*2),('PidsLimit',30),
                        ('MemorySwappiness',50),('NetworkMode','bridge'),('ReadonlyRootfs',False)]:
            obj=copy.deepcopy(ACTUAL_INSPECT);obj['HostConfig'][key]=val
            with self.subTest(key=key),self.assertRaises(sec.GateError):
                sec.verify_container_inspect(obj,runtime,fixtures,obj['Image'],ACTUAL_INFO)
    def test_p3_running_cgroup_four_mandatory_fields_missing_duplicated_or_wrong(self):
        self.assertEqual(sec.verify_cgroups(output())['memory.swap.current'],'0')
        for key in ('memory.max','memory.swap.max','memory.swap.current','pids.max'):
            good=key+':'+EVENTS[key]
            for new in ('', key+':bad', key+':max', good+'\n'+good):
                altered=output().replace(good,new,1)
                with self.subTest(key=key,new=new),self.assertRaises(sec.GateError):
                    sec.verify_cgroups(altered)
        for key,wrong in [('memory.max','1073741823'),('memory.swap.max','1'),
                          ('memory.swap.current','1'),('pids.max','33')]:
            with self.subTest(key=key,wrong=wrong),self.assertRaises(sec.GateError):
                sec.verify_canary(output().replace(key+':'+EVENTS[key],key+':'+wrong,1),
                                  'net:[100]',MOUNTS)
    def test_p3_requires_actual_cgroup2_mount(self):
        for bad in (MOUNTS.replace(' - cgroup2 cgroup2 ro',' - cgroup cgroup ro'),
                    MOUNTS.replace('9 1 0:9 / /sys/fs/cgroup ro - cgroup2 cgroup2 ro\n','')):
            with self.subTest(bad=bad[-100:]),self.assertRaises(sec.GateError):
                sec.verify_canary(output(),'net:[100]',bad)
    def test_p3_final_inventory_includes_cleanup_and_controller_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d)
            (root/'raw').mkdir()
            for n,data in [('cleanup_before.txt','container-id\n'),('cleanup_after.txt',''),
                           ('SECURITY_PREFLIGHT.json','{"status":"HOLD"}'),
                           ('SHA256SUMS.txt','p2 census\n'),('raw/probe.stdout.bin','observed')]:
                p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(data)
            result=finalizer.seal(root)
            self.assertEqual(result['status'],'PASS_EVIDENCE_SEAL_ONLY')
            manifest=(root/'FINAL_SHA256SUMS.txt').read_text()
            for name in ['cleanup_before.txt','cleanup_after.txt','SECURITY_PREFLIGHT.json',
                         'SHA256SUMS.txt','FINAL_EVIDENCE_STATUS.json','raw/probe.stdout.bin']:
                self.assertIn('  '+name+'\n',manifest)
            self.assertNotIn('  FINAL_SHA256SUMS.txt\n',manifest)
            with self.assertRaises(RuntimeError):finalizer.seal(root)
    def test_p3_final_inventory_missing_or_nonempty_cleanup_fails_closed(self):
        for case in ['missing_before','missing_after','nonempty_after','cleanup_failure']:
            with tempfile.TemporaryDirectory() as d:
                root=pathlib.Path(d)
                (root/'SECURITY_PREFLIGHT.json').write_text('{"status":"HOLD"}')
                (root/'SHA256SUMS.txt').write_text('precleanup manifest')
                if case!='missing_before':(root/'cleanup_before.txt').write_text('')
                if case!='missing_after':(root/'cleanup_after.txt').write_text('container' if case=='nonempty_after' else '')
                if case=='cleanup_failure':(root/'cleanup_failure.txt').write_text('failed')
                result=finalizer.seal(root)
                with self.subTest(case=case):
                    self.assertEqual(result['status'],'HOLD_INCOMPLETE_CLEANUP_EVIDENCE')
                    self.assertIn('  FINAL_EVIDENCE_STATUS.json\n',(root/'FINAL_SHA256SUMS.txt').read_text())
    def test_p3_final_inventory_symlink_escape_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d);(root/'cleanup_before.txt').write_text('');(root/'cleanup_after.txt').write_text('')
            (root/'SECURITY_PREFLIGHT.json').write_text('{}');(root/'SHA256SUMS.txt').write_text('x')
            (root/'bad_link').symlink_to('/etc/passwd')
            with self.assertRaises(RuntimeError):finalizer.seal(root)
    def test_network_valid(self):self.assertTrue(sec.network_evidence(output(),'net:[100]')['distinct'])
    def test_network_absent_rejected(self):
        with self.assertRaises(sec.GateError):sec.network_evidence(output().replace('NETNS_MARKER:net:[200]',''),'net:[100]')
    def test_network_same_rejected(self):
        with self.assertRaises(sec.GateError):sec.network_evidence(output(),'net:[200]')
    def test_network_malformed_rejected(self):
        with self.assertRaises(sec.GateError):sec.network_evidence(output().replace('net:[200]','net:bad'),'net:[100]')
    def test_network_duplicate_rejected(self):
        with self.assertRaises(sec.GateError):sec.network_evidence(output()+'NETNS_MARKER:net:[300]\n','net:[100]')
    def test_network_missing_route_rejected(self):
        with self.assertRaises(sec.GateError):sec.network_evidence(output().replace('ROUTES_EMPTY:yes',''),'net:[100]')
    def test_network_missing_connect_rejected(self):
        with self.assertRaises(sec.GateError):sec.network_evidence(output().replace('NET_CONNECT_DENIED:yes',''),'net:[100]')
    def test_valid_hostconfig(self):self.assertTrue(sec.verify_hostconfig(BASE,'/r','/f','image',ACTUAL_INFO)['hostconfig_checked'])
    def test_config_each_critical_setting_fails(self):
        mutations={'ReadonlyRootfs':False,'NetworkMode':'bridge','IpcMode':'private',
            'Memory':999,'MemorySwap':2*sec.MEM,'PidsLimit':99,'NanoCpus':0,'MemorySwappiness':15,
            'Privileged':True,'CgroupnsMode':'host','SecurityOpt':[],'CapDrop':[],'Ulimits':[],'Tmpfs':{},'Mounts':[],
            'Binds':['/host:/x'],'VolumesFrom':['unsafe'],'Links':['other'],'Devices':[{'PathOnHost':'/dev/sda'}],'CapAdd':['SYS_ADMIN']}
        for k,v in mutations.items():
            cfg=BASE.copy();cfg[k]=v
            with self.subTest(key=k),self.assertRaises(sec.GateError):sec.verify_hostconfig(cfg,'/r','/f','image',ACTUAL_INFO)
    def test_bad_tmpfs_flags_fails(self):
        for flag in ['noexec','nosuid','nodev','size=67108864']:
            cfg=BASE.copy();cfg['Tmpfs']={'/scratch':','.join(x for x in BASE['Tmpfs']['/scratch'].split(',') if x!=flag)}
            with self.subTest(flag=flag),self.assertRaises(sec.GateError):sec.verify_hostconfig(cfg,'/r','/f','image',ACTUAL_INFO)
    def test_ro_bind_fails_if_rw(self):
        cfg=BASE.copy();cfg['Mounts']=[dict(BASE['Mounts'][0],ReadOnly=False),BASE['Mounts'][1]]
        with self.assertRaises(sec.GateError):sec.verify_hostconfig(cfg,'/r','/f','image',ACTUAL_INFO)
    def test_full_inspect_image_user(self):
        valid={'Image':'sha256:image','Config':{'Image':sec.IMAGE,'User':'65534:65534','WorkingDir':'','Entrypoint':None,'Env':['HOME=/scratch','TMPDIR=/scratch']},'HostConfig':BASE,
               'Mounts':[{'Type':'bind','Source':'/r','Destination':'/runtime','RW':False},{'Type':'bind','Source':'/f','Destination':'/fixtures','RW':False}]}
        self.assertTrue(sec.verify_container_inspect(valid,'/r','/f','sha256:image',ACTUAL_INFO))
        for k,v in [('Image','sha256:wrong'),('Config',dict(valid['Config'],User='0:0'))]:
            c=valid.copy();c[k]=v
            with self.subTest(k=k),self.assertRaises(sec.GateError):sec.verify_container_inspect(c,'/r','/f','sha256:image',ACTUAL_INFO)
    def test_mountinfo_valid(self):self.assertEqual(sec.verify_mountinfo(MOUNTS)['scratch'],'tmpfs')
    def test_extra_writable_mount_rejected(self):
        with self.assertRaises(sec.GateError):sec.verify_mountinfo(MOUNTS+'10 1 0:10 / /var/log rw - tmpfs tmpfs rw\n')
    def test_writable_shm_rejected(self):
        with self.assertRaises(sec.GateError):sec.verify_mountinfo(MOUNTS+'11 6 0:11 / /dev/shm rw - tmpfs tmpfs rw\n')
    def test_missing_mountinfo_rejected(self):
        with self.assertRaises(sec.GateError):sec.verify_mountinfo('')
    def test_bad_cgroup_fails(self):
        self.assertEqual(sec.verify_cgroups(output())['pids.max'],'32')
        for k,v in [('memory.max','max'),('memory.swap.max','200'),('pids.max','unlimited'),('memory.swap.current','1'),('memory.events',{'oom':1}),('pids.events',{'max':1})]:
            txt=output();old=EVENTS[k];old=json.dumps(old,separators=(',',':')) if isinstance(old,dict) else old
            new=json.dumps(v,separators=(',',':')) if isinstance(v,dict) else v
            with self.subTest(k=k),self.assertRaises(sec.GateError):sec.verify_cgroups(txt.replace(k+':'+old,k+':'+new))
    def test_missing_non_scratch_denial_rejected(self):
        with self.assertRaises(sec.GateError):sec.verify_canary(output().replace('DENY_DEV_SHM:yes',''),'net:[100]',MOUNTS)
    def test_stream_overflow_fails_not_truncates(self):
        with tempfile.TemporaryDirectory() as d:
            a=pathlib.Path(d)/'a';b=pathlib.Path(d)/'b';a.write_bytes(b'x'*26);b.write_bytes(b'')
            with self.assertRaises(sec.GateError):sec.bounded_complete_streams(a,b,24)
    def test_stream_full_retained(self):
        with tempfile.TemporaryDirectory() as d:
            a=pathlib.Path(d)/'a';b=pathlib.Path(d)/'b';a.write_bytes(b'x'*24000);b.write_bytes(b'')
            self.assertTrue(sec.bounded_complete_streams(a,b,24000))
    def test_reject_tar_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'bad.tar.gz';o=pathlib.Path(d)/'dest';o.mkdir()
            with tarfile.open(p,'w:gz') as f:
                m=tarfile.TarInfo('brlcad-runtime/bin/step-g');m.type=tarfile.SYMTYPE;m.linkname='/etc/passwd';f.addfile(m)
            with self.assertRaises(RuntimeError):pre.safe_extract_runtime(p,o)
    def test_reject_tar_traversal(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'bad.tar.gz';o=pathlib.Path(d)/'dest';o.mkdir()
            with tarfile.open(p,'w:gz') as f:
                m=tarfile.TarInfo('brlcad-runtime/../evil');m.size=3;f.addfile(m,io.BytesIO(b'bad'))
            with self.assertRaises(RuntimeError):pre.safe_extract_runtime(p,o)
    def test_no_geometry_execution_in_workflow(self):
        import yaml
        path=pathlib.Path(__file__).resolve().parents[1]/'.github/workflows/adr001-public-ap242-preflight.yml'
        v=yaml.safe_load(path.read_text())
        self.assertEqual(list(v['on']),['workflow_dispatch'])
        all_runs='\n'.join(x.get('run','') for x in v['jobs']['security_preflight']['steps'])
        self.assertNotIn('step-g --schema',all_runs)
        self.assertNotIn('ci/build.py',all_runs)
        self.assertLess([x.get('name','') for x in v['jobs']['security_preflight']['steps']].index('OFFLINE regression and syntax checks BEFORE artifact acquisition'), [x.get('name','') for x in v['jobs']['security_preflight']['steps']].index('Authenticated artifact acquisition and confined security canaries only'))
    def test_process_tree_parent_child(self):
        observed='PID PPID COMMAND\n101 1 /bin/sh -ec sleep 180 & wait\n102 101 sleep 180\n'
        self.assertEqual(sec.extract_observed_sleep_tree(observed)['child_pid'],102)
        for bad in [
          'PID PPID COMMAND\n101 1 /bin/sh -ec sleep 180 & wait\n',
          'PID PPID COMMAND\n101 1 /bin/sh -ec sleep 180 & wait\n102 999 sleep 180\n',
          'PID PPID COMMAND\n101 1 /bin/sh -ec sleep 180 & wait\n102 101 sleep 180\n103 101 sleep 180\n']:
            with self.subTest(bad=bad),self.assertRaises(sec.GateError):sec.extract_observed_sleep_tree(bad)
    def test_cleanup_negative_gate(self):
        self.assertTrue(sec.verify_cleanup_observed(0,1,[],{101:False,102:False}))
        for obs in [(1,1,[],{101:False}),(0,0,[],{101:False}),(0,1,['id'],{101:False}),(0,1,[],{101:True})]:
            with self.subTest(obs=obs),self.assertRaises(sec.GateError):sec.verify_cleanup_observed(*obs)
    def test_watchdog_command_times_out_with_complete_logs(self):
        with tempfile.TemporaryDirectory() as d:
            result=pre.command(['/bin/sh','-c','sleep 4 & wait'],timeout=0.1,
                evidence=pathlib.Path(d),label='timeout',byte_cap=4096)
            self.assertEqual(result['rc'],124)
            self.assertTrue(result['timed_out'])
            self.assertTrue((pathlib.Path(d)/'timeout.stdout.bin').exists())
    def test_cleanup_contract_static(self):
        source=(pathlib.Path(__file__).parent/'ap242_preflight.py').read_text()
        self.assertIn("['docker','rm','-f',name]",source)
        self.assertIn("['docker','inspect',name]",source)
        self.assertIn("['docker','wait',name],3",source)
        self.assertIn("tree['observed_pids']",source)
        self.assertIn("container_ids('finished')",source)
    def test_watchdog_script_is_long(self):
        script=(pathlib.Path(__file__).parent/'process_tree_canary.sh').read_text()
        self.assertIn('sleep 180',script)
        self.assertIn('WATCHDOG_UNEXPECTED_COMPLETION',script)

if __name__=='__main__':unittest.main(verbosity=2)
