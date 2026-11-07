"""Read-only offline checks; requires existing PyYAML, no install or build.

Run from any directory. Prints JSON, exits nonzero on a failed assertion.
Bash is used with -n only; workflow run blocks are never executed here.
"""
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
PIN_FILE_SHA256 = '3e5b8cb57b8d020d0761a4a578e7699a03a7b39f4b23009bc08f2694fc5c1256'


def inspect():
    checks = []

    def record(name, ok, details=''):
        checks.append({'check': name, 'passed': bool(ok), 'details': details})

    text = (ROOT / '.github/workflows/build-brlcad.yml').read_text()
    workflow = yaml.safe_load(text)
    job = workflow['jobs']['build']
    record('YAML parses and manual-only trigger', set(workflow['on']) == {'workflow_dispatch'})
    record('standard runner and bounded timeout', job['runs-on'] == 'ubuntu-24.04' and job['timeout-minutes'] == 240)
    record('read-only token and noncancelling serialization', workflow['permissions'] == {'contents': 'read'}
           and workflow['concurrency']['cancel-in-progress'] is False)
    record('public exact-repository initial-attempt job gate', all(x in job['if'] for x in
           ['gr8form1/manhardt-brlcad-build', 'github.event.repository.private == false',
            'workflow_dispatch', 'github.run_attempt == 1']))
    record('immutable action pins', all(re.fullmatch(r'actions/(checkout|upload-artifact)@[a-f0-9]{40}', x['uses'])
           for x in job['steps'] if 'uses' in x))
    record('no secret expressions or private checkout target', 'secrets.' not in text and
           all('repository' not in x.get('with', {}) for x in job['steps']))
    for n, step in enumerate(job['steps']):
        if 'run' in step:
            process = subprocess.run(['bash', '-n'], input=step['run'], text=True, capture_output=True)
            record(f'inline shell syntax step {n + 1}', process.returncode == 0, process.stderr)
    files = sorted((ROOT / 'ci').glob('*.py')) + sorted((ROOT / 'tests').glob('*.py'))
    for file in files:
        ast.parse(file.read_text())
    record('all shipped Python parses', True, ', '.join(str(p.relative_to(ROOT)) for p in files))
    code = '\n'.join(p.read_text() for p in (ROOT / 'ci').glob('*.py'))
    record('no retired resource-HOLD adapters/controllers', all(x not in code for x in
           ['release_gate', 'campaign_entry', 'cgroup.kill', 'memory.max', 'swapon', 'tc qdisc', 'iptables', 'quotaon']))
    record('one worker explicit in workflow and driver', "CMAKE_BUILD_PARALLEL_LEVEL: '1'" in text
           and "'--parallel', '1'" in code)
    record('accepted manifest schema retained', 'ADR001_RUNTIME_CONTENTS/2' in (ROOT / 'ci/bundle.py').read_text())
    record('offline checks produced no live build output', not (ROOT / 'out').exists())
    record('public source lock byte-identical to accepted v2.0 planning/PINNED_INPUTS.json',
           hashlib.sha256((ROOT / 'pins/sources.json').read_bytes()).hexdigest() == PIN_FILE_SHA256)
    return {'schema': 'ADR001_OFFLINE_STATIC_CHECKS/3', 'passed': all(r['passed'] for r in checks),
            'checks': checks, 'PyYAML_version': yaml.__version__,
            'actionlint': 'NOT RUN - not installed; no installation attempted',
            'build_or_dispatch': 'NOT RUN'}


if __name__ == '__main__':
    result = inspect()
    print(json.dumps(result, indent=2))
    sys.exit(0 if result['passed'] else 1)
