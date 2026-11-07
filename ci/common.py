"""Public-build helpers. No resource-enforcement or host-qualification claims."""
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import time


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def write_json(path, obj):
    p = Path(path);p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n')


def clean_environment(home, temp):
    # Do not pass GitHub/Actions tokens or user loader/config overrides to builds.
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(home),
           'TMPDIR': str(temp), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
           'CMAKE_BUILD_PARALLEL_LEVEL': '1', 'MAKEFLAGS': '-j1',
           'CC': '/usr/bin/gcc-13', 'CXX': '/usr/bin/g++-13',
           'CFLAGS': '-O2 -march=x86-64 -mtune=generic',
           'CXXFLAGS': '-O2 -march=x86-64 -mtune=generic',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
           'GIT_TERMINAL_PROMPT': '0', 'GIT_ALLOW_PROTOCOL': 'https'}
    return env


class Recorder:
    def __init__(self, output, env):
        self.output = Path(output);self.output.mkdir(parents=True, exist_ok=True)
        self.env = env;self.records = []

    def run(self, argv, cwd=None, allow_failure=False, env=None):
        number = len(self.records) + 1
        stem = f'{number:04d}'
        stdout = self.output / (stem + '.stdout')
        stderr = self.output / (stem + '.stderr')
        start = time.monotonic();wall = time.time()
        with stdout.open('wb') as out, stderr.open('wb') as err:
            r = subprocess.run([str(x) for x in argv], cwd=cwd,
                               env=self.env if env is None else env,
                               stdout=out, stderr=err, check=False)
        record = {'argv': [str(x) for x in argv], 'cwd': str(cwd) if cwd else None,
                  'exit_status': r.returncode, 'signal': -r.returncode if r.returncode < 0 else None,
                  'started_unix': wall, 'elapsed_seconds': time.monotonic() - start,
                  'stdout': stdout.name, 'stderr': stderr.name}
        self.records.append(record)
        write_json(self.output / 'commands.json', self.records)
        if r.returncode and not allow_failure:
            raise RuntimeError(f'Command {stem} failed ({r.returncode}): {argv[0]}; see raw logs')
        return stdout.read_text(errors='replace')


def needed_from_readelf(text):
    return re.findall(r'\(NEEDED\).*Shared library: \[([^\]]+)\]', text)


def ldd_map(text):
    if 'not found' in text:
        raise ValueError('Unresolved runtime library')
    result = {}
    for line in text.splitlines():
        if '=>' not in line:
            continue
        name, right = line.strip().split('=>', 1)
        resolved = right.strip().split(' (', 1)[0]
        if not resolved.startswith('/'):
            raise ValueError('Unrecognized loader result')
        result[name.strip()] = str(Path(resolved).resolve())
    return result


def elf_code_sections(path):
    """Read-only ELF64 LE section hashes to audit post-link RPATH edits."""
    b = Path(path).read_bytes()
    if b[:6] != b'\x7fELF\x02\x01' or len(b) < 64:
        raise ValueError('Not ELF64 little-endian')
    eh = struct.unpack_from('<16sHHIQQQIHHHHHH', b)
    if eh[2] != 62 or not eh[12] or eh[11] != 64 or eh[13] >= eh[12]:
        raise ValueError('Unsupported machine/section encoding')
    offset, count, strings = eh[6], eh[12], eh[13]
    if offset + count * 64 > len(b):
        raise ValueError('Truncated section table')
    headers = [struct.unpack_from('<IIQQQQIIQQ', b, offset + i * 64) for i in range(count)]
    sh = headers[strings];names = b[sh[4]:sh[4] + sh[5]]
    out = {}
    for h in headers:
        if h[0] >= len(names):
            raise ValueError('Invalid section name')
        name = names[h[0]:].split(b'\0', 1)[0].decode('ascii')
        if name == '.text' or name.startswith(('.text.', '.rodata')):
            if h[4] + h[5] > len(b):
                raise ValueError('Truncated code/constant section')
            out[name] = hashlib.sha256(b[h[4]:h[4] + h[5]]).hexdigest()
    if '.text' not in out:
        raise ValueError('No .text section')
    return out
