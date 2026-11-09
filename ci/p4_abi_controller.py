#!/usr/bin/env python3
"""ADR-001 P4 ABI-only proposal: future runner use AFTER independent acceptance.

No step-g program invocation, no STEP import, no output database. The dynamic
loader --list resolves a binary's shared-library closure without transferring
control to its entry point. Loading a DSO for dependency listing is NOT native
AP242e2 plugin dispatch. Any ambiguity is a HOLD.
"""
import argparse, base64, hashlib, io, json, os, pathlib, posixpath, re, shutil, stat, sys, time, zipfile
from ap242_preflight import (REPO,ARTIFACT_ID,ZIP_SHA,TAR_SHA,IMAGE,MEM,PID_MAX,FIXTURES,
   build_artifact_download,bounded_http,hash_bytes,hash_file,safe_extract_runtime,
   command,require_success,stdout_text,docker_json,write_json)
from p2_security import GateError,verify_docker_cgroup_v2,verify_container_inspect,verify_canary,verify_cleanup_observed,bounded_complete_streams

EXPECTED_CONTROL_SHA256={
 'ci/ap242_preflight.py':'f18b20b42ffb3b8aabde1b905319470e227762a5a2b9df9ed4da61ec7bbfe33e',
 'ci/p2_security.py':'cffb1fc7f7d8ef6a479c9b2a14509a7adba28480e2010d3f509921c65322d0f0',
 'ci/p3_finalize.py':'1807edefbeee57eb427a90f5c866a0f4ec366cebc840126eda89aa616b6264a9',
 'ci/fixture_canary.sh':'0580c060343b903e655658741e8c5bf1b2ddb6aeffff34ec845f4e21e2e8582d',
 'ci/process_tree_canary.sh':'e5fc2dd0e405c7638ec2c2e313e6aa84cff4789762fd364a12f162268752245b',
 'ci/test_preflight.py':'f89683e31edd21dea4e7953f49a9953f27c6227547d5cccf3b1e9d1498220160',
 '.github/workflows/adr001-public-ap242-preflight.yml':'459344c93205f1fcb8e8af8c13f315699c3a0d37821b6da99ea0303037eecf70',
 'reference/P2_run42511228612_docker_info.json':'87516538cbd89afb36beaddc02bae8e19ebe43c62921b18d395fd049c5903c8b',
 'reference/P2_run42511228612_docker_inspect.json':'c24fe3d8209c4c0d226141008cbed8380afe3a050f97c071887da9240e258f77',
 'reference/P31_run42518017322_native_canary_sanitized.txt':'399c880381a4fef21107c64d1f6908c17e8d984d225c43ce964623bb7443e332'
}
BINARY_SHA='5cb3c20ac53827be697e1dcd6fe153586a9b13bab537166f9e27e8ead5f01e73'
PLUGIN_SHA='0580fe3e551387a21fca7661c4b369ff8a07292b8daaba789ce4171442367bfa'
CONTROL_COMMIT='e25c46a1967fbca64948449d3fe027b657472f15'
EXPECTED_IMAGE_ID='sha256:35a88802559dd2077e584394471ddaa1a2c5bfd16893b829ea57619301eb3908'

# Only read-only loader dependency listing. No --schema, -D, -o or step-g entrypoint.
ABI_SHELL = '''
set -eu
printf 'P4_ABI_BEGIN\\n'
# Nonexecuting UID=65534 read gates before any loader qualification.
for public_file in /runtime/bin/step-g /runtime/libexec/step/libstep-schema-ap242e2.so /fixtures/base_attachment.step /fixtures/M015.stp; do
  test -r "$public_file" || exit 83
done
test -r /lib64/ld-linux-x86-64.so.2
test "$(sha256sum /runtime/bin/step-g | cut -d' ' -f1)" = '5cb3c20ac53827be697e1dcd6fe153586a9b13bab537166f9e27e8ead5f01e73'
test "$(sha256sum /runtime/libexec/step/libstep-schema-ap242e2.so | cut -d' ' -f1)" = '0580fe3e551387a21fca7661c4b369ff8a07292b8daaba789ce4171442367bfa'
printf 'P4_BINARIES_REHASHED:yes\\n'
/lib64/ld-linux-x86-64.so.2 --version
printf 'P4_LOADER_LIST_EXEC_BEGIN\\n'
printf 'P4_LD_DEBUG_EXEC_BEGIN\\n' >&2
LD_DEBUG=libs,versions /lib64/ld-linux-x86-64.so.2 --list /runtime/bin/step-g
printf 'P4_LD_DEBUG_EXEC_END\\n' >&2
printf 'P4_LOADER_LIST_EXEC_END\\n'
printf 'P4_LOADER_LIST_PLUGIN_BEGIN\\n'
printf 'P4_LD_DEBUG_PLUGIN_BEGIN\\n' >&2
LD_DEBUG=libs,versions /lib64/ld-linux-x86-64.so.2 --list /runtime/libexec/step/libstep-schema-ap242e2.so
printf 'P4_LD_DEBUG_PLUGIN_END\\n' >&2
printf 'P4_LOADER_LIST_PLUGIN_END\\n'
# These exact provider files must be visible in the digest-pinned image.
sha256sum /lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/libc.so.6 /usr/lib/x86_64-linux-gnu/libstdc++.so.6 /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib/x86_64-linux-gnu/libm.so.6
printf 'P4_PROVIDER_FILES_HASHED:yes\\n'
printf 'P4_ABI_END\\n'
'''

def verify_control_source(root):
    actual={}
    for rel,expect in EXPECTED_CONTROL_SHA256.items():
        p=root/rel
        if not p.is_file() or p.is_symlink() or hash_file(p)!=expect:
            raise GateError('Accepted P3.2.1 control-file identity mismatch '+rel)
        actual[rel]=expect
    return actual

# Structural completeness, not a provider compatibility verdict. An independent
# reviewer must inspect the *raw*, hash-identified stdout/stderr and pinned image.
ABI_MARKERS = (
    'P4_ABI_BEGIN', 'P4_BINARIES_REHASHED:yes', 'P4_LOADER_LIST_EXEC_BEGIN',
    'P4_LOADER_LIST_EXEC_END', 'P4_LOADER_LIST_PLUGIN_BEGIN',
    'P4_LOADER_LIST_PLUGIN_END', 'P4_PROVIDER_FILES_HASHED:yes', 'P4_ABI_END',
)
DEBUG_MARKERS = (
    'P4_LD_DEBUG_EXEC_BEGIN', 'P4_LD_DEBUG_EXEC_END',
    'P4_LD_DEBUG_PLUGIN_BEGIN', 'P4_LD_DEBUG_PLUGIN_END',
)
EXEC_TARGET = '/runtime/bin/step-g'
PLUGIN_TARGET = '/runtime/libexec/step/libstep-schema-ap242e2.so'
FROZEN_ELF_MANIFEST_SHA256 = 'b5553144e4d68fb4f4605794c816c67bd36c13deee17438a154cb40a7eca1a58'
PROVIDER_PATHS = (
    '/lib64/ld-linux-x86-64.so.2', '/lib/x86_64-linux-gnu/libc.so.6',
    '/usr/lib/x86_64-linux-gnu/libstdc++.so.6',
    '/lib/x86_64-linux-gnu/libgcc_s.so.1', '/lib/x86_64-linux-gnu/libm.so.6',
)
DEP_MAPPING = re.compile(r'^([A-Za-z0-9_+.-]+)\s+=>\s+(/[^\s()]+)\s+\(0x[0-9a-fA-F]+\)$')
DEP_DIRECT = re.compile(r'^(/[^\s()]+|linux-vdso\.so\.1)\s+\(0x[0-9a-fA-F]+\)$')
VERSION_CHECK = re.compile(
    r"checking for version [`']((?:GLIBC|GLIBCXX|CXXABI)_[0-9.]+)[`']"
    r" in file (/[^\s]+) \[\d+\] required by file (/[^\s]+) \[\d+\]"
)


def _complete_capture(stdout_raw, stderr_raw, status):
    if not isinstance(stdout_raw, bytes) or not isinstance(stderr_raw, bytes):
        raise GateError('Raw ABI evidence must be supplied as unmodified bytes')
    if not isinstance(status, dict) or status.get('rc') != 0 or status.get('timed_out') is not False:
        raise GateError('ABI process exit unsuccessful, absent or timed out')
    for stream, data in (('stdout', stdout_raw), ('stderr', stderr_raw)):
        cap = status.get(stream + '_cap')
        if not isinstance(cap, int) or not 0 < cap <= 4_000_000:
            raise GateError('Untrusted or absent ABI stream cap: ' + stream)
        if not 0 < len(data) < cap or status.get(stream + '_bytes') != len(data):
            raise GateError('ABI stream absent, overflowed or length mismatch: ' + stream)
        if status.get(stream + '_sha256') != hashlib.sha256(data).hexdigest():
            raise GateError('ABI raw stream hash mismatch: ' + stream)
        if b'\x00' in data or not data.endswith(b'\n'):
            raise GateError('ABI stream malformed or truncated: ' + stream)
    try:
        return stdout_raw.decode('utf-8', 'strict'), stderr_raw.decode('utf-8', 'strict')
    except UnicodeDecodeError as exc:
        raise GateError('ABI stream invalid UTF-8') from exc


def _ordered_single_markers(lines, markers, channel):
    positions = []
    for marker in markers:
        if lines.count(marker) != 1:
            raise GateError('ABI ' + channel + ' marker missing or duplicate: ' + marker)
        positions.append(lines.index(marker))
    if positions != sorted(positions):
        raise GateError('ABI ' + channel + ' marker order violated')
    # Markers cannot be embedded as data in a longer line.
    if any(marker in line and line != marker for line in lines for marker in markers):
        raise GateError('ABI ' + channel + ' embedded marker')
    return positions


# The frozen 22-ELF inventory describes the bundled dependency graph, not the
# image's provider libraries. These checks are necessary evidence conditions;
# their success must never be reported as actual G1 provider ABI acceptance.
LOADER_SONAME = 'ld-linux-x86-64.so.2'
PROVIDER_PREFIXES = ('/lib/', '/lib64/', '/usr/lib/', '/usr/lib64/')
FAMILY_PROVIDER = {'GLIBC': 'libc.so.6',
                   'GLIBCXX': 'libstdc++.so.6', 'CXXABI': 'libstdc++.so.6'}
LIBRARY_SEARCH = re.compile(r'\bfind library=([A-Za-z0-9_+.-]+)\s+\[\d+\]; searching\b')
LIBRARY_TRY = re.compile(r'\btrying file=(/[^\s]+)')
# Explicit GNU-loader failure symptoms, matched case-insensitively in the
# bounded diagnostic stream. This gate is intentionally conservative: an
# unreviewed error-looking record cannot be silently accepted as ABI evidence.
LOADER_FAILURE = re.compile(
    r'\b(?:error|errors|fatal|failed|failure|cannot|unable|invalid|corrupt|'
    r'corrupted|not[ \t]+found|undefined[ \t]+symbol|permission[ \t]+denied|'
    r'no[ \t]+such[ \t]+file|file[ \t]+too[ \t]+short)\b',
    re.IGNORECASE)

# P43-R1: explicit glibc/ELF ABI anomalies can be advisory with a zero exit
# status (notably absent DT_VERDEF version information). Their presence makes
# loader *evidence* unqualified even if all expected version-check rows exist.
# This is a bounded anomaly gate, NOT a complete ABI semantic validator.
LOADER_ABI_ANOMALY = re.compile(
    r'\b(?:no[ \t]+version[ \t]+information[ \t]+available|'
    r'wrong[ \t]+ELF[ \t]+class|'
    r'unsupported[ \t]+(?:ELF[ \t]+|ABI[ \t]+|symbol[ \t]+)?version|'
    r'version[ \t]+(?:is[ \t]+)?not[ \t]+supported)\b',
    re.IGNORECASE)


def _canonical_provider_path(path):
    """Reject traversal and noncanonical lexical paths; never host-resolve.

    These paths describe the future pinned Ubuntu container, not this host.
    Host realpath() would test an unrelated filesystem and may fabricate
    confidence. A positive result is lexical provenance evidence ONLY; actual
    symlink targets and provider binary identities remain G1 review HOLD.
    """
    if not isinstance(path, str) or not path.startswith('/') or path.startswith('//'):
        return False
    if '//' in path or any(bit in ('', '.', '..') for bit in path.split('/')[1:]):
        return False
    if posixpath.normpath(path) != path:
        return False
    return any(path.startswith(prefix) for prefix in PROVIDER_PREFIXES)


def _manifest_closure(manifest, root):
    """Derive the recursive DT_NEEDED SONAME set for one frozen target.

    Provider ELFs are *not* included in the 22-file bundle manifest; they are
    retained as named unknown-provider boundaries for independent G1 review.
    """
    files = manifest.get('files')
    if not isinstance(files, dict) or len(files) != 22 or root not in files:
        raise GateError('Frozen ELF manifest file census invalid')
    indexed = {}
    for path, entry in files.items():
        if not isinstance(path, str) or not (path.startswith('lib/') or
               path in (EXEC_TARGET.removeprefix('/runtime/'),
                        PLUGIN_TARGET.removeprefix('/runtime/'))):
            raise GateError('Unrecognized bundled ELF path')
        name = pathlib.PurePosixPath(path).name
        if name in indexed:
            raise GateError('Ambiguous bundled SONAME: ' + name)
        if not isinstance(entry, dict) or not isinstance(entry.get('needed'), list):
            raise GateError('Missing manifest DT_NEEDED metadata: ' + path)
        indexed[name] = path
    providers = manifest.get('nonbundled_needed')
    if not isinstance(providers, list) or len(providers) != len(set(providers)) or set(providers) != {
            LOADER_SONAME, 'libc.so.6', 'libm.so.6',
            'libgcc_s.so.1', 'libstdc++.so.6'}:
        raise GateError('Frozen provider boundary invalid')
    nodes, needed = set(), set()
    todo = [root]
    while todo:
        path = todo.pop()
        if path in nodes:
            continue
        if len(nodes) > 22:
            raise GateError('ELF dependency graph exceeds frozen bounds')
        nodes.add(path)
        dep_list = files[path]['needed']
        if len(dep_list) != len(set(dep_list)) or not dep_list:
            raise GateError('Duplicate or empty manifest DT_NEEDED: ' + path)
        for name in dep_list:
            if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_+.-]+', name):
                raise GateError('Malformed manifest SONAME: ' + path)
            needed.add(name)
            if name in indexed:
                todo.append(indexed[name])
            elif name not in providers:
                raise GateError('Unattributed provider SONAME: ' + name)
    return {'needed': needed, 'objects': nodes,
            'bundled': {name: indexed[name] for name in needed if name in indexed},
            'providers': set(providers) & needed}


def _dependency_listing(lines, closure, label):
    if not 0 < len(lines) <= 512 or sum(map(len, lines)) > 262_144:
        raise GateError('ABI dependency listing empty or oversized: ' + label)
    seen = {}
    for line in lines:
        mapped = DEP_MAPPING.fullmatch(line.strip())
        direct = DEP_DIRECT.fullmatch(line.strip()) if mapped is None else None
        if mapped:
            soname, resolved = mapped.groups()
        elif direct:
            resolved = direct.group(1)
            soname = pathlib.PurePosixPath(resolved).name
        else:
            raise GateError('Malformed or unresolved ABI dependency: ' + label)
        if soname in seen:
            raise GateError('Duplicate ABI dependency record: ' + soname)
        if soname == 'linux-vdso.so.1':
            if resolved != 'linux-vdso.so.1':
                raise GateError('Invalid VDSO pseudo-path: ' + label)
        elif not resolved.startswith('/') or pathlib.PurePosixPath(resolved).name != soname:
            raise GateError('ABI dependency path/SONAME mismatch: ' + soname)
        seen[soname] = resolved
    missing = closure['needed'] - set(seen)
    if missing:
        raise GateError('ABI transitive DT_NEEDED closure incomplete: ' + label +
                        ' missing ' + ','.join(sorted(missing)))
    for name, path in closure['bundled'].items():
        if seen[name] != '/runtime/' + path:
            raise GateError('Bundled ELF resolution provenance mismatch: ' + name)
    for name in set(seen) - set(closure['bundled']) - {'linux-vdso.so.1'}:
        resolved = seen[name]
        if not _canonical_provider_path(resolved):
            raise GateError('Provider path escapes or is noncanonical: ' + name)
    return {'records': len(seen), 'manifest_transitive_closure_count': len(closure['needed']),
            'manifest_closure_present': True,
            'resolved_paths': dict(sorted(seen.items())),
            'extra_image_provider_names': sorted(set(seen)-closure['needed']-{'linux-vdso.so.1'}),
            'provider_dependency_closure': 'NOT_STATICALLY_INVENTORIED_IN_PINNED_IMAGE'}


def _version_diagnostics(lines, root, closure, seen, manifest, label):
    if not root.startswith('/runtime/') or root.removeprefix('/runtime/') not in closure['objects']:
        raise GateError('Inconsistent loader diagnostic target')
    if not 0 < len(lines) <= 50_000 or sum(map(len, lines)) > 3_500_000:
        raise GateError('LD_DEBUG diagnostics empty or oversized: ' + label)
    searches, attempts, checks = set(), {}, set()
    current_search = None
    for line in lines:
        found = LIBRARY_SEARCH.search(line)
        if found:
            current_search = found.group(1)
            searches.add(current_search)
            attempts.setdefault(current_search, set())
        attempted = LIBRARY_TRY.search(line)
        if attempted:
            if current_search is None:
                raise GateError('LD_DEBUG unscoped resolved-path attempt: ' + label)
            attempts[current_search].add(attempted.group(1))
        version = VERSION_CHECK.search(line)
        if version:
            symbol, provider, requestor = version.groups()
            checks.add((requestor, symbol, provider))
        if LOADER_FAILURE.search(line) or LOADER_ABI_ANOMALY.search(line):
            raise GateError('LD_DEBUG loader reported an error or ABI anomaly: ' + label)
    # The ELF interpreter is already mapped by ld.so, and linux-vdso is a kernel
    # virtual object, so neither is required to have a 'find library' event.
    required_searches = set(seen) - {LOADER_SONAME, 'linux-vdso.so.1'}
    absent = required_searches - searches
    if absent:
        raise GateError('LD_DEBUG transitive library-search trace missing: ' + label +
                        ' ' + ','.join(sorted(absent)))
    # Correlate the trace's observed pathname attempts to the exact stdout
    # resolutions for EVERY manifest-covered library except the interpreter.
    missing_attempts = {name for name in required_searches
                        if seen[name] not in attempts.get(name, set())}
    if missing_attempts:
        raise GateError('LD_DEBUG resolved-path attempt missing: ' + label +
                        ' ' + ','.join(sorted(missing_attempts)))
    # For every bundled object on the target's transitive graph, require each
    # frozen versioned relocation requirement, attributed to its own requesting
    # object (not merely the executable/DSO at the root).
    expected_count = 0
    for object_path in sorted(closure['objects']):
        required = manifest['files'][object_path]['required_symbol_versions']
        requestor = '/runtime/' + object_path
        for family, versions in required.items():
            if family not in FAMILY_PROVIDER or not isinstance(versions, list):
                raise GateError('Malformed manifest symbol version family')
            provider_name = FAMILY_PROVIDER[family]
            if provider_name not in seen:
                raise GateError('Version provider absent from dependency listing')
            provider_path = seen[provider_name]
            for version in versions:
                symbol = family + '_' + version
                expected_count += 1
                if (requestor, symbol, provider_path) not in checks:
                    raise GateError('LD_DEBUG transitive object/version record missing: ' +
                                    label + ' ' + requestor + ' ' + symbol)
    if expected_count == 0:
        raise GateError('No static version evidence to corroborate')
    return {'versioned_manifest_object_requirements_observed': expected_count,
            'manifest_bundled_objects_covered': len(closure['objects']),
            'required_library_searches_observed': len(required_searches),
            'diagnostics_correlated_to_each_observed_resolved_path': True,
            'resolved_path_attempts_observed': len(required_searches),
            'observed_extra_searches': sorted(searches - required_searches),
            'version_checks_scope': 'FROZEN_BUNDLED_OBJECTS_ONLY',
            'image_provider_transitive_versions': 'INDEPENDENT_REVIEW_HOLD'}


def check_abi_markers(stdout_raw, stderr_raw, status, manifest=None):
    """Reject incomplete loader evidence, but ALWAYS leave G1 provider verdict on HOLD.

    `status` is the bounded, hash-identified `start_abi` command receipt.
    This is not an oracle for correctness of the dynamic loader or providers.
    """
    stdout, stderr = _complete_capture(stdout_raw, stderr_raw, status)
    manifest_path = (pathlib.Path(__file__).resolve().parents[1] /
                     'reference/P4_Build5_Static_ELF_Manifest.json')
    if hash_file(manifest_path) != FROZEN_ELF_MANIFEST_SHA256:
        raise GateError('Frozen static ELF manifest identity mismatch')
    manifest = manifest if manifest is not None else json.loads(manifest_path.read_text())
    targets = (('exec', 'bin/step-g', EXEC_TARGET, 2, 3),
               ('plugin', 'libexec/step/libstep-schema-ap242e2.so', PLUGIN_TARGET, 4, 5))
    out_lines = stdout.splitlines()
    err_lines = stderr.splitlines()
    pos = _ordered_single_markers(out_lines, ABI_MARKERS, 'stdout')
    dbg = _ordered_single_markers(err_lines, DEBUG_MARKERS, 'stderr')
    if pos[0] != 0:
        raise GateError('ABI unattributed leading stdout before initial marker')
    if pos[-1] != len(out_lines)-1 or dbg[0] != 0 or dbg[-1] != len(err_lines)-1:
        raise GateError('ABI evidence trailing data or unattributed stderr')
    if pos[1] != pos[0]+1:
        raise GateError('ABI initial rehash marker not adjacent')
    # Each same-stream frame pair is consecutive in the frozen ABI_SHELL.
    # Unattributed output between frames must not evade either parser.
    if pos[4] != pos[3]+1:
        raise GateError('ABI unattributed stdout between dependency listing frames')
    if dbg[2] != dbg[1]+1:
        raise GateError('ABI unattributed stderr between loader diagnostic frames')
    version_lines = out_lines[pos[1]+1:pos[2]]
    if not 0 < len(version_lines) <= 12 or not any(
        'version ' in line and ('ld.so' in line or 'ld-linux' in line)
        for line in version_lines):
        raise GateError('Loader --version output absent or malformed')
    # P432-R1: explicit anomalies in the bounded --version stdout are not
    # attributed to either dependency-listing frame. Reuse the existing
    # conservative loader-error predicates; this is not ABI semantic proof.
    if any(LOADER_FAILURE.search(line) or LOADER_ABI_ANOMALY.search(line)
           for line in version_lines):
        raise GateError('Loader --version output contains error or ABI anomaly')
    provider_lines = out_lines[pos[5]+1:pos[6]]
    if len(provider_lines) != len(PROVIDER_PATHS):
        raise GateError('Provider identity hash section incomplete')
    actual_paths = []
    for line in provider_lines:
        m = re.fullmatch(r'([0-9a-f]{64})  (/[^\s]+)', line)
        if m is None:
            raise GateError('Malformed provider hash record')
        actual_paths.append(m.group(2))
    if tuple(actual_paths) != PROVIDER_PATHS:
        raise GateError('Provider hash path order or identity mismatch')
    if pos[7] != pos[6]+1:
        raise GateError('Missing or extra data after provider hash marker')
    details = {}
    for label, key, target, start, stop in targets:
        closure = _manifest_closure(manifest, key)
        dependency = _dependency_listing(out_lines[pos[start]+1:pos[stop]],
                                         closure, label)
        debug = _version_diagnostics(err_lines[dbg[0 if label=='exec' else 2]+1:
                                               dbg[1 if label=='exec' else 3]],
                                     target, closure, dependency['resolved_paths'],
                                     manifest, label)
        details[label] = {'dependencies': dependency, 'debug': debug}
    return {'loader_dependency_listing_complete': True,
            'completeness_scope': 'FROZEN_BUNDLED_ELF_TRANSITIVE_CLOSURE_ONLY',
            'image_provider_transitive_abi': 'INDEPENDENT_REVIEW_HOLD',
            'raw_stdout_sha256': status['stdout_sha256'],
            'raw_stderr_sha256': status['stderr_sha256'],
            'raw_stdout_bytes': status['stdout_bytes'],
            'raw_stderr_bytes': status['stderr_bytes'],
            'structurally_checked': details,
            'explicit_plugin_dispatch': 'NOT_TESTED',
            'provider_version_acceptance': 'INDEPENDENT_REVIEW_HOLD',
            'entrypoint_step_g_invoked': False, 'step_geometry_invoked': False}



# The frozen fixture_canary.sh precedes ABI_SHELL within ONE start_abi
# command. Its stdout is a distinct security phase, not unframed ABI data.
# These fixed fields are emitted in this exact order by the hash-pinned canary.
CANARY_FIXED_PREFIX = (
    'ROUTES_EMPTY:yes', 'IPV6_ROUTES_EMPTY:yes', 'ONLY_LOOPBACK:yes',
    'NET_CONNECT_DENIED:yes', 'SCRATCH_WRITE_PASS:yes',
    'DENY_ETC:yes', 'DENY_RUNTIME:yes', 'DENY_FIXTURES:yes',
    'DENY_DEV:yes', 'DENY_DEV_SHM:yes', 'DENY_PROC:yes', 'DENY_SYS:yes',
    'DENY_ROOT:yes', 'DENY_TMP:yes', 'DENY_VAR_TMP:yes',
    'UID_GID:65534:65534', 'NO_NEW_PRIVS:1',
    'CAP_EFF:0000000000000000',
)
CANARY_CGROUP_FIELDS = (
    'memory.max', 'memory.swap.max', 'pids.max',
    'memory.current', 'memory.swap.current', 'pids.current',
    'memory.events', 'memory.swap.events', 'pids.events',
)


def _canary_stdout_mountinfo(canary_raw):
    """Frame the exact frozen canary output; no unattributed prefix lines."""
    if not isinstance(canary_raw, bytes) or not canary_raw.endswith(b'FROZEN_PASS:yes\n'):
        raise GateError('Canary phase lacks final authenticated PASS boundary')
    try:
        text = canary_raw.decode('utf-8', 'strict')
    except UnicodeDecodeError as exc:
        raise GateError('Canary phase invalid UTF-8') from exc
    lines = text.splitlines()
    first_field_count = 1 + len(CANARY_FIXED_PREFIX) + len(CANARY_CGROUP_FIELDS)
    if (len(lines) < first_field_count + 4 or
        re.fullmatch(r'NETNS_MARKER:net:\[\d+\]', lines[0]) is None or
        tuple(lines[1:1+len(CANARY_FIXED_PREFIX)]) != CANARY_FIXED_PREFIX):
        raise GateError('Canary static marker order or identity invalid')
    for index, key in enumerate(CANARY_CGROUP_FIELDS, 1+len(CANARY_FIXED_PREFIX)):
        if not lines[index].startswith(key + ':') or not lines[index][len(key)+1:]:
            raise GateError('Canary cgroup field missing/reordered: ' + key)
    if (lines[first_field_count] != 'MOUNTINFO_BEGIN' or
        lines[-2:] != ['MOUNTINFO_END', 'FROZEN_PASS:yes'] or
        lines.count('MOUNTINFO_BEGIN') != 1 or
        lines.count('MOUNTINFO_END') != 1 or
        lines.count('FROZEN_PASS:yes') != 1 or
        not lines[first_field_count+1:-2]):
        raise GateError('Canary mountinfo frame or final PASS boundary invalid')
    return '\n'.join(lines[first_field_count+1:-2]) + '\n'


def check_combined_canary_abi(stdout_raw, stderr_raw, status, host_ns,
                              masked_paths=None, manifest=None):
    """Verify complete original receipt, canary phase, then strict ABI slice.

    Never substitute a derived receipt for the immutable original start_abi
    command receipt. Return the slice and exact source-byte provenance for
    separate evidence preservation. No provider ABI decision is made here.
    """
    _complete_capture(stdout_raw, stderr_raw, status)  # FULL original bytes
    if hash_file(pathlib.Path(__file__).resolve().parents[1] /
                 'ci/fixture_canary.sh') != EXPECTED_CONTROL_SHA256['ci/fixture_canary.sh']:
        raise GateError('Frozen security canary source hash mismatch')
    boundary = b'FROZEN_PASS:yes\nP4_ABI_BEGIN\n'
    first_abi = b'P4_ABI_BEGIN\n'
    if (stdout_raw.count(first_abi) != 1 or
        stdout_raw.count(b'FROZEN_PASS:yes\n') != 1 or
        stdout_raw.count(boundary) != 1):
        raise GateError('Canary/ABI transition missing, duplicated or reordered')
    offset = stdout_raw.index(first_abi)
    if offset == 0 or stdout_raw[offset-len(b'FROZEN_PASS:yes\n'):offset] != b'FROZEN_PASS:yes\n':
        raise GateError('Canary/ABI transition is not immediately adjacent')
    canary_raw = stdout_raw[:offset]
    abi_raw = stdout_raw[offset:]
    mountinfo = _canary_stdout_mountinfo(canary_raw)
    # The frozen P3.2.1 security checker is applied to the isolated prefix,
    # never to ABI data that might accidentally satisfy canary markers.
    security = verify_canary(canary_raw.decode('utf-8'), host_ns, mountinfo,
                             masked_paths=masked_paths)
    # Derived status contains only fields needed by the strict ABI checker.
    # The original command status, files and hashes remain unchanged.
    abi_status = {
        'rc': status['rc'], 'timed_out': status['timed_out'],
        'stdout_cap': status['stdout_cap'], 'stderr_cap': status['stderr_cap'],
        'stdout_bytes': len(abi_raw), 'stderr_bytes': len(stderr_raw),
        'stdout_sha256': hashlib.sha256(abi_raw).hexdigest(),
        'stderr_sha256': status['stderr_sha256'],
    }
    abi = check_abi_markers(abi_raw, stderr_raw, abi_status, manifest=manifest)
    source = {
        'original_command_label': 'start_abi',
        'original_stdout_file': status.get('stdout_file', 'start_abi.stdout.bin'),
        'original_stderr_file': status.get('stderr_file', 'start_abi.stderr.bin'),
        'original_stdout_bytes': len(stdout_raw),
        'original_stdout_sha256': status['stdout_sha256'],
        'original_stderr_bytes': len(stderr_raw),
        'original_stderr_sha256': status['stderr_sha256'],
        'canary_stdout_offset_bytes': 0,
        'canary_stdout_bytes': len(canary_raw),
        'canary_stdout_sha256': hashlib.sha256(canary_raw).hexdigest(),
        'abi_stdout_offset_bytes': offset,
        'abi_stdout_bytes': len(abi_raw),
        'abi_stdout_sha256': abi_status['stdout_sha256'],
        'abi_stderr_offset_bytes': 0,
        'abi_stderr_bytes': len(stderr_raw),
        'abi_stderr_sha256': status['stderr_sha256'],
        'verified_exact_concatenation': (
            canary_raw + abi_raw == stdout_raw and offset + len(abi_raw) == len(stdout_raw)),
        'transition': 'FROZEN_PASS:yes\nP4_ABI_BEGIN\n',
        'security_canary_sha256': EXPECTED_CONTROL_SHA256['ci/fixture_canary.sh'],
    }
    if not source['verified_exact_concatenation']:
        raise GateError('Canary/ABI derived stream provenance invalid')
    return security, abi, source, abi_raw


def cleanup_scratch(scratch, remover=None):
    """Fail closed on *both* deletion errors and a surviving host scratch path."""
    remover = shutil.rmtree if remover is None else remover
    scratch = pathlib.Path(scratch)
    result = {'host_scratch_path': str(scratch), 'status': 'HOLD',
              'deletion_attempted': False, 'verified_absent': False}
    try:
        if scratch.is_symlink() or not scratch.is_dir():
            raise GateError('Expected controller-created scratch directory absent or replaced')
        result['deletion_attempted'] = True
        remover(scratch)  # Never ignore errors; rmtree refuses a symlink root.
    except Exception as exc:
        result['deletion_error'] = repr(exc)
    try:
        # lexists catches dangling symlinks; pathlib.Path.exists would not.
        surviving = os.path.lexists(scratch)
        result['surviving_path'] = bool(surviving)
        if not surviving and 'deletion_error' not in result:
            result['verified_absent'] = True
            result['status'] = 'VERIFIED'
    except Exception as exc:
        result['verification_error'] = repr(exc)
    return result


def record_scratch_cleanup(rec, scratch, remover=None):
    rec['host_scratch_cleanup'] = cleanup_scratch(scratch, remover)
    if rec['host_scratch_cleanup']['status'] != 'VERIFIED':
        rec['status'] = 'HOLD'
    return rec['host_scratch_cleanup']


def controller_exit_code(rec):
    return (0 if rec.get('status') ==
            'PASS_RAW_ABI_LOADER_EVIDENCE_ONLY_NOT_PROVIDER_ACCEPTANCE' and
            rec.get('controller_cleanup') == 'VERIFIED' and
            rec.get('host_scratch_cleanup', {}).get('status') == 'VERIFIED'
            else 1)


def seal_controller_evidence(out, rec, scratch, remover=None):
    """Apply final host cleanup gate *before* writing and sealing final evidence."""
    out = pathlib.Path(out)
    record_scratch_cleanup(rec, scratch, remover)
    write_json(out/'SECURITY_PREFLIGHT.json', rec)
    # Intermediate manifest; independent workflow later applies final post-cleanup.
    for f in sorted(out.rglob('*')):
        if f.is_symlink():
            raise GateError('Symlink evidence not allowed')
    rawlist=[]
    for f in sorted(out.rglob('*')):
        if f.is_file() and f.name != 'SHA256SUMS.txt':
            rawlist.append(f'{hash_file(f)}  {f.relative_to(out).as_posix()}\n')
    (out/'SHA256SUMS.txt').write_text(''.join(rawlist))
    return controller_exit_code(rec)

def _public_tree_manifest(root, expected, executable=()):
    """Fail-closed public bind mount preparation; never touch private scratch.

    expected is authenticated SHA-256 data, not inferred from a directory walk.
    Directory mode 0755 and regular-file mode 0644/0755 establish safe
    traverse/read access for UID/GID 65534 independent of host ownership.
    This proves host bind-source mode bits, not future container mount success.
    """
    root = pathlib.Path(root)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise GateError('Public bind root absent, relative or symlink')
    if not isinstance(expected, dict) or not expected or len(expected) > 2600:
        raise GateError('Public bind expected-file inventory invalid')
    executable = set(executable)
    if not executable.issubset(expected):
        raise GateError('Uninventoried executable public file')
    dirs = {''}
    for name, digest in expected.items():
        if (not isinstance(name, str) or len(name) > 240 or
            not all(32 <= ord(ch) <= 126 and ch != chr(92) for ch in name) or
            any(p in ('', '.', '..') for p in name.split('/')) or
            not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest)):
            raise GateError('Invalid public bind file path/digest')
        parts = name.split('/')
        dirs.update('/'.join(parts[:i]) for i in range(1, len(parts)))
    observed_dirs = set()
    observed_files = set()
    def walk_error(exc):
        raise GateError('Public bind tree traversal failed') from exc
    for parent, childdirs, files in os.walk(root, topdown=True, followlinks=False,
                                           onerror=walk_error):
        directory = pathlib.Path(parent)
        relative = directory.relative_to(root).as_posix()
        relative = '' if relative == '.' else relative
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or directory.is_symlink():
            raise GateError('Non-directory or symlink in public bind tree')
        observed_dirs.add(relative)
        for name in childdirs:
            child = directory/name
            if not stat.S_ISDIR(child.lstat().st_mode) or child.is_symlink():
                raise GateError('Unexpected symlink/non-directory public bind path')
        for name in files:
            file = directory/name
            rel = file.relative_to(root).as_posix()
            if not stat.S_ISREG(file.lstat().st_mode) or file.is_symlink():
                raise GateError('Unexpected symlink/nonregular public bind file')
            observed_files.add(rel)
    if observed_dirs != dirs or observed_files != set(expected):
        raise GateError('Unexpected/missing public bind files or directories')
    # Authenticate before changing metadata; never silently repair bytes.
    for name, digest in expected.items():
        if hash_file(root/name) != digest:
            raise GateError('Public bind bytes failed pre-permission authentication: '+name)
    try:
        for name in sorted(dirs, key=lambda x: x.count('/'), reverse=True):
            (root/name).chmod(0o755)
        for name in sorted(expected):
            (root/name).chmod(0o755 if name in executable else 0o644)
    except OSError as exc:
        raise GateError('Public bind permission setting failed') from exc
    # Exact modes are also a conservative UID=65534 read/traversal proof:
    # every owner/group/other class has the needed bits; no write for others.
    for name in dirs:
        entry = root/name
        info = entry.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o755:
            raise GateError('Public bind directory mode mismatch: '+name)
    for name, digest in expected.items():
        entry = root/name
        info = entry.lstat()
        required = 0o755 if name in executable else 0o644
        if (not stat.S_ISREG(info.st_mode) or
            stat.S_IMODE(info.st_mode) != required or hash_file(entry) != digest):
            raise GateError('Public bind file mode or post-permission SHA mismatch: '+name)
    records = ''.join(name+' '+expected[name]+'\n' for name in sorted(expected))
    return {'directory_count':len(dirs), 'file_count':len(expected),
            'directories_mode':'0755', 'nonexecutables_mode':'0644',
            'explicit_executable_mode':'0755', 'uid_gid':'65534:65534',
            'uid_65534_read_traversal':'PASS_STATIC_MODE_BITS_ONLY',
            'exact_file_sha256_inventory_sha256':hashlib.sha256(records.encode()).hexdigest(),
            'symlink_count':0, 'bytes_unchanged':True,
            'container_access_and_ABI':'NOT_TESTED'}


def _authenticated_runtime_public_files(root, extracted):
    """Rebuild the already-attested 2410-file inventory, without new trust pins."""
    root = pathlib.Path(root)
    obj = json.loads((root/'MANIFEST.json').read_text())
    entries = obj.get('files') if isinstance(obj, dict) else None
    if not isinstance(entries, list) or len(entries) != 2408:
        raise GateError('Authenticated runtime manifest census invalid')
    file_map = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise GateError('Runtime manifest entry malformed')
        name, digest = entry.get('path'), entry.get('sha256')
        if not isinstance(name, str) or name in file_map:
            raise GateError('Runtime manifest duplicate/invalid path')
        file_map[name] = digest
    if 'MANIFEST.json' in file_map or 'SHA256SUMS' in file_map:
        raise GateError('Runtime manifest overlaps metadata files')
    if hash_file(root/'MANIFEST.json') != extracted['manifest_sha256']:
        raise GateError('Runtime manifest identity lost after safe extraction')
    file_map['MANIFEST.json'] = extracted['manifest_sha256']
    file_map['SHA256SUMS'] = hash_file(root/'SHA256SUMS')
    if len(file_map) != extracted['files_extracted'] or len(file_map) != 2410:
        raise GateError('Runtime files differ from authenticated extraction')
    return file_map


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',required=True)
    args=ap.parse_args()
    out=pathlib.Path(args.output).resolve();out.mkdir(parents=True,exist_ok=True)
    ev=out/'raw';ev.mkdir(exist_ok=True)
    src=pathlib.Path(__file__).resolve().parents[1]
    rec={'status':'HOLD','qualification':'P4_ABI_DEPENDENCY_LIST_ONLY',
         'source_commit':CONTROL_COMMIT,'original_security_run':42524555371,
         'original_build_artifact':ARTIFACT_ID,'no_step_g_entrypoint':True,
         'no_plugin_registration_test':True,'no_step_geometry':True,'commands':{}}
    started=time.monotonic();name='adr001-p4-abi-'+str(os.getpid())
    parent=pathlib.Path(os.environ.get('RUNNER_TEMP','/tmp'))
    scratch=parent/('adr001-p4-abi-'+str(os.getpid()))
    scratch.mkdir(mode=0o700)
    created=False
    def cmd(tag,argv,sec=30,cap=4_000_000):
        if time.monotonic()-started>480:raise GateError('ABI controller deadline reached')
        status=command(argv,timeout=sec,evidence=ev,label=tag,byte_cap=cap)
        rec['commands'][tag]=status
        return status
    def contents(tag,argv,sec=30):
        s=cmd(tag,argv,sec);require_success(s);return stdout_text(s,ev)
    try:
        rec['control_source_sha256']=verify_control_source(src)
        if not os.environ.get('GH_TOKEN'):
            raise GateError('GH_TOKEN absent: no acquisition permitted')
        if os.uname().machine!='x86_64':raise GateError('x86-64 host required')
        rec['host_namespace']=os.readlink('/proc/self/ns/net')
        b=build_artifact_download(260_000_000)
        if len(b)!=224909478 or hash_bytes(b)!=ZIP_SHA:
            raise GateError('Original Build #5 outer ZIP size/hash mismatch')
        with zipfile.ZipFile(io.BytesIO(b)) as z:
            if z.testzip() is not None:raise GateError('Original ZIP CRC failed')
            tb=z.read('brlcad-runtime.tar.gz')
        if hash_bytes(tb)!=TAR_SHA:raise GateError('Original runtime tar SHA mismatch')
        archive=scratch/'runtime.tar.gz';archive.write_bytes(tb)
        runtime=scratch/'runtime';runtime.mkdir()
        rec['runtime_manifest']=safe_extract_runtime(archive,runtime)
        if rec['runtime_manifest']['step_g_sha256']!=BINARY_SHA or rec['runtime_manifest']['plugin_sha256']!=PLUGIN_SHA:
            raise GateError('Original Build #5 binary SHA mismatch')
        # Normalize only the authenticated disposable bind source, not scratch.
        rec['runtime_public_permissions'] = _public_tree_manifest(
            runtime, _authenticated_runtime_public_files(runtime, rec['runtime_manifest']),
            executable=('bin/step-g',))
        fixtures=scratch/'fixtures';fixtures.mkdir()
        rec['fixtures']=[]
        for fn,owner,repo,blob,digest in FIXTURES:
            metadata=json.loads(bounded_http(f'https://api.github.com/repos/{owner}/{repo}/git/blobs/{blob}',100_000))
            if metadata.get('sha')!=blob or metadata.get('encoding')!='base64':
                raise GateError('Fixture metadata mismatch '+fn)
            data=base64.b64decode(metadata['content'])
            gitsha=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
            if gitsha!=blob or hash_bytes(data)!=digest or not data.startswith(b'ISO-10303-21;'):
                raise GateError('Public fixture identity mismatch '+fn)
            (fixtures/fn).write_bytes(data)
            rec['fixtures'].append({'name':fn,'git_blob':blob,'sha256':digest})
        rec['fixtures_public_permissions'] = _public_tree_manifest(
            fixtures, {item['name']:item['sha256'] for item in rec['fixtures']})
        info=json.loads(contents('docker_info',['docker','info','--format','{{json .}}']))
        rec['docker_cgroup_version']=verify_docker_cgroup_v2(info)
        rec['docker_version']=contents('docker_version',['docker','version','--format','{{.Server.Version}}']).strip()
        require_success(cmd('image_pull',['docker','pull','--platform','linux/amd64',IMAGE],120))
        image=docker_json(cmd('image_inspect',['docker','image','inspect',IMAGE,'--format','{{json .}}']),ev)
        if image.get('Architecture')!='amd64' or image.get('Id')!=EXPECTED_IMAGE_ID or not any(
            IMAGE.split('@')[1] in d for d in image.get('RepoDigests') or []):
            raise GateError('Pinned image digest/ID mismatch')
        script=(src/'ci/fixture_canary.sh').read_text()+ '\n' + ABI_SHELL
        args=['docker','create','--name',name,'--label','adr001.p4=abi-only',
              '--platform','linux/amd64','--read-only','--network','none','--ipc','none','--cgroupns','private',
              '--cap-drop','ALL','--security-opt','no-new-privileges:true','--user','65534:65534',
              '--pids-limit',str(PID_MAX),'--memory',str(MEM),'--memory-swap',str(MEM),
              '--memory-swappiness','0','--cpus','1','--ulimit','core=0:0',
              '--ulimit','fsize=8388608:8388608',
              '--tmpfs','/scratch:rw,nosuid,nodev,noexec,size=67108864,mode=1777',
              '--mount',f'type=bind,src={runtime},dst=/runtime,readonly',
              '--mount',f'type=bind,src={fixtures},dst=/fixtures,readonly',
              '-e','HOME=/scratch','-e','TMPDIR=/scratch',IMAGE,'/bin/sh','-ec',script]
        require_success(cmd('create_abi',args,35));created=True
        observed=docker_json(cmd('inspect_abi',['docker','inspect',name,'--format','{{json .}}']),ev)
        verify_container_inspect(observed,str(runtime),str(fixtures),EXPECTED_IMAGE_ID,info)
        probe=cmd('start_abi',['docker','start','-a',name],60)
        bounded_complete_streams(ev/probe['stdout_file'],ev/probe['stderr_file'],4_000_000)
        require_success(probe)
        # Original start_abi stdout/stderr and receipt remain unmodified.
        security, abi, source, abi_only_stdout = check_combined_canary_abi(
            (ev/probe['stdout_file']).read_bytes(),
            (ev/probe['stderr_file']).read_bytes(), probe, rec['host_namespace'],
            masked_paths=(observed.get('HostConfig') or {}).get('MaskedPaths'))
        # Preserve derived bytes in a distinct, non-overwriting file, linked to
        # the exact full start_abi capture by offset/length/SHA-256.
        derived_file = ev/'start_abi.abi_only.stdout.bin'
        with derived_file.open('xb') as f:
            f.write(abi_only_stdout)
        if (derived_file.stat().st_size != source['abi_stdout_bytes'] or
            hash_file(derived_file) != source['abi_stdout_sha256']):
            raise GateError('Derived ABI evidence file mismatch')
        source['derived_abi_stdout_file'] = derived_file.name
        rec['security_in_same_container'] = security
        rec['abi_evidence_slice'] = source
        rec['abi_raw'] = abi
        rec['status']='PASS_RAW_ABI_LOADER_EVIDENCE_ONLY_NOT_PROVIDER_ACCEPTANCE'
    except Exception as exc:
        rec['error']=repr(exc)
        rec['status']='HOLD'
    finally:
        if created:
            try:
                rm=cmd('remove_abi',['docker','rm','-f',name],25)
                ins=cmd('inspect_after_removal',['docker','inspect',name],15)
                ids=contents('labeled_after_cleanup',['docker','ps','-aq','--no-trunc','--filter','label=adr001.p4=abi-only']).splitlines()
                verify_cleanup_observed(rm['rc'],ins['rc'],ids,{})
                rec['controller_cleanup']='VERIFIED'
            except Exception as exc:
                rec['controller_cleanup']='HOLD '+repr(exc)
                rec['status']='HOLD'
        else:
            rec['controller_cleanup']='NO_CONTAINER_CREATED'
        # Host scratch gate precedes the receipt and complete evidence census.
        rec['elapsed_seconds']=time.monotonic()-started
        exit_code=seal_controller_evidence(out,rec,scratch)
    return exit_code

if __name__=='__main__':raise SystemExit(main())
