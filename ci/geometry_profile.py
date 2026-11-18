"""Headless engineering-toolkit contents, separate from frozen Build #5."""
from pathlib import Path

EXECUTABLES = ('step-g', 'g-step', 'gsh', 'gqa')
# Match all seven schema targets actually built by the pinned upstream tree.
# AP242 editions share a FILE_SCHEMA identifier but differ in generated bindings.
SCHEMAS = ('ap203', 'ap203e2', 'ap214', 'ap242e1', 'ap242e2', 'ap242e3', 'ap242e4')
BUILD_TARGETS = EXECUTABLES + ('ged_subprocesses',)

# BRL-CAD src/CMakeLists.txt consumes a CMake list, not bext's colon profile.
# Invalid single-string values can silently omit every source component and
# fail only after the multi-hour bext dependency build.
SOURCE_COMPONENTS = ('conv', 'gtools')


def cmake_source_components_arg(components=SOURCE_COMPONENTS):
    import re
    if not components or len(set(components)) != len(components):
        raise ValueError('Missing or duplicate BRL-CAD source component')
    if any(not isinstance(name, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]*', name)
           for name in components):
        raise ValueError('Each BRL-CAD source component must be a single directory name')
    return '-DBRLCAD_COMPONENTS=' + ';'.join(components)


def runtime_layout(build, targets):
    """Resolve required executables and plugin/subprocess products from CMake."""
    build = Path(build).resolve()
    layout = {}
    for name in EXECUTABLES:
        artifacts = targets.get(name, [])
        if len(artifacts) != 1 or not artifacts[0].is_file():
            raise RuntimeError(f'Missing/ambiguous executable target: {name}')
        layout['bin/' + name] = artifacts[0]
    for schema in SCHEMAS:
        artifacts = targets.get('step-schema-' + schema, [])
        if len(artifacts) != 1 or not artifacts[0].is_file():
            raise RuntimeError(f'Missing/ambiguous schema target: {schema}')
        layout['libexec/step/' + artifacts[0].name] = artifacts[0]
    # gsh command modules and spawned GED helpers are runtime dependencies too.
    # Select only artifacts produced by the configured target graph; do not
    # recursively package the runner, source tree or compiler workspace.
    allowed = ('libexec/ged/', 'libexec/dm/', 'libexec/ged_exec/')
    for artifacts in targets.values():
        for artifact in artifacts:
            artifact = Path(artifact)
            if not artifact.is_file():
                continue
            try:
                rel = artifact.resolve().relative_to(build).as_posix()
            except ValueError:
                continue
            if rel.startswith(allowed):
                old = layout.get(rel)
                if old is not None and old.resolve() != artifact.resolve():
                    raise RuntimeError(f'Runtime path collision: {rel}')
                layout[rel] = artifact
    return layout


def runpath(relative):
    import os
    parent = Path(relative).parent.as_posix()
    return '$ORIGIN/' + os.path.relpath('lib', parent)


def manifest_role(relative):
    if relative.startswith(('bin/', 'libexec/ged_exec/')):
        return 'executable'
    if relative.startswith('libexec/'):
        return 'plugin'
    if relative.startswith('lib/'):
        return 'library'
    if relative.startswith('licenses/'):
        return 'license'
    if relative.startswith('share/'):
        return 'application-data'
    return 'evidence'
