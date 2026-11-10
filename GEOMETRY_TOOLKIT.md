# Reusable BRL-CAD engineering toolkit candidate

This adds a feature-branch manual build, **Manhardt reusable BRL-CAD geometry tools**,
while keeping the original Build #5 driver and source pins. The existing
`build-brlcad.yml` workflow entry selects the new driver only on this branch;
main and the frozen Build #5 commit remain unchanged. It builds a candidate;
it does not certify the repaired SPK16 cabinet or any acoustic calculation.

## Why this build exists

Build #5 contains `step-g` but no database shell, quantitative analysis program,
neutral-format exporter, headers or reusable CMake build tree. The Lenovo has now
demonstrated native import and database writing. Repeating that demonstration
cannot establish fidelity of repaired surfaces.

The motivating private CAD trial completed with repairs, but its diagnostic
trace disclosed material local tolerance increases. Detailed private geometry
identities and diagnostic values stay in the engineering archive, outside this
public build repository. Successful import alone cannot establish unchanged
source validation or a whole-surface accuracy bound.

## Required reusable tools

| Program | Purpose |
|---|---|
| step-g | STEP import, explicit repair policy, source-ID diagnostics |
| gsh | Native database trees, B-rep validity/solidness, bounds and detailed inspection |
| g-step | Export saved geometry to STEP for independent measurement and downstream meshing |
| gqa | Quantitative/ray-based analysis for later separately qualified uses |

Bundle AP203, AP214 and AP242e2 modules, all produced GED/DM modules, generated GED
subprocess executables, their shared-library dependencies and public application
data. A four-executable directory without those runtime dependencies is inadequate.
The new candidate uses the same upstream commit, STEPcode and OpenNURBS pins as
Build #5. No geometry-kernel source patch or automatic tolerance change is made.
This separates adding missing tools from changing importer behavior.

GUI, Tcl/Tk, Qt, OpenGL and X11 remain disabled. Existing source and dependency
acquisition/build operations run only on the explicitly selected GitHub manual
workflow, with the existing single-worker settings. Nothing installs on Lenovo.

## Checks that must execute in the new build

At two different runtime prefixes, with the original build and dependency trees
hidden, check every ELF loader dependency, compiled version and all four CLI help
paths. Run the pinned upstream AP242 direct-BREP tetrahedron through:

1. Strict import and real database write; complete 1/1 coverage and no invalid B-rep.
2. Native `gsh` top-level/object discovery, B-rep validity and solidness.
3. Native geometry-derived axis-aligned bounds for the untrimmed analytic tetrahedron, 0–10 mm on each axis within 0.001 mm. Do not use the approximate ray-sampled `bb -t` path as a micrometre-level fidelity gate.
4. Strict STEP export with explicit millimetre units and radian angles.
5. Independent standard-library STEP parsing: one solid, four faces, six edges,
   four correct vertices within 0.00001 mm, and analytic tetrahedron volume
   166.6666667 mm³ within 0.001 mm³.
6. Complete reimport of the exported STEP, and byte preservation of the database
   through the inspection commands.

Any failed check fails the candidate build; do not weaken it after seeing a
failure. These controls verify the named public tetrahedron I/O/inspection path.
They do not qualify arbitrary STEP, curved geometry, repair fidelity or acoustics.
`gqa` is bundled and its CLI is checked, but its numerical analysis is unqualified.

## Next SPK16 check, after the toolkit passes

Use a copy of the already saved database. Inspect the baffle and the selected source face and its loops, native surfaces/trim curves and actual stored tolerances.
Export a separate STEP and compare geometry, boundary locations, assembly
transforms, connected parts, bounds and volume against authenticated source.
Use the original analytic cone/circle definitions where possible, not the failed
OCCT validity flag as the sole truth. Distinguish unchanged support surfaces from
changed trim domains, loop orientation, seam insertion and tolerance allowances.

The saved private database and frozen Build #5 must stay unchanged. If the new
inspection exposes a material conversion error, fix it as a separately reviewed
kernel change with an independent analytic curved-surface regression. A rebuild
of unchanged kernel source cannot by itself fix that error. Mesh/source-boundary
and acoustic acceptance remain separate downstream questions.

## Preservation and execution

The CI artifact is a transfer copy with the existing one-day retention, not the
durable engineering archive. Before calling delivery complete, retrieve and
hash-verify the candidate, archive it in the engineering archive and Library,
and return durable links. Preserve Build #5 as the working reference.
`geometry-compiled-checkpoint.tar.gz` preserves all tools and their module/library
closure, but is not a reusable CMake build tree or SDK and is not a runnable release.
There is no claim of a trusted reusable dependency cache; this build can require
the original full dependency compilation. Source pins and all acquisition/build
logs remain preserved.

## No Unintended Consequences review

The new driver keeps the original public-repository/manual-event guard and
clean subprocess environment. Network operations are the declared public git and
CMake downloads. Builds write under the runner's new temporary attempt directory
and repository `out/`; packaging copies selected build products and public data,
adjusts only packaged ELF RUNPATH, checks code/constant-section preservation,
temporarily renames build trees with guaranteed restoration, and removes its own
temporary compiled-checkpoint directory after sealing it.

The native test uses only a public upstream fixture and generated temporary
databases. `gsh` is a general editing application; it is not represented as a
read-only utility. The particular inspection commands here are checked for input
database byte preservation. Native test commands have 90-second timeouts and help
commands have 20-second timeouts. The build has the existing 240-minute job limit.
These are build/test controls, not another execution-assurance architecture.

No user account, privilege, service, audio, reboot/shutdown, purchasing or private
geometry operation is introduced. No Lenovo operation occurs in this workflow.
Offline tests establish packaging/reference checks only; the native build and
its tests must still execute before the candidate can be accepted.
