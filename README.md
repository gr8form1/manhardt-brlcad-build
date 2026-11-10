# Staged workflow update — November 10, 2026

A separate, **manual-only** workflow now exists at
`.github/workflows/build-brlcad-staged.yml`. Its definition is also
registered on the default branch so GitHub Actions can display and dispatch
it, but both jobs have a strict
`refs/heads/feature/reusable-geometry-toolkit` branch guard.

The dependency job compiles the same pinned bext prefix and uploads an
authenticated tar checkpoint. The completion job downloads that checkpoint
from the **same GitHub run and commit**, rejects any changed source pin,
runner-image identity, compiler binary hash, absolute build path or file
inventory, then compiles the pinned BRL-CAD targets and packages the seven
required schema libraries. Both jobs have independent 240-minute limits;
no automatic retries, source substitution or OEM CAD are included.

**No native staged execution or release acceptance has yet taken place.**
The staged workflow avoids the aggregate four-hour single-job deadline;
it does not eliminate compilation or guarantee artifact-size and
cross-job ABI acceptance. The dependency checkpoint is capped at 1.8 GB,
and the completion job fails closed if its same-run checkpoint is missing
or incompatible. Both outputs have one-day retention and need prompt
independent archive custody.

The original `build-brlcad.yml` and frozen Build #8 artifacts are unchanged.
No Lenovo audio services or production numerical pipelines are altered.

---

# Current execution status and AP242 schema-closure correction — November 10, 2026

**Current active implementation branch:** `feature/reusable-geometry-toolkit`.
The November 7 candidate description below is historical. Its statements that the
repository has not been created or that no GitHub build has run are superseded.
Do not use those statements to determine current execution or qualification status.

**Authenticated baseline:** Build #8, GitHub run `42743543664`, branch commit
`f847b636be24d8499b44b075483cf1f5562a9ab1`, completed successfully.
It compiled stock target files for seven STEP editions, but the reusable
runtime profile selected only `ap203`, `ap214`, and `ap242e2`, so the
relocated artifact lacked `libstep-schema-ap242e4.so`. Independently replayed
automatic `step-g` import of a public tetrahedron failed with that missing
library; explicit AP242e2 import of the same tetrahedron succeeded.

**Corrective scope for the next manually dispatched workflow:**

- Retain existing pinned BRL-CAD, bext, STEPcode, openNURBS, CMake, GCC,
  command sources, branch isolation and 240-minute CI timeout.
- Require and package all seven stock plugins: AP203, AP203e2, AP214,
  AP242e1, AP242e2, AP242e3 and AP242e4. The build target graph already
  produces these binaries; packaging is the defect.
- Reuse the two independent relocated-prefix checks and full SHA-256
  manifests, now covering the expanded plugin and dynamic-library closure.
- Exercise the existing AP242e2 analytic tetrahedron round trip, plus a
  separate explicit AP242e4 **strict no-repair** native import, geometric
  inspection, export and strict reimport; also check automatic selection
  without asserting that a shared Part 21 FILE_SCHEMA text identifies an
  exact AP242 edition.
- Preserve the successful Build #8 artifact and frozen Build #5 unchanged.
  No manufacturer CAD, customer data, account credentials, geometry repair
  or solver-production authority is introduced into the public repository.

**Qualification boundary:** passing these tests establishes only an
authenticated, portable schema-complete CLI candidate on the public
analytic fixture. It does NOT establish AP242 edition identification for
an OEM STEP, unchanged geometry on arbitrary curved surfaces, SPK16/C16
source equivalence, mesh suitability or acoustic-model correctness.
Those remain under VQ-001 G1 HOLD pending independent source-grounded
cross-kernel testing.

**Dispatch:** this workflow is intentionally manual-only. Start a fresh
`workflow_dispatch` against this feature branch after the corrective
commit is verified. Do not rerun an earlier failed run: GitHub reruns use
their previous commits. Retain and independently review the artifact
before its one-day expiration. The founder's capital STOP remains in force.

---
# ADR-001 — Public BRL-CAD Build Candidate v3.0

November 7, 2026 · Implementation-side preparation · **Not dispatched or independently accepted**

This is a runnable candidate for the founder-selected two-environment architecture: GitHub builds public BRL-CAD source; private Work later qualifies the transferred runtime. **Dispatch remains HOLD pending repository selection, effective Actions permissions and billing safeguards.** No repository has been created, changed or made public by this delivery.

The founder's November 7 revision supersedes the former GitHub compilation caps. This candidate uses ordinary standard `ubuntu-24.04` resources. It contains no custom cgroups, disk/network quotas, swap control, 4 GiB/8 GiB/1 GiB/256 MiB build limits or unconditional resource-HOLD adapters. The initial build uses one worker and a **240-minute job timeout**. This is a bounded first attempt, not an estimate that compilation will finish. No automatic build retry, alternate source, fallback kernel or source repair is implemented.

## 1. Exact deployable candidate

The workflow is [.github/workflows/build-brlcad.yml](.github/workflows/build-brlcad.yml). Deploy the **reviewed files of this directory**, including `ci/` and `pins/`, to a separately approved public-source-only repository. The reserved name is `gr8form1/manhardt-brlcad-build`; it is a proposal, not an assertion that this repository exists. Do not deploy it in `gr8form1/manhardt-numerical`.

The job-level condition refuses a private repository, a different repository, a nonmanual event or an Actions rerun. The inline guard and build driver repeat those checks. A skipped job is **not** a built/qualified candidate. Changing the selected repository requires changing and reviewing all three literal guards. Concurrency serializes this workflow's jobs without cancelling an active attempt; it is not a durable one-shot permit or billing control. A new manual dispatch remains a separate founder decision.

Only `workflow_dispatch` is enabled. Checkout and upload actions are pinned to immutable commits. The token has `contents: read`; checkout does not persist credentials, and build subprocesses receive a fresh allowlisted environment without GitHub tokens, personal Git configuration or loader overrides. The upload is only `out/`, not the checkout, home directory or engineering archive. No Drive credential, private repository content, PURIFI CAD or OEM-derived geometry enters the job or artifact.

### Dispatch checklist — no action performed

| Requirement | Evidence needed before dispatch | Present status |
|---|---|---|
| Repository | Founder approves a separate public-source-only repository and its exact reviewed control commit; verify `private=false` | Proposed name only |
| Actions | Account/org/repository policy permits manual Actions and the two pinned actions; appropriate actor has dispatch permission; workflow is on default branch | Not account-verified |
| Runner | Standard GitHub-hosted x64 `ubuntu-24.04`, not a larger/paid or self-hosted runner | Fixed in YAML; actual eligibility unverified |
| Billing | Founder checks account plan, current Actions/Packages storage usage, included allowances and effective paid-usage blocking; no unapproved charge can result | Unverified; workflow is not a spending cap |
| Deployment | Review this package, then separately authorize committing it and first manual dispatch | Not authorized/performed by this delivery |

Standard public-repository runner compute is documented as free. Artifact storage can involve account usage/billing independently; one-day retention reduces retention but does not guarantee zero cost. No paid runner or package installation is requested. If the billing condition cannot be established, keep dispatch HOLD. No resource-enforcement feasibility investigation needs to be reopened.

## 2. Pinned public inputs and toolchain

| Input | Exact identity |
|---|---|
| BRL-CAD | `bc130e1e7a9f179fe95fb42cde1a7d3becb512df` · source version **7.47.0 development**, not an asserted numbered release |
| bext | `42d8d7ca57f9d2f61192b41f0b41a731f1ba6c47` |
| STEPcode | `ed686ee1d9cb8bf763ab8d61ef6d417c3b45c146` |
| openNURBS | `23fc677ba06e49212296ca75fab7fb6c2851b4ce` |
| CMake | Official Linux x64 3.31.10 archive; 55,010,952 bytes; SHA-256 `3cb3dd247b6a1de2d0f4b20c6fd4326c9024e894cebc9dc8699758887e566ca7` |
| Checkout action | `11bd71901bbe5b1630ceea73d27597364c9af683` |
| Artifact upload action | `ea165f8d65b6e75b540449e92b4886f43607fa02` |

`pins/sources.json` preserves the accepted public source inventory, including every bext root gitlink. Its SGM fields are historical inventory only; SGM is never acquired or built. `built_binary_hashes: null` correctly represents that no binaries exist from this candidate.

The driver verifies CMake's archive digest/size before extraction, exact Git HEADs and pinned STEPcode/openNURBS gitlinks. Other selected bext submodules are pinned transitively by their repository gitlinks and their initialized identities are recorded. Stock version-matched bext patches remain part of the pinned recipe; their bytes/hashes are retained. No locally authored patch or version change is applied.

Use the runner's existing GCC/G++ 13, Make, Git, curl, patch, readelf, ldd, patchelf, Python 3 and `/usr/bin/time`. Actual paths, binary hashes, versions, ImageOS/ImageVersion and installed package inventory are recorded. Missing tools stop the attempt; there is no `apt`, root install, substitute compiler or fallback build. Parent compile flags request generic x86-64; **all dependency flags and actual ISA requirements still require artifact review**. The moving runner image is recorded rather than falsely described as a reproducible frozen OS. This is a reproducible recipe, not a claim of byte-identical repeated binaries.

## 3. Stock dependency and target approach

`ci/build.py` contains the complete command argv; no unpublished command plan or unconditional-HOLD shell is needed. It:

1. Creates fresh runner-temp source/build/tool/private-install directories and an `out/` evidence directory. Refuses reuse.
2. Acquires the authenticated CMake and pinned public Git sources. Uses a clean home/config environment.
3. Configures pinned bext using the supported expanded `conv` directory closure, `ENABLE_ALL=OFF`, core/extra BRL-CAD dependency groups enabled and Qt/Tcl/GDAL/Appleseed/OSPRay groups disabled. Builds selected stock providers with one worker into a private prefix.
4. Configures BRL-CAD against that prefix using `BRLCAD_COMPONENTS=conv`, STEP enabled, minimal/headless settings, shared libraries and no docs/tests/example geometry. GUI-facing features are disabled. Builds **only main target `step-g`**, never the main all/install target, mged or SGM.
5. Reads CMake File API output to locate actual executables/plugins rather than guessing filenames. The stock `step-g` target requires seven schema-module outputs; those are built. AP242e2 alone is selected for the minimum transfer profile.
6. Computes the actual recursive ELF runtime closure, gathers notices, relocates copied ELFs, performs two-prefix smoke checks, and emits a tarball plus evidence.

The supported directory-level dependency closure is wider than an ideal one-plugin graph. Pinned bext can select OpenVDB, Bullet, asset-import or OSMesa support through `conv` dependencies even though the main target disables optional consumers. We do not patch upstream graphs or promise these support libraries are excluded. No GUI application or unrelated main executable is requested. System versus bundled providers, nested submodules, stock patches, configure cache, File API graph, ExternalProject logs and bext install manifest are retained so the **actual selected closure** can be reviewed. If the stock recipe fails or unexpectedly needs a new dependency/version/source patch, retain the failed attempt and return for review; do not silently repair it.

No build has been performed in Work or GitHub. These source-backed commands have not yet established that the graph completes within 240 minutes, or that every optional provider behaves as expected.

## 4. Artifact, relocation and version contract

See [ARTIFACT_CONTRACT.md](ARTIFACT_CONTRACT.md). The essential payload is `bin/step-g`, `libexec/step/<actual AP242e2 module>`, actual nonbaseline libraries under `lib/`, licenses and source/build evidence. Host libc, ELF loader, libstdc++ and libgcc are not blindly copied. Required versioned symbols/ISA and allowed destination providers must be independently checked in Work and again on Lenovo.

The packager uses existing `patchelf` **on copied binaries only**, recording original/new hashes and exact RPATH changes. It requires unchanged NEEDED, SONAME, interpreter and `.text`/`.rodata` hashes. These checks do not prove complete functional equivalence. The original main build, bext build and dependency output trees are temporarily renamed during two-prefix loader/help/library-version smoke tests, then restored even on ordinary exceptions.

The pinned CLI has no `step-g --version` option. Version evidence is source/ELF identity plus an explicitly typed `bu_version()` call against the resolved bundled libbu. Help must show strict/exact/repair/report/jobs controls. Help text, module presence and ldd do **not** establish actual AP242e2 import or absence of geometric healing. No CAD is processed in this build job.

Tar/gzip metadata is canonical and regular-file-only. Executable mode 0755 is preserved inside the tar; library/module/evidence modes are 0644. Manifest schema remains `ADR001_RUNTIME_CONTENTS/2`, with exact sizes/hashes/modes. Compression and in-run log timestamps are not a promise of repeatable build output bytes. Artifacts are retained for one day: download/custody review must be arranged promptly after any future authorized build.

## 5. Work and Lenovo remain separate

The accepted v2.0 two-environment packaging/compatibility baseline remains governing except for the explicitly superseded **GitHub compilation** resource limits. Its read-only Work observations found x86-64, glibc 2.41 and libstdc++ through GLIBCXX_3.4.33; these are historical observations, not newly measured guarantees. The current instance, filesystem-execution policy and every transferred ELF/provider/symbol must be rechecked. Ubuntu 24.04 origin is plausible compatibility, not proof.

After independent build-provenance/packaging acceptance, separately authorized Work qualification must establish applicable resource/filesystem controls **before loading transferred code**, inspect safe archive extraction, authenticate external hashes, validate ELF/ISA/symbol closure, use Work's coherent libc/loader, demonstrate two-prefix relocation and execute independently authenticated AP242e2 positive/negative controls. Baseline provider hashes may differ from GitHub; the GitHub smoke's same-host hash equality is not a Work ABI requirement. Test strict/exact/no-repair behavior, diagnostics, omitted entities and tolerances. Zero exit or successful import is not whole-solid validity.

No independently prepared AP242e2 geometry fixture is newly authenticated in this delivery. The actual module load and geometric controls are explicit Work gates, not invented completed evidence. The original private SPK16 STEP requires a subsequent separate authorization. No CAD face-index correspondence is assumed.

Lenovo release needs its own CPU/ABI/dependency/performance/resource/audio-isolation/rollback qualification. Work success does not establish it. Established Lenovo numerical constraints, Stage 0B backups, audio protections, ADR-001 scientific HOLDs, October 18 capital STOP, zero production credit and S0/XL-B350 standing remain unchanged.

## 6. What has actually been verified

Run `python3 -m unittest discover -s tests -v` from this directory. The 19 tests exercise shipped helper code with synthetic data, an actual benign Python subprocess failing with status 7, log retention and local-build refusal. No compiler, ldd, ctypes, patchelf, package installation, GitHub job, CAD import, systemd or host/audio operation is run by the test suite. `review/tests.stdout` and `.stderr` contain raw results. Static checks cover YAML parsing, shell/Python syntax, fixed pins/trigger/runner/permissions, no private checkout, no unconditional-HOLD helper and no former build-resource machinery; raw results are also included. This is developer verification, not independent acceptance or a build-success claim.

Remaining genuine gates are repository/Actions/billing dispatch checks; actual first-build results/provider closure; independently accepted artifact provenance/packaging; Work runtime/geometry controls; separate private CAD authorization; and separate Lenovo release qualification. A failed attempt or missing/cancelled artifact remains nonpassing.

## 7. Source references

- [Pinned BRL-CAD source](https://github.com/BRL-CAD/brlcad/tree/bc130e1e7a9f179fe95fb42cde1a7d3becb512df): root `CMakeLists.txt`, `misc/CMake/BRLCAD_ExternalDeps.cmake`, `src/conv/step/CMakeLists.txt`, `StepPluginHost.cpp`, CLI option table, `src/libbu/vers.c` and path setup. Original authenticated source captures remain in Build Preparation v1.0.
- [Pinned bext source](https://github.com/BRL-CAD/bext/tree/42d8d7ca57f9d2f61192b41f0b41a731f1ba6c47): root CMake, dependency selectors, `.gitmodules`, STEPcode/openNURBS recipes and patches.
- [CMake 3.31.10 release](https://github.com/Kitware/CMake/releases/tag/v3.31.10).
- [GitHub workflow syntax](https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions), [standard runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners), [Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions), [runner Ubuntu 24.04 tool inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md). Published runner contents may change; the driver checks actual tools.

**Recommendation: ready as a dispatch-candidate implementation for independent review; actual dispatch HOLD until the three account/repository prerequisites are verified and deployment/dispatch is separately authorized.**
