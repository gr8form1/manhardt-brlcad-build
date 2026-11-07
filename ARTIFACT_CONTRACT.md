# Runtime artifact and acceptance contract — v3.0

This is the contract for a future build output. No runtime binary, plugin hash, completion receipt or measured build resource usage is prepopulated here.

## Output structure

| Output | Meaning / acceptance rule |
|---|---|
| `out/RESULT.json` | `ADR001_BUILD_ATTEMPT/3`; `BUILD_PACKAGE_CANDIDATE` only after the driver/packager return successfully and final evidence collection succeeds. `BUILD_ATTEMPT_FAILED` otherwise. Neither is scientific qualification. |
| `out/brlcad-runtime.tar.gz` | Canonical gzip + USTAR, single `brlcad-runtime/` path domain, regular files only, no link/special entries, uid/gid/mtime zero. Failed partial archives stay outside `out/`. |
| `out/brlcad-runtime.tar.gz.sha256` | Digest of the inner tar.gz bytes. Must be authenticated against accepted run/control-source records, not trusted merely because it travels beside the archive. |
| `out/SHA256SUMS` | Every output file except this outer census. It includes the tar and completed RESULT/evidence. |
| `out/evidence/commands/` | Exact argv/cwd, wall start, elapsed time, independent raw stdout/stderr, original exit/signal status. Nonzero commands fail unless expressly diagnostic snapshot/license lookup. |
| `source-pins.json`, `*-source.json`, `patch-inventory.json` | Pinned source/actual Git HEAD/tree/status/diff and initialized submodules; stock patch bytes retained. Full raw earlier snapshots remain command records. |
| `host-tools.json`, CMake receipt, raw package inventory | Actual runner tool versions/hashes, compiler/linker identity and host/provider environment. Runner image label alone is insufficient. |
| `stock-build-records/`, caches, target artifacts, bext install manifest | Actual selected dependencies, configure/build diagnostics and CMake File API dependency/target graph; also collected on ordinary failure. |
| `*-build-rusage.txt`, raw `df/free` | Per-command GNU time and point-in-time disk/memory observations. These are **not** aggregate hard-limit receipts and do not resurrect superseded build limits. |
| `runtime-providers.json`, relocation and loader maps | Exact bundled/nonbundled provider identity, pre/post-RPATH hashes, code/constant/NEEDED checks and two-prefix host smoke results. |
| `runtime-profile.json` | Explicitly records geometry controls/AP242e2 import as not run/tested, Work qualification pending, Lenovo pending. |

A timeout, cancellation, checkout failure, abrupt runner loss or upload failure can prevent terminal evidence/RESULT creation; Actions status/logs then evidence an incomplete attempt. `always()` is best-effort preservation, not guaranteed sealing after a hard job timeout. Upload success is not build success. A tarball present beside a failed RESULT is not an acceptable candidate. No automatic restart follows any failure.

## Inside the tar

| Relative path | Exact policy |
|---|---|
| `bin/step-g` | Only packaged program; 0755, actual CMake target output copied before relocation |
| `libexec/step/<actual module filename>` | One actual AP242e2 module; 0644. Keep libexec-relative layout used by pinned plugin loader. Other stock-built modules are not represented as usable. |
| `lib/<actual NEEDED SONAME>` | Complete measured nonbaseline recursive linker closure for executable and module; regular 0644 copies, no guessed filename list or dependency symlinks |
| `licenses/` | BRL-CAD COPYING/legal records, selected bext notices, bundled system-library package notices and source/patch references |
| `metadata/` | Public-source/build evidence snapshot through packaging smoke checks; final outer RESULT/census and later snapshots are outside this inner commitment to avoid circular digests |
| `MANIFEST.json` | Existing schema `ADR001_RUNTIME_CONTENTS/2`, pinned BRL source commit, rows `{path,sha256,size,mode,role}` for every payload except MANIFEST and SHA256SUMS |
| `SHA256SUMS` | Every file including MANIFEST, except SHA256SUMS itself |

The tar content grammar follows accepted v2.0. The old Work auditor's 96 MiB archive/payload limits are **not GitHub build limits**. No size-fit is promised: actual transfer/extraction and simultaneous Work storage budgets must be approved from measured artifact size before transfer/loading. The archive writer fails rather than switching to unsupported tar extensions if a path exceeds USTAR representation. Artifact-upload container digest and inner tar digest identify different objects.

## Coherent baseline providers

Not bundled: `libc.so.6`, `libm.so.6`, `libdl.so.2`, `libpthread.so.0`, `librt.so.1`, `libresolv.so.2`, `libgcc_s.so.1`, `libstdc++.so.6`, `ld-linux-x86-64.so.2`. Actual source/provider hashes are retained. Work and Lenovo must supply coherent verified providers satisfying **each** versioned-symbol requirement and ISA constraint; neither a filename nor maximum GLIBCXX value suffices. Do not replace host libc/loader or add a global LD_LIBRARY_PATH. GitHub same-host baseline hash checks are not a cross-environment equality requirement.

All other ldd-resolved providers must be bundled and resolve inside the relocated tree during GitHub smoke. AP242e2 is a dlopen seed and is audited independently; ordinary DT_NEEDED recursion cannot enumerate every possible runtime dlopen/data dependency. Actual public AP242e2 execution and diagnostic module-path correspondence remain mandatory in Work. Help/version success does not close that gap.

## Qualification gates

1. Independently accept public workflow commit, run identity, exact pins, selected providers, patches, source/build receipts, linkage, relocation and notices. Hashes prove identity/consistency, not a trustworthy execution history by themselves.
2. In separately authorized private Work preparation, authenticate tar externally and inspect/extract safely with an approved size/member/path budget. Reestablish runtime resource and filesystem controls before executable loading.
3. Statically audit every ELF and AP242e2 module for machine/ISA, interpreter, search paths, needed/versioned symbols and provider closure. Audit all dependency compiler flags for accidental native CPU optimization. Unknown/missing/ambiguous requirements: HOLD.
4. Under applicable Work limits, test loader resolution/help/compiled-libbu version and two-prefix relocation with original tree absent. Preserve raw statuses and unchanged input/binary hashes.
5. Use independently authenticated public AP242e2 positive/negative geometric fixtures. Verify actual module loading and exact/strict/reject-invalid/repair-none diagnostics. No repair, omitted required entity, hidden tolerance alteration or merely successful import can certify geometric validity. Fixture preparation/acceptance is not claimed completed here.
6. Only after independent Work capability acceptance may a separately authorized private SPK16 test occur. Lenovo remains a separate release qualification and approval. No automatic installation or host action is permitted.
