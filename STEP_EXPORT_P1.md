# ADR-001 — P1 source-locked STEP export correction candidate

**Date:** November 10, 2026  
**Status:** IMPLEMENTATION CANDIDATE / NATIVE INTEROPERABILITY HOLD  
**Branch:** feature/step-export-p1-signedzero  
**Upstream BRL-CAD:** bc130e1e7a9f179fe95fb42cde1a7d3becb512df (unchanged pin)  
**Frozen runtime:** Build #9, run 42818003613

## Reproduced mechanism

Public OCCT box and cylinder imports via Build #9 step-g (--strict --repair safe), re-exported using g-step AP242e4, contain a transforming representation relationship for a single product without an NAUO/CDSR assembly occurrence. Independent OCCT transfers zero shapes.

Saved BRL-CAD product-to-representation combination matrices represent the mathematical identity, but contain IEEE-754 negative-zero components. The pinned source implementation of bn_mat_is_identity is a bytewise memcmp with the positive-zero identity. Independently invoking the frozen Build #9 libbn.so.20 gave:

- Ordinary identity: 1 (true).
- Mathematically identical matrix with negative-zero components: 0 (false).
- Genuinely nonidentity matrix with 1e-12 off-diagonal component: 0 (false).

The exporter consequently chooses the transforming-representation branch for the first two public fixtures. The separate missing PRODUCT_DEFINITION_CONTEXT.name and PRODUCT_CONTEXT.discipline_type fields also require correction. Populating only those fields never restored the independent geometry transfer.

## Candidate scope

ci/step_export_p1_patch.py acts only on the temporary checkout of the approved upstream BRL-CAD pin. It requires a clean tracked source tree, verifies exact source anchors and preserves original/patched SHA-256 receipts for exactly two files:

- src/conv/step/STEPProductExport.cpp
- src/conv/step/g-step/Assembly_Product.cpp

The patch sets the required context strings using the existing SetString API. In emit_representation_membership only, it replaces the bytewise identity check with component-by-component exact numerical equality. This admits signed zero but does not silently discard any nonzero component. Existing nonidentity membership handling and assembly-occurrence handling remain unchanged.

It does not change bn_mat_is_identity globally, rewrite output STEP text, alter CAD, modify the upstream commit, or deploy anything to Lenovo.

## Offline preflight

The five tests in tests/test_step_export_p1_patch.py cover required-field insertion, retention of assembly relationship generation, duplicate or changed source rejection, reapplication rejection, and signed-zero/nonzero controls. The build driver records source-patch receipts and complete diff evidence after applying the patch during the toolkit stage, not the bext-only stage.

These are source-level unit checks, not independent native STEP interoperability qualification.

## Required acceptance gates

1. Independently inspect patch, review the source receipts and run the full offline suite.
2. Manually authorize a candidate build only after review. Preserve frozen Build #9 and its original branch.
3. Independently generate box/cylinder/tetrahedron STEP controls and require OCCT readback of exact solid counts, valid topology, adaptive volume/area and correct product contexts; distinguish safe-import repairs from uncompromised strict imports.
4. Preserve transformations in nonidentity nested and repeated assemblies (NAUO/CDSR), genuinely transformed secondary representations, and require explicit failure on unsupported transforms. Never silently flatten or discard transforms.
5. Only after public controls pass, resume source-locked SPK16/C16 curved-face, trim, topology, dimensional and cross-kernel fidelity checks.

**Known limitation:** nonzero transformed secondary representations may still use an OCCT-unreadable complex relationship; P1 does not claim general STEP export qualification.

The NC-001 LF solver phasor issue, C16 aperture/header/boss issues, VQ-001 restrictions, SPK16 geometry HOLD, numerical production HOLD and October 18 capital STOP remain unchanged. No spending, purchasing, fabrication, service changes, source CAD mutation or release is authorized.