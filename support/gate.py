"""Non-scientific one-shot admission gate for M1 IR-01.

This module imports no private scientific source. It waits on a supervisor-owned FIFO,
checks the original-T0 release cutoff after receipt and again immediately before exec,
then performs exactly one execve of the frozen scientific entry point. The one-use secret
capability is inherited from a root-owned/systemd-read environment file as
MA_M1_RUN_CAPABILITY; it is never printed or serialized by this gate.
"""
from __future__ import annotations
import argparse, os, stat, sys, time
from pathlib import Path

RELEASE_RECORD = b"RELEASE\n"
EXPECTED_RELEASE_CUTOFF_S = 540.0


def _fail(code: int, message: str) -> "NoReturn":
    # Deliberately generic: no private source path, source line, or capability material.
    print(f"GATE_STOP:{message}", file=sys.stderr, flush=True)
    raise SystemExit(code)


def _deadline_ns(t0_monotonic_ns: int, release_cutoff_s: float) -> int:
    now=time.monotonic_ns()
    if t0_monotonic_ns <= 0 or t0_monotonic_ns > now or release_cutoff_s != EXPECTED_RELEASE_CUTOFF_S:
        _fail(76, "RELEASE_DEADLINE_INVALID")
    return t0_monotonic_ns + int(release_cutoff_s * 1_000_000_000)


def _require_before_deadline(deadline_ns: int, code: int = 77) -> None:
    # Fresh monotonic read. Equality is late: no scientific exec at or after the cutoff.
    if time.monotonic_ns() >= deadline_ns:
        _fail(code, "RELEASE_CUTOFF_REACHED")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release-fifo", required=True)
    ap.add_argument("--t0-monotonic-ns", type=int, required=True)
    ap.add_argument("--release-cutoff-s", type=float, required=True)
    ap.add_argument("--python", required=True)
    ap.add_argument("--m1", required=True)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--level", type=int, required=True)
    ap.add_argument("--frequency", type=float, required=True)
    ap.add_argument("--phase", choices=("real", "rotated"), required=True)
    args = ap.parse_args()

    capability = os.environ.get("MA_M1_RUN_CAPABILITY", "")
    if not capability:
        _fail(70, "CAPABILITY_MISSING")

    deadline_ns = _deadline_ns(args.t0_monotonic_ns, args.release_cutoff_s)

    fifo = Path(args.release_fifo)
    try:
        st = os.stat(fifo, follow_symlinks=False)
    except OSError:
        _fail(71, "RELEASE_CHANNEL_UNAVAILABLE")
    if not stat.S_ISFIFO(st.st_mode):
        _fail(72, "RELEASE_CHANNEL_NOT_FIFO")

    try:
        with fifo.open("rb", buffering=0) as stream:
            record = stream.readline(len(RELEASE_RECORD) + 1)
    except OSError:
        _fail(73, "RELEASE_CHANNEL_READ_FAILED")
    if record != RELEASE_RECORD:
        _fail(74, "RELEASE_RECORD_INVALID")

    # The release record is not sufficient by itself. It must still be timely when read.
    _require_before_deadline(deadline_ns)

    env = dict(os.environ)
    env.pop("MA_M1_RUN_CAPABILITY", None)
    env["MA_M1_RUN_TOKEN"] = capability  # frozen m1.py contract; not serialized evidence.
    argv = [
        args.python,
        args.m1,
        "--authorized-run-token",
        capability,
        "--output-dir",
        args.output_dir,
        "--level",
        str(args.level),
        "--frequency",
        str(args.frequency),
        "--phase",
        args.phase,
    ]

    # A second fresh read is deliberately adjacent to execve. Any intervening delay that
    # crosses T0+540 converts the admission to a non-scientific gate failure.
    _require_before_deadline(deadline_ns)
    try:
        os.execve(args.python, argv, env)
    except OSError:
        _fail(75, "SCIENTIFIC_EXEC_FAILED")
    return 75


if __name__ == "__main__":
    raise SystemExit(main())
