"""M1 BRQ-01 proposal: read-only, fail-closed D-Bus timer schedule verification.

This file is an OFFLINE REVIEW CANDIDATE, not an installed production helper.
The attached workflow integration patch embeds this module's Python logic inline
before checkout; it must be independently reviewed before any publication/use.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

SERVICE = "org.freedesktop.systemd1"
MANAGER = "/org/freedesktop/systemd1"
MANAGER_IFACE = "org.freedesktop.systemd1.Manager"
TIMER_IFACE = "org.freedesktop.systemd1.Timer"
UNIT_IFACE = "org.freedesktop.systemd1.Unit"
MAX_UINT64 = 2**64 - 1
PATH_ROOT = "/org/freedesktop/systemd1/unit/"


class ReadbackRejected(Exception):
    """Only constant failure codes are exposed; raw process outputs remain private."""


def _reject(reason: str):
    raise ReadbackRejected(reason)


def parse_busctl_path(value: str) -> str:
    """Only a validated systemd unit object path; allow quoted or unquoted terse form."""
    value = value.strip()
    pattern = r'o (?:(?:"(' + re.escape(PATH_ROOT) + r'[A-Za-z0-9_]+)")|(' + re.escape(PATH_ROOT) + r'[A-Za-z0-9_]+))'
    m = re.fullmatch(pattern, value, re.ASCII)
    if m is None:
        _reject("BAD_UNIT_PATH_PRESENTATION")
    return m.group(1) or m.group(2)


def parse_busctl_string(value: str) -> str:
    m = re.fullmatch(r's "([A-Za-z0-9_.-]+)"', value.strip(), re.ASCII)
    if m is None:
        _reject("BAD_UNIT_ID_PRESENTATION")
    return m.group(1)


def parse_busctl_u64(value: str) -> int:
    """D-Bus uint64 ('t') in microseconds; reject bare/pretty/unitless forms."""
    m = re.fullmatch(r't ([0-9]+)', value.strip(), re.ASCII)
    if m is None:
        _reject("BAD_TYPED_USEC_PRESENTATION")
    n = int(m.group(1))
    if n > MAX_UINT64:
        _reject("U64_OVERFLOW")
    return n


def parse_busctl_bool(value: str) -> bool:
    if value.strip() == "b false":
        return False
    if value.strip() == "b true":
        return True
    _reject("BAD_TYPED_BOOLEAN_PRESENTATION")


def _busctl(argv: list[str], runner=subprocess.run) -> str:
    """Local system bus GET/READ only; bounded time and output, no raw diagnostic echo."""
    cmd = ["sudo", "-n", "busctl", "--system", *argv]
    try:
        r = runner(cmd, capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        _reject("DBUS_READBACK_UNAVAILABLE")
    if r.returncode != 0 or not isinstance(r.stdout, str) or len(r.stdout) > 512:
        _reject("DBUS_READBACK_UNAVAILABLE")
    return r.stdout.strip()


def verify_timer_schedule(
    *, unit: str, t0_ns: int, target_s: int, lead_s: int = 2,
    runner=subprocess.run, clock_ns=time.monotonic_ns,
) -> dict:
    """Check exact unit, typed timer, clock semantics and original-T0 schedule."""
    if target_s not in (540, 570, 600) or lead_s != 2 or t0_ns <= 0:
        _reject("BAD_ORIGINAL_T0_CONTRACT")
    key = {540: "stop", 570: "quiescence", 600: "timeout"}[target_s]
    if re.fullmatch(r'ma-m1-t0-' + key + r'-[0-9]+-[0-9]+\.timer', unit, re.ASCII) is None:
        _reject("UNEXPECTED_UNIT_OR_TARGET_BINDING")

    def busctl(*argv: str) -> str:
        return _busctl(list(argv), runner=runner)

    path = parse_busctl_path(busctl("call", SERVICE, MANAGER, MANAGER_IFACE, "GetUnit", "s", unit))
    actual_id = parse_busctl_string(busctl("get-property", SERVICE, path, UNIT_IFACE, "Id"))
    if actual_id != unit:
        _reject("UNIT_ID_MISMATCH")

    wake = parse_busctl_bool(busctl("get-property", SERVICE, path, TIMER_IFACE, "WakeSystem"))
    if wake:
        _reject("WRONG_MONOTONIC_CLOCK_DOMAIN")

    realtime = parse_busctl_u64(busctl("get-property", SERVICE, path, TIMER_IFACE, "NextElapseUSecRealtime"))
    if realtime != 0:
        _reject("UNEXPECTED_REALTIME_ELAPSE")

    next_us = parse_busctl_u64(busctl("get-property", SERVICE, path, TIMER_IFACE, "NextElapseUSecMonotonic"))
    if next_us == 0:
        _reject("NO_PENDING_MONOTONIC_ELAPSE")

    now_ns = int(clock_ns())  # sampled AFTER completed D-Bus readback
    if now_ns < t0_ns:
        _reject("MONOTONIC_CLOCK_PRECEDES_T0")
    if now_ns >= t0_ns + target_s * 1_000_000_000:
        _reject("VERIFICATION_TOO_LATE")

    # Preserves original workflow acceptance window: a monotonic timer is
    # scheduled approximately two seconds before its root-owned action deadline.
    # The independent action enforces T0+target; this is NOT proof of exact firing.
    target_us = t0_ns // 1_000 + target_s * 1_000_000
    min_us = t0_ns // 1_000 + (target_s - lead_s - 1) * 1_000_000
    if next_us < min_us or next_us > target_us:
        _reject("TIMER_OUTSIDE_ORIGINAL_T0_WINDOW")

    return {
        "key": key,
        "timer_unit": unit,
        "target_s": target_s,
        "target_monotonic_usec": target_us,
        "next_elapse_monotonic_usec": next_us,
        "verified_not_late": True,
        "arm_lead_s": lead_s,
        "verified_at_monotonic_ns": now_ns,
        "readback_interface": "org.freedesktop.systemd1.Timer",
        "readback_transport": "typed-system-bus-D-Bus",
        "clock_domain": "CLOCK_MONOTONIC",
        "unit_identity_verified": True,
        "wake_system_false_verified": True,
        "no_realtime_elapse_verified": True,
        "absolute_stop_guarantee": False,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print("timer verification rejected: INVALID_ARGUMENT_COUNT", file=sys.stderr)
        return 2
    out, unit, t0_text, target_text, lead_text = argv
    try:
        if not re.fullmatch(r"[0-9]+", t0_text, re.ASCII):
            _reject("BAD_T0_ARGUMENT")
        if not re.fullmatch(r"[0-9]+", target_text, re.ASCII):
            _reject("BAD_TARGET_ARGUMENT")
        if not re.fullmatch(r"[0-9]+", lead_text, re.ASCII):
            _reject("BAD_LEAD_ARGUMENT")
        report = verify_timer_schedule(
            unit=unit, t0_ns=int(t0_text), target_s=int(target_text), lead_s=int(lead_text)
        )
        with Path(out).open("x", encoding="utf-8") as f:
            json.dump(report, f, sort_keys=True)
            f.write("\n")
    except ReadbackRejected as err:
        print(f"timer verification rejected: {err}", file=sys.stderr)
        return 2
    except (OSError, ValueError):
        print("timer verification rejected: OUTPUT_UNAVAILABLE", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
