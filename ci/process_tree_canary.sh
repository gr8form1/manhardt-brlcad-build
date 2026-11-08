# Force-watchdog canary. Deliberately exceeds bounded timeout; no geometry.
set -eu
printf 'WATCHDOG_CANARY_STARTED:yes\n'
sleep 180 &
child=$!
printf 'WATCHDOG_CHILD_PID:%s\n' "$child"
wait "$child"
# Success here indicates watchdog was NOT enforced.
printf 'WATCHDOG_UNEXPECTED_COMPLETION\n'
exit 90
