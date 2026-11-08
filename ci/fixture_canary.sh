# R2 security canary: no geometry invocation, no network intended.
set -eu
printf 'NETNS_MARKER:%s\n' "$(readlink /proc/self/ns/net)"
test "$(awk 'NR>1 {n++} END {print n+0}' /proc/net/route)" = 0
printf 'ROUTES_EMPTY:yes\n'
# For IPv6, the only acceptable route belongs to loopback.
test "$(awk '$10 != "lo" {n++} END {print n+0}' /proc/net/ipv6_route)" = 0
printf 'IPV6_ROUTES_EMPTY:yes\n'
test "$(find /sys/class/net -mindepth 1 -maxdepth 1 -type l -printf '%f\n' | grep -v '^lo$' | wc -l)" -eq 0
printf 'ONLY_LOOPBACK:yes\n'
if /bin/bash -c 'exec 9<>/dev/tcp/1.1.1.1/80' >/dev/null 2>&1; then exit 81; fi
printf 'NET_CONNECT_DENIED:yes\n'
touch /scratch/adr001-write-test
printf 'SCRATCH_WRITE_PASS:yes\n'
reject() { if touch "$2" >/dev/null 2>&1; then echo "UNEXPECTED_WRITE:$1"; exit 82; fi; printf 'DENY_%s:yes\n' "$1"; }
reject ETC /etc/adr001-preflight-denied
reject RUNTIME /runtime/adr001-preflight-denied
reject FIXTURES /fixtures/adr001-preflight-denied
reject DEV /dev/adr001-preflight-denied
reject DEV_SHM /dev/shm/adr001-preflight-denied
reject PROC /proc/adr001-preflight-denied
reject SYS /sys/adr001-preflight-denied
reject ROOT /adr001-preflight-denied
reject TMP /tmp/adr001-preflight-denied
reject VAR_TMP /var/tmp/adr001-preflight-denied
printf 'UID_GID:%s:%s\n' "$(id -u)" "$(id -g)"
printf 'NO_NEW_PRIVS:%s\n' "$(awk '/^NoNewPrivs:/ {print $2}' /proc/self/status)"
printf 'CAP_EFF:%s\n' "$(awk '/^CapEff:/ {print $2}' /proc/self/status)"
for name in memory.max memory.swap.max pids.max memory.current memory.swap.current pids.current; do
  printf '%s:%s\n' "$name" "$(cat /sys/fs/cgroup/$name)"
done
# JSON line per cgroup event set; missing files are fatal.
for name in memory.events memory.swap.events pids.events; do
  printf '%s:' "$name"
  awk 'BEGIN {printf "{"} {if(NR>1)printf ",";printf "\"%s\":%s",$1,$2} END {printf "}\n"}' "/sys/fs/cgroup/$name"
done
printf 'MOUNTINFO_BEGIN\n'
cat /proc/self/mountinfo
printf 'MOUNTINFO_END\n'
printf 'FROZEN_PASS:yes\n'
