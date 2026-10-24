#!/bin/bash
# Run only inside a disposable privileged container; never on the host.
# Model a kernel without IPv6: new interfaces disable IPv6 and its sysctl tree is absent.
set -euo pipefail

BIN=$(realpath "${BIN:-target/release/ghostun}")
LOG=${LOG:-/tmp/ghostun-ipv6-disabled}
ENTRY=ghostun-v4-entry
EXIT=ghostun-v4-exit
mkdir -p "$LOG"
PIDS=()

cleanup() {
    for p in "${PIDS[@]}"; do kill -TERM "$p" 2>/dev/null || true; done
    for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
    for n in "$ENTRY" "$EXIT"; do ip netns del "$n" 2>/dev/null || true; done
}
trap cleanup EXIT
fail() { echo "FAIL: $*"; tail -n 20 "$LOG"/*.log; exit 1; }
ns() { ip netns exec "$@"; }

for n in "$ENTRY" "$EXIT"; do
    ip netns add "$n"
    ns "$n" ip link set lo up
    ns "$n" sysctl -qw net.ipv6.conf.default.disable_ipv6=1
done
ip link add e0 netns "$ENTRY" type veth peer name x0 netns "$EXIT"
ns "$ENTRY" ip addr add 192.0.2.1/30 dev e0
ns "$EXIT" ip addr add 192.0.2.2/30 dev x0
ns "$ENTRY" ip link set e0 up
ns "$EXIT" ip link set x0 up

# ip netns exec gives each process a private mount namespace; hide only its IPv6 sysctls.
ip netns exec "$EXIT" bash -c '
    set -e
    mount -t tmpfs tmpfs /proc/sys/net/ipv6
    exec "$@"
' _ "$BIN" exit --listen 443 --iface x0 --conns 1 >"$LOG/exit.log" 2>&1 &
PIDS+=("$!")
ip netns exec "$ENTRY" bash -c '
    set -e
    mount -t tmpfs tmpfs /proc/sys/net/ipv6
    exec "$@"
' _ "$BIN" entry --remote 192.0.2.2:443 --iface e0 --conns 1 >"$LOG/entry.log" 2>&1 &
PIDS+=("$!")

connected=false
for _ in $(seq 20); do
    for p in "${PIDS[@]}"; do kill -0 "$p" 2>/dev/null || fail "startup failed"; done
    if ns "$ENTRY" ping -c1 -W1 10.200.0.2 >/dev/null 2>&1; then connected=true; break; fi
    sleep 0.1
done
$connected || fail "default configuration did not fall back to IPv4"
ns "$ENTRY" ping -c2 -W1 -M do -s 1432 10.200.0.2 >/dev/null || fail "full-MTU IPv4 packet"
for n in "$ENTRY" "$EXIT"; do
    [[ -z $(ns "$n" ip -6 -o addr show dev ghostun0) ]] || fail "$n has inner IPv6"
    ns "$n" nft list table inet ghostun_ghostun0 >/dev/null || fail "$n nft table missing"
done
echo "PASS: default Entry and Exit forward full-MTU IPv4 with IPv6 unavailable"

for p in "${PIDS[@]}"; do kill -TERM "$p"; done
for p in "${PIDS[@]}"; do wait "$p" || fail "shutdown failed"; done
PIDS=()
for n in "$ENTRY" "$EXIT"; do
    ! ns "$n" ip link show ghostun0 >/dev/null 2>&1 || fail "$n TUN still present"
    ! ns "$n" nft list table inet ghostun_ghostun0 >/dev/null 2>&1 || fail "$n nft table still present"
done
echo "PASS: IPv4 fallback shutdown removes TUN and nftables state"
echo "ALL PASSED"
