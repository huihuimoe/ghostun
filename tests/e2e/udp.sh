#!/bin/bash
# End-to-end UDP smoke test over real kernels inside a disposable privileged container:
#   entry --veth-- fw --veth-- exit --veth-- inet
set -euo pipefail

BIN=$(realpath "${BIN:-target/release/ghostun}")
TOOLS=$(realpath tests/e2e/tcp-tools.py)
LOG=${LOG:-target/e2e-udp}
OUTER_FAMILY=${OUTER_FAMILY:-ipv4}
N=${N:-2}
MTU=1420
DEAD=4

case "$OUTER_FAMILY" in
    ipv4) OVERHEAD=28; EXIT_IP=10.2.0.1; REMOTE=10.2.0.1:443 ;;
    ipv6) OVERHEAD=48; EXIT_IP=fd00:2::1; REMOTE='[fd00:2::1]:443' ;;
    *) echo "OUTER_FAMILY must be ipv4 or ipv6" >&2; exit 1 ;;
esac

mkdir -p "$LOG"
LOG=$(realpath "$LOG")
umask 077
# Public test-only keys, never deployment credentials.
printf "[global]\nauth_key = '%064d'\n" 1 >"$LOG/auth.toml"
printf "[global]\nauth_key = '%064d'\n" 2 >"$LOG/wrong.toml"
PIDS=()

ns() { ip netns exec "$@"; }
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; tail -n 30 "$LOG"/*.log 2>/dev/null || true; exit 1; }

cleanup() {
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
    for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
    for n in entry fw exit inet; do ip netns del "$n" 2>/dev/null || true; done
}
trap cleanup EXIT

veth() {
    ip link add "$2" netns "$1" mtu $MTU type veth peer name "$5" netns "$4" mtu $MTU
    ns "$1" ip addr add "$3" dev "$2"
    ns "$4" ip addr add "$6" dev "$5"
    ns "$1" ip link set "$2" up
    ns "$4" ip link set "$5" up
}

for n in entry fw exit inet; do ip netns add "$n"; ns "$n" ip link set lo up; done
veth entry e0 10.1.0.1/24 fw f0 10.1.0.254/24
veth fw f1 10.2.0.254/24 exit x0 10.2.0.1/24
veth exit x1 10.3.0.1/24 inet i0 10.3.0.2/24
ns exit ip -6 addr add fd00:3::1/64 dev x1 nodad
ns inet ip -6 addr add fd00:3::2/64 dev i0 nodad
ns inet ip route add default via 10.3.0.1
ns inet ip -6 route add default via fd00:3::1
ns entry ip route add default via 10.1.0.254
ns exit ip route add default via 10.2.0.254

if [[ $OUTER_FAMILY == ipv6 ]]; then
    ns entry ip -6 addr add fd00:1::1/64 dev e0 nodad
    ns fw ip -6 addr add fd00:1::fe/64 dev f0 nodad
    ns fw ip -6 addr add fd00:2::fe/64 dev f1 nodad
    ns exit ip -6 addr add fd00:2::1/64 dev x0 nodad
    ns entry ip -6 route add default via fd00:1::fe
    ns exit ip -6 route add default via fd00:2::fe
    ns fw sysctl -qw net.ipv6.conf.all.forwarding=1
    ns entry ip -4 route del default
    ns exit ip -4 route del default
    ns entry ip -4 addr del 10.1.0.1/24 dev e0
    ns exit ip -4 addr flush dev x0
fi
ns fw sysctl -qw net.ipv4.ip_forward=1
ns fw nft -f - <<'EOF'
table inet fw {
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        udp dport 443 ct state new accept
    }
}
EOF

ip netns exec exit "$BIN" --config "$LOG/auth.toml" exit --transport udp --listen "$REMOTE" --ping-interval 1 --dead-timeout $DEAD >"$LOG/exit.log" 2>&1 &
EXIT_PID=$!; PIDS+=("$EXIT_PID")
ip netns exec entry "$BIN" --config "$LOG/auth.toml" entry --transport udp --remote "$REMOTE" --iface e0 --conns "$N" --ping-interval 1 --dead-timeout $DEAD >"$LOG/entry.log" 2>&1 &
ENTRY_PID=$!; PIDS+=("$ENTRY_PID")

for _ in $(seq 50); do
    kill -0 "$ENTRY_PID" "$EXIT_PID" 2>/dev/null || fail "startup failed"
    ns entry ip link show ghostun0 >/dev/null 2>&1 && ns exit ip link show ghostun0 >/dev/null 2>&1 && break
    sleep 0.1
done
ns entry ip route add 10.3.0.0/24 dev ghostun0
ns entry ip -6 route add fd00:3::/64 dev ghostun0

wait_ping() {
    local start=$SECONDS
    while ((SECONDS - start < $1)); do
        if ns entry ping -c1 -W1 10.3.0.2 >/dev/null 2>&1; then echo $((SECONDS - start)); return 0; fi
    done
    return 1
}

t=$(wait_ping 10) || fail "tunnel never came up"
pass "$OUTER_FAMILY UDP outer tunnel up in ${t}s"

TUN_MTU=$((MTU - OVERHEAD))
for side in entry exit; do
    mtu=$(ns "$side" cat /sys/class/net/ghostun0/mtu)
    [[ $mtu == "$TUN_MTU" ]] || fail "$side tun mtu $mtu, want $TUN_MTU"
    rules=$(ns "$side" nft list table inet ghostun_ghostun0)
    ! [[ $rules =~ notrack|pkttype|flags\ rst ]] || fail "FakeTCP rule in UDP instance"
done
pass "tun mtu auto-derived as $TUN_MTU and ordinary nft tables installed"

ns entry ping -c3 -i0.2 -W1 10.3.0.2 >/dev/null || fail "inner IPv4 ping"
ns entry ping -6 -c3 -i0.2 -W1 fd00:3::2 >/dev/null || fail "inner IPv6 ping"
ns entry ping -c2 -W1 -M do -s $((TUN_MTU - 28)) 10.3.0.2 >/dev/null || fail "full-size inner IPv4 packet"
ns entry ping -6 -c2 -W1 -M do -s $((TUN_MTU - 48)) fd00:3::2 >/dev/null || fail "full-size inner IPv6 packet"

for address in 10.3.0.2 fd00:3::2; do
    ip netns exec inet python3 "$TOOLS" serve "$address" >"$LOG/echo-$address.log" 2>&1 & PIDS+=("$!")
done
for address in 10.200.0.1 fd00:200::1; do
    ip netns exec entry python3 "$TOOLS" serve "$address" >"$LOG/echo-$address.log" 2>&1 & PIDS+=("$!")
done
sleep 0.2

check_data() {
    for address in 10.3.0.2 fd00:3::2; do
        ns entry python3 "$TOOLS" check "$address" >/dev/null || fail "TCP data $address"
        ns entry python3 "$TOOLS" check "$address" --udp >/dev/null || fail "UDP data $address"
    done
    for address in 10.200.0.1 fd00:200::1; do
        ns exit python3 "$TOOLS" check "$address" >/dev/null || fail "reverse TCP data $address"
        ns exit python3 "$TOOLS" check "$address" --udp >/dev/null || fail "reverse UDP data $address"
    done
}
check_data
pass "inner IPv4/IPv6 ping, full-MTU DF packet, and bidirectional TCP/UDP payloads"

# Wrong key cannot authenticate or disturb active tunnel.
ip netns exec inet "$BIN" --config "$LOG/wrong.toml" entry --transport udp --remote "$REMOTE" --iface i0 --tun unauth0 --conns "$N" --ping-interval 1 --dead-timeout $DEAD >"$LOG/wrong.log" 2>&1 &
WRONG_PID=$!; PIDS+=("$WRONG_PID")
for _ in $(seq 50); do
    kill -0 "$WRONG_PID" 2>/dev/null || fail "wrong-key client failed to start"
    ns inet ip link show unauth0 >/dev/null 2>&1 && break
    sleep 0.1
done
if ns inet ping -I unauth0 -c2 -W1 10.200.0.2 >/dev/null 2>&1; then
    fail "wrong-key client forwarded inner traffic"
fi
check_data
kill -TERM "$WRONG_PID"; wait "$WRONG_PID" || fail "wrong-key client shutdown"
pass "wrong-key client rejected without disturbing active sessions"

# Rolling SIGHUP key rotation across Entry and Exit.
printf "[global]\nauth_key = '%064d'\n" 3 >"$LOG/auth.toml"
kill -HUP "$ENTRY_PID"
sleep 0.3
if ((N > 1)); then
    ns entry ping -c2 -i0.2 -W1 10.3.0.2 >/dev/null || fail "rolling reload disrupted IPv4 forwarding before Exit reloaded"
    ns entry ping -6 -c2 -i0.2 -W1 fd00:3::2 >/dev/null || fail "rolling reload disrupted IPv6 forwarding before Exit reloaded"
fi
kill -HUP "$EXIT_PID"
for _ in $(seq 150); do
    grep -q "configuration reload complete (generation 1)" "$LOG/entry.log" &&
        grep -q "configuration reload complete (generation 1)" "$LOG/exit.log" && break
    sleep 0.1
done
grep -q "configuration reload complete (generation 1)" "$LOG/entry.log" || fail "entry reload incomplete"
grep -q "configuration reload complete (generation 1)" "$LOG/exit.log" || fail "exit reload incomplete"
check_data
pass "SIGHUP rolling key rotation completed"

kill -TERM "$ENTRY_PID" "$EXIT_PID"
wait "$ENTRY_PID" || fail "entry exit status $?"
wait "$EXIT_PID" || fail "exit exit status $?"
for side in entry exit; do
    ! ns "$side" ip link show ghostun0 >/dev/null 2>&1 || fail "$side ghostun0 still present"
    ! ns "$side" nft list table inet ghostun_ghostun0 >/dev/null 2>&1 || fail "$side nft table still present"
done
pass "SIGTERM: ghostun0 and nft tables removed"
echo "ALL PASSED"
