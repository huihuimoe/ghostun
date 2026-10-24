#!/bin/bash
# End-to-end smoke test over real kernels:
#   entry --veth-- fw (stateful nftables, strict conntrack) --veth-- exit --veth-- inet
# Needs root plus ip, nft, conntrack, ping, iperf3. Run it in a disposable privileged container (see README "Testing").
set -euo pipefail

BIN=$(realpath "${BIN:-target/release/ghostun}")
N=${N:-2}
MTU=1420
DEAD=4
OUTER_FAMILY=${OUTER_FAMILY:-ipv4}
case "$OUTER_FAMILY" in
    ipv4) OVERHEAD=40; EXIT_IP=10.2.0.1; REMOTE=10.2.0.1:443; ADDR_MATCH=ip ;;
    ipv6) OVERHEAD=60; EXIT_IP=fd00:2::1; REMOTE='[fd00:2::1]:443'; ADDR_MATCH=ip6 ;;
    *) echo "OUTER_FAMILY must be ipv4 or ipv6" >&2; exit 1 ;;
esac
LOG=${LOG:-/tmp/ghostun-e2e}
TABLE=ghostun_ghostun0
mkdir -p "$LOG"

ns() { ip netns exec "$@"; }
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; tail -n 30 "$LOG"/*.log; exit 1; }

cleanup() {
    for p in ${PIDS:-}; do kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
    for n in entry fw exit inet; do ip netns del "$n" 2>/dev/null || true; done
}
trap cleanup EXIT

veth() { # veth <ns-a> <if-a> <addr-a> <ns-b> <if-b> <addr-b>
    ip link add "$2" netns "$1" mtu $MTU type veth peer name "$5" netns "$4" mtu $MTU
    ns "$1" ip addr add "$3" dev "$2"
    ns "$4" ip addr add "$6" dev "$5"
    ns "$1" ip link set "$2" up
    ns "$4" ip link set "$5" up
}

setup() {
    for n in entry fw exit inet; do ip netns add "$n"; ns "$n" ip link set lo up; done
    veth entry e0 10.1.0.1/24 fw f0 10.1.0.254/24
    veth fw f1 10.2.0.254/24 exit x0 10.2.0.1/24
    veth exit x1 10.3.0.1/24 inet i0 10.3.0.2/24
    ns exit ip -6 addr add fd00:3::1/64 dev x1 nodad
    ns inet ip -6 addr add fd00:3::2/64 dev i0 nodad
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
        # Prove neither endpoint needs IPv4 on its outer interface.
        ns entry ip -4 route del default
        ns exit ip -4 route del default
        ns entry ip -4 addr del 10.1.0.1/24 dev e0
        ns exit ip -4 addr del 10.2.0.1/24 dev x0
    fi
    ns fw sysctl -qw net.ipv4.ip_forward=1
    # Without loose pickup, packets of a flushed connection are INVALID and silently dropped.
    ns fw sysctl -qw net.netfilter.nf_conntrack_tcp_loose=0
    ns fw nft -f - <<'EOF'
table inet fw {
    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        tcp flags & (syn | ack | fin | rst) == syn ct state new accept
    }
}
EOF
}

start() {
    # Not via ns(): backgrounding a shell function makes $! a subshell, not ghostun.
    ip netns exec exit "$BIN" exit --listen 443 --outer-family "$OUTER_FAMILY" --conns "$N" --ping-interval 1 --dead-timeout $DEAD >"$LOG/exit.log" 2>&1 &
    EXIT_PID=$!
    ip netns exec entry "$BIN" entry --remote "$REMOTE" --iface e0 --conns "$N" --ping-interval 1 --dead-timeout $DEAD >"$LOG/entry.log" 2>&1 &
    ENTRY_PID=$!
    PIDS="$EXIT_PID $ENTRY_PID"
    for _ in $(seq 50); do
        ns entry ip link show ghostun0 >/dev/null 2>&1 && ns exit ip link show ghostun0 >/dev/null 2>&1 && break
        sleep 0.1
    done
    # Upstream proxies bind ghostun0; for the test, route the "internet" through it instead.
    ns entry ip route add 10.3.0.0/24 dev ghostun0
    ns entry ip -6 route add fd00:3::/64 dev ghostun0
}

established() { ns fw conntrack -L -f "$OUTER_FAMILY" -p tcp --state ESTABLISHED 2>/dev/null | grep -c 'dport=443' || true; }

# Seconds until an inner ping succeeds, or fails after $1 seconds.
wait_ping() {
    local start=$SECONDS
    while ((SECONDS - start < $1)); do
        if ns entry ping -c1 -W1 10.3.0.2 >/dev/null 2>&1; then echo $((SECONDS - start)); return 0; fi
    done
    return 1
}

setup
start

t=$(wait_ping 10) || fail "tunnel never came up"
pass "$OUTER_FAMILY outer tunnel up in ${t}s"

for side in entry exit; do
    mtu=$(ns $side cat /sys/class/net/ghostun0/mtu)
    [[ $mtu == $((MTU - OVERHEAD)) ]] || fail "$side tun mtu $mtu, want $((MTU - OVERHEAD))"
    ns $side nft list table inet $TABLE >/dev/null || fail "$side nft table missing"
done
pass "tun mtu auto-derived as $((MTU - OVERHEAD)) and nft tables installed"

ns entry ping -c3 -i0.2 -W1 10.3.0.2 >/dev/null || fail "inner IPv4 ping"
ns entry ping -6 -c3 -i0.2 -W1 fd00:3::2 >/dev/null || fail "inner IPv6 ping"
ns entry ping -c2 -W1 -M do -s $((MTU - OVERHEAD - 28)) 10.3.0.2 >/dev/null || fail "full-size inner IPv4 packet"
ns entry ping -6 -c2 -W1 -M do -s $((MTU - OVERHEAD - 48)) fd00:3::2 >/dev/null || fail "full-size inner IPv6 packet"
pass "inner IPv4/IPv6 ping, full-MTU DF packet"

ns inet iperf3 -s -D -1 -p 5201 && sleep 0.5
ns entry iperf3 -c 10.3.0.2 -p 5201 -t 3 -P 8 >"$LOG/iperf4.log" || fail "iperf3 IPv4"
ns inet iperf3 -s -D -1 -p 5202 && sleep 0.5
ns entry iperf3 -6 -c fd00:3::2 -p 5202 -t 3 -P 8 -R >"$LOG/iperf6.log" || fail "iperf3 IPv6 reverse"
pass "bulk TCP: v4 up $(grep -E 'SUM.*receiver' "$LOG/iperf4.log" | awk '{print $(NF-2), $(NF-1)}'), v6 down $(grep -E 'SUM.*receiver' "$LOG/iperf6.log" | awk '{print $(NF-2), $(NF-1)}')"

c=$(established)
[[ $c == "$N" ]] || fail "firewall tracks $c outer connections, want $N"
pass "firewall conntrack holds exactly $N ESTABLISHED outer connections"

# Firewall silently forgets every connection.
ns fw conntrack -F >/dev/null 2>&1
sleep 1
t=$(wait_ping $((DEAD + 10))) || fail "no recovery after conntrack flush"
sleep 2
c=$(established)
[[ $c == "$N" ]] || fail "after flush: $c ESTABLISHED, want $N"
pass "recovered ${t}s after silent conntrack flush; $N ESTABLISHED"

# Firewall keeps state but black-holes exit->entry; old entries must be RST-closed, not leaked.
ns fw nft insert rule inet fw forward "$ADDR_MATCH" saddr "$EXIT_IP" drop
sleep $((DEAD + 1))
ns fw nft flush chain inet fw forward
ns fw nft add rule inet fw forward ct state established,related accept
ns fw nft add rule inet fw forward 'tcp flags & (syn | ack | fin | rst) == syn ct state new accept'
t=$(wait_ping $((DEAD + 10))) || fail "no recovery after black hole"
sleep 2
c=$(established)
[[ $c == "$N" ]] || fail "after black hole: $c ESTABLISHED (leaked slots), want $N"
pass "recovered ${t}s after one-way black hole; stale entries closed by RST, $N ESTABLISHED"

kill -TERM "$ENTRY_PID" "$EXIT_PID"
wait "$ENTRY_PID" || fail "entry exit status $?"
wait "$EXIT_PID" || fail "exit exit status $?"
PIDS=
[[ $(established) == 0 ]] || fail "outer connections still ESTABLISHED after shutdown RST"
for side in entry exit; do
    ! ns $side ip link show ghostun0 >/dev/null 2>&1 || fail "$side ghostun0 still present"
    ! ns $side nft list table inet $TABLE >/dev/null 2>&1 || fail "$side nft table still present"
done
pass "SIGTERM: RSTs released firewall slots, ghostun0 and nft tables removed"
echo "ALL PASSED"
