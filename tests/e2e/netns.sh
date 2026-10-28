#!/bin/bash
# End-to-end smoke test over real kernels:
#   entry --veth-- fw (stateful nftables, strict conntrack) --veth-- exit --veth-- inet
# Needs root plus ip, nft, conntrack, ping, iperf3. Disposable container only; see tests/README.md.
set -euo pipefail

BIN=$(realpath "${BIN:-target/release/ghostun}")
N=${N:-2}
MTU=1420
DEAD=4
OUTER_FAMILY=${OUTER_FAMILY:-ipv4}
EXPECT_TUN_DRIVER=${EXPECT_TUN_DRIVER:-}
if [[ -z ${ENTRY_CPUS:-} && -z ${EXIT_CPUS:-} ]]; then
    mapfile -t CPUS < <(awk '/^Cpus_allowed_list:/ { n=split($2, a, ","); for (i=1; i<=n; i++) if (split(a[i], r, "-") == 2) for (c=r[1]; c<=r[2]; c++) print c; else print a[i] }' /proc/self/status)
    if ((${#CPUS[@]} >= 2 * N)); then
        IFS=,; ENTRY_CPUS="${CPUS[*]:0:N}"; EXIT_CPUS="${CPUS[*]:N:N}"; unset IFS
    fi
fi
ENTRY_CPU_ARGS=(${ENTRY_CPUS:+--cpus "$ENTRY_CPUS"})
EXIT_CPU_ARGS=(${EXIT_CPUS:+--cpus "$EXIT_CPUS"})
case "$OUTER_FAMILY" in
    ipv4) OVERHEAD=40; EXIT_IP=10.2.0.1; SIBLING_IP=10.2.0.2; REMOTE=10.2.0.1:443; ADDR_MATCH=ip ;;
    ipv6) OVERHEAD=60; EXIT_IP=fd00:2::1; SIBLING_IP=fd00:2::2; REMOTE='[fd00:2::1]:443'; ADDR_MATCH=ip6 ;;
    *) echo "OUTER_FAMILY must be ipv4 or ipv6" >&2; exit 1 ;;
esac
LOG=${LOG:-/tmp/ghostun-e2e}
TABLE=ghostun_ghostun0
mkdir -p "$LOG"
umask 077
# Public test-only keys, never deployment credentials.
printf "auth_key = '%064d'\n" 1 >"$LOG/auth.toml"
printf "auth_key = '%064d'\n" 2 >"$LOG/wrong.toml"

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
    ns exit ip addr add 10.2.0.2/24 dev x0
    veth exit x1 10.3.0.1/24 inet i0 10.3.0.2/24
    ns exit ip -6 addr add fd00:3::1/64 dev x1 nodad
    ns inet ip -6 addr add fd00:3::2/64 dev i0 nodad
    ns inet ip route add 10.2.0.0/24 via 10.3.0.1
    ns inet ip -6 route add fd00:2::/64 via fd00:3::1
    ns entry ip route add default via 10.1.0.254
    ns exit ip route add default via 10.2.0.254

    if [[ $OUTER_FAMILY == ipv6 ]]; then
        ns entry ip -6 addr add fd00:1::1/64 dev e0 nodad
        ns fw ip -6 addr add fd00:1::fe/64 dev f0 nodad
        ns fw ip -6 addr add fd00:2::fe/64 dev f1 nodad
        ns exit ip -6 addr add fd00:2::1/64 dev x0 nodad
        ns exit ip -6 addr add fd00:2::2/64 dev x0 nodad
        ns entry ip -6 route add default via fd00:1::fe
        ns exit ip -6 route add default via fd00:2::fe
        ns fw sysctl -qw net.ipv6.conf.all.forwarding=1
        # Prove neither endpoint needs IPv4 on its outer interface.
        ns entry ip -4 route del default
        ns exit ip -4 route del default
        ns entry ip -4 addr del 10.1.0.1/24 dev e0
        ns exit ip -4 addr flush dev x0
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

start_entry() {
    # Not via ns(): backgrounding a shell function makes $! a subshell, not ghostun.
    ip netns exec entry "$BIN" --config "$LOG/auth.toml" entry --remote "$REMOTE" --iface e0 --conns "$N" "${ENTRY_CPU_ARGS[@]}" --ping-interval 1 --dead-timeout $DEAD >"$LOG/entry.log" 2>&1 &
    ENTRY_PID=$!
    PIDS="$EXIT_PID $ENTRY_PID"
}

route_inner() {
    for _ in $(seq 50); do
        kill -0 "$ENTRY_PID" "$EXIT_PID" 2>/dev/null || fail "startup failed"
        ns entry ip link show ghostun0 >/dev/null 2>&1 && ns exit ip link show ghostun0 >/dev/null 2>&1 && break
        sleep 0.1
    done
    # Upstream proxies bind ghostun0; route the test internet through it instead.
    ns entry ip route add 10.3.0.0/24 dev ghostun0
    ns entry ip -6 route add fd00:3::/64 dev ghostun0
}

start() {
    ip netns exec exit "$BIN" --config "$LOG/auth.toml" exit --listen "$REMOTE" --conns "$N" "${EXIT_CPU_ARGS[@]}" --ping-interval 1 --dead-timeout $DEAD >"$LOG/exit.log" 2>&1 &
    EXIT_PID=$!
    PIDS="$EXIT_PID"
    start_entry
    route_inner
}

established() { ns fw conntrack -L -f "$OUTER_FAMILY" -p tcp --state ESTABLISHED 2>/dev/null | grep -c 'dport=443' || true; }

outer_tuples() {
    ns fw conntrack -L -f "$OUTER_FAMILY" -p tcp --state ESTABLISHED 2>/dev/null |
        awk '{ n=0; for (i=1; i<=NF; i++) if ($i ~ /^(src|dst|sport|dport)=/) { printf "%s%s", $i, ++n == 4 ? ORS : OFS; if (n == 4) break } }' | sort
}

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
    if [[ $EXPECT_TUN_DRIVER == uring ]]; then
        grep -q 'TUN io_uring fast-path enabled' "$LOG/$side.log" || fail "$side fast path not enabled"
        ! grep -q 'using poll fallback' "$LOG/$side.log" || fail "$side unexpectedly fell back to poll"
    elif [[ $EXPECT_TUN_DRIVER == poll ]]; then
        grep -q 'using poll fallback' "$LOG/$side.log" || fail "$side did not fall back to poll"
    fi
done

for side in entry exit; do
    mtu=$(ns $side cat /sys/class/net/ghostun0/mtu)
    [[ $mtu == $((MTU - OVERHEAD)) ]] || fail "$side tun mtu $mtu, want $((MTU - OVERHEAD))"
    ns $side nft list table inet $TABLE >/dev/null || fail "$side nft table missing"
done
pass "tun mtu auto-derived as $((MTU - OVERHEAD)) and nft tables installed"
ns exit iperf3 -s -D -1 -B "$SIBLING_IP" -p 443 && sleep 0.2
ns fw iperf3 -c "$SIBLING_IP" -p 443 -n 64K >/dev/null || fail "sibling IP port 443 TCP service hijacked by FakeTCP"
pass "specific listen IP ($REMOTE) leaves sibling IP ($SIBLING_IP:443) kernel TCP untouched"

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

before=$(outer_tuples)
ip netns exec inet "$BIN" --config "$LOG/wrong.toml" entry --remote "$REMOTE" --iface i0 --tun unauth0 --conns "$N" --base-port 50000 --ping-interval 1 --dead-timeout $DEAD >"$LOG/wrong.log" 2>&1 &
WRONG_PID=$!
PIDS="$PIDS $WRONG_PID"
for _ in $(seq 50); do
    kill -0 "$WRONG_PID" 2>/dev/null || fail "wrong-key client failed to start"
    ns inet ip link show unauth0 >/dev/null 2>&1 && break
    sleep 0.1
done
if ns inet ping -I unauth0 -c2 -W1 10.200.0.2 >"$LOG/wrong-ping.log" 2>&1; then
    fail "wrong-key client forwarded inner traffic"
fi
ns entry ping -c3 -i0.2 -W1 10.3.0.2 >/dev/null || fail "wrong-key client disrupted the active tunnel"
[[ $(outer_tuples) == "$before" ]] || fail "wrong-key client changed active outer tuples"
kill -TERM "$WRONG_PID"
wait "$WRONG_PID" || fail "wrong-key client shutdown"
PIDS="$EXIT_PID $ENTRY_PID"
! ns inet ip link show unauth0 >/dev/null 2>&1 || fail "wrong-key TUN survived shutdown"
! ns inet nft list table inet ghostun_unauth0 >/dev/null 2>&1 || fail "wrong-key firewall table survived shutdown"
pass "wrong-key client cannot forward or replace active connections"

# Real kernel TCP handshakes and unauthenticated Hellos, with no extra test tools.
for _ in $(seq 32); do
    ns inet timeout 2 bash -c '
        exec 3<>/dev/tcp/"$1"/443
        printf "\003\001\001%032d" 0 >&3
        exec 3>&-
    ' _ "$EXIT_IP" >/dev/null 2>&1 || fail "unauthenticated handshake injection failed"
done
ns entry ping -c3 -i0.2 -W1 10.3.0.2 >/dev/null || fail "unauthenticated handshakes disrupted forwarding"
[[ $(outer_tuples) == "$before" ]] || fail "unauthenticated handshakes rotated active tuples"
pass "32 unauthenticated handshakes leave legitimate forwarding and tuples unchanged"

# Kill Entry without sending RST, then change its public source address. The old
# Exit session remains until an authenticated replacement or its ordinary timeout.
kill -KILL "$ENTRY_PID"
wait "$ENTRY_PID" 2>/dev/null || [[ $? == 137 ]] || fail "unexpected killed Entry status"
PIDS="$EXIT_PID"
if [[ $OUTER_FAMILY == ipv4 ]]; then
    ns entry ip addr del 10.1.0.1/24 dev e0
    ns entry ip addr add 10.1.0.2/24 dev e0
    ns entry ip route replace default via 10.1.0.254 src 10.1.0.2
else
    ns entry ip -6 addr add fd00:1::2/64 dev e0 nodad
    ns entry ip -6 addr del fd00:1::1/64 dev e0
    ns entry ip -6 route replace default via fd00:1::fe src fd00:1::2
fi
# Drop Hello while allowing the complete ordinary TCP handshake. This also
# exercises real conntrack acceptance of retransmitted authentication sequence ranges.
ns fw nft -f - <<'EOF'
table inet auth_loss {
    chain forward {
        type filter hook forward priority -10; policy accept;
        tcp dport 443 @th,160,24 0x030101 drop
    }
}
EOF
start_entry
route_inner
if ns entry ping -c1 -W1 10.3.0.2 >/dev/null 2>&1; then fail "transport handshake granted access without authentication"; fi
ns fw nft delete table inet auth_loss
t=$(wait_ping $((DEAD + 10))) || fail "no authenticated recovery after source-address change and lost Hello"
sleep 1
[[ $(established) == "$N" ]] || fail "source-address replacement leaked old conntrack slots"
[[ $(outer_tuples) != "$before" ]] || fail "Entry source-address change was not observed"
pass "authenticated source-address replacement and Hello-loss recovery in ${t}s; $N ESTABLISHED"
printf 'OBSERVE: Entry '
awk '/^VmRSS:/ { print $0 }' "/proc/$ENTRY_PID/status"
printf 'OBSERVE: Exit '
awk '/^VmRSS:/ { print $0 }' "/proc/$EXIT_PID/status"

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

# Live SIGHUP reload: reject immutable/invalid config changes without disturbing sessions,
# exercise rollback without resetting untouched sibling workers, then complete a staged
# rolling auth_key rotation across Entry and Exit.
pre_reload=$(outer_tuples)
printf "auth_key = '%064d'\ntun_name = 'other0'\n" 1 >"$LOG/auth.toml"
kill -HUP "$ENTRY_PID" "$EXIT_PID"
sleep 0.3
[[ $(outer_tuples) == "$pre_reload" ]] || fail "rejected reload altered active outer tuples"
ns entry ping -c2 -i0.2 -W1 10.3.0.2 >/dev/null || fail "rejected reload disrupted forwarding"

printf "auth_key = '%064d'\n" 2 >"$LOG/auth.toml"
kill -HUP "$ENTRY_PID"
sleep 0.4
if ((N > 1)); then
    ns entry ping -c2 -i0.2 -W1 10.3.0.2 >/dev/null || fail "mid-rotation disrupted IPv4 forwarding on sibling workers"
    ns entry ping -6 -c2 -i0.2 -W1 fd00:3::2 >/dev/null || fail "mid-rotation disrupted IPv6 forwarding on sibling workers"
fi
printf "auth_key = '%064d'\n" 1 >"$LOG/auth.toml"
kill -HUP "$ENTRY_PID"
# Conntrack may retain an RST-closed tuple briefly in ESTABLISHED for challenge ACKs.
for _ in $(seq 150); do
    [[ $(established) == "$N" ]] && grep -q "configuration reload complete (generation 2)" "$LOG/entry.log" && break
    sleep 0.1
done
after_rollback=$(outer_tuples)
preserved=$(comm -12 <(printf '%s\n' "$pre_reload") <(printf '%s\n' "$after_rollback") | grep -c . || true)
[[ $preserved == $((N - 1)) ]] || fail "rollback preserved $preserved tuples, want $((N - 1)) (pre: $pre_reload | after: $after_rollback)"

printf "auth_key = '%064d'\n" 3 >"$LOG/auth.toml"
kill -HUP "$ENTRY_PID"
sleep 0.4
if ((N > 1)); then
    ns entry ping -c2 -i0.2 -W1 10.3.0.2 >/dev/null || fail "rolling reload disrupted IPv4 forwarding before Exit reloaded"
    ns entry ping -6 -c2 -i0.2 -W1 fd00:3::2 >/dev/null || fail "rolling reload disrupted IPv6 forwarding before Exit reloaded"
fi
kill -HUP "$EXIT_PID"
for _ in $(seq 150); do
    grep -q "configuration reload complete (generation 3)" "$LOG/entry.log" &&
        grep -q "configuration reload complete (generation 1)" "$LOG/exit.log" &&
        [[ $(established) == "$N" ]] && break
    sleep 0.1
done
after_rotate=$(outer_tuples)
overlap=$(comm -12 <(printf '%s\n' "$after_rollback") <(printf '%s\n' "$after_rotate") | grep -c . || true)
[[ $overlap == 0 ]] || fail "SIGHUP key rotation left $overlap unrotated outer tuples"
ns entry ping -c2 -i0.2 -W1 10.3.0.2 >/dev/null || fail "inner IPv4 ping after SIGHUP reload"
ns entry ping -6 -c2 -i0.2 -W1 fd00:3::2 >/dev/null || fail "inner IPv6 ping after SIGHUP reload"
ns inet iperf3 -s -D -1 -p 5203 && sleep 0.3
ns entry iperf3 -c 10.3.0.2 -p 5203 -t 1 -P 8 >/dev/null || fail "multi-stream TCP after SIGHUP reload"
sleep 0.2
pass "SIGHUP reload: rejected invalid config, rolled back cleanly, and rotated all $N sessions"

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

# Routed L3 mode (--no-masq): preserve inner source IPs in both directions while keeping
# FakeTCP bypass and Exit MSS clamping (Exit tun_mtu=1280 < Entry tun_mtu and inet MTU=1420).
ns inet ip route add 10.200.0.0/30 via 10.3.0.1
ns inet ip -6 route add fd00:200::/126 via fd00:3::1
ip netns exec exit "$BIN" --config "$LOG/auth.toml" exit --listen 443 --outer-family "$OUTER_FAMILY" --conns "$N" "${EXIT_CPU_ARGS[@]}" --tun-mtu 1280 --no-masq --ping-interval 1 --dead-timeout $DEAD >"$LOG/exit-nomasq.log" 2>&1 &
EXIT_PID=$!
PIDS="$EXIT_PID"
start_entry
route_inner
wait_ping 10 >/dev/null || fail "--no-masq tunnel never came up"
exit_rules=$(ns exit nft list table inet "$TABLE")
! [[ $exit_rules =~ postrouting|masquerade ]] || fail "--no-masq installed masquerade rules"
python3 - <<'PY' || fail "--no-masq source IP preservation or Exit MSS clamping failed"
import socket, subprocess

def check(server_ns, bind_addr, client_ns, dst_addr, want_peer, max_mss):
    fam = int(socket.AF_INET6 if ":" in bind_addr else socket.AF_INET)
    srv = subprocess.Popen(
        ["ip", "netns", "exec", server_ns, "python3", "-c",
         f"import socket; s=socket.socket({fam}); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); "
         f"s.bind(({bind_addr!r}, 9001)); s.listen(1); c,a=s.accept(); "
         f"print(a[0], c.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)); c.sendall(b'ok'); c.close(); s.close()"],
        stdout=subprocess.PIPE, text=True,
    )
    cli_mss = int(subprocess.check_output(
        ["ip", "netns", "exec", client_ns, "python3", "-c",
         f"import socket,time\nfor _ in range(30):\n try:\n  c=socket.socket({fam}); c.settimeout(2); c.connect(({dst_addr!r}, 9001)); assert c.recv(2)==b'ok'; "
         f"print(c.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)); c.close(); break\n except OSError: time.sleep(0.05)\nelse: raise SystemExit(1)"],
        text=True,
    ).strip())
    peer, srv_mss = srv.communicate(timeout=5)[0].strip().split()
    clamped_mss = cli_mss if client_ns == "entry" else int(srv_mss)
    assert peer == want_peer, f"expected peer {want_peer}, got {peer}"
    assert clamped_mss <= max_mss, f"expected Exit-clamped MSS <= {max_mss}, got {clamped_mss}"

check("inet", "10.3.0.2", "entry", "10.3.0.2", "10.200.0.1", 1240)
check("inet", "fd00:3::2", "entry", "fd00:3::2", "fd00:200::1", 1220)
check("entry", "10.200.0.1", "inet", "10.200.0.1", "10.3.0.2", 1240)
PY
kill -TERM "$ENTRY_PID" "$EXIT_PID"
wait "$ENTRY_PID" || fail "--no-masq entry exit status $?"
wait "$EXIT_PID" || fail "--no-masq exit exit status $?"
PIDS=
for side in entry exit; do
    ! ns $side ip link show ghostun0 >/dev/null 2>&1 || fail "--no-masq $side ghostun0 survived shutdown"
    ! ns $side nft list table inet "$TABLE" >/dev/null 2>&1 || fail "--no-masq $side nft table survived shutdown"
done
pass "--no-masq: routed IPv4/IPv6 preserved source IPs in both directions with Exit-clamped MSS"
if [[ $EXPECT_TUN_DRIVER == uring ]]; then
    ! grep -q 'using poll fallback' "$LOG/entry.log" "$LOG/exit.log" "$LOG/exit-nomasq.log" || fail "fast path unexpectedly fell back during e2e"
fi
echo "ALL PASSED"
