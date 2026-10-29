#!/bin/bash
# Disposable privileged container only. No host routes, firewall, or impairments.
set -euo pipefail
BIN=$(realpath "${BIN:-target/release/ghostun}")
TOOLS=$(realpath tests/perf/tcp-tools.py)
LOG=${LOG:-target/e2e-tcp}
OUTER_FAMILY=${OUTER_FAMILY:-ipv4}
RELAY=${RELAY:-1}
N=2
DEAD=4
mkdir -p "$LOG"
LOG=$(realpath "$LOG")
umask 077
printf "auth_key = '%064d'\nping_interval = 1\ndead_timeout = 4\n" 1 >"$LOG/auth.toml"
printf "auth_key = '%064d'\n" 2 >"$LOG/wrong.toml"
PIDS=()
ENTRY_CPUS=0-1
EXIT_CPUS=2-3
write_configs() {
    cat "$LOG/auth.toml" >"$LOG/entry.toml"
    printf "cpus = '%s'\n" "$ENTRY_CPUS" >>"$LOG/entry.toml"
    cat "$LOG/auth.toml" >"$LOG/exit.toml"
    printf "cpus = '%s'\n" "$EXIT_CPUS" >>"$LOG/exit.toml"
}
write_configs
ns() { ip netns exec "$@"; }
fail() { echo "FAIL: $*"; tail -n 30 "$LOG"/*.log; exit 1; }
pass() { echo "PASS: $*"; }
cleanup() {
    for p in "${PIDS[@]}"; do kill -CONT "$p" 2>/dev/null || true; kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
    for n in entry fw exit inet; do ip netns del "$n" 2>/dev/null || true; done
}
trap cleanup EXIT
veth() {
    ip link add "$2" netns "$1" mtu 1420 type veth peer name "$5" netns "$4" mtu 1420
    ns "$1" ip addr add "$3" dev "$2"; ns "$4" ip addr add "$6" dev "$5"
    ns "$1" ip link set "$2" up; ns "$4" ip link set "$5" up
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
ns fw sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 net.netfilter.nf_conntrack_tcp_loose=0
ns fw nft -f - <<'RULES'
table inet fw {
 chain forward {
  type filter hook forward priority filter; policy drop;
  ct state established,related accept
  tcp flags & (syn | ack | fin | rst) == syn ct state new accept
 }
}
RULES
if [[ $OUTER_FAMILY == ipv4 ]]; then
    EXIT_IP=10.2.0.1; RELAY_IP=10.1.0.254; MATCH=ip
    REMOTE=$EXIT_IP:443; MTU=1380
else
    ns entry ip -6 addr add fd00:1::1/64 dev e0 nodad
    ns fw ip -6 addr add fd00:1::fe/64 dev f0 nodad
    ns fw ip -6 addr add fd00:2::fe/64 dev f1 nodad
    ns exit ip -6 addr add fd00:2::1/64 dev x0 nodad
    ns entry ip -6 route add default via fd00:1::fe
    ns exit ip -6 route add default via fd00:2::fe
    EXIT_IP=fd00:2::1; RELAY_IP=fd00:1::fe; MATCH=ip6
    REMOTE="[$EXIT_IP]:443"; MTU=1360
fi
start_relay() {
    ip netns exec fw python3 "$TOOLS" relay "$RELAY_IP" "$EXIT_IP" >"$LOG/relay.log" 2>&1 &
    RELAY_PID=$!; PIDS+=("$RELAY_PID"); sleep 0.2
}
if [[ $RELAY == 1 ]]; then
    start_relay
    if [[ $OUTER_FAMILY == ipv4 ]]; then REMOTE=$RELAY_IP:8443; else REMOTE="[$RELAY_IP]:8443"; fi
fi
start_exit() {
    ip netns exec exit "$BIN" --config "$LOG/exit.toml" exit --transport tcp --tcp-notsent 64 --listen 443 --outer-family "$OUTER_FAMILY" --conns $N --outer-mtu 1420 >"$LOG/exit.log" 2>&1 &
    EXIT_PID=$!; PIDS+=("$EXIT_PID")
}
start_entry() {
    ip netns exec entry "$BIN" --config "$LOG/entry.toml" entry --transport tcp --tcp-notsent 64 --remote "$REMOTE" --iface e0 --conns $N --outer-mtu 1420 >"$LOG/entry.log" 2>&1 &
    ENTRY_PID=$!; PIDS+=("$ENTRY_PID")
    for _ in $(seq 50); do
        ns entry ip -o link show up dev ghostun0 2>/dev/null | grep -q . && break; sleep 0.1
    done
    ns entry ip route replace 10.3.0.0/24 dev ghostun0
    ns entry ip -6 route replace fd00:3::/64 dev ghostun0
}
wait_ping() {
    local start=$SECONDS
    while ((SECONDS-start < ${1:-25})); do
        if [[ $(active) == "$N" ]] && ns entry ping -c1 -W1 10.3.0.2 >/dev/null 2>&1; then
            sleep 1
            if [[ $(active) == "$N" ]]; then echo $((SECONDS-start)); return; fi
        fi
    done
    return 1
}
active() { ns exit ss -Hnt state established '( sport = :443 )' | wc -l; }
# A bind failure occurs after TUN/rule setup, and must unwind both resources.
ip netns exec exit python3 - "$EXIT_IP" <<'PYTEST' >"$LOG/occupied.log" 2>&1 &
import socket,sys,time
s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET)
s.bind((sys.argv[1],443));s.listen();time.sleep(30)
PYTEST
occupied=$!; PIDS+=("$occupied"); sleep 0.2
if ns exit "$BIN" --config "$LOG/auth.toml" exit --transport tcp --listen 443 --outer-family "$OUTER_FAMILY" --tun failed0 --conns $N --outer-mtu 1420 >"$LOG/failed-start.log" 2>&1; then fail "occupied listener accepted startup"; fi
! ns exit ip link show failed0 >/dev/null 2>&1 || fail "failed startup leaked TUN"
! ns exit nft list table inet ghostun_failed0 >/dev/null 2>&1 || fail "failed startup leaked rules"
kill "$occupied"; wait "$occupied" 2>/dev/null || true
pass "failed startup unwinds TUN and owned network rules"
start_exit; start_entry
wait_ping 15 >/dev/null || fail "startup"
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
[[ $(active) == "$N" ]] || fail "stable connection count"
for side in entry exit; do
    [[ $(ns "$side" cat /sys/class/net/ghostun0/mtu) == "$MTU" ]] || fail "MTU"
    rules=$(ns "$side" nft list table inet ghostun_ghostun0)
    ! [[ $rules =~ notrack|pkttype|flags\ rst ]] || fail "FakeTCP rule in TCP instance"
done
ns entry ip route show default | grep -q 'via 10.1.0.254' || fail "default route changed"
fd_count() { local pid=$1; local fds=(/proc/"$pid"/fd/*); echo "${#fds[@]}"; }
ENTRY_FDS=$(fd_count "$ENTRY_PID")
EXIT_FDS=$(fd_count "$EXIT_PID")
pass "$OUTER_FAMILY relay=$RELAY: exact TCP/UDP payloads in both directions, dual-stack, $N connections, ordinary TCP rules"

# Wrong-key and mismatched parameters cannot disturb existing slots or carry data.
for args in "wrong.toml 2 $MTU" "auth.toml 3 $MTU" "auth.toml 2 $((MTU-20))"; do
    read -r file conns mtu <<<"$args"
    ip netns exec inet "$BIN" --config "$LOG/$file" entry --transport tcp --remote "$([[ $OUTER_FAMILY == ipv4 ]] && echo "$EXIT_IP:443" || echo "[$EXIT_IP]:443")" --iface i0 --tun unauth0 --conns "$conns" --outer-mtu 1420 --tun-mtu "$mtu" --ping-interval 1 --dead-timeout $DEAD >"$LOG/rejected.log" 2>&1 &
    bad=$!; PIDS+=("$bad"); sleep 0.5
    if ns inet ping -I unauth0 -c1 -W1 10.200.0.2 >/dev/null 2>&1; then fail "invalid peer forwarded data"; fi
    check_data
    kill -TERM "$bad"; wait "$bad" || fail "invalid peer shutdown"
done
pass "wrong key/conns/MTU reject forwarding and leave active tunnel usable"

# Fill all unauthenticated candidate capacity and try excess real sockets.
ip netns exec inet python3 - "$EXIT_IP" <<'PY' >"$LOG/saturation.log" 2>&1 &
import select,socket,sys,time
address=sys.argv[1]; family=socket.AF_INET6 if ':' in address else socket.AF_INET
sockets=[]
for _ in range(20):
 s=socket.socket(family); s.settimeout(1); s.connect((address,443)); sockets.append(s)
pending=set(sockets)
deadline=time.monotonic()+1
while pending and time.monotonic()<deadline:
 for s in select.select(list(pending),[],[],max(0,deadline-time.monotonic()))[0]:
  try: data=s.recv(1)
  except ConnectionResetError: data=b''
  assert data==b''
  pending.remove(s)
assert len(pending)==4, f'expected 4 candidates before auth deadline, got {len(pending)}'
# The initial candidates must time out and make capacity available again.
time.sleep(4)
for s in pending:
 try: assert not s.recv(1)
 except ConnectionResetError: pass
fresh=[]
for _ in range(4):
 s=socket.socket(family); s.settimeout(.2); s.connect((address,443));fresh.append(s)
for s in fresh:
 try:
  s.recv(1)
  raise AssertionError('expired candidates did not release capacity')
 except socket.timeout: pass
for s in fresh:s.close()
for s in sockets:s.close()
PY
saturation=$!; PIDS+=("$saturation"); sleep 0.3
check_data
wait "$saturation" || fail "candidate cap"
wait_ping 10 >/dev/null || fail "candidate expiry"
pass "candidate saturation is bounded; active payload traffic continues"

# A kernel TCP handshake alone cannot forward packets; invalid frames close candidates.
ip netns exec inet python3 - "$EXIT_IP" <<'PY'
import socket,sys
for payload in (b'\x00\x00',b'\xff\xff',b'\x00\x01\x40'):
 s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET);s.settimeout(5)
 s.connect((sys.argv[1],443));s.sendall(payload)
 try: assert not s.recv(1)
 except ConnectionResetError: pass
 s.close()
PY
check_data
pass "malformed framing closes candidate without disturbing active slots"

# Freeze the old Entry's userspace while its kernel sockets stay alive. A fully
# authenticated new Entry must immediately replace slots without waiting for liveness expiry.
kill -STOP "$ENTRY_PID"
ip netns exec inet "$BIN" --config "$LOG/auth.toml" entry --transport tcp --remote "$([[ $OUTER_FAMILY == ipv4 ]] && echo "$EXIT_IP:443" || echo "[$EXIT_IP]:443")" --iface i0 --tun takeover0 --conns $N --outer-mtu 1420 >"$LOG/takeover.log" 2>&1 &
replacement=$!; PIDS+=("$replacement")
connected=false
for _ in $(seq 20); do
    if ns inet ping -I takeover0 -c1 -W1 10.200.0.2 >/dev/null 2>&1; then connected=true; break; fi
    sleep 0.05
done
$connected || fail "authenticated takeover did not forward"
ns inet ping -I takeover0 -6 -c1 -W1 fd00:200::2 >/dev/null || fail "takeover inner IPv6"
kill -TERM "$replacement"; wait "$replacement" || fail "replacement shutdown"
kill -CONT "$ENTRY_PID"
wait_ping 30 >/dev/null || fail "original Entry did not recover after takeover"
check_data
pass "authenticated replacement takes over worker slots; old Entry recovers with fresh traffic"

if [[ $RELAY == 1 ]]; then
    # Relay ACKs the Entry leg while no bytes can reach Exit. End-to-end timeout is mandatory.
    ns fw nft add table inet blackhole
    ns fw nft 'add chain inet blackhole output { type filter hook output priority -10; policy accept; }'
    ns fw nft add rule inet blackhole output "$MATCH" daddr "$EXIT_IP" tcp dport 443 drop
    sleep $((DEAD+2))
    ns fw nft delete table inet blackhole
    wait_ping 30 >/dev/null || fail "relay ACK blackhole recovery"
    check_data
    pass "relay ACKs do not conceal an unreachable Exit; recovery after one-way blackhole"
    for cycle in 1 2 3; do
        kill -TERM "$RELAY_PID"; wait "$RELAY_PID" 2>/dev/null || true
        start_relay
        t=$(wait_ping 30) || fail "relay restart $cycle"
        check_data
        sleep 0.5
        [[ $(active) == "$N" ]] || fail "leaked Exit connections after relay restart"
        [[ $(ns fw ss -Hnt state established '( sport = :8443 or dport = :443 )' | wc -l) == $((2*N)) ]] || fail "relay connections not reclaimed"
        [[ $(fd_count "$ENTRY_PID") == "$ENTRY_FDS" ]] || fail "Entry socket/fd accumulation"
        [[ $(fd_count "$EXIT_PID") == "$EXIT_FDS" ]] || fail "Exit socket/candidate/fd accumulation"
        pass "relay restart $cycle recovered ${t}s; stable endpoint/relay connections and process fd counts"
        awk '/^VmRSS:/ { print "OBSERVE: pid " FILENAME " " $0 }' "/proc/$ENTRY_PID/status" "/proc/$EXIT_PID/status"
    done
fi
kill -TERM "$EXIT_PID"; wait "$EXIT_PID" || fail "exit shutdown"
start_exit
t=$(wait_ping 30) || fail "Exit restart"
check_data
pass "Exit restart recovered ${t}s with fresh payloads"

# Reload immutable transport atomically, timers in place, then rotate keys on both ends.
printf "auth_key = '%064d'\ntransport = 'faketcp'\n" 1 >"$LOG/auth.toml"
# CLI transport has precedence, so change topology to prove rejection too.
printf "tun_name = 'other0'\n" >>"$LOG/auth.toml"
write_configs
kill -HUP "$ENTRY_PID" "$EXIT_PID"; sleep 0.2
check_data
printf "auth_key = '%064d'\nping_interval = 1\ndead_timeout = 5\n" 1 >"$LOG/auth.toml"
ENTRY_CPUS=2-3
EXIT_CPUS=0-1
write_configs
kill -HUP "$ENTRY_PID" "$EXIT_PID"; sleep 0.2
check_data
worker_cpus() {
    for task in /proc/"$1"/task/*; do
        if [[ $(cat "$task/comm") == ghostun-w* ]]; then
            awk '/^Cpus_allowed_list:/ { print $2 }' "$task/status"
        fi
    done | sort -n | paste -sd,
}
[[ $(worker_cpus "$ENTRY_PID") == 2,3 ]] || fail "Entry affinity reload"
[[ $(worker_cpus "$EXIT_PID") == 0,1 ]] || fail "Exit affinity reload"
printf "auth_key = '%064d'\nping_interval = 1\ndead_timeout = 4\n" 3 >"$LOG/auth.toml"
write_configs
kill -HUP "$ENTRY_PID" "$EXIT_PID"
wait_ping 30 >/dev/null || fail "key reload"
# Wait until both workers, not merely one ping flow, have completed rolling reload.
for _ in $(seq 150); do
    grep -q 'configuration reload complete (generation 2)' "$LOG/entry.log" && grep -q 'configuration reload complete (generation 2)' "$LOG/exit.log" && break
    sleep 0.1
done
grep -q 'configuration reload complete (generation 2)' "$LOG/entry.log" || fail "Entry key reload incomplete"
grep -q 'configuration reload complete (generation 2)' "$LOG/exit.log" || fail "Exit key reload incomplete"
check_data
[[ $(active) == "$N" ]] || fail "key reload connection count"
pass "rejected topology reload, timer/actual CPU-affinity reload, and rolling key reauthentication"


ENTRY_CPUS=0-1; EXIT_CPUS=2-3; write_configs
kill -HUP "$ENTRY_PID" "$EXIT_PID"
sleep 0.3
[[ $(worker_cpus "$ENTRY_PID") == 0,1 ]] || fail "Entry benchmark affinity"
[[ $(worker_cpus "$EXIT_PID") == 2,3 ]] || fail "Exit benchmark affinity"
ENTRY_PID=$ENTRY_PID EXIT_PID=$EXIT_PID LOG=$LOG OUTER_FAMILY=$OUTER_FAMILY RELAY=$RELAY bash tests/perf/performance.sh

kill -TERM "$ENTRY_PID" "$EXIT_PID"
wait "$ENTRY_PID" || fail "Entry shutdown"; wait "$EXIT_PID" || fail "Exit shutdown"
for side in entry exit; do
    ! ns "$side" ip link show ghostun0 >/dev/null 2>&1 || fail "TUN survived shutdown"
    ! ns "$side" nft list table inet ghostun_ghostun0 >/dev/null 2>&1 || fail "rules survived shutdown"
done
[[ $(active) == 0 ]] || fail "TCP connections survived shutdown"
pass "graceful shutdown releases TUN, network tables and sockets"
echo 'ALL PASSED'
