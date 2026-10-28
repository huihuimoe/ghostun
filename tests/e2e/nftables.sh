#!/bin/bash
# Run only inside a disposable privileged container; never on the host.
# The harness keeps nft available while each Ghostun process gets it masked in
# its private ip-netns mount namespace. See tests/README.md.
set -euo pipefail

BIN=$(realpath "${BIN:-target/release/ghostun}")
LOG=${LOG:-target/e2e-nftables}
TABLE=ghostun_ghostun0
mkdir -p "$LOG"
LOG=$(realpath "$LOG")
umask 077
printf "auth_key = '%064d'\n" 1 >"$LOG/auth.toml"

PIDS=()
NETNS=()
ns() { ip netns exec "$@"; }
pass() { echo "PASS: $*"; }
fail() {
    echo "FAIL: $*"
    for log in "$LOG"/*.log; do
        [[ -f $log ]] || continue
        echo "=== $log"
        tail -n 30 "$log"
    done
    exit 1
}
cleanup() {
    for p in "${PIDS[@]}"; do kill -TERM "$p" 2>/dev/null || true; done
    for p in "${PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
    for n in "${NETNS[@]}"; do ip netns del "$n" 2>/dev/null || true; done
}
trap cleanup EXIT

# Resolve PATH's nft and all conventional hard-coded locations before masking
# the real files. Resolving symlinks also covers /sbin -> /usr/sbin and similar
# aliases; each namespace gets its own mounts, so the harness observer is intact.
HIDE_NFT='
set -euo pipefail
IFS=: read -r -a path_dirs <<<"$PATH"
candidates=()
for dir in "${path_dirs[@]}"; do
    [[ -n $dir ]] || dir=.
    candidates+=("$dir/nft")
done
candidates+=(./nft "$(command -v nft)" /usr/sbin/nft /sbin/nft /usr/bin/nft /bin/nft)
for candidate in "${candidates[@]}"; do
    [[ -e $candidate ]] || continue
    resolved=$(realpath "$candidate")
    if [[ -f $resolved && -x $resolved ]]; then
        mount --bind /dev/null "$resolved"
    fi
done
for candidate in "${candidates[@]}"; do
    [[ -e $candidate ]] || continue
    resolved=$(realpath "$candidate")
    if [[ -x $resolved ]]; then
        echo "nft remains executable at $candidate ($resolved)" >&2
        exit 126
    fi
done
exec "$@"
'

run_transport() {
    local transport=$1
    local entry="ghostun-nft-${transport}-entry"
    local exit="ghostun-nft-${transport}-exit"
    local entry_pid exit_pid connected=false rules
    NETNS=("$entry" "$exit")
    for n in "${NETNS[@]}"; do ip netns del "$n" 2>/dev/null || true; done
    for n in "${NETNS[@]}"; do
        ip netns add "$n"
        ns "$n" ip link set lo up
    done
    ip link add e0 netns "$entry" type veth peer name x0 netns "$exit"
    ns "$entry" ip addr add 192.0.2.1/30 dev e0
    ns "$exit" ip addr add 192.0.2.2/30 dev x0
    ns "$entry" ip link set e0 up
    ns "$exit" ip link set x0 up

    ip netns exec "$exit" bash -c "$HIDE_NFT" _ \
        "$BIN" --config "$LOG/auth.toml" exit --transport "$transport" \
        --listen 443 --iface x0 --conns 1 --ping-interval 1 --dead-timeout 4 \
        >"$LOG/$transport-exit.log" 2>&1 &
    exit_pid=$!
    PIDS+=("$exit_pid")
    ip netns exec "$entry" bash -c "$HIDE_NFT" _ \
        "$BIN" --config "$LOG/auth.toml" entry --transport "$transport" \
        --remote 192.0.2.2:443 --iface e0 --conns 1 --ping-interval 1 --dead-timeout 4 \
        >"$LOG/$transport-entry.log" 2>&1 &
    entry_pid=$!
    PIDS+=("$entry_pid")

    for _ in $(seq 100); do
        kill -0 "$exit_pid" 2>/dev/null || fail "$transport Exit startup failed"
        kill -0 "$entry_pid" 2>/dev/null || fail "$transport Entry startup failed"
        if ns "$entry" ping -c1 -W1 10.200.0.2 >/dev/null 2>&1; then
            connected=true
            break
        fi
        sleep 0.1
    done
    $connected || fail "$transport did not forward inner IPv4 traffic with nft hidden"

    for n in "$entry" "$exit"; do
        ns "$n" ip link show dev ghostun0 >/dev/null 2>&1 || fail "$transport $n TUN missing"
        rules=$(ns "$n" nft list table inet "$TABLE" 2>/dev/null) || fail "$transport $n owned nft table missing"
        if [[ $transport == tcp ]] && grep -Eiq 'notrack|pkttype|flags.*rst' <<<"$rules"; then
            fail "TCP $n installed FakeTCP-specific rules"
        fi
    done
    pass "$transport: Ghostun started without nft executable, forwarded inner IPv4, and installed owned tables"

    kill -TERM "$entry_pid" "$exit_pid"
    wait "$entry_pid" || fail "$transport Entry shutdown failed"
    wait "$exit_pid" || fail "$transport Exit shutdown failed"
    PIDS=()
    for n in "$entry" "$exit"; do
        ! ns "$n" ip link show ghostun0 >/dev/null 2>&1 || fail "$transport $n TUN survived shutdown"
        ! ns "$n" nft list table inet "$TABLE" >/dev/null 2>&1 || fail "$transport $n owned nft table survived shutdown"
    done
    pass "$transport: SIGTERM removed TUN and owned nft tables"
    for n in "${NETNS[@]}"; do ip netns del "$n"; done
    NETNS=()
}

run_transport faketcp
run_transport tcp
echo "ALL PASSED"
