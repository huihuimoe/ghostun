#!/bin/bash
# Called by the disposable-container acceptance suites while their topology is alive.
set -euo pipefail
TOOLS=$(realpath tests/perf/tcp-tools.py)
servers=()
cleanup() {
    for p in "${servers[@]}"; do kill "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
    ip netns exec entry tc qdisc del dev e0 root 2>/dev/null || true
    ip netns exec fw tc qdisc del dev f0 root 2>/dev/null || true
}
trap cleanup EXIT
for address in 10.3.0.2 fd00:3::2; do
    ip netns exec inet python3 "$TOOLS" serve "$address" --port 7100 >"$LOG/perf-echo-$address.log" 2>&1 & servers+=("$!")
done
sleep 0.2
for condition in clean rtt20-loss0.1; do
    extra=()
    [[ $condition == clean ]] || extra=(delay 10ms loss 0.1%)
    # Both transports see the same bounded 100 Mbit/s Entry-facing link. Never impair host links.
    ip netns exec entry tc qdisc replace dev e0 root netem rate 100mbit "${extra[@]}"
    ip netns exec fw tc qdisc replace dev f0 root netem rate 100mbit "${extra[@]}"
    for inner in ipv4 ipv6; do
        address=10.3.0.2
        [[ $inner == ipv4 ]] || address=fd00:3::2
        for direction in upload download; do
            ip netns exec inet iperf3 -s -1 -p 5208 >"$LOG/perf-server.log" 2>&1 & server=$!; servers+=("$server")
            sleep 0.2
            CONDITION=$condition INNER=$inner DIRECTION=$direction ADDRESS=$address TOOLS=$TOOLS TRANSPORT=${TRANSPORT:-tcp} OUTER_FAMILY=${OUTER_FAMILY:-ipv4} RELAY=${RELAY:-0} \
                python3 tests/perf/performance.py >>"$LOG/performance.jsonl"
            python3 - "$LOG/performance.jsonl" <<'PYTEST'
import json,sys
row=json.loads(open(sys.argv[1]).readlines()[-1]);row.pop('sockets')
print(json.dumps(row))
PYTEST
            wait "$server"
        done
    done
done
