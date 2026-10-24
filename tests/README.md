# Testing

Run these commands from the repository root. Privileged network tests must run inside a disposable container, never on the host.

```sh
cargo test                                   # unprivileged unit tests
docker build -t ghostun .
docker run --rm --privileged -v "$PWD":/src:ro -w /src --entrypoint sh ghostun -c \
  'apk add -q bash conntrack-tools iputils iperf3 mount &&
   for family in ipv4 ipv6; do
     BIN=/usr/local/bin/ghostun OUTER_FAMILY=$family bash tests/e2e/netns.sh || exit
   done &&
   BIN=/usr/local/bin/ghostun bash tests/e2e/ipv6-disabled.sh'
```

## Dual-stack forwarding and recovery

[`e2e/netns.sh`](e2e/netns.sh) builds `entry ↔ stateful firewall ↔ exit ↔ internet` network namespaces. Run it once per outer family using `OUTER_FAMILY=ipv4` (default) or `OUTER_FAMILY=ipv6`. Each run checks authenticated inner dual-stack connectivity, full-MTU IPv4/IPv6 packets, bulk TCP, an exact N steady-state conntrack count, recovery after a silent conntrack flush and a one-way black hole, and clean shutdown. The IPv6 run removes IPv4 addresses from the endpoints' outer interfaces.

The same topology also checks wrong-key denial, active-tuple preservation during 32 unauthenticated TCP handshakes, and source-address replacement after killing Entry without RST. During replacement it drops authentication Hello frames while permitting the ordinary TCP handshake, verifies forwarding is still denied, then restores Hello delivery and observes authenticated retry through strict conntrack. RSS and throughput are observations, not performance pass/fail thresholds.

The scripts create mode-0600 TOML files containing public test-only keys inside the test container. Never reuse these keys in deployment. Session tests cover malformed and reflected proofs, old-exchange replay, active-liveness isolation, legitimate admission during unrelated candidate attempts, timeout/expiry (including Finished received at or after the deadline before a timer tick), and loss of each of the four authentication messages.

## IPv6-unavailable fallback

[`e2e/ipv6-disabled.sh`](e2e/ipv6-disabled.sh) disables IPv6 on newly created interfaces and hides the IPv6 sysctl tree in private mount namespaces. It checks that default Entry and Exit configurations still forward full-MTU inner IPv4 packets and clean up TUN and nftables state. The fixture requires `mount` only in the test container, not in production.
