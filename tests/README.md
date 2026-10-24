# Testing

Run unit tests directly on the host. Run privileged network tests inside a disposable Docker container so host networking is never touched:

```sh
cargo test --locked

docker build -t ghostun .
docker run --rm --privileged -v "$PWD":/src:ro -w /src --entrypoint sh ghostun -c \
  'apk add -q bash conntrack-tools iputils iperf3 mount &&
   for family in ipv4 ipv6; do
     BIN=/usr/local/bin/ghostun OUTER_FAMILY=$family bash tests/e2e/netns.sh || exit
   done &&
   BIN=/usr/local/bin/ghostun bash tests/e2e/ipv6-disabled.sh'
```

## Suites

- **[`e2e/netns.sh`](e2e/netns.sh)** — Builds `entry ↔ firewall ↔ exit ↔ internet` network namespaces for `OUTER_FAMILY=ipv4` and `ipv6`. Verifies mutual authentication, wrong-key rejection, inner dual-stack ping and bulk TCP, exact `--conns` conntrack state, recovery after conntrack flush or blackhole, and clean `SIGTERM` teardown.
- **[`e2e/ipv6-disabled.sh`](e2e/ipv6-disabled.sh)** — Disables kernel IPv6 on new interfaces and masks `/proc/sys/net/ipv6` to verify that default Entry and Exit configs fall back cleanly to inner IPv4.
