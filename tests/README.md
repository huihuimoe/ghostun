# Testing

Run unit tests on the host. Run privileged network tests
inside a disposable Docker container.
Build outputs and logs below stay in the checkout's ignored `target/` directory.

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
cargo build --release --locked
sudo docker build -f tests/Dockerfile -t ghostun-e2e .

sudo docker run -d --name ghostun-e2e --privileged --network none \
  -v "$PWD":/src -w /src -e BIN=/src/target/release/ghostun ghostun-e2e -c "sleep infinity"
sudo docker exec ghostun-e2e bash -c '
    set -e
    for family in ipv4 ipv6; do
      LOG=/src/target/e2e-faketcp-$family OUTER_FAMILY=$family bash tests/e2e/netns.sh
      for relay in 0 1; do
        LOG=/src/target/e2e-tcp-$family-$relay OUTER_FAMILY=$family RELAY=$relay bash tests/e2e/tcp.sh
      done
    done
    for transport in faketcp tcp; do
      LOG=/src/target/e2e-noipv6-$transport TRANSPORT=$transport bash tests/e2e/ipv6-disabled.sh
    done'
```

The container needs four usable CPUs. Inspect logs under `target/` with
`sudo docker exec ghostun-e2e cat <log-path>`, then remove the container with
`sudo docker rm -f ghostun-e2e`.

- `e2e/netns.sh`: FakeTCP forwarding, authentication, firewall recovery, reload and cleanup.
- `e2e/tcp.sh`: direct/relayed TCP, exact bidirectional IPv4/IPv6 TCP/UDP payloads,
  rejection and admission limits, takeover, restarts, blackholes, reload and cleanup.
- `e2e/ipv6-disabled.sh`: IPv4 fallback with kernel IPv6 disabled, for both transports.
- Rust tests cover deterministic framing, authentication and bounded backpressure.
