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
    for binary in target/debug/deps/ghostun-*; do
      if [ -f "$binary" ] && [ -x "$binary" ]; then
        "$binary" --ignored --exact netfilter::tests::atomic_table_replacement
      fi
    done
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
- The ignored `atomic_table_replacement` Rust test runs only in the container; it checks
  failed-install rollback, preservation of an existing table, replacement, and removal.
- Rust tests cover fixed wire-format vectors, sliced packet buffers, strict message lengths,
  deterministic framing, authentication and bounded backpressure.

For the automatic FakeTCP TUN fast path, run `netns.sh` with `EXPECT_TUN_DRIVER=uring`
for each outer family; the suite requires io_uring to stay enabled. Run it again
with `EXPECT_TUN_DRIVER=poll` to check policy fallback. For that container, replace
`--privileged` with `--cap-add=ALL --device=/dev/net/tun
--security-opt apparmor=unconfined --security-opt systempaths=unconfined
--security-opt seccomp="$PWD/tests/deny-io-uring.json"`;
Docker bypasses seccomp in privileged containers.
Run the ignored `sys::batch_tests::entry_raw_socket_binds_and_connects_both_families`
and `faketcp::tun::tests::uring_recycles_buffers_and_preserves_backlog_across_runtime_fallback`
tests inside the privileged container too.

To run the performance scenarios from `README.md`, run:

```sh
sudo docker exec ghostun-e2e python3 tests/perf/benchmark.py --mode all
```

TCP peers use `tcp_notsent = 64` KiB for the 100 Mbit/s comparison and
`128` KiB for uncapped large, mixed and small packet throughput.
The JSON results record `tcp_notsent_kib`; stored baselines may use different tuning.
`perf/tcp-perf.sh` also uses 64 KiB for its 100 Mbit/s measurements.
