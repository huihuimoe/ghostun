# Ghostun Specification: SIGHUP Configuration Reload and Rolling Session Rotation

## Problem Statement

Ghostun currently loads its TOML configuration file and command-line flags once at process startup. Changing any operational parameter—such as rotating the shared `auth_key`, tuning `ping_interval` or `dead_timeout` for changing link conditions, or adjusting worker CPU affinity (`cpus`)—requires a full process restart on Entry and Exit.

Restarting the process destroys the inner TUN interface (`ghostun0`), removes and reinstalls the `nftables` table, and tears down all `N` outer FakeTCP worker sessions simultaneously. Every active inner connection experiences a hard outage until the process restarts, recreates the TUN device, and re-establishes handshakes. Worse, if an operator introduces a syntax or validation error in the edited TOML file before restarting, the daemon fails to start and leaves the tunnel completely offline.

Operators need a way to reload safe runtime settings from the configuration file on demand via `SIGHUP` without tearing down the TUN interface or dropping all outer worker sessions at once, while guaranteeing that invalid configuration changes or unsupported topology changes are rejected atomically without disturbing the running tunnel.

## Solution

Support live configuration reload triggered by `SIGHUP`. When `SIGHUP` arrives, re-read the `--config` TOML file, re-apply the original startup command-line flag overrides (`CLI > TOML > defaults`), and run full configuration validation plus reload-compatibility checks before touching any running worker.

Scope reloadable settings to the four session- and worker-local parameters that do not alter kernel interfaces, raw socket bindings, cBPF steering programs, buffer layouts, or `nftables` rules:

- `auth_key`
- `ping_interval`
- `dead_timeout`
- `cpus`

If the TOML file cannot be read or parsed, fails validation, or modifies any of the remaining twelve immutable topology/transport fields (`mode`, `outer_family`, `tun_name`, `tun_ipv4`, `tun_ipv6`, `conns`, `outer_mtu`, `tun_mtu`, `iface`, `netfilter`, `remote`, `listen`, `base_port`), reject the entire reload, log an error, and keep the current configuration running unchanged.

When a valid reload only modifies `ping_interval`, `dead_timeout`, or `cpus`, apply those changes in place across workers without resetting active FakeTCP sessions. When a worker's effective `auth_key` changes, perform a rolling session rotation across workers `0..conns` one worker at a time: send `RST` on the worker's current session, switch that worker to the new configuration, and—if that worker was `Established` prior to rotation—wait until it reaches `Established` under the new configuration before rotating the next worker.

## User Stories

1. As an operator, I want to send `SIGHUP` (or `systemctl reload`) to a running `ghostun` process, so that configuration changes take effect without restarting the daemon or recreating the inner TUN device.
2. As an operator, I want `SIGHUP` to re-read the `--config` file while preserving any command-line flags passed at startup, so that reload respects the `CLI > TOML > defaults` precedence contract.
3. As an operator who started `ghostun` without `--config`, I want `SIGHUP` to log a warning and leave the running tunnel untouched, so that an accidental signal does not crash or disrupt a CLI-only instance.
4. As an operator, I want a missing, unreadable, or syntactically invalid TOML file on `SIGHUP` to be rejected without affecting active sessions, so that a typo during editing never takes down the tunnel.
5. As an operator, I want invalid parameter values (such as a malformed `auth_key`, `ping_interval = 0`, or `dead_timeout <= ping_interval`) on `SIGHUP` to be rejected atomically, so that bad configuration values never partially apply.
6. As an operator, I want changes to immutable fields (`mode`, `outer_family`, `tun_name`, `tun_ipv4`, `tun_ipv6`, `conns`, `outer_mtu`, `tun_mtu`, `iface`, `netfilter`, `remote`, `listen`, `base_port`) on `SIGHUP` to be rejected with a clear error log, so that settings requiring TUN/socket/firewall recreation are never silently ignored or partially applied.
7. As an operator, I want `auth_key` material kept out of reload error messages and logs, so that failed or successful reloads never leak secrets into system logs.
8. As an operator tuning `ping_interval` or `dead_timeout`, I want those timer changes applied in place without sending `RST` or re-running the handshake, so that health-probe tuning causes zero packet loss or session churn.
9. As an operator adjusting `cpus`, I want each worker thread to update its CPU affinity in place on reload, so that core allocation can be rebalanced without resetting outer sessions.
10. As an operator rotating `auth_key`, I want worker sessions rotated one at a time (`0..conns`), so that the remaining `conns - 1` workers continue forwarding inner traffic while one worker re-authenticates.
11. As an Entry operator rotating `auth_key`, I want the rotating worker to send `RST` on its old outer tuple, switch to the new `auth_key`, and immediately initiate a fresh handshake on its next source port, so that firewall state for the old session is released and replacement begins immediately.
12. As an Exit operator rotating `auth_key`, I want the rotating worker to send `RST` to its active Entry peer, switch to the new `auth_key`, and transition to `Closed`, so that the Entry peer immediately observes the `RST` and reconnects rather than waiting for `dead_timeout`.
13. As an operator rotating `auth_key` across Entry and Exit sequentially, I want the reload coordinator to wait for worker `0` to re-reach `Established` before rotating worker `1`, so that while the peer node has not yet reloaded its key, at most one worker slot is disconnected and `conns - 1` slots remain active.
14. As an operator reloading a node whose worker is not currently `Established` (for example, an Exit reloaded while Entry is offline), I want that worker to switch to the new configuration immediately without blocking subsequent workers on `Established`, so that all idle slots are ready with the new key before the peer connects.
15. As an operator recovering from a mistaken `auth_key` reload by restoring the original key in the TOML file and sending a second `SIGHUP`, I want the new reload to supersede the in-progress rotation and compare against each worker's currently active `auth_key`, so that worker `0` reverts to the original key and workers `1..conns - 1` that never left the original key are not unnecessarily reset.
16. As an operator sending `SIGINT` or `SIGTERM` while a rolling rotation is waiting on a worker, I want the process to abort the rotation immediately and perform normal clean shutdown, so that service stop commands never hang behind an unestablished reload.
17. As a performance engineer, I want reload coordination kept out of the per-packet encapsulation, decapsulation, `recvmmsg`, and `sendmmsg` loops, so that steady-state throughput and zero-copy buffer handling remain unchanged.

## Implementation Decisions

### 1. Reload Scope and Validation Boundary

- Retain the startup command-line argument snapshot alongside the active runtime configuration.
- On `SIGHUP`, if no `--config` path was supplied at startup, log a warning and leave the running configuration unchanged.
- Otherwise, re-parse and validate the configuration using the exact startup precedence (`CLI > TOML > defaults`) and existing validation rules.
- Compare the newly validated configuration against the active configuration:
  - **Mutable on reload**: `auth_key`, `ping_interval`, `dead_timeout`, `cpus`.
  - **Immutable on reload**: `mode`, `outer_family`, `tun_name`, `tun_ipv4`, `tun_ipv6`, `conns`, `outer_mtu`, `tun_mtu`, `iface`, `netfilter`, `remote`, `listen`, `base_port`.
  - Notice that when `tun_ipv6` was cleared at startup because inner IPv6 was unavailable in the kernel, reload comparison must treat the effective inner IPv6 state consistently rather than falsely flagging a mismatch when the config file itself did not change.
- If any immutable field differs, reject the reload as an incompatible configuration change, log an error naming the rejected field(s), and leave all workers untouched.
- If neither any mutable field nor any immutable field changed, log an informational no-op reload message and do not disturb workers.

### 2. Coordinator and Worker Communication

- Install a `SIGHUP` handler alongside `SIGINT` and `SIGTERM` that sets an atomic reload flag without performing non-async-signal-safe work in the handler.
- Turn the main thread (previously blocked unconditionally in `join` on worker threads) into the reload and shutdown coordinator.
- Maintain a lightweight shared control slot per worker between the coordinator and that worker thread:
  - The coordinator publishes a target worker update (`auth_key`, `ping_interval`, `dead_timeout`, `cpu`, and a monotonically increasing generation number).
  - The worker checks for a new target generation once per outer `poll` iteration (outside the inner `ROUNDS` / `RAW_BATCH` packet-processing loops) and reports back its applied generation and whether its session is currently `Established` (and whether its latest reload step required waiting for `Established`).
- Do not introduce mutex locks into the per-packet data path, extra sockets, or additional threads. Because each worker's `poll` timeout is bounded by `MAX_POLL` (200 ms) or the next session timer deadline, a worker observes a staged reload within at most one `poll` wakeup cycle without requiring an extra `eventfd` per worker (or may optionally use a wakeup primitive if immediate sub-millisecond reaction on idle workers is desired).

### 3. Per-Worker Application Semantics (In-Place vs. Session Rotation)

- When a worker observes a new target generation from the coordinator:
  1. **CPU affinity (`cpus`)**: If the worker's target CPU index changed, call `pin_to_cpu` for the new core; log a warning on failure without aborting the worker.
  2. **Timers (`ping_interval`, `dead_timeout`)**: Update `ping_interval` and `dead_timeout` in the worker's `SessionConfig` and update the `Auth` replay/cookie window (`dead_timeout`). Recompute `next_ping` relative to `now` so shortened intervals take effect without waiting for a stale long deadline.
  3. **Authentication key (`auth_key`)**: Compare the target `auth_key` against **this worker's currently active `auth_key`**:
     - **Unchanged `auth_key`**: Keep the current session state (`Established`, sequence numbers, peer tuple, and replay/ticket watermarks) intact. Mark the worker's reload generation as complete immediately.
     - **Changed `auth_key`**:
       - Record whether the session was `Established` immediately before this update (`was_established`).
       - Replace the worker's `Auth` state with the new `auth_key` (preserving the startup cookie key or reinitializing with the new `auth_key` while keeping monotonic ticket/ISN safety).
       - If the session is `Established` (or in `SynSent` / `Authenticating` on Entry with an active tuple), emit `RST` to the current peer tuple so the peer and stateful firewalls drop the old session immediately.
       - On **Entry**: immediately start a fresh connection attempt (`reconnect`) on the next port from the worker's port pool using the new `auth_key`.
       - On **Exit**: clear the active peer and transition to `Closed`, awaiting the Entry peer's re-handshake under the new `auth_key`.
       - Report to the coordinator whether the coordinator must wait for `Established` (`was_established == true`) before advancing to the next worker.

### 4. Rolling Rotation State Machine

- When the coordinator validates a reload:
  - If the new configuration changes `auth_key` relative to any worker's active configuration, the coordinator steps through workers `0..conns` sequentially:
    1. Publish the new target configuration to worker `i`.
    2. Wait until worker `i` acknowledges the target generation **and** either:
       - worker `i` did not require an `Established` wait (because its own `auth_key` was already equal to the target `auth_key`, or because worker `i` was not `Established` when the update was applied), **or**
       - worker `i` has reached `Established` under the new target generation.
    3. Advance to worker `i + 1`.
  - If a reload only modifies `ping_interval`, `dead_timeout`, or `cpus`, the coordinator still steps through (or publishes to) workers `0..conns`; since none of the workers change `auth_key`, every worker completes in place without waiting for handshake re-establishment.
- **Superseding reload on overlapping `SIGHUP`**:
  - While the coordinator is waiting for worker `i` to reach `Established`, it continues polling `STOP` and `RELOAD`.
  - If `STOP` is set, the coordinator immediately breaks out of the rotation loop, lets workers send shutdown `RST`s and exit, and removes the `nftables` table.
  - If another `SIGHUP` arrives mid-rotation and produces a valid configuration, the coordinator immediately restarts the rolling pass from worker `0` with the newest target configuration. Because each worker diffs the target `auth_key` against its own currently active `auth_key`, workers that had not yet rotated to an intermediate key will not reset if the new reload reverts to their existing key.

## Testing Decisions

### 1. Observable Behavior and Seams

Verify configuration reload at the existing `config` validation seam, the deterministic `Session` protocol seam, and the isolated Docker `netns` E2E seam. Do not expose private worker internals solely for testing.

Good tests assert:
- Which reloads succeed or fail validation/compatibility checks.
- Emitted wire frames (`RST`, `SYN`, authentication frames, `PING`) and forwarding continuity across reload events.
- Per-worker rolling progression ( specifically that worker `1` continues forwarding traffic while worker `0` is waiting to re-establish with a new key, and that restoring the original key recovers worker `0` without resetting worker `1`).

### 2. Configuration Reload Validation Tests (`config`)

- Verify that reloading a TOML file with updated `auth_key`, `ping_interval`, `dead_timeout`, or `cpus` succeeds and preserves startup CLI flag overrides.
- Verify that syntax errors, missing files, invalid `auth_key` values (and redaction of key material in errors), or invalid timer bounds are rejected on reload.
- Verify that modifying any immutable field (`mode`, `outer_family`, `tun_name`, `tun_ipv4`, `tun_ipv6`, `conns`, `outer_mtu`, `tun_mtu`, `iface`, `netfilter`, `remote`, `listen`, `base_port`) is rejected when checked against the running configuration.

### 3. Session Reload Behavior Tests (`session`)

- Verify that updating `ping_interval` and `dead_timeout` on an `Established` session preserves `Established` state, sequence numbers, and data forwarding without emitting `RST` or `SYN`, while adopting the new timer intervals on subsequent ticks.
- Verify that updating `auth_key` with the same key is a no-op that preserves the active session.
- Verify that updating `auth_key` with a new key on an `Established` Entry session emits `RST` on the old tuple, rotates the source port, and initiates a new handshake that only completes against an Exit configured with the new key.
- Verify that updating `auth_key` with a new key on an `Established` Exit session emits `RST` to the Entry peer, transitions Exit to `Closed`, causes Entry to immediately reconnect upon receiving that `RST`, and completes mutual authentication under the new key.
- Verify that updating `auth_key` on a `Closed` session updates the key without emitting `RST` or blocking on an active peer.

### 4. Containerized Netns E2E (`tests/e2e/netns.sh`)

- In the disposable privileged Docker `netns` harness (`N=2`), exercise live `kill -HUP` reload:
  - Reject an invalid/immutable config reload and verify existing tunnel traffic continues uninterrupted.
  - Perform a staged `auth_key` reload (`Entry` reloaded first while `Exit` still holds the old key, then `Exit` reloaded, or vice versa) and verify that rolling rotation completes and inner IPv4/IPv6 traffic flows across all worker connections afterward.

## Out of Scope

1. Hot-reloading topology, interface, addressing, or steering parameters (`mode`, `outer_family`, `tun_name`, `tun_ipv4`, `tun_ipv6`, `conns`, `outer_mtu`, `tun_mtu`, `iface`, `netfilter`, `remote`, `listen`, `base_port`).
2. Changing the `--config` file path itself after startup or enabling reload for processes launched without `--config`.
3. File-system watchers (`inotify`) that reload automatically on file save without an explicit `SIGHUP`.
4. Control sockets, HTTP/gRPC admin APIs, or external secret-manager integrations.
5. Accepting multiple `auth_key` values simultaneously within a single worker slot.
6. Updating `deploy/` systemd unit files or README documentation unless requested alongside implementation.

## Further Notes

- Rolling rotation by waiting for `Established` on previously active workers provides a natural safety barrier during two-node `auth_key` rotation: between the time the first node receives `SIGHUP` and the second node receives `SIGHUP`, only worker `0` is in handshake retry while workers `1..conns - 1` remain `Established` on the prior session and continue forwarding inner traffic. Once the second node receives `SIGHUP`, worker `0` completes authentication and the remaining workers rotate in rapid succession.
