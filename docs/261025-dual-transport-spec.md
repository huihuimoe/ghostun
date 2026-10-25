# Ghostun Specification: FakeTCP and Relay-Compatible TCP Transports

## Problem Statement

Operators need an alternative transport for environments where FakeTCP is unavailable or unsuitable. Ghostun should add a TCP-based transport while retaining FakeTCP, allowing operators to choose the appropriate transport without changing the existing Entry/Exit tunnel model.

## Solution

Support two explicitly selected outer transports in the same binary: the existing `faketcp` transport and a new kernel-backed `tcp` transport with explicit framing and independent mutual authentication. Preserve `mode` for the Entry/Exit role and add `transport`, defaulting to `faketcp` so existing configurations retain their behavior.

Each instance runs exactly one transport. Both peers must select the same transport; switching requires restarting the instance. TCP supports both direct connections and ordinary byte-stream relays. FakeTCP remains for paths that do not terminate its TCP connection or alter the worker-port mapping on which it depends.

Keep the existing inner TUN, dual-stack forwarding, Exit NAT, proxy binding, worker count, and CPU-affinity model. In TCP mode, identify workers explicitly in the authenticated handshake rather than through source ports. Bound application buffering and incomplete authentication, preserve end-to-end health checks, and reconnect with bounded jittered backoff.

This feature authenticates connections but does not add encryption or cryptographic integrity protection to established tunnel data. TCP-over-TCP head-of-line blocking and retransmission are accepted costs of compatibility with the existing relay.

## User Stories

1. As an operator, I want one binary to support FakeTCP and real TCP, so that I can select the transport appropriate to each route.
2. As an existing operator, I want omitted transport configuration to retain FakeTCP, so that upgrading does not silently change my network behavior.
3. As an operator, I want the role and transport to be separate settings, so that Entry/Exit selection remains unambiguous.
4. As an operator, I want matching TOML and CLI transport selection with CLI precedence, so that deployment and interactive operation follow existing conventions.
5. As an operator, I want invalid transport values rejected before networking starts, so that configuration mistakes do not create partial deployments.
6. As an operator, I want each instance to run one explicit transport, so that failures do not trigger an unexpected downgrade or route change.
7. As an operator, I want transport changes to require a restart, so that a reload cannot replace socket and firewall semantics underneath active traffic.
8. As an operator, I want TCP mode to work through a relay that terminates and recreates TCP, so that my existing forwarding infrastructure remains usable.
9. As an operator, I want TCP mode to work directly as well, so that a relay is optional rather than part of the protocol.
10. As an operator, I want FakeTCP's existing wire protocol preserved, so that the new transport does not require a coordinated FakeTCP protocol migration.
11. As a proxy operator, I want to keep binding outbound traffic to the inner TUN, so that proxy integration does not change with the outer transport.
12. As an operator, I want inner IPv4 and IPv6 over either supported outer family, so that inner and outer addressing remain independent.
13. As an operator, I want both inner TCP and UDP forwarded, so that changing the outer transport does not remove existing inner protocols.
14. As an operator, I want Entry to leave my default route unchanged, so that starting a tunnel does not redirect unrelated host traffic.
15. As an operator, I want the same configured worker count on both peers, so that tunnel capacity and connection budgeting remain predictable.
16. As an operator, I want one long-lived TCP connection per worker, so that Ghostun does not scale outer connection count with inner client count.
17. As an operator, I want worker identity authenticated explicitly, so that relay-assigned source ports cannot select the wrong worker.
18. As an operator, I want mismatched worker counts or effective TUN MTUs rejected, so that an apparently connected tunnel does not silently lose selected traffic.
19. As an Entry operator, I want to authenticate Exit, so that a successful TCP connection alone does not authorize forwarding.
20. As an Exit operator, I want to authenticate Entry before admitting traffic, so that knowing my listen address is insufficient to use the tunnel.
21. As an operator, I want authentication independent of socket addresses and TCP sequence numbers, so that ordinary relays and changing public addresses remain compatible.
22. As an operator, I want fresh, direction-bound authentication proofs, so that recorded or reflected handshakes cannot directly authorize a new connection.
23. As an operator, I want incomplete or failed authentication to leave an active worker unchanged, so that unauthenticated clients cannot replace or keep alive an existing tunnel.
24. As an operator, I want an authenticated replacement to take over its worker and close the old connection, so that recovery does not wait for the old connection to time out.
25. As an operator, I want to retain the existing mandatory shared-key provisioning model, so that this feature does not require certificates or an identity service.
26. As an operator, I want secrets excluded from logs and validation errors, so that troubleshooting does not disclose the shared key.
27. As an operator, I want the absence of encryption and per-packet authentication stated explicitly, so that I do not mistake handshake authentication for protection against a malicious relay.
28. As an operator, I want stream parsing to handle arbitrary fragmentation and coalescing, so that TCP segmentation never changes inner packet boundaries.
29. As an operator, I want malformed or oversized frames to close the connection, so that corrupt input cannot desynchronize subsequent packet parsing.
30. As an operator, I want bounded send and receive buffers with backpressure, so that a slow peer cannot grow process memory without limit.
31. As an operator, I want bounded incomplete authentication, so that pending candidates do not grow without limit or evict active tunnels.
32. As an operator, I want disconnected workers to discard traffic rather than build an offline queue, so that recovery does not release stale packets or unbounded backlog.
33. As an operator, I want unsent contents of an old connection discarded rather than replayed on a replacement, so that reconnect does not introduce application-level duplicate forwarding.
34. As an operator, I want end-to-end application health checks, so that a relay's TCP acknowledgments cannot conceal an unreachable Exit.
35. As an operator, I want connection establishment and authentication to have one bounded attempt deadline, so that a silent peer cannot occupy an attempt indefinitely.
36. As an operator, I want persistent recovery with capped jittered backoff, so that outages do not create a reconnect storm.
37. As an operator, I want brief successful connections not to reset backoff immediately, so that a flapping peer cannot force rapid repeated attempts.
38. As an operator, I want TCP mode to preserve supported key, timer, and CPU-affinity reloads, so that selecting TCP does not remove existing operational capabilities.
39. As an operator, I want key changes to force fresh authentication without an implicit old-key grace period, so that old credentials do not authorize indefinitely.
40. As an operator, I want TCP mode to use normal kernel TCP firewall behavior, so that FakeTCP-specific bypass and RST suppression cannot break ordinary sockets.
41. As an operator, I want Exit NAT and inner MSS handling retained, so that decapsulated traffic continues to reach the internet.
42. As an operator, I want meaningful connection, authentication, framing, takeover, and timeout logs, so that I can identify the stage at which a tunnel fails.
43. As an operator, I want relay and Exit restarts, disconnects, and black holes to recover, so that temporary failures do not require a manual restart of Entry.
44. As an operator, I want old connections and buffers reclaimed, so that repeated failures do not cause persistent connection or memory accumulation.
45. As a performance engineer, I want direct and relayed TCP compared with FakeTCP under controlled conditions, so that throughput and latency claims are based on evidence.
46. As a performance engineer, I want loaded small-request tail latency measured alongside throughput, so that a bulk transfer benchmark does not hide head-of-line blocking.
47. As an operator, I want tests isolated from production networking, so that verification does not alter host routing or stress live routes.
48. As a maintainer, I want tests of observable tunnel behavior rather than internal wiring, so that transport implementations can evolve without weakening their contracts.

## Implementation Decisions

### 1. Configuration and Compatibility

- Add a transport enum with exactly `faketcp` and `tcp`; default to `faketcp`.
- Preserve `mode` as the existing Entry/Exit role. Add the corresponding transport CLI option with the existing CLI-over-TOML precedence.
- Validate unsupported values and configuration errors before acquiring network resources.
- Each process instance runs one transport and one selected outer family. Entry derives the outer family from the remote address; Exit retains explicit outer-family selection.
- Peers must use the same transport. There is no automatic detection, fallback, or same-instance mixed-protocol listener.
- TCP uses kernel-assigned source ports. An explicitly configured `base_port` produces a warning in TCP mode and has no effect; its normal FakeTCP meaning is unchanged.
- Preserve existing MTU default calculations and validation ranges in both modes. Do not automatically increase TUN MTU because TCP can segment a frame.
- TCP authentication requires equal effective TUN MTUs and equal `conns`. Peers whose detected defaults differ must explicitly configure a common valid TUN MTU.
- Preserve existing FakeTCP wire behavior. The TCP protocol has an independent initial version; both peers must be upgraded to use it. Do not retrofit TCP framing or TCP authentication changes into FakeTCP.

### 2. Transport Seam and Module Responsibilities

- Introduce transport selection at the outer-I/O startup and worker-runtime seam. Keep inner TUN provisioning, configuration precedence, CPU assignment, reload coordination, and Exit forwarding/NAT common where their behavior is identical.
- Keep FakeTCP's raw-socket session state machine responsible for its existing packet sequence accounting, source-port steering, and raw transport recovery.
- Give the TCP transport module responsibility for kernel socket establishment, framed byte-stream I/O, TCP-specific authentication and worker admission, bounded backpressure, end-to-end health checks, and retry state.
- The TCP transport module hides accept/dispatch mechanics behind its worker-slot contract. Do not make worker identity depend on which thread accepted the socket or on the observed source port.
- Each worker continues to own its corresponding TUN queue and long-lived outer connection. Preserve CPU-affinity behavior and make worker completion visible to process lifecycle coordination.
- Do not introduce a general transport-plugin framework or abstractions beyond the two concrete transports and their shared operational needs.

### 3. TCP Worker Admission and Replacement

- Entry initiates one TCP connection per configured worker; Exit listens for candidates and routes them using authenticated worker identity.
- Authenticate the worker ID and total connection count. Reject out-of-range worker IDs and incompatible peer parameters.
- One worker slot has at most one active authenticated connection. A fresh authenticated candidate may replace that connection; close and release the old connection after successful admission.
- An incomplete or failed candidate must not replace, close, refresh, or otherwise modify the active slot.
- One Exit instance serves one Entry worker set. Another Entry possessing the same key is authorized to take over the corresponding slots; shared-key holders are not isolated tenants.
- The steady-state target is exactly `conns` active outer connections, independent of inner flow count. Replacement and teardown can temporarily overlap old and new connections.
- Keep each inner flow on its owning worker connection rather than striping its packets across different TCP connections to evade head-of-line blocking.

### 4. TCP Mutual Authentication

- Keep the existing mandatory 32-byte high-entropy TOML `auth_key`, encoded as 64 hexadecimal characters. Do not add a CLI key, short-password mode, authentication bypass, or key disclosure in diagnostics.
- Use HMAC-SHA256 with direction- and message-specific domain separation, fresh challenges from both peers, and explicit completion semantics. Verify tags with a constant-time verification API.
- Authenticate an unambiguous transcript containing the protocol identifier and version, roles, both challenges, worker ID, total connection count, effective TUN MTU, and other admission parameters actually exchanged.
- Do not bind authentication to IP addresses, ports, initial TCP sequence numbers, or other transport metadata that changes across a terminating relay.
- Fresh per-attempt challenges must prevent a captured authentication exchange from directly authorizing a different connection. A randomness-generation failure fails the attempt rather than using predictable replacement values.
- Neither direction forwards inner packets before mutual authentication completes. A partially completed handshake does not grant temporary forwarding access.
- Reject unsupported versions, malformed authentication messages, invalid proofs, and incompatible parameters without downgrade. Bound authentication message sizes and parsing before allocating from untrusted lengths.
- TCP wire encoding must define exact message types, field serialization, transcript ordering, proof domains, and completion transitions before implementation. These details must satisfy this contract without reusing FakeTCP's sequence-bound transcript or inventing additional configuration.
- The shared key authorizes connection establishment and slot replacement only. This feature adds no encryption, data MAC, or cryptographic protection against a relay that observes or modifies established traffic.

### 5. Stream Framing and Validation

- Frame TCP messages with a two-byte unsigned big-endian payload length followed by exactly that payload. The prefix does not count itself.
- Each data frame carries one complete inner IPv4 or IPv6 packet. Control messages have explicit types distinguishable from IP data and from authentication messages in the relevant protocol phase.
- Support arbitrary splitting of the length prefix and payload, multiple frames in one read, and partial writes. TCP read/write boundaries have no protocol meaning.
- Validate lengths, message types, protocol phase, inner packet structure, and the agreed effective TUN MTU. Never allocate unbounded storage based on peer-supplied lengths.
- Close and diagnose a connection on invalid lengths, malformed packets, illegal messages, or oversized data. Do not scan forward to guess a new frame boundary.
- TCP segmentation of one frame into several network segments is permitted. Do not add a separate tunnel fragmentation/reassembly mechanism or combine multiple inner packets into one data payload.
- Keep the current control semantics for health probes and responses while giving them a valid bounded stream encoding.

### 6. Bounded Buffering and Backpressure

- Cap pending application-level transmit bytes at 256 KiB per worker, including frame prefixes. This is an internal constant, not a new tuning option.
- Stop reading the corresponding TUN queue when there is insufficient space for another maximum-size frame. Preserve partial-write state without copying or rebuilding already queued frames unnecessarily.
- On receive, retain at most one complete frame plus fixed bounded parsing state. If writing its data packet to TUN would block, keep the frame and stop reading that TCP stream until delivery can proceed.
- Keep control-message and authentication buffering bounded too; repeated timer events or blocked writes must not create unbounded queues.
- While a worker has no authenticated connection, drain and discard packets read from its TUN queue rather than retaining an offline backlog.
- Discard the old connection's pending data on disconnect or replacement. Do not replay it through a new connection, because delivery at the old peer may be ambiguous.
- Inner TCP relies on its own recovery after loss; inner UDP may lose packets. Backpressure does not guarantee that finite kernel TUN queues never drop packets.
- Cap simultaneous unauthenticated candidates per Exit instance at `min(2 * conns, 256)`. Immediately close new candidates exceeding the cap without evicting active tunnels. Every admitted candidate still has a finite authentication deadline.
- The cap does not promise admission fairness or DDoS resistance against an attacker continuously filling candidate capacity.
- Application bounds exclude kernel TCP send/receive buffers, listener backlog, and TUN queues. Account for these separately in resource measurements; do not present 256 KiB as total connection memory.

### 7. End-to-End Health and Attempt Deadlines

- Reuse `ping_interval` and `dead_timeout`; their existing positivity and ordering validation remains applicable.
- One Entry attempt has a total `dead_timeout` budget covering connection establishment and authentication, not a fresh full budget for every handshake step.
- An accepted Exit candidate must authenticate within `dead_timeout` from acceptance; receiving partial input must not extend this deadline indefinitely.
- After establishment, only valid tunnel data or valid health-control messages refresh peer receive liveness. Kernel TCP ACKs, arbitrary bytes, malformed messages, and incomplete frames do not count.
- A transport ACK from a relay proves only progress on that TCP leg, not that Exit is processing tunnel traffic. Application-level health checking is mandatory even when the kernel considers the socket established.
- EOF, unrecoverable I/O errors, authentication failure, protocol errors, and attempt or liveness expiration end the relevant connection and release its resources.
- Congestion or TCP head-of-line blocking can delay valid health messages beyond `dead_timeout`. Such a connection is still eligible for timeout and reconnect; the protocol does not promise to distinguish congestion from peer failure.

### 8. Retry and Connection Reclamation

- Entry retries indefinitely with base delays of 1, 2, 4, 8, then 15 seconds for subsequent failures. Draw each actual delay randomly from 50% through 100% of its base; no retry delay exceeds 15 seconds.
- Count connection, authentication, and short-lived established failures toward the same consecutive-failure backoff. Reset backoff only after an established connection has survived at least one `dead_timeout`.
- Do not expose new backoff configuration or automatically increase `conns` during recovery.
- Close failed, replaced, expired, and shutdown sockets through normal kernel TCP lifecycle handling; release associated framing and pending-data state. TCP mode does not use FakeTCP source-port rotation or raw reset construction.
- Verify that repeated failures do not leave a continuously growing set of process-owned sockets, pending candidates, or buffers. Observe relay-side reclamation in the controlled relay scenario as well.
- Relay-specific teardown timers and kernel closing states can cause temporary connection-count overlap. Ghostun cannot guarantee immediate deletion from an arbitrary relay's monitoring UI or forcibly reclaim third-party state.

### 9. Network Setup and Shutdown

- TCP mode uses ordinary kernel TCP semantics. Do not apply FakeTCP outer notrack rules, packet-type changes that bypass local TCP input, or kernel RST suppression to its connections.
- Retain applicable inner MSS handling, Exit forwarding and masquerade, interface selection, outer-family selection, and the existing external-firewall-management option.
- Do not alter Entry's default route. Proxy traffic continues to opt into the inner TUN.
- Preserve dedicated per-instance network-rule ownership and cleanup, including startup/early-failure resource unwinding and graceful signal-driven shutdown.
- Stop retries, close listeners and connections, release worker resources and TUN descriptors, and remove owned network rules on normal shutdown.
- Keep operational privilege documentation accurate for the actual socket and interface operations; do not assume that replacing raw sockets removes every privileged setup requirement.

### 10. Hot Reload

- Preserve reload support for the shared key, health timers, and CPU affinity in both transports. Continue using the existing per-worker reload coordination model.
- A shared-key change updates the worker connection and requires fresh authentication. Do not leave old-key authenticated connections permanently authorized.
- Retain immutable topology/socket fields: role, transport, remote/listen address and port, outer family, TUN identity and addresses, MTU configuration, connection count, interface, network-rule management, and source-port configuration still require restart.
- Reject an incompatible reload without partially applying it. Retain startup CLI precedence and current configuration validation.
- Do not add simultaneous old/new key acceptance or a grace period. Coordinated key changes can interrupt traffic; zero-downtime key rotation is not promised.

### 11. Diagnostics

- Identify transport and worker in relevant lifecycle logs. Distinguish connection failure, authentication failure or timeout, unsupported protocol version, invalid worker or peer parameters, invalid framing, peer EOF, I/O errors, liveness timeout, successful establishment, authenticated takeover, and scheduled retry delay.
- Do not report the tunnel as established merely because a TCP handshake succeeded.
- Diagnose parameter mismatches when enough valid protocol context is available. For a peer that does not speak this protocol, report the observed protocol error or timeout rather than guessing its software or transport.
- Never print the shared key, secret-bearing configuration excerpts, or secret material in parser errors or debug output.
- Avoid adding a metrics service, telemetry framework, or independent diagnostics subsystem for this feature.

## Testing Decisions

### Primary Seam and Prior Art

Use the actual Entry/Exit process and inner TUN interface as the primary acceptance seam. Extend the existing disposable-container, real-kernel network-namespace approach rather than introducing a separate simulated tunnel implementation. Its existing coverage of authenticated establishment, dual-stack forwarding, stateful firewalls, black holes, recovery, exact stable connection count, and graceful teardown is the starting point.

The TCP path adds a real byte-stream relay between Entry and Exit. It must terminate and recreate TCP rather than merely translate packets; otherwise it does not exercise the reported failure. Verify direct TCP too. Retain the existing FakeTCP packet-path regression scenarios and inner-IPv6-disabled fallback coverage.

Use narrower tests only for behavior that is difficult to drive deterministically through the primary seam, such as exact framing splits, authentication replay, attempt deadlines, and partial I/O. Exercise the production parser, authentication, and worker behavior, not copies of their logic. Existing pure session/authentication tests, configuration parsing and reload tests, and worker coordination tests provide prior art.

Good permanent tests assert externally meaningful data, rejection, bounds, state transitions, recovery, or cleanup. Do not test source text, internal helper wiring, exact log wording, mock echoes, or successful handshakes as a substitute for actual packet transfer.

### Required Functional Scenarios

1. Default and explicit FakeTCP retain current behavior, including its existing wire protocol and authenticated forwarding.
2. TCP works directly and through the terminating relay for both supported outer families and bidirectional inner IPv4/IPv6 TCP and UDP traffic. Assert packet contents and successful consumer-visible delivery, not only nonzero traffic counters.
3. Multiple workers remain usable when backend source ports are unrelated to Entry source ports, including collisions in their modulo classes. Admission uses authenticated worker identity.
4. Prefix splitting, payload splitting, coalesced frames, and partial writes preserve exact packet boundaries and order within each worker stream. Force these conditions deterministically rather than relying on incidental network segmentation.
5. Wrong keys, unsupported versions, reflected or replayed authentication, incomplete handshakes, invalid worker IDs, and incompatible `conns` or effective MTU deny access in both directions.
6. Failed or incomplete candidates do not replace or keep alive an active connection. A genuinely authenticated replacement takes over the intended worker and retires the old connection.
7. Zero/invalid lengths, illegal message types or phases, malformed inner packets, and oversized payloads close the connection without parser resynchronization or unbounded allocation.
8. A slow TCP receiver and a blocked TUN writer cause bounded backpressure. Verify payload correctness after progress resumes and the agreed application-level storage bounds during the stall.
9. Candidate saturation is bounded, excess candidates are closed, and active tunnel traffic continues. Expired candidates release their capacity.
10. Offline traffic and old pending writes are not accumulated or replayed after reconnect. Recovery is shown with fresh traffic, including inner TCP recovery and the documented possibility of UDP loss.
11. Relay restart, Exit restart, EOF, reset, black holes, and one-way failure lead to bounded attempt termination and automatic recovery. A relay ACK without valid Exit traffic does not keep a tunnel alive.
12. Verify capped jittered retry progression, stable-connection backoff reset, and the absence of rapid retries from a briefly established flapping connection. Narrow timing tests may use controlled time/randomness without exposing product tuning just for tests.
13. Repeated reconnect and takeover cycles do not produce monotonically growing socket, candidate, or buffer populations. Check stable connection counts and eventual relay-side reclamation, allowing normal teardown overlap.
14. Timer, key, and CPU reloads follow the existing coordination contract; key changes require new authentication. Immutable transport/topology changes are rejected without modifying the live configuration.
15. Normal shutdown and failed startup release owned networking resources. Check actual TCP connectivity alongside packet forwarding so accidental FakeTCP notrack or RST rules cannot pass unnoticed.
16. Configuration exercises CLI precedence, invalid values, the TCP-only warning for explicitly configured `base_port`, common MTU requirements, and unchanged behavior when transport is omitted.

### Performance Evidence

Compare FakeTCP over a valid packet path, direct TCP, and TCP through the real byte-stream relay in the same controlled environment. Record topology, CPU allocation, connection count, inner/outer families, MTUs, and link constraints. Exercise clean links and controlled RTT/loss conditions.

Report bidirectional throughput; loaded small-request p95/p99 latency; whole-system CPU rather than process CPU alone; process and socket memory; failure recovery time; and connection reclamation. Include concurrent bulk and interactive traffic so average throughput cannot conceal head-of-line blocking.

Correctness, bounded application memory, and connection/resource reclamation are hard acceptance criteria. Produce reproducible throughput and latency baselines, not an invented Gbit/s target or percentage-regression promise. Previous FakeTCP performance numbers do not establish TCP performance. Do not run stress or impairment scenarios against production routes.

## Out of Scope

- Implementing the feature as part of this specification-writing task.
- Automatic transport negotiation, fallback, downgrade, or simultaneous dual-transport operation inside one instance.
- Compatibility with old binaries in the new TCP mode, or changes to the existing FakeTCP wire protocol.
- Encryption, TLS, per-packet MACs, established-data replay protection, or guarantees against a malicious relay.
- Multi-tenant Exit service, per-client identities, permissions, or isolation between holders of the same shared key.
- Dynamic worker counts, adaptive connection pools, or packet striping across outer connections to avoid head-of-line blocking.
- Additional retry, queue-size, kernel-buffer, or authentication-capacity configuration knobs.
- Offline packet persistence, cross-connection replay, compression, tunnel fragmentation, jumbo-packet optimization, or automatic MTU expansion.
- Zero-downtime key rotation, simultaneous old/new key grace periods, or automatic transport changes during reload.
- DDoS protection, guaranteed admission fairness under hostile saturation, or instantaneous cleanup of arbitrary relay state.
- Promises to preserve FakeTCP latency under TCP loss, congestion, or head-of-line blocking.
- A new observability service, production traffic experiments, or changes to the relay software itself.

## Further Notes

- This specification records the confirmed Q1–Q17 decisions. It is a design deliverable, not a claim that TCP transport is already implemented.
- Existing architecture and authentication specifications describe the FakeTCP path. This specification resolves their original assumption that a terminating `splice` relay could transparently carry FakeTCP: such relays require the new TCP transport. Existing reload semantics remain applicable except for the explicit addition of immutable transport selection.
- TCP's costs are workload dependent. Clean-link bulk throughput may approach available bandwidth; loss or congestion can block unrelated inner flows sharing an outer connection. Splitting the path at a relay can also shorten transport recovery on an individual leg. No fixed performance change is supported without measurement.
- Inner UDP over TCP remains logically UDP at the TUN but inherits outer reliable, ordered delivery and its latency risks. Document this distinction rather than presenting TCP mode as retaining FakeTCP's loss-isolation properties.
- Exact TCP wire message layouts must be recorded as part of implementation design before code is written, using the authentication and framing requirements above. This specification does not authorize undocumented wire assumptions or a weakened authentication contract.
- The existing local session suite passed during diagnosis, but it does not exercise a terminating relay or prove this unimplemented TCP feature. The local Docker daemon was unavailable during preparation; no privileged end-to-end or performance verification of the proposed feature has been performed.
- Implementation, behavioral verification, and deployment require separate authorization after this specification-only stage.

## TCP v1 Wire Encoding

Frames use `payload_length:u16be || payload`. The payload excludes the prefix.
All integers are unsigned big-endian.
After authentication, payloads are one complete IPv4/IPv6 packet, `0x10 || nonce:8`
(ping), or `0x11 || nonce:8` (pong). Authentication uses these payloads in order:

| Sender | Message | Payload |
| --- | --- | --- |
| Entry | Hello | `0x01 || "GTCP" || version:u8=1 || worker:u16 || conns:u16 || mtu:u16 || entry_nonce:32` (44 bytes) |
| Exit | Challenge | `0x02 || exit_nonce:32 || exit_tag:32` (65 bytes) |
| Entry | Proof | `0x03 || entry_tag:32` (33 bytes) |
| Exit | Finished | `0x04 || finished_tag:32` (33 bytes) |
| Entry | Ready | `0x05 || ready_tag:32` (33 bytes) |

Both nonces come from the OS CSPRNG for each attempt. The transcript is exactly
`"ghostun-tcp" || [version=1, entry_role=1, exit_role=2] || Hello || Challenge[0..33]`.
Each tag is HMAC-SHA256(shared_key, domain || transcript); domains are the literal
ASCII strings `ghostun-tcp-v1/exit`, `ghostun-tcp-v1/entry`,
`ghostun-tcp-v1/finished`, and `ghostun-tcp-v1/ready`, respectively.
Entry verifies Challenge and Finished, then writes Ready before forwarding.
Exit verifies Ready before admitting the worker or forwarding. Tags use constant-time
verification. The stream orders Ready before Entry data.
