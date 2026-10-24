# Ghostun Specification: Mandatory Mutual Handshake Authentication

## Problem Statement

Ghostun currently treats knowledge of the Exit address and port as sufficient to attempt a tunnel connection. The Exit accepts an incoming SYN for a worker slot and replaces that slot's peer before the sender has even completed the FakeTCP handshake. An unauthenticated sender can therefore disrupt an existing tunnel without successfully establishing a replacement connection.

Operators need to prevent unauthorized tunnel access and unauthenticated handshake takeover while retaining support for Entry nodes whose public source address changes. A static source-IP allowlist alone does not meet that requirement. Sending a plaintext password, or a fixed reusable password-derived token, would expose a reusable credential rather than prove possession of a secret for a fresh connection.

The deployment is not yet released, so compatibility with unauthenticated versions is unnecessary. Connection establishment and reconnection may take additional round trips, but established data forwarding must retain the existing packet overhead and must not acquire additional protocol round trips.

## Solution

Require both Entry and Exit to possess the same high-entropy pre-shared key. Preserve the ordinary FakeTCP three-way handshake, then exchange authentication control frames that use fresh challenges and cryptographic message authentication to prove possession of the key in both directions.

Completing the TCP handshake does not authorize tunnel traffic. Only a successfully authenticated candidate may become the active session or replace an existing session. Unauthenticated candidates must not replace the active peer, refresh its liveness, or monopolize the authentication mechanism by repeatedly sending SYN packets.

Use a mandatory TOML `auth_key` containing a 32-byte random key encoded as 64 hexadecimal characters. Do not offer a plaintext short-password mode, a command-line key argument, an authentication bypass, or automatic fallback to the old protocol.

Authentication is a connection-time operation. Established inner IPv4 and IPv6 packets retain the outer family's existing encapsulation: 40 bytes over IPv4 or 60 bytes over IPv6. Authentication adds no per-packet MAC, encryption, exchange, or outer retransmission layer. Operators may still deploy external nftables allowlists where useful, but static source addresses are not a prerequisite for authentication.

## User Stories

1. As an Exit operator, I want unknown senders to prove possession of the shared key before receiving tunnel access, so that knowing my address and port is insufficient to use the tunnel.
2. As an Exit operator, I want an unauthenticated SYN to leave an active session unchanged, so that internet scanners cannot replace my Entry connection.
3. As an Entry operator, I want to authenticate the Exit before forwarding inner traffic, so that a TCP handshake alone does not establish trust in a responder.
4. As an operator, I want authentication proofs to depend on fresh connection challenges, so that a recorded proof cannot simply authorize a new connection.
5. As an operator, I want proofs to be bound to the handshake context and authentication direction, so that a proof for one exchange or role cannot be reused as a different proof.
6. As an operator with a dynamic public address, I want to reconnect using the same shared key after an address change, so that I do not have to update an Exit IP allowlist first.
7. As an operator restarting Entry, I want a successfully authenticated replacement to take over immediately, so that recovery does not wait for the previous session's dead timeout.
8. As an operator, I want incomplete or failed authentication to leave the active peer and its liveness deadline untouched, so that invalid connection attempts cannot disrupt or artificially prolong that session.
9. As an operator, I want repeated unauthenticated SYNs to be unable to monopolize the only authentication candidate position, so that a legitimate Entry retains a path to authenticate.
10. As an operator, I want authentication resource use to remain bounded, so that connection attempts do not create an unbounded pending-session table.
11. As an operator, I want lost or duplicated authentication frames to be handled within bounded retry and timeout behavior, so that ordinary packet loss does not require manual recovery.
12. As an operator, I want failed authentication to deny inner traffic in both directions, so that a partially completed handshake never grants temporary tunnel access.
13. As an operator, I want every configured outer worker connection to authenticate independently, so that authorization applies to every tunnel slot rather than only the first one.
14. As an operator, I want both roles to reject a missing or malformed `auth_key` before starting networking, so that a configuration mistake never launches an unauthenticated instance.
15. As an operator, I want to configure one random key in TOML on both nodes, so that deployment does not require certificates, accounts, or an identity service.
16. As an operator, I want keys kept out of command-line arguments and logs, so that routine process inspection and diagnostics do not expose credentials.
17. As an operator, I want documentation to explain key generation and configuration-file permissions, so that the shared secret is provisioned and stored appropriately.
18. As an operator, I want mismatched keys to prevent tunnel establishment while preserving unrelated active sessions, so that configuration errors fail closed rather than replace working peers.
19. As a performance engineer, I want authentication work restricted to connection establishment and recovery, so that steady-state packet forwarding does not perform new cryptographic operations.
20. As a performance engineer, I want established packets to retain the current 40-byte IPv4 or 60-byte IPv6 outer overhead, so that authentication does not further reduce the inner MTU.
21. As an application operator, I want data forwarding to proceed without an extra authentication round trip per exchange, so that established traffic retains the current latency model.
22. As an operator, I want ordinary FakeTCP handshake options and packet shapes retained, so that authentication does not depend on custom SYN options or SYN payload support in intermediate firewalls.
23. As an operator, I want firewall-state loss and one-way black holes to recover through authenticated reconnection, so that adding authentication preserves the existing self-healing behavior.
24. As a maintainer, I want mandatory authentication with no legacy downgrade path, so that there is only one supported trust model to maintain.
25. As a maintainer, I want mature cryptographic primitives rather than custom cryptographic implementations, so that the feature does not depend on homegrown MAC or hash constructions.
26. As an operator, I want the security limits documented explicitly, so that handshake authentication is not mistaken for encryption, packet integrity, or DDoS protection.

## Implementation Decisions

### 1. Trust Model and Security Boundary

- Use one shared key per tunnel trust domain. Entry and Exit both prove possession; there are no individual client identities or permissions.
- A holder of the key has permission to establish a session and replace an existing session in the corresponding worker slot. Two Entry instances sharing a key are not isolated from one another.
- Protect against unauthorized connection attempts and unauthenticated handshake takeover. Do not claim protection against an attacker who can forge accepted packets of an active connection or observe and manipulate its traffic.
- Handshake replay resistance does not imply replay protection for established data or control frames. Existing RST, health-control, and data behavior is not automatically authenticated by this feature.

### 2. Configuration and Secret Handling

- Both roles require a TOML `auth_key` encoding exactly 32 bytes as 64 hexadecimal characters. Missing, incorrectly sized, or non-hexadecimal values are configuration errors.
- Validate the key before creating TUN devices, installing firewall rules, or starting workers.
- Do not expose a command-line key argument, short-password mode, authentication-disable switch, or automatic downgrade.
- Do not log the key or include it in configuration-validation errors or debug representations. Existing diagnostic paths must respect this boundary.
- Document key generation using an existing system tool and recommend restrictive configuration-file permissions. Examples must not suggest that a public example key is safe for deployment.
- Key changes require a coordinated restart. Hot rotation and simultaneous old/new key acceptance are not included.

### 3. Connection-Time Mutual Authentication

- Preserve the ordinary SYN, SYN-ACK, ACK exchange and its existing MSS, SACK-permitted, and window-scale options. Do not embed authentication in custom SYN options or SYN payloads.
- After the transport handshake, use dedicated authentication control frames before enabling inner-packet forwarding. Keep authentication frames distinct from IPv4, IPv6, and existing health-control frames.
- Use fresh challenges generated from an operating-system cryptographic randomness source. Authenticate the relevant handshake transcript, including challenges and role/direction, so that stale or reflected proofs cannot authorize a different exchange.
- Verify authentication tags using an appropriate constant-time verification API from the selected cryptographic library.
- Both sides must verify the peer's proof before treating that peer as authenticated. Provide explicit completion semantics so that handshake completion cannot be confused with authentication completion.
- Authentication frames must participate correctly in FakeTCP sequence/acknowledgment accounting, including retransmission and duplicate handling, so that strict conntrack continues to accept the exchange and subsequent traffic.
- Budget approximately two additional RTTs for establishment and reconnection. This is an accepted design budget, not a measured latency or a promise about application RTT.
- The Version 1 Wire Protocol below resolves the implementation choices for encoding, primitives, challenges, transcript serialization, and retries. These choices were confirmed before implementing the exchange.
- Necessary mature cryptographic dependencies are authorized as an exception to the original dependency whitelist. This does not authorize a TLS stack or a general encrypted transport framework.

#### Version 1 Wire Protocol

The implementation uses RustCrypto `hmac` 0.13.0 and `sha2` 0.11.1: HMAC-SHA-256 with full 32-byte tags and `Mac::verify_slice` for constant-time verification. `getrandom` 0.4.3 supplies OS-backed random challenges. No C/assembly build dependency is required. All integers below use network byte order. Authentication payloads start with `03 01 <kind>`: control type, protocol version, and message kind. Exact lengths are required; unknown versions, kinds, trailing bytes, and truncated messages are rejected without downgrade.

| Message | Kind | Payload after the three-byte header | Total bytes |
|---|---|---|---:|
| Hello | 1 | Entry challenge (32 bytes) | 35 |
| Challenge | 2 | Ticket (u64), issuance time (u64 milliseconds), Entry challenge (32), Exit challenge (32), cookie (32), Exit proof (32) | 147 |
| Proof | 3 | The entire Challenge body, followed by Entry proof (32) | 179 |
| Finished | 4 | Ticket (u64), completion proof (32) | 43 |

After SYN, SYN-ACK, and ACK, Entry sends Hello; Exit returns Challenge with its proof; Entry verifies it and sends Proof; Exit verifies it, promotes the candidate, and sends Finished. Entry enables forwarding only after verifying Finished. Authentication consumes exactly 214 Entry sequence bytes and 190 Exit sequence bytes, in addition to each SYN. Retransmissions reuse their original sequence ranges and never advance the data sequence counters again.

The common proof transcript is `version || Entry ISN || Exit ISN || ticket || issuance time || Entry challenge || Exit challenge || cookie`. Prefix it with the ASCII domain `ghostun-auth-v1/exit`, `ghostun-auth-v1/entry`, or `ghostun-auth-v1/finished` for the corresponding shared-key HMAC. Neither SYN contains authentication options or payloads.

Exit keeps no pending-candidate table. Its SYN-ACK ISN is the first four bytes of an HMAC under a per-worker, OS-random startup cookie key, using domain `ghostun-syn-v1`, the observed Entry and Exit socket addresses, Entry ISN, and a time bucket. Each bucket lasts `dead_timeout`; current and previous buckets are accepted. Addresses serialize as IP version (one byte), network-order IP octets, and network-order port. This binds admission to the tuple Exit actually observes without requiring Entry to know its NAT mapping.

A valid Hello must acknowledge a valid SYN cookie. Exit then generates a fresh random challenge and a monotonically increasing ticket. The authentication cookie is an HMAC under the same startup cookie key with domain `ghostun-cookie-v1`, the observed addresses, both ISNs, and the Challenge body preceding the cookie. Its lifetime is `2 * dead_timeout`, measured against the worker's monotonic startup clock. Entry proves possession of the shared key over the opaque cookie; it does not need the observed public addresses. A changed NAT mapping requires a fresh handshake.

Only a verified Proof with a ticket above the worker's accepted-ticket watermark may promote a candidate. The watermark survives active-session timeout. The current successful exchange is cached so an exact repeated Proof can recover a lost Finished, without resetting sequence space or refreshing liveness. Older tickets cannot take a slot back. Restarting Exit generates a fresh cookie key, invalidating all previous cookies.

After verifying a replacement on a different tuple, Exit sends two RSTs to the retired peer to reclaim its conntrack slot. It does not reset a reused tuple, which the firewall may already associate with the new handshake. Unverified candidates never trigger this cleanup. The fixed connection count is a steady-state property; candidates may temporarily create additional firewall entries.

Entry retries its current SYN, Hello, or Proof every second. The whole attempt is bounded by `dead_timeout` from the first SYN; candidate responses never extend it. Receive processing also enforces this deadline, so even a valid Finished arriving at or after expiry cannot authorize the attempt before the next timer tick. On expiry, Entry resets the old tuple, rotates its source port, and starts again with a fresh challenge. Exit replies to retransmitted requests rather than running candidate timers. A repeated Hello may receive a new Challenge; after choosing a valid Challenge, Entry retains that exchange and retransmits its Proof until Finished or timeout. Empty transport ACKs and authentication control frames do not refresh active-session liveness.

This bounds per-worker state to one active session, one Entry attempt, the cookie key and counters, and the latest successful completion. Unauthenticated requests cannot reserve a candidate slot. It does not provide a flood-resistance or throughput guarantee under arbitrary hostile traffic.

### 4. Active Session and Candidate Isolation

- Extend the existing Session state machine rather than adding a separate transport stack. Keep authenticated active-session state separate from unauthenticated candidate processing.
- A SYN, a completed transport handshake, an invalid proof, or a candidate timeout must not replace the active peer, reset its sequence state, alter its authenticated status, or refresh its liveness deadline.
- Do not forward candidate inner traffic into TUN or send inner traffic to a candidate before authentication permits it.
- Successfully authenticated candidates may immediately replace the corresponding active peer, including when the candidate's public source address or port has changed.
- Keep pending-authentication resources bounded. The design must also prevent unauthenticated traffic from indefinitely occupying the sole candidate position and excluding legitimate authentication. A bounded table alone is not sufficient to establish this property.
- Candidate loss, duplicates, invalid frames, and timeouts must have defined recovery behavior without disturbing a still-active authenticated session. A delayed duplicate from an older authentication attempt must not switch the slot back to an old peer.
- Retain per-worker ownership and deterministic port-modulo steering. Do not introduce a global authentication lock or cross-worker session registry.

### 5. Unchanged Established Data Path

- Retain the single multi-queue TUN, per-worker raw sockets, existing port steering, inner dual-stack support, MTU derivation, and threshold ACK behavior.
- Retain exactly 40 bytes of outer overhead over IPv4 or 60 bytes over IPv6 for established inner packets. Authentication control traffic does not add a header to normal data packets or change outer-family selection.
- Do not add per-packet cryptography, stop-and-wait behavior, outer data retransmission, or authentication round trips to established traffic.
- Continue health probing and source-port rotation for recovery. Every replacement connection must authenticate again; reconnection does not inherit authorization merely from a previously used address or slot.
- Do not interpret the steady-state latency requirement as an absolute one-RTT application guarantee. The contract is that this feature adds no steady-state protocol round trips.

### 6. Deployment and Documentation Cutover

- Update configuration loading, example configuration, deployment guidance, and affected smoke-test invocations to supply the mandatory key.
- Document how both roles obtain the same secret without transmitting it as a plaintext authentication credential.
- Do not retain an unauthenticated compatibility path. Existing unauthenticated peers are unsupported after this change.
- External nftables source allowlists remain optional operator-managed defense in depth. Do not automatically maintain an allowlist or require fixed Entry addresses.

## Testing Decisions

### 1. Observable Behavior and Existing Seams

Prefer the existing Session/packet seam for deterministic protocol behavior and the existing containerized netns E2E seam for actual forwarding through strict stateful conntrack. Do not create a parallel transport abstraction or expose private state solely for tests.

A useful test observes acceptance or rejection, emitted wire frames, delivery or non-delivery of inner packets, replacement behavior, and recovery across externally supplied frames and time advances. Do not assert private layout, helper names, exact diagnostic wording, or incidental implementation defaults.

### 2. Session and Packet Behavior

- Exercise a complete mutual-authentication exchange with matching keys and prove that inner traffic is denied before authentication and delivered afterward.
- Exercise mismatched keys and invalid proofs in both directions; neither role may accept the unauthenticated peer.
- Replay an earlier exchange against a fresh challenge and verify that it cannot authorize or replace a session. Cover direction/reflection misuse and malformed authentication frames at the protocol boundary.
- Establish a working authenticated session, then inject unauthenticated SYNs, candidate traffic, invalid proofs, duplicates, and candidate timeouts. Verify continued forwarding to the original peer and the absence of active-liveness refresh from candidate traffic.
- Verify successful authenticated replacement from a changed source address or port, and verify that delayed frames from the old authentication exchange cannot take the slot back.
- Verify legitimate authentication remains possible during repeated unrelated unauthenticated attempts under the chosen bounded-resource design. Do not equate bounded memory with availability.
- Exercise lost, repeated, and reordered authentication frames where the chosen protocol must recover. Assert bounded retry/timeout behavior and correct sequence accounting rather than a particular internal state representation.
- Verify inner IPv4/IPv6 framing and established encapsulation remain unchanged for both outer families: 40 bytes for IPv4 outer transport or 60 for IPv6. Use the existing packet tests where they already cover these contracts.
- Strengthen configuration tests for missing, malformed, and valid keys, including the absence of raw key material in diagnostics that could otherwise expose it.

### 3. Containerized Netns E2E

- Extend the existing Entry, stateful-firewall, Exit, and internet topology rather than introducing another integration harness.
- Supply matching test-only keys to the actual binaries and run both outer IPv4 and IPv6 variants, retaining inner IPv4/IPv6 connectivity, full-MTU packets, bulk TCP, steady-state outer connection count, and signal-cleanup checks.
- Demonstrate that a wrong-key client cannot forward inner packets or replace a working authenticated connection.
- Inject unauthenticated handshake attempts against an active slot and observe continued legitimate forwarding.
- Verify authenticated recovery after conntrack flush and a one-way black hole. Allow the additional connection-time authentication RTT budget rather than preserving old exact recovery timings.
- Exercise authenticated replacement after an Entry source-address change within the isolated topology.
- Run all privileged networking inside a disposable privileged Docker container. Never modify host networking for these checks.

### 4. Performance Evidence and Prior Art

Use the existing FakeTCP handshake, SYN retransmission, health probing, port rotation, cBPF, and netns tests as prior art. Use throwaway measurements or the existing smoke harness to observe authentication-time resource use and steady-state throughput/latency; do not make noisy performance numbers permanent pass/fail assertions.

Do not claim measured CPU, memory, or latency costs until exercised. Confirm that additional authentication packets are limited to establishment/recovery and that established forwarding does not wait for a new control exchange.

## Out of Scope

1. Data-plane encryption, TLS, certificates, or an encrypted transport framework.
2. Per-packet MACs, established-packet replay protection, or cryptographic authentication of every RST, health frame, or data packet.
3. Protection against on-path attackers or attackers able to forge accepted traffic for an active connection.
4. DDoS or volumetric flood mitigation, guaranteed availability under arbitrary hostile load, or complete invisibility to port scanners.
5. Static source-IP requirements or automatic nftables allowlist management.
6. User accounts, client identities, per-client authorization, individual revocation, or isolation between peers sharing a key.
7. Human-memorable passwords, password-based key derivation, or plaintext password transmission.
8. Optional authentication, legacy interoperability, automatic downgrade, or compatibility shims.
9. Hot key rotation, multiple concurrently accepted keys, or an external secret-management service integration.
10. Changes to the established data-plane architecture, extra data-packet framing, or outer reliable data transport.

## Further Notes

- This specification defines mandatory admission for both roles and supersedes the baseline's original immediate peer-replacement behavior and dependency restriction. The baseline tunnel specification links to this cutover; there is no unauthenticated compatibility path.
- The key is an admission credential for one trust domain. Anyone possessing it may replace a session; accidental duplicate Entry deployments can still contend for worker slots.
- The startup/reconnection latency tradeoff was explicitly accepted in exchange for a simpler authentication exchange and unchanged established forwarding.
- Exact wire details and cryptographic library selection were settled during implementation design and are recorded above. They do not expand the security boundary to established packets or arbitrary hostile load.
