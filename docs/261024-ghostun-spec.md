# Ghostun Specification: High-Performance L3-over-FakeTCP Tunnel (`Entry` <-> `Exit`)

Mandatory mutual authentication is defined in [the handshake authentication specification](261024-handshake-auth-spec.md). It supersedes unauthenticated admission: TCP handshake completion alone never permits forwarding or peer replacement.

Transport selection and ordinary TCP relay support are defined in [the dual-transport specification](261025-dual-transport-spec.md). The FakeTCP design below requires a packet-forwarding path; a relay that terminates and recreates TCP, including a `splice` relay, requires the new `tcp` transport. Supporting that transport is specified, not yet implemented.

## Problem Statement

In the existing `Client <--> relay <--> Server` cross-border/cross-network proxy architecture, relay acts as an L4 TCP byte-stream proxy based on `splice`: it terminates the incoming TCP connection and opens a separate outgoing connection rather than preserving packets or sequence spaces. All expensive proxy protocol termination—authentication, traffic accounting, TLS/AEAD encryption and decryption, and multiplexed-stream decoding—runs on the remote `Server` (the egress node). As a result, the egress node has high CPU and connection-state costs and becomes a single-machine performance bottleneck. The original assumption that this relay could transparently carry the FakeTCP design was incorrect; the dual-transport specification resolves that conflict.

Moving expensive proxy termination to the ingress node (`Entry`) and making the egress node (`Exit`) lightweight requires an L3 IP tunnel between Entry and Exit. Exit should only decapsulate tunnel traffic and use Linux kernel `MASQUERADE` NAT for internet egress. However, the intermediate network imposes strict stateful-firewall constraints:

1. **Non-TCP protocols are blocked**: UDP, GRE, IPIP, WireGuard, and other non-TCP packets are dropped outright.
2. **Concurrent TCP connection limits (`conntrack`)**: To mitigate DDoS, the intermediate firewall strictly limits concurrent TCP connections between a pair of IP addresses. Mapping each client connection to a separate backend TCP connection quickly exhausts the firewall's state capacity and causes packet loss.
3. **TCP-over-TCP head-of-line blocking and retransmission storms**: Carrying inner L3 IP traffic over real kernel TCP sockets causes severe head-of-line blocking when multiple inner flows share one outer connection, together with nested congestion control and retransmission amplification.
4. **Silent state expiration and heterogeneous gateway MTUs**: The intermediate firewall may delete `conntrack` state without sending an RST, silently black-holing subsequent non-SYN packets. Physical outer-path MTUs can also differ from the standard `1500`, such as PPPoE `1492` or VPC `1420`.
5. **Limitations of existing open-source components such as `phantun` / `fake-tcp`**: Using `phantun` directly requires two TUN layers (`inner_tun` + `outer_tun`) and outer `SNAT/DNAT`, with four user/kernel context switches per packet. In addition, Linux `IFF_MULTI_QUEUE` hashing of a small number of outer connection five-tuples has a queue-collision probability as high as $90.6\%$ for $N=4$, undermining lock-free per-core affinity.

## Solution

Design and deliver `ghostun`: a high-performance, low-memory L3-over-FakeTCP tunnel written in Rust, using a single multi-queue TUN and an independent per-core `SOCK_RAW` (`IPPROTO_TCP`) socket. Provide `entry` and `exit` roles and a complete production deployment suite: Dockerfile, Docker Compose, systemd service units, and configuration templates.

1. **Move proxy termination to Entry and minimize Exit**:
   - Entry runs the proxy server, terminates client protocols, and binds decapsulated outbound traffic directly to the virtual L3 interface created by ghostun, for example `interface_name: "ghostun0"`.
   - Exit runs no heavyweight proxy software. `ghostun exit` restores inner IPv4/IPv6 packets from outer FakeTCP packets and writes them to local `ghostun0`. Kernel nftables (`table inet ghostun_<tun_name>`) handles `MASQUERADE` NAT forwarding.
2. **Single TUN plus per-core raw sockets with precise BPF steering**:
   - Create exactly one inner multi-queue virtual interface with `IFF_TUN | IFF_MULTI_QUEUE | IFF_NO_PI`. The kernel destroys it automatically when the process exits or crashes (`kill -9`), leaving no orphaned interface.
   - Eliminate `outer_tun` and outer NAT. Use `SOCK_RAW` with `IPPROTO_TCP` and caller-supplied IP headers (`IP_HDRINCL` for IPv4, `IPV6_HDRINCL` for IPv6). Established packets have 40 bytes of IPv4/TCP overhead or 60 bytes of IPv6/TCP overhead, without TCP timestamps.
   - Each pinned worker thread (`sched_setaffinity`) owns an independent raw socket with a classic BPF filter (`SO_ATTACH_FILTER`). Port-modulo steering (`sport % N == worker_id`) provides deterministic one-to-one delivery to the corresponding worker, without global locks or cross-core channels.
3. **Constant outer connection count (`--conns N`) and firewall-window maintenance**:
   - Establish a fixed number $N$ of standard TCP three-way handshakes at startup, defaulting to the CPU core count and configurable explicitly. Handshake options include MSS, Window Scale = 14, and SACK-permitted. Keep the normal outer `conntrack` count fixed at $N$.
   - Disable outer retransmission and congestion control in the data plane, leaving them to real inner TCP. Maintain outer `seq` / `ack_seq` in both directions, and send standalone ACKs when accumulated unacknowledged received bytes reach a threshold or periodic maintenance is due, preventing firewall window violations.
4. **Zero-additional-framing inner IPv4/IPv6 and control multiplexing**:
   - Valid IP packets begin with version nibble `0x4` (IPv4) or `0x6` (IPv6). Reserve payloads whose first-byte high nibble is `0x0` for internal control frames: `0x01` Health Ping and `0x02` Health Pong. This provides native inner dual-stack forwarding and bidirectional health probing without adding any framing bytes to data packets.
5. **Recovery from silent firewall drops and conntrack-slot reclamation**:
   - Each outer FakeTCP connection independently exchanges Health Ping/Pong. When responses remain absent beyond the dead timeout, Entry first sends RST packets on the old five-tuple to release lingering firewall state. It then rotates to a new source port in the same `sport % N == worker_id` class and starts another three-way handshake.
6. **Dynamic MTU detection and self-contained Netfilter lifecycle**:
   - Support explicit outer MTUs and automatic physical egress-interface MTU detection for networks such as Ethernet `1500`, PPPoE `1492`, or VPC `1420`. Derive the inner TUN MTU as `outer_mtu - overhead`, with overhead 40 for IPv4 outer transport or 60 for IPv6.
   - By default, manage kernel-generated RST suppression, inner dual-stack TCP MSS clamping (`maxseg size set rt mtu`), and Exit `MASQUERADE` in a dedicated nftables table (`table inet ghostun_<tun_name>`). Clean stale state at startup and remove rules on signal-driven shutdown. Provide `--no-netfilter` for externally managed firewall rules.

## User Stories

1. As an infrastructure operator, I want to terminate heavy proxy protocols (TLS/AEAD decryption, authentication, and accounting) on the Entry node and forward plain L3 traffic through the tunnel to the Exit node, so that the Exit node's CPU and memory footprint remain minimal.
2. As an infrastructure operator, I want the Exit node to forward decapsulated traffic to the internet using only native Linux kernel `MASQUERADE` NAT without running a user-space proxy daemon, so that Exit nodes are stateless, cheap to run, and trivial to maintain.
3. As a network engineer operating across a connection-limited stateful firewall, I want `ghostun` to lock the total number of outer TCP connections to a fixed configurable constant $N$ (`--conns N`, defaulting to CPU core count), so that thousands of inner user flows never exhaust the intermediate firewall's `conntrack` table.
4. As a network engineer, I want each outer tunnel connection to perform a standard TCP 3-way handshake (`SYN` -> `SYN/ACK` -> `ACK`) with realistic TCP options (`MSS`, `Window Scale = 14`, `SACK_PERM`), so that the intermediate stateful firewall registers every tunnel channel as a legitimate `ESTABLISHED` TCP connection.
5. As a performance engineer, I want outer tunnel packets to carry raw L3 IP packets without outer TCP retransmission or outer congestion control, so that packet loss on one inner flow never causes TCP-over-TCP retransmission amplification or Head-of-Line (HoL) blocking for other inner flows sharing the same core.
6. As a performance engineer, I want `ghostun` to use only a single inner `TUN` interface paired with outer `SOCK_RAW` (`IPPROTO_TCP`) sockets instead of dual `inner_tun` + `outer_tun` devices, so that each packet crosses the kernel-userspace `TUN` boundary only once per node and avoids outer `SNAT`/`DNAT` overhead.
7. As a performance engineer, I want each worker thread to be pinned 1-to-1 to a dedicated CPU core (`sched_setaffinity`) with its own `TUN` queue and its own `SOCK_RAW` socket, so that packet processing scales linearly across cores with zero cross-thread locks or channels.
8. As a performance engineer, I want each worker's `SOCK_RAW` socket to attach a classic kernel BPF filter (`SO_ATTACH_FILTER`) that matches `sport % N == worker_id` and the tunnel port, so that the Linux kernel routes incoming outer packets directly to the owning CPU core's socket without waking other workers or suffering from `IFF_MULTI_QUEUE` hash collisions.
9. As a performance engineer, I want data-plane outer FakeTCP headers to omit the 12-byte TCP Timestamps option after handshake, so that total tunnel overhead is limited to 40 bytes over IPv4 or 60 bytes over IPv6 and inner payload capacity is maximized.
10. As a network engineer dealing with strict stateful firewalls, I want `ghostun` to dynamically advance `seq` and `ack_seq` on every outer packet and send standalone `ACK` packets whenever unacknowledged received bytes exceed a threshold, so that unidirectional heavy traffic (e.g., large downloads) never stalls or gets dropped by firewall TCP window enforcement.
11. As a reliability engineer, I want each of the $N$ outer FakeTCP connections to exchange periodic bidirectional Health Ping (`0x01`) and Health Pong (`0x02`) control frames, so that both keeping the firewall's idle `conntrack` timer alive and detecting silent firewall state drops happen per connection.
12. As a performance engineer, I want Health Ping and Health Pong control frames to be multiplexed using the first-byte version nibble (`0x0` vs. IPv4 `0x4` and IPv6 `0x6`), so that normal inner IPv4 and IPv6 data packets incur zero extra framing bytes.
13. As a reliability engineer, I want the Entry worker to detect when an outer FakeTCP connection misses consecutive Health Pongs beyond the configured dead timeout, so that silent black-holing by an intermediate firewall is detected within seconds even when the firewall sends no `RST`.
14. As a network engineer, I want the Entry worker to transmit `RST` packets on the old 5-tuple before rotating to a new source port (`sport % N == worker_id`) upon reconnection, so that any lingering `ESTABLISHED` entry in the intermediate firewall transitions immediately to `CLOSE` and does not leak `conntrack` quota slots.
15. As a reliability engineer, I want the Exit worker to immediately accept a successfully authenticated replacement for slot $i$ (`sport % N == i`), so that Entry-initiated reconnections recover traffic without waiting for the old peer's dead timeout or allowing unauthenticated takeover.
16. As a network engineer deploying on heterogeneous networks (PPPoE `1492`, cloud VPC `1420`, jumbo frames, or standard `1500` Ethernet), I want explicit `--outer-mtu` / `--tun-mtu` flags and automatic egress-interface MTU detection, so that the inner TUN MTU fits the selected outer family's encapsulation overhead.
17. As a network engineer, I want automatic inner TCP SYN MSS clamping to the route MTU (`tcp flags syn tcp option maxseg size set rt mtu`), so that negotiated inner segments fit after adding the 40-byte IPv4 or 60-byte IPv6 outer headers.
18. As a proxy administrator, I want both inner IPv4 and IPv6 over either outer IPv4 or IPv6, so that the inner traffic family is independent of the available outer network.
19. As a proxy administrator running on an IPv4-only host, I want a `--no-ipv6` option (and graceful fallback if IPv6 is disabled in the kernel), so that `ghostun` runs cleanly on systems without IPv6 support.
20. As a proxy administrator on the Entry node, I want `ghostun` to create a clean named `TUN` interface (default `ghostun0`) without modifying the host's default routing table, so that upstream proxy software (`sing-box`, `xray`, etc.) can bind outbound traffic via `interface_name: "ghostun0"` (`SO_BINDTODEVICE`) without risking SSH lockouts or routing loops.
21. As a systems administrator, I want the `TUN` device to be created without `IFF_PERSIST`, so that if the `ghostun` process crashes or is killed with `SIGKILL`, the Linux kernel automatically destroys the `TUN` interface.
22. As a systems administrator, I want `ghostun` to manage its required firewall rules (kernel `RST` suppression on tunnel ports, inner MSS clamping, and Exit `MASQUERADE`) inside a dedicated, self-contained `nftables` table (`table inet ghostun_<tun_name>`), so that startup idempotently flushes any stale table from a prior crash and graceful shutdown (`SIGINT`/`SIGTERM`) removes all rules cleanly without touching other firewall tables.
23. As a systems administrator in a locked-down environment where firewall rules are provisioned externally by configuration management, I want a `--no-netfilter` flag that disables all automatic `nftables`/`sysctl` modifications, so that `ghostun` only manages the `TUN` device and raw sockets.
24. As a DevOps engineer, I want `ghostun` to support both CLI flags and a TOML configuration file (`--config`), so that I can test quickly from the command line and deploy reproducibly in production.
25. As a DevOps engineer, I want ready-to-use `Dockerfile`, `docker-compose` files (for Entry and Exit), `systemd` service unit files, and a comprehensive `README.md` with proxy integration examples, so that I can build, deploy, and operate the tunnel out of the box.
26. As an operator, I want Entry to select the outer family from its remote IP literal and Exit to select it explicitly, so that each instance has one predictable outer transport without automatic family switching.
27. As an operator, I want invalid explicit or detected MTU combinations rejected before networking is changed, so that an outer IPv6 path with MTU 1280 is not incorrectly treated as able to carry a 1280-byte inner IPv6 packet.

## Implementation Decisions

### 1. Single-Binary Dual-Role Architecture

- Compile the system as one `ghostun` executable. Select the role with `ghostun entry` / `ghostun exit`, or with `mode = "entry" | "exit"` in the configuration file.
- Remove legacy reference directories from the repository and organize the core modules directly under the project root: CLI/configuration, Netlink/TUN device management, Netfilter lifecycle, zero-copy packet encoding/decoding and BPF generation, the FakeTCP session state machine, and pinned Entry/Exit worker loops.
- Expose operational settings through CLI and configuration files. The mandatory 32-byte `auth_key` is TOML-only, encoded as 64 hexadecimal characters and validated before networking. Explicit CLI arguments take precedence over other `--config` values:
  - `--tun <NAME>`: name of the inner TUN to create and bind; default `ghostun0`. Supports isolated instances on one host.
  - `--tun-ipv4 <CIDR>` / `--tun-ipv6 <CIDR>`: inner addresses. Entry defaults to `10.200.0.1/30` and `fd00:200::1/126`; Exit defaults to `10.200.0.2/30` and `fd00:200::2/126`.
  - `--conns <N>`: number of persistent outer FakeTCP connections and pinned worker threads; defaults to the system CPU core count.
  - `--cpus <LIST>`: optional comma-separated CPU IDs or `start-end` ranges for worker thread pinning; defaults to all usable CPUs in the current affinity mask.
  - `--outer-mtu <MTU>` / `--tun-mtu <MTU>`: explicit outer physical-path MTU or inner TUN MTU.
  - `--iface <IFACE>`: outer physical egress interface, used for local outer-address and MTU detection and Exit masquerade egress selection.
  - `--base-port <PORT>`: Entry source-port pool start; default `32768`.
  - `--ping-interval <SECS>` / `--dead-timeout <SECS>`: health-probe interval and reconnect timeout; defaults `5` and `15`.
  - `--no-ipv6`: disable inner dual-stack IPv6 configuration.
  - `--no-netfilter`: disable automatic nftables/sysctl management.
  - Role-specific required arguments: Entry uses `--remote <EXIT_IP:PORT>` for the outer Exit address; Exit uses `--listen <PORT>` for its FakeTCP listening port. Both roles must use the same `--conns`, because Exit slot $i$ serves only connections where `sport % N == i`.
  - Exit-only `--outer-family ipv4|ipv6` / TOML `outer_family`: default `ipv4`. Entry derives the family from `--remote`, using bracketed IPv6 literals such as `[2001:db8::10]:443`. Each instance uses exactly one outer family; `--no-ipv6` affects only inner IPv6.

### 2. Inner Multi-Queue TUN and Dual-Stack Addressing

- Create the virtual interface through Linux `/dev/net/tun` and `TUNSETIFF` with `IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE`; default name `ghostun0`. Do not set `IFF_PERSIST`.
- Match the TUN queue count to the worker count. Linux applies `txqueuelen` independently to each queue; set it to `min(256, floor(256 KiB / tun_mtu))` packets per queue. Automatically configure inner IPv4 (Entry `10.200.0.1/30`, Exit `10.200.0.2/30`) and IPv6 ULA (Entry `fd00:200::1/126`, Exit `fd00:200::2/126`) addresses, with `--no-ipv6` available to disable IPv6.
- Configure the TUN before installing firewall rules. If inner IPv6 configuration fails because IPv6 is unavailable, log a warning and continue with inner IPv4; omit IPv6 forwarding sysctls and masquerade rules. Do not change the selected outer transport family.
- With `IFF_NO_PI`, the kernel identifies the address family from each packet's first IP version nibble (`4` or `6`); user space does not prepend a four-byte PI header.

### 3. Dynamic MTU Derivation and MSS Clamping

- Outer data encapsulation is **40 bytes over IPv4** (20-byte IP + 20-byte TCP) or **60 bytes over IPv6** (40-byte IP + 20-byte TCP), with no extension headers or TCP options in emitted data packets.
- If `--tun-mtu` is not specified:
  - Prefer `--outer-mtu`; otherwise detect the physical egress-interface MTU through route/interface queries, falling back to `1500`.
  - Calculate and configure `tun_mtu = outer_mtu - overhead`. For outer MTU 1500, this gives 1460 over IPv4 or 1440 over IPv6; for outer MTU 1420, 1380 or 1360 respectively.
- Clamp inner IPv4/IPv6 TCP SYN MSS in Netfilter forwarding/output chains using `tcp flags syn tcp option maxseg size set rt mtu`, preventing encapsulated inner packets from exceeding the outer-path MTU.
- Validate explicit and detected MTUs before changing networking. An explicit TUN MTU must fit `outer_mtu - overhead`. Inner IPv6 requires TUN MTU at least 1280, hence outer MTU at least 1320 over IPv4 or 1340 over IPv6. Outer IPv6 itself requires MTU at least 1280. Do not add a tunnel fragmentation/reassembly mechanism or automatic path-MTU adaptation.

### 4. Per-Worker SOCK_RAW and Classic BPF (`SO_ATTACH_FILTER`) Modulo Steering

- Set the number of outer FakeTCP connections to $N$ with `--conns N`, defaulting to the CPU core count.
- Start $N$ independent OS threads. Use `sched_setaffinity` to bind thread $i$, where $i \in [0, N-1]$, to the $i$th available CPU, and run an independent single-threaded `poll(2)` event loop in each worker.
- Each worker has one dedicated raw TCP socket: `AF_INET` with `IP_HDRINCL` for IPv4, or `AF_INET6` with `IPV6_HDRINCL` for IPv6. Enlarge `SO_RCVBUF` / `SO_SNDBUF`. Route/source-address queries use the selected family; Entry honors an explicit egress interface when querying the route.
- Attach a classic BPF program with `SO_ATTACH_FILTER` to each socket to filter incoming TCP packets in the kernel:
  - **Entry worker $i$** accepts only `src_ip == exit_ip && src_port == exit_port && dst_port >= base_port && (dst_port % N) == i`.
  - **Exit worker $i$** accepts only `dst_port == listen_port && (src_port % N) == i`.
- This deterministically assigns each outer connection to one worker at the socket-filter boundary, eliminating cross-worker locks/channels and the small-flow-count hashing collisions associated with relying on TUN multi-queue hashing for outer steering.
- IPv6 raw receive returns TCP without the IPv6 base header. Use `recvmsg()` and `IPV6_RECVPKTINFO` to obtain source/destination metadata, receive TCP directly after reserved header space, and reconstruct the internal base header in place without moving payload bytes. Enable TCP checksum validation at offset 16 and prohibit source fragmentation. IPv6 cBPF reads ports from the transport payload and source-address words through network-header-relative offsets.

### 5. FakeTCP State Machine, Window Maintenance, and Control Multiplexing

- Each worker slot $i$ independently maintains one outer FakeTCP session:

  ```text
  State Machine per Worker Slot i (i in 0..N):
  [Disconnected]
     |-- (Entry sends SYN with MSS, WS=14, SACK_PERM on sport where sport % N == i) --> [SynSent]
     |-- (Entry receives SYN+ACK, sends ACK) --> [Authenticating]
     |-- (Exit receives SYN, returns stateless SYN+ACK) --> active session unchanged
  [Authenticating]
     |-- Hello -> Challenge + Exit proof -> Entry proof -> Finished
     |-- Exit verifies Entry proof --> [Established], replacing only after verification
     |-- Entry verifies Exit proof and Finished --> [Established]

  In [Established]:
     - Outbound L3 packet (first nibble 0x4 or 0x6):
         prepend 20B IPv4 or 40B IPv6 + 20B TCP (PSH|ACK, seq, ack_seq, win=65535), seq += payload_len
     - Inbound FakeTCP packet:
         update ack_seq = remote_seq + payload_len
         if unacked_bytes >= ACK_THRESHOLD (e.g. 1 MiB): send bare 0-byte ACK immediately
         dispatch payload by first nibble:
           0x4 or 0x6 -> write to inner TUN queue i
           0x0 (0x01 Ping) -> reply 0x02 Pong with echoed 8-byte timestamp/nonce
           0x0 (0x02 Pong) -> update last_rx_instant
     - Health Timer (every ping_interval, default 5s):
         send 0x01 Ping frame over FakeTCP
         if now - last_rx_instant > dead_timeout (default 15s):
           send 2x RST on current (sport, dport) to purge firewall conntrack entry
           advance sport to next port where next_sport % N == i
           transition to [Disconnected] and immediately initiate new SYN handshake
  ```

- **Three-way handshake options**: SYN and SYN-ACK carry MSS, Window Scale = 14 (scaling the 16-bit window by $2^{14}$, for an upper limit of approximately 1 GB), and SACK-permitted. Established data packets retain only the standard 20-byte TCP header.
- **Duplicate SYN handling**: A retransmitted SYN cannot reset an authenticated session or refresh its liveness. For the active exchange, reuse the original SYN-ACK sequence and acknowledgment numbers even after data advances the session. A new SYN starts stateless candidate processing, never immediate replacement. Authentication replay and completion rules are defined in the authentication specification.
- **Stateless cross-worker L3 multiplexing**: Inner L3 forwarding is stateless across workers. Even if forward and return traffic hash to different outer slots, each outer connection independently maintains its sequence window and firewall state using threshold ACKs and bidirectional Health Ping/Pong every five seconds.

### 6. Self-Contained Netfilter Lifecycle (`--no-netfilter` Opt-out)

- Unless `--no-netfilter` is set, manage rules directly through `NETLINK_NETFILTER`, without invoking `nft`. Use table name `ghostun_<tun_name>`, replacing characters outside `[A-Za-z0-9_]` with `_` to support multiple instances on one host:
  1. In one batch transaction, ensure the table exists, delete it, and recreate it with the required chains and rules. This clears stale state on success while preserving the old table if any operation fails.
  2. Preserve these rule semantics:
     - **Shared Entry/Exit rules**: In the prerouting chain, match non-TUN outer tunnel frames (`iifname != "<tun>"`) and apply `notrack meta pkttype set other` so outer traffic bypasses host conntrack and is discarded immediately at local `tcp_v4_rcv` / `tcp_v6_rcv` entry after `SOCK_RAW` delivery. In the output chain, match `notrack` and drop fallback kernel-generated `tcp flags rst` for local tunnel ports in the selected outer family. Use `ip`/`ip6` endpoint matching on Entry, and `meta nfproto ipv4`/`ipv6` on Exit. Ghostun sockets set `SO_MARK = 0x67687374`; `meta mark != 0x67687374` exempts intentionally emitted RSTs.
     - **Exit-specific rules**: Enable `net.ipv4.ip_forward=1` and, in dual-stack mode, `net.ipv6.conf.all.forwarding=1`. In the forward chain, apply `maxseg size set rt mtu` to TCP SYNs entering or leaving `ghostun0`. In postrouting, masquerade inner networks (`10.200.0.0/30` and `fd00:200::/126`) on traffic leaving through non-tunnel interfaces.
  3. On SIGINT/SIGTERM, have Entry send RSTs for every outer connection to release firewall slots, then remove `table inet ghostun_<tun_name>` before exiting.

## Testing Decisions

### 1. What Makes a Good Test

- Test externally observable behavior and protocol contracts: binary packet layout, checksum validity, BPF acceptance/rejection of five-tuples, session transitions and emitted packets after incoming frames or timeouts, and end-to-end namespace connectivity. Do not couple tests to private fields or helper-function implementation details.

### 2. Highest Testing Seams

Use **two core testing seams** to verify behavior at the highest practical abstraction level:

1. **Packet and Session seam: pure logic without privileges**:
   - Decouple the FakeTCP Session and packet codec from TUN/raw-socket OS I/O. Inputs are current time plus received outer frames or inner L3 packets. Observable outputs are emitted outer TCP frames, inner packets for TUN delivery, and connection state.
   - Without root, verify the three-way handshake, IPv4/IPv6 dispatch, Health Ping/Pong, threshold ACKs under one-way bulk traffic, timeout recovery that sends RST before rotating the source port within `sport % N == i`, checksums, and classic BPF rules.
   - Verify delayed duplicate SYNs before and after bidirectional data over both outer families, and verify that a genuinely new handshake on the same tuple can still establish a replacement session. Derive endpoint assertions from emitted frames rather than test-only field accessors.
   - Require mutual authentication before forwarding; verify invalid proofs, replay resistance, candidate isolation and expiry, legitimate admission during unrelated attempts, authenticated replacement, and loss/duplicate sequence accounting.
2. **Linux netns E2E seam: real-kernel integration**:
   - Use `ip netns` to build `entry_ns <--> fw_ns <--> exit_ns`, with strict nftables conntrack in the firewall namespace and a separate internet namespace for inner traffic. Exercise outer IPv4 and IPv6 separately, including inner IPv4/IPv6 in each run. Remove IPv4 addresses from endpoint outer interfaces in the IPv6 run.
   - Launch the compiled `ghostun entry` and `ghostun exit` processes and verify at the system boundary:
     - End-to-end inner IPv4/IPv6 ping and large-packet TCP transfers, including MTU derivation and MSS clamping.
     - Under concurrent inner flows, inspect `/proc/net/nf_conntrack` or `conntrack -L` in the firewall namespace and verify exactly `--conns N` established outer connections.
     - Flush firewall conntrack state to simulate silent connection loss. Verify health-based detection, RST cleanup of old slots, reconnection, and restored inner traffic.
     - Send SIGTERM and verify removal of the `ghostun0` interface and `table inet ghostun_ghostun0`.
     - Supply mandatory keys, deny wrong-key forwarding and takeover, retain active tuples during unauthenticated handshakes, and authenticate source-address replacement and recovery after lost authentication messages.
     - Disable IPv6 for new interfaces and hide its sysctl tree in private mount namespaces. Verify automatic inner IPv4 fallback for both default roles, full-MTU forwarding, and clean shutdown without accessing unavailable IPv6 forwarding controls.
   - Run the netns topology inside a privileged Docker container (`sudo docker run -d --privileged`) to avoid modifying host networking. Remove the container after testing.

### 3. Prior Art

- Draw on the design experience of the community `phantun` project, but avoid the dual-TUN and smoltcp stack used by `fake-tcp`. Validate kernel interaction through a lightweight state machine and real netns E2E smoke tests.

## Out of Scope

1. **Additional tunnel-layer encryption**: Client-to-Entry traffic is already encrypted by the front-end proxy protocol, and much internet egress traffic uses HTTPS/TLS. Do not add TLS/AEAD/WireGuard encryption at the tunnel layer.
2. **Outer-payload DPI camouflage, such as fake TLS ClientHello or HTTP headers**: The target firewall enforces L4 TCP state tracking and connection limits, not application-payload inspection.
3. **Simultaneous dual-stack outer listening and automatic outer-family switching**: Each instance uses one explicitly selected or remote-derived outer family. Do not add DNS resolution, racing, or automatic fallback between families.
4. **Built-in proxy protocol parsing, including Shadowsocks, VMess, VLESS, or Trojan**: Ghostun is a pure L3-over-FakeTCP tunnel, integrated with upstream proxy software through a standard TUN interface and `SO_BINDTODEVICE` / `interface_name`.
5. **Windows or macOS support**: Depend on Linux-specific privileged facilities: multi-queue TUN, `SOCK_RAW`, `IP_HDRINCL`, `SO_ATTACH_FILTER`, and nftables. Target Linux production servers only.

## Further Notes

- **Privileges**: Running ghostun requires `CAP_NET_ADMIN` and `CAP_NET_RAW`, or root. Docker deployment needs host networking and both capabilities.
- **Proxy integration example: Entry sing-box outbound**:

  ```json
  {
    "type": "direct",
    "tag": "tunnel-out",
    "bind_interface": "ghostun0",
    "inet4_bind_address": "10.200.0.1",
    "inet6_bind_address": "fd00:200::1"
  }
  ```
