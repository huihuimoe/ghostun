# ghostun

High-performance, low-memory L3-over-FakeTCP tunnel for Linux. One binary, two roles:

- **entry** — runs next to your proxy server. The proxy sends decrypted outbound traffic into the `ghostun0` TUN device.
- **exit** — decapsulates and lets the kernel `MASQUERADE` the traffic to the internet. No user-space proxy runs there.

Built for paths behind stateful firewalls that drop non-TCP traffic, cap concurrent TCP connections, and silently drop conntrack state. Design and rationale: [`docs/261024-ghostun-spec.md`](docs/261024-ghostun-spec.md).

```mermaid
flowchart LR
  C[clients] --> P[proxy on entry] -->|bind ghostun0| E[ghostun entry]
  E ==>|N fake TCP connections| FW{{stateful firewall}} ==> X[ghostun exit]
  X -->|ghostun0 + MASQUERADE| I[internet]
```

## How it works

- **One multi-queue TUN, raw outer sockets.** Inner packets cross the TUN boundary once per node. Outer frames use `SOCK_RAW` with `IP_HDRINCL` (IPv4) or `IPV6_HDRINCL` (IPv6): 40 B or 60 B of IP + TCP headers, no outer TUN, no outer NAT.
- **Exactly N steady-state outer connections.** `--conns N` workers, each pinned to one CPU, own one authenticated connection (SYN with MSS, SACK_PERM, WScale 14). Candidate handshakes may temporarily add conntrack entries; authenticated replacement resets the retired tuple.
- **Kernel steering.** Each worker's raw socket has a classic BPF filter, so worker `i` only receives its own connection (entry: `dport % N == i`, exit: `sport % N == i`). No locks or channels between cores.
- **No outer retransmission.** Inner TCP handles loss, so there is no TCP-over-TCP meltdown. Sequence and ack numbers advance for every frame. A bare ACK goes out after 1 MiB of one-way data, which keeps the firewall's window tracking satisfied.
- **Unframed data, separate control.** Payloads starting with `0x01` or `0x02` are health ping/pong frames; `0x03` identifies connection-time authentication. IPv4/IPv6 packets start with `0x4`/`0x6`, so data frames carry no extra framing.
- **Self-healing.** Both sides ping every `--ping-interval`. If the entry hears nothing for `--dead-timeout`, it sends 2 RSTs on the old tuple, moves to the next source port of its residue class, and authenticates again. The exit answers stray non-SYN data with RST, triggering reconnection without waiting for the Entry dead timer.
- **Independent inner and outer families.** Inner IPv4 and IPv6 work over either IPv4 or IPv6 outer transport. Each instance uses one outer family, without simultaneous dual-stack listening or automatic family switching.
- **Mandatory mutual authentication.** Each worker proves possession of the same random 32-byte key after the ordinary TCP handshake. Authentication adds about two setup RTTs, not steady-state MACs, data headers, or exchanges. Unauthenticated candidates cannot replace or keep an active session alive.

## Build

```sh
cargo build --release        # target/release/ghostun, ~2 MB, ~4 MB RSS at runtime
docker build -t ghostun .    # Chainguard rust build stage, wolfi-base runtime (~50 MB)
```

Runtime needs `ip` (iproute2) and, unless `--no-netfilter` is set, `nft` (nftables). It also needs `CAP_NET_ADMIN` + `CAP_NET_RAW` (in practice, root).

## Quick start

Generate a key-only config once, then securely copy the same file to both nodes. This uses standard Linux tools; the key is not passed through process arguments:

```sh
umask 077
{
    printf 'auth_key = "'
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
    printf '"\n'
} > auth.toml
```

```sh
# exit (public IP 203.0.113.10)
ghostun --config auth.toml exit --listen 443 --conns 4

# entry
ghostun --config auth.toml entry --remote 203.0.113.10:443 --conns 4
```

For an IPv6 outer path:

```sh
# exit (public IPv6 address 2001:db8::10)
ghostun --config auth.toml exit --listen 443 --outer-family ipv6 --conns 4

# entry: bracket the IPv6 literal; its family is selected automatically
ghostun --config auth.toml entry --remote '[2001:db8::10]:443' --conns 4
```

Exit defaults to `--outer-family ipv4`. `--outer-family` / TOML `outer_family` is Exit-only; Entry derives the family from `remote`. `--no-ipv6` disables only inner IPv6 and does not disable an IPv6 outer path. Remote addresses must be IP literals, not hostnames.

`--conns` **must be identical on both ends**. Allow inbound TCP to the listen port on the exit.

The entry does not change your routing table. Point the proxy at the TUN device instead.

sing-box:

```json
{
  "type": "direct",
  "tag": "tunnel-out",
  "bind_interface": "ghostun0",
  "inet4_bind_address": "10.200.0.1",
  "inet6_bind_address": "fd00:200::1"
}
```

xray:

```json
{
  "protocol": "freedom",
  "tag": "tunnel-out",
  "streamSettings": { "sockopt": { "interface": "ghostun0" } }
}
```

Several instances can share a host if each one has a different `--tun` name, inner subnet, and port (`--listen` on exit; `--base-port` range on entry).

## CLI

```
ghostun --config PATH entry --remote IP:PORT [options]
ghostun --config PATH exit  --listen PORT    [options]
ghostun --config PATH          # role taken from `mode` in the file
```

| Flag | Default | Meaning |
|---|---|---|
| `--tun`, `--tun-name NAME` | `ghostun0` | Inner TUN device name (`[A-Za-z0-9_.-]`, ≤15 chars) |
| `--tun-ipv4 CIDR` | entry `10.200.0.1/30`, exit `10.200.0.2/30` | Inner IPv4 address |
| `--tun-ipv6 CIDR` | entry `fd00:200::1/126`, exit `fd00:200::2/126` | Inner IPv6 address |
| `--no-ipv6` | off | No inner IPv6. If the kernel has IPv6 disabled, ghostun logs a warning and continues without it |
| `--conns N` | CPU count | Outer connections = pinned worker threads (1–256) |
| `--outer-mtu MTU` | egress interface MTU, else 1500 | Outer path MTU |
| `--tun-mtu MTU` | `outer_mtu - 40` (IPv4 outer), `outer_mtu - 60` (IPv6 outer) | Inner MTU (≥1280 with inner IPv6); must fit the outer MTU |
| `--iface IFACE` | from routing table | Outer egress interface. Entry: source address. Exit: also limits masquerade to this interface |
| `--base-port PORT` | `32768` | Entry: lowest outer source port |
| `--ping-interval SECS` | `5` | Health ping period |
| `--dead-timeout SECS` | `15` | Silence before reconnect (entry) or dropping the peer (exit) |
| `--no-netfilter` | off | Do not touch nftables or sysctl |
| `--remote IP:PORT` | — | Entry only, required |
| `--listen PORT` | — | Exit only, required |
| `--outer-family ipv4\|ipv6` | `ipv4` | Exit only: outer transport family; Entry uses `--remote` |

Logging: `RUST_LOG=debug ghostun ...` (default `info`).

## Config file

Both roles require a file-only `auth_key`: exactly 64 hexadecimal characters encoding 32 random bytes. A missing or malformed key is rejected before networking starts. There is no CLI key argument, password mode, bypass, or legacy fallback. Keep configuration files mode `0600`; never use a public example key. Start with the generated `auth.toml` above and add the settings below.

Other TOML keys are the long flag names in snake_case. CLI flags override the file. Unknown keys are rejected. See [`deploy/config.example.toml`](deploy/config.example.toml).

```toml
mode = "exit"
listen = 443
conns = 4
iface = "eth0"
```

## Authentication and security

- The key is shared by one trust domain. Any holder may replace a session, including from a changed source address; there are no individual identities, permissions, or revocation. Avoid duplicate Entry deployments with the same key.
- Authentication protects admission, not established packets: there is no tunnel encryption, per-packet integrity, or established-packet replay protection. On-path attackers or attackers able to forge accepted data, health frames, or RSTs remain outside this protection.
- Stateless candidates cannot reserve the only authentication slot, but this is not DDoS protection or scanner invisibility. Optional operator-managed source allowlists remain defense in depth, not a requirement for fixed Entry addresses.
- Rotate keys by securely updating both configuration files and restarting both peers. Hot rotation and unauthenticated-version interoperability are unsupported.

Wire format, replay handling, and retry rules: [`docs/261024-handshake-auth-spec.md`](docs/261024-handshake-auth-spec.md).

## MTU and MSS

The tunnel adds 40 bytes over outer IPv4 or 60 bytes over outer IPv6, so the default TUN MTU is `outer_mtu - overhead`:

| Outer MTU | TUN MTU over IPv4 | TUN MTU over IPv6 |
|---|---|---|
| 1500 | 1460 | 1440 |
| 1492 | 1452 | 1432 |
| 1420 | 1380 | 1360 |

Inner TCP SYNs crossing `ghostun0` get their MSS clamped to the route MTU (`tcp option maxseg size set rt mtu`). Set `--outer-mtu` if the real path MTU is lower than the local interface MTU; there is no automatic path-MTU adjustment or tunnel fragmentation/reassembly layer.

Before changing networking, ghostun rejects explicit or detected MTUs that cannot carry the configured inner packets. With inner IPv6 enabled, the TUN MTU must be at least 1280: this requires outer MTU ≥1320 over IPv4 or ≥1340 over IPv6. Outer IPv6 itself requires MTU ≥1280. An explicit `--tun-mtu` cannot exceed `outer_mtu - overhead`.

## Netfilter

Without `--no-netfilter`, ghostun owns the table `inet ghostun_<tun>` (for example `ghostun_ghostun0`):

- On start, it deletes any stale table left by a crash and creates a new one, atomically.
- On SIGINT/SIGTERM, it deletes the table. The TUN device has no `IFF_PERSIST`, so the kernel removes it even after SIGKILL. In that case, the table remains until the next start.

Equivalent rules if you manage the firewall yourself (`--no-netfilter`), shown here for the exit with listen port 443:

```nft
table inet ghostun_ghostun0 {
    chain output {
        type filter hook output priority filter; policy accept;
        # The kernel has no socket for the tunnel tuples and would RST the peer.
        # ghostun's own RSTs carry fwmark 0x67687374 and pass.
        meta nfproto ipv4 tcp sport 443 tcp flags rst meta mark != 0x67687374 drop
        oifname "ghostun0" tcp flags syn tcp option maxseg size set rt mtu
    }
    chain forward {
        type filter hook forward priority filter; policy accept;
        oifname "ghostun0" tcp flags syn tcp option maxseg size set rt mtu
        iifname "ghostun0" tcp flags syn tcp option maxseg size set rt mtu
    }
    chain postrouting {   # exit only
        type nat hook postrouting priority srcnat; policy accept;
        ip saddr 10.200.0.0/30 oifname != "ghostun0" masquerade
        ip6 saddr fd00:200::/126 oifname != "ghostun0" masquerade
    }
}
```

On the entry, the RST rule matches the outer tuple instead: `ip daddr <exit_ip> tcp dport <exit_port> tcp sport >= <base_port>`. For IPv6 outer transport, use `ip6 daddr` on Entry and `meta nfproto ipv6` in the Exit RST rule above. Inner masquerade rules remain independent of the outer family. Exit also needs `net.ipv4.ip_forward=1` (and `net.ipv6.conf.all.forwarding=1` for inner IPv6). Ghostun sets these on start unless they are already set.

Ghostun configures the TUN before installing firewall rules. If the kernel rejects inner IPv6 configuration, it logs a warning and continues with inner IPv4, without accessing IPv6 forwarding sysctls or installing IPv6 masquerade rules. This does not change the selected outer family: an IPv6 outer path still requires kernel IPv6 support.

## Deployment

### systemd

```sh
install -m755 target/release/ghostun /usr/local/bin/
install -d -m700 /etc/ghostun
install -m600 deploy/config.example.toml /etc/ghostun/entry.toml  # edit; add the generated auth_key
install -m644 deploy/ghostun-entry.service /etc/systemd/system/
systemctl enable --now ghostun-entry
```

Use `exit.toml` and `ghostun-exit.service` on the exit. Both files must contain the same generated `auth_key` before starting the services.

### Docker Compose

```sh
cd deploy
install -m600 config.example.toml entry.toml   # edit; add the generated auth_key
docker compose -f docker-compose.entry.yml up -d --build
```

The containers use host networking with `NET_ADMIN`, `NET_RAW` and `/dev/net/tun`. `/proc/sys` is read-only inside them, so enable forwarding on the exit host first:

```sh
sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
```

## Troubleshooting

- **Firewall connection count**: on a box that sees the traffic, `conntrack -L -p tcp --dport <listen>` should show exactly N `ESTABLISHED` entries.
- **`peer silent ..., reconnecting` loops**: check `--conns` matches on both ends, the exit port is reachable, and nothing else on the hosts answers or drops the tunnel tuples.
- **Large transfers stall but ping works**: the path MTU is below the interface MTU. Set `--outer-mtu`.

## Testing

See [tests/README.md](tests/README.md) for unit tests and isolated network integration tests.

## What to handle separately

- **Confidentiality:** ghostun does not encrypt tunnel traffic. Use encryption outside the tunnel when the traffic requires it.
- **Application-layer filtering:** ghostun does not disguise payloads as TLS, HTTP, or another application protocol. Use a transport designed for that environment if the network inspects application payloads.
- **Proxy services:** keep proxy protocol termination, client authentication, and traffic accounting in your proxy software; ghostun does not provide them.
