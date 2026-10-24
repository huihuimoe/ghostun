# ghostun

`ghostun` is a lightweight Linux L3-over-FakeTCP tunnel for paths behind stateful firewalls that drop UDP or cap concurrent TCP connections.

One binary runs in two roles:

- **Entry** sits next to your proxy server and exposes a `ghostun0` TUN device.
- **Exit** decapsulates traffic from the tunnel and NATs it to the internet.

```mermaid
flowchart LR
  C[Clients] --> P[Proxy on Entry] -->|bind ghostun0| E[ghostun entry]
  E ==>|N FakeTCP connections| FW{{Stateful firewall}} ==> X[ghostun exit]
  X -->|ghostun0 + MASQUERADE| I[Internet]
```

## Requirements

- Linux with `CAP_NET_ADMIN` and `CAP_NET_RAW` (or root)
- `iproute2` (`ip`) and `nftables` (`nft`, unless `--no-netfilter` is set)
- Inbound TCP allowed on the Exit `--listen` port

## Build

```sh
cargo build --release --locked
docker build -t ghostun .
```

## Quick start

1. Generate a shared 32-byte key file (`0600`) and copy it to both hosts:

```sh
umask 077
{
    printf 'auth_key = "'
    od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
    printf '"\n'
} > auth.toml
```

2. Start Exit and Entry (`--conns` must match on both ends):

```sh
# Exit (IPv4 outer)
ghostun --config auth.toml exit --listen 443 --conns 4

# Entry (IPv4 outer)
ghostun --config auth.toml entry --remote 203.0.113.10:443 --conns 4
```

For an IPv6 outer path, set `--outer-family ipv6` on Exit and pass a bracketed IPv6 address on Entry:

```sh
ghostun --config auth.toml exit --listen 443 --outer-family ipv6 --conns 4
ghostun --config auth.toml entry --remote '[2001:db8::10]:443' --conns 4
```

3. Bind your proxy outbound to `ghostun0` (Entry does not alter system routes):

**sing-box**

```json
{
  "type": "direct",
  "tag": "tunnel-out",
  "bind_interface": "ghostun0",
  "inet4_bind_address": "10.200.0.1",
  "inet6_bind_address": "fd00:200::1"
}
```

**xray**

```json
{
  "protocol": "freedom",
  "tag": "tunnel-out",
  "streamSettings": { "sockopt": { "interface": "ghostun0" } }
}
```

## CLI and configuration

```text
ghostun [options] [entry|exit]
```

| Flag | Default | Description |
|---|---|---|
| `--config PATH` | — | TOML configuration file (required for `auth_key`) |
| `--remote IP:PORT` | — | Entry only: Exit outer address (IP literal) |
| `--listen PORT` | — | Exit only: outer listen port |
| `--outer-family ipv4\|ipv6` | `ipv4` | Exit only: outer transport family (Entry derives it from `--remote`) |
| `--conns N` | CPU count | Number of pinned workers and outer connections (`1..=256`) |
| `--cpus LIST` | all usable CPUs | Worker CPU list or ranges (e.g. `0,1` or `2-3`) |
| `--tun NAME` | `ghostun0` | Inner TUN device name (`[A-Za-z0-9_.-]`, up to 15 chars) |
| `--tun-ipv4 CIDR` | `10.200.0.1/30` / `.2/30` | Inner IPv4 address (Entry / Exit) |
| `--tun-ipv6 CIDR` | `fd00:200::1/126` / `::2/126` | Inner IPv6 address (Entry / Exit) |
| `--no-ipv6` | off | Disable inner IPv6 |
| `--outer-mtu MTU` | egress MTU or `1500` | Outer path MTU |
| `--tun-mtu MTU` | `outer_mtu - 40` / `- 60` | Inner TUN MTU (IPv4 / IPv6 outer overhead) |
| `--iface IFACE` | route lookup | Outer egress interface |
| `--base-port PORT` | `32768` | Entry only: starting source port |
| `--ping-interval SECS` | `5` | Health probe interval |
| `--dead-timeout SECS` | `15` | Silence timeout before reconnecting |
| `--no-netfilter` | off | Skip automatic `nftables` and `sysctl` setup |
| `-V`, `--version` | — | Print version and exit |
| `-h`, `--help` | — | Show help and exit |

All CLI options can be placed in the TOML file using `snake_case` keys (`mode = "entry"` or `"exit"`). Explicit CLI flags override file values. See [`deploy/config.example.toml`](deploy/config.example.toml).

## Deployment

### systemd

```sh
install -m755 target/release/ghostun /usr/local/bin/
install -d -m700 /etc/ghostun
install -m600 deploy/config.example.toml /etc/ghostun/entry.toml  # set auth_key and role settings
install -m644 deploy/ghostun-entry.service /etc/systemd/system/
systemctl enable --now ghostun-entry
```

Use `exit.toml` and `deploy/ghostun-exit.service` on the Exit host.

### Docker Compose

```sh
cd deploy
install -m600 config.example.toml entry.toml   # set auth_key and role settings
docker compose -f docker-compose.entry.yml up -d --build
```

For Exit, enable IP forwarding on the host before starting `docker-compose.exit.yml`:

```sh
sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
```

## Performance

Measured inside a single 4-vCPU VM (AMD EPYC-Genoa, Linux 7.2) running Entry (`--cpus 0-1`), a stateful `nftables` firewall, Exit (`--cpus 2-3`), and `iperf3 -P 8` across isolated network namespaces in Docker with `--conns 2` (outer MTU `1420`):

| Outer family | Inner IPv4 upload | Inner IPv6 download | Entry RSS | Exit RSS |
|---|---|---|---|---|
| IPv4 (TUN MTU 1380) | 2.30 Gbit/s | 2.29 Gbit/s | ~2.9 MB | ~2.9 MB |
| IPv6 (TUN MTU 1360) | 2.00 Gbit/s | 1.99 Gbit/s | ~3.0 MB | ~2.9 MB |

Stripped release binary size is ~800 KB.

## Operational notes

- **MTU:** Outer headers take 40 bytes over IPv4 and 60 bytes over IPv6. If your path MTU is lower than the NIC MTU (for example PPPoE `1492` or cloud VPC `1420`) and large transfers stall while ping works, set `--outer-mtu`.
- **Firewall rules:** Unless `--no-netfilter` is set, `ghostun` manages `table inet ghostun_<tun>` (kernel RST suppression, MSS clamping, and Exit masquerade) and cleans it up on `SIGINT`/`SIGTERM`.
- **Security boundary:** `auth_key` authenticates tunnel handshakes so stray clients cannot claim worker slots. `ghostun` does not encrypt traffic or disguise payloads as TLS/HTTP; keep encryption and client authentication in your proxy layer.
- **Further docs:** [Testing guide](tests/README.md), [architecture spec](docs/261024-ghostun-spec.md), and [authentication spec](docs/261024-handshake-auth-spec.md).
