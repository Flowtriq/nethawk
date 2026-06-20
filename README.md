<h1 align="center">◆ NetHawk</h1>

<h3 align="center">Real-time network traffic analysis in your terminal.</h3>

<p align="center">
  <a href="#install">Install</a> •
  <a href="#usage">Usage</a> •
  <a href="#features">Features</a> •
  <a href="#json-mode">JSON Mode</a> •
  <a href="#attack-detection">Attack Detection</a> •
  <a href="#contributing">Contributing</a>
</p>

<p align="center">
  <a href="https://github.com/Flowtriq/nethawk/releases"><img src="https://img.shields.io/github/v/release/Flowtriq/nethawk?style=flat-square&color=00d4aa" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
  <a href="https://github.com/Flowtriq/nethawk/actions"><img src="https://img.shields.io/github/actions/workflow/status/Flowtriq/nethawk/build.yml?style=flat-square" alt="Build"></a>
  <a href="https://goreportcard.com/report/github.com/Flowtriq/nethawk"><img src="https://goreportcard.com/badge/github.com/Flowtriq/nethawk?style=flat-square" alt="Go Report"></a>
</p>

---

<p align="center">
  <img src="https://raw.githubusercontent.com/Flowtriq/nethawk/main/.github/demo.gif" alt="NetHawk Demo" width="700">
</p>

---

SSH into a server. Run `nethawk`. See everything hitting your network in real time.

No config files. No databases. No web servers. One 5MB binary.

## Install

### One-liner (Linux/macOS)

```bash
curl -sSfL https://raw.githubusercontent.com/Flowtriq/nethawk/main/install.sh | sudo sh
```

### From source

```bash
go install github.com/Flowtriq/nethawk/cmd/nethawk@latest
```

### From release

Download the binary for your platform from [Releases](https://github.com/Flowtriq/nethawk/releases).

### Prerequisites

NetHawk uses `libpcap` for packet capture:

- **Linux (Debian/Ubuntu):** `sudo apt install libpcap-dev`
- **Linux (RHEL/CentOS):** `sudo yum install libpcap-devel`
- **macOS:** included with the system

## Usage

```bash
# auto-detect interface, default threshold
sudo nethawk

# specify interface
sudo nethawk -i eth0

# custom attack detection threshold (PPS)
sudo nethawk -i eth0 -t 100000

# JSON output (for piping to other tools)
sudo nethawk -json

# list available interfaces
nethawk -list
```

Root is required because raw packet capture needs it. That's the same as tcpdump, Wireshark, or any other packet capture tool.

## Features

### Real-Time Traffic Dashboard

- **Bandwidth and packet rate** — live Gbps/Mbps and PPS with peak tracking
- **60-second sparkline** — color-coded traffic history at a glance
- **Protocol breakdown** — TCP, UDP, ICMP percentages with visual bars
- **Top source IPs** — who's sending you the most traffic, ranked by packet count
- **Top destination ports** — which services are being hit, with percentages

### Attack Detection

NetHawk classifies traffic patterns in real time. When packets per second exceed your threshold, it identifies the attack vector:

| Severity | Trigger | Color |
|----------|---------|-------|
| NORMAL | Below threshold | Green |
| MEDIUM | 1x threshold | Yellow |
| HIGH | 2x threshold | Orange |
| CRITICAL | 5x threshold | Red |

Attack types detected:

- DNS Amplification (UDP/53)
- NTP Amplification (UDP/123)
- Memcached Amplification (UDP/11211)
- SSDP Amplification (UDP/1900)
- LDAP Amplification (UDP/389)
- SNMP Amplification (UDP/161)
- CharGEN Amplification (UDP/19)
- UDP Flood
- SYN Flood
- TCP Flood (with port identification)
- ICMP Flood
- Volumetric (mixed protocol)

### JSON Mode

Pipe structured data to jq, custom alerting, log aggregation, or anything else:

```bash
sudo nethawk -json | jq '.severity'
```

```json
{
  "timestamp": "2026-06-20T14:30:00Z",
  "interface": "eth0",
  "pps": 234000,
  "bps": 1240000000,
  "tcp_pct": 45.2,
  "udp_pct": 42.1,
  "icmp_pct": 12.7,
  "unique_src_ips": 847,
  "top_sources": [
    {"ip": "192.168.1.100", "count": 89000}
  ],
  "top_ports": [
    {"port": 53, "protocol": "UDP", "count": 98700, "percent": 42.1}
  ],
  "avg_pkt_size": 512,
  "severity": "NORMAL"
}
```

## How It Works

NetHawk captures packets directly from your network interface using libpcap. Every second, it aggregates:

1. **Packet and byte counters** — total throughput
2. **Protocol classification** — L4 protocol of each packet
3. **Source IP tracking** — unique source IPs (capped at 100K to bound memory)
4. **Destination port tracking** — which ports are receiving traffic
5. **Attack classification** — compares current PPS against threshold, identifies vector from protocol/port patterns

Everything runs in-process. No data leaves the machine. No cloud. No accounts. No phone-home.

## Comparison

| | NetHawk | iftop | nload | bandwhich | Wireshark |
|--|---------|-------|-------|-----------|-----------|
| Real-time TUI | Yes | Yes | Yes | Yes | No (GUI) |
| Protocol breakdown | Yes | No | No | No | Yes |
| Top source IPs | Yes | Connections | No | Per-process | Yes |
| Top dest ports | Yes | No | No | No | Yes |
| Attack detection | Yes | No | No | No | No |
| Attack classification | Yes | No | No | No | No |
| JSON output | Yes | No | No | No | Yes |
| Single binary | Yes | No | No | Yes | No |
| Zero config | Yes | Yes | Yes | Yes | No |

## For production DDoS protection

NetHawk shows you what's hitting your network. If you need something that **stops** it automatically — 24/7 monitoring, auto-mitigation, alerting, team dashboards, incident forensics — check out [Flowtriq](https://flowtriq.com).

## Contributing

Contributions welcome. Some ideas:

- **Detection algorithms** — new attack vector classifiers
- **Output formats** — CSV, InfluxDB line protocol, Prometheus metrics
- **GeoIP enrichment** — map source IPs to countries/ASNs
- **Historical views** — longer time windows, scrollable history
- **Interface switching** — toggle between interfaces in the TUI

```bash
git clone https://github.com/Flowtriq/nethawk
cd nethawk
make build
sudo ./bin/nethawk
```

## License

MIT. See [LICENSE](LICENSE).

## See also

- [ftagent-lite](https://github.com/Flowtriq/ftagent-lite) — lightweight Python DDoS monitor (single-file, pip install, JSON output)
- [Flowtriq](https://flowtriq.com) — managed DDoS detection and mitigation platform
