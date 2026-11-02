# pcapport

pcapport analyses PCAP capture files entirely on your own machine.
Point it at a classic libpcap file and it summarises what is inside:
DNS questions and response codes, DHCP message types and the servers
and clients involved, ICMP traffic, TCP connections with state
estimates, TCP anomalies and retransmissions, traffic flow to and
from one server, SIP calls, and basic capture information such as
packet count, duration, and encapsulation.

There is no network access, no API key, and no live capture: the
tool only reads the capture file you name. The parser is an original
minimal implementation covering Ethernet (including a single VLAN
tag) and raw-IP captures carrying IPv4, with TCP, UDP, and ICMP
decoded, and DNS, DHCP, and SIP payloads understood.

## Install

```bash
npx @reneturcios/pcapport analyze_capinfos '{"pcap_file":"capture.pcap"}'
```

Or run the container image:

```bash
docker run -i ghcr.io/cloudcorprecords/pcapport
```

The container defaults to the MCP server. Pass CLI arguments to use
it as a CLI instead.

## CLI

The CLI mirrors the tools: one subcommand per tool, taking its
arguments as a single JSON object.

```bash
pcapport analyze_capinfos '{"pcap_file":"capture.pcap"}'
pcapport analyze_dns_packets '{"pcap_file":"capture.pcap"}'
pcapport analyze_tcp_connections '{"pcap_file":"capture.pcap","detailed":true}'
pcapport analyze_tcp_retransmissions '{"pcap_file":"capture.pcap","threshold":0.05}'
pcapport analyze_traffic_flow '{"pcap_file":"capture.pcap","server_ip":"10.0.0.5","server_port":80}'
pcapport --version
```

Exit codes: `0` on success, `1` on an error (the error names the
problem, e.g. a bad PCAP magic or a truncated file), `2` for usage
errors. An empty capture is not an error: tools return zeroed
summaries for it.

## MCP server

One bin serves both faces. The `mcp` subcommand starts a stdio MCP
server:

```bash
npx -y @reneturcios/pcapport mcp
```

MCP client configuration:

```json
{
  "mcpServers": {
    "pcapport": {
      "command": "npx",
      "args": ["-y", "@reneturcios/pcapport", "mcp"]
    }
  }
}
```

### Tools

| Tool | Input | What it does |
| --- | --- | --- |
| `analyze_dns_packets` | `pcap_file` (required) | DNS query/response counts, top questions (aggregated, top 20), and a response-code summary. |
| `analyze_dhcp_packets` | `pcap_file` (required) | DHCP packet count by message type (discover, offer, request, ack, ...), server IPs, and client MACs. |
| `analyze_icmp_packets` | `pcap_file` (required) | ICMP counts by type, echo requests/replies, unreachable count, and top talkers. |
| `analyze_tcp_connections` | `pcap_file` (required), `server_ip`, `server_port`, `detailed` | Connections keyed by the normalised 4-tuple with client/server, packets, bytes, SYN/FIN/RST counts, and a state estimate (established, closed, reset, half-open). With `detailed`, a per-connection timestamp summary is included. |
| `analyze_tcp_anomalies` | `pcap_file` (required), `server_ip`, `server_port` | Counts of reset connections, half-open connections (SYN with no SYN-ACK), connections without data, and zero-window advertisements, computed from flags and window fields. |
| `analyze_tcp_retransmissions` | `pcap_file` (required), `server_ip`, `threshold` (default 0.02) | A retransmission is a repeated (tuple, sequence, payload-length) data segment. Reports data segments, retransmissions, the rate, whether it exceeds the threshold, and the top offending connections. |
| `analyze_traffic_flow` | `pcap_file` (required), `server_ip` (required), `server_port` | Packets and bytes to and from the server, the unique client count, and the top clients by bytes. |
| `analyze_sip_packets` | `pcap_file` (required) | SIP requests by method, responses by status class, and calls (Call-ID, From, To). Payloads on port 5060 plus any payload starting with a SIP method or `SIP/2.0` are considered. |
| `analyze_capinfos` | `pcap_file` (required) | Packet count, duration, data bytes, average packet size, first/last packet times, encapsulation, and capture length. |

## Scope and limits

The parser covers classic libpcap only (big/little endian, micro-
and nanosecond timestamps) — no pcapng. Only IPv4 is decoded; IPv6
and other ethertypes are counted in packet totals but not analysed.
There is no TCP stream reassembly, so SIP over TCP is matched per
segment, and TLS payloads are opaque. Anomaly and state heuristics
are deliberately simple approximations, not a substitute for a full
tshark-grade analysis.

## Development

```bash
npm install
npm run build   # tsc -> dist/
npm test        # node test runner over test/*.test.ts, synthetic captures only, no network
npm run dev     # run the CLI from source via tsx
```

## License

MIT — see `LICENSE`.
