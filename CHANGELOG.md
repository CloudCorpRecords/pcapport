# Changelog

## 0.1.0 (2026-10-26)

- Initial release. Full documented set (9 tools) for local PCAP analysis.
- Original minimal libpcap parser: classic PCAP (both endians, micro/nanosecond), Ethernet with a single VLAN tag and raw-IP linktypes, IPv4 with TCP/UDP/ICMP, and DNS/DHCP/SIP payload decoders.
- CLI: one subcommand per MCP tool (same name as the tool), each taking its arguments as a JSON object on the command line, plus `--version`.
- MCP server (`pcapport mcp`, stdio) with 9 tools: `analyze_dns_packets`, `analyze_dhcp_packets`, `analyze_icmp_packets`, `analyze_tcp_connections`, `analyze_tcp_anomalies`, `analyze_tcp_retransmissions`, `analyze_traffic_flow`, `analyze_sip_packets`, and `analyze_capinfos`.
- Bad magic and truncated files raise clean named errors; empty captures return zeroed summaries.
