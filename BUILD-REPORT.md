# pcapport — Build Report

Clean-room rebuild of mcpcap/mcpcap (rank 43, 52 stars), Tranche #101+ Batch 2.
Local Tier A tool: real PCAP analysis in TypeScript, no network, no API key.
Not pushed, not published.

## Files (19-file fleet factory set)

- package.json (@reneturcios/pcapport, bin pcapport: dist/cli.js, mcpName io.github.CloudCorpRecords/pcapport)
- server.json (description 81 chars, ≤100; npm entry version 0.1.0; OCI entry ghcr.io/cloudcorprecords/pcapport:0.1.0 with NO version field; no environmentVariables)
- Dockerfile (node:20-alpine two-stage, label io.modelcontextprotocol.server.name="io.github.CloudCorpRecords/pcapport")
- tsconfig.json (fleet-identical), .gitignore, LICENSE (MIT © 2026 Rene Turcios)
- README.md (fresh), CHANGELOG.md (single 0.1.0, 2026-10-26)
- package-lock.json (Route 3, see below)
- src/index.ts, src/cli.ts, src/mcp.ts, src/types.ts, src/pcapport.ts
- test/pcapport.test.ts
- .github/workflows/ci.yml, publish.yml, publish-container.yml, registry-publish.yml (mechanics copied from textgraph, name/image substituted to pcapport)

Plus: parity-out/parity.json + parity.md, BUILD-REPORT.md (this file).
Fixture created: ~/workspace/mcp-rebuild-100/harness/fixtures/mcpcap-tools-original.json with the task-specified _source.

## Tools (9, full documented set)

analyze_dns_packets, analyze_dhcp_packets, analyze_icmp_packets,
analyze_tcp_connections (server_ip?, server_port?, detailed?),
analyze_tcp_anomalies (server_ip?, server_port?),
analyze_tcp_retransmissions (server_ip?, threshold? default 0.02),
analyze_traffic_flow (server_ip required, server_port?),
analyze_sip_packets, analyze_capinfos.
pcap_file is required on every tool. Low-level Server API with explicit
schema literals matching the fixture exactly; zod validates internally.
File access behind injectable deps.readFile (default node:fs/promises).

## Parser

Original minimal libpcap parser: classic PCAP magic 0xa1b2c3d4 /
swapped / nanosecond variants (both endians), per-packet records,
linktype 1 Ethernet (incl. single VLAN tag) and 101/raw IP, IPv4,
UDP, TCP (flags/seq/window/payload len), ICMP; DNS decode (header
counts, first questions with compression pointers, response codes),
DHCP (BOOTP magic cookie, option 53 message type, server id/siaddr,
client MAC), SIP text decode (method/status line, Call-ID, From/To).
Bad magic / truncated file → clean thrown error naming the problem.
Empty capture → zeroed summaries.

## Exact foreground outputs

- tsc: `./node_modules/.bin/tsc` → exit 0 (verified twice, foreground).
- Tests: `npm test` (tsx --test test/*.test.ts) → tests 14, pass 14, fail 0.
  Synthetic pcaps built in-test (Ethernet/IP/UDP/TCP/ICMP frame helpers
  wrapped into pcap records) covering DNS query+response, DHCP
  discover/ack, ICMP echo request/reply, TCP handshake + data + one
  retransmission (data_segments 2, retransmissions 1, rate 0.5,
  exceeds_threshold true) + FIN-closed state, a reset connection, a
  half-open connection, a zero-window ACK, SIP INVITE with call
  extraction, raw-IP linktype, bad-magic and truncated errors, and
  empty-capture zeroed summaries. One initial failure was a bug in
  the test's own short-header fixture (filled with 0xd4 bytes, so bad
  magic correctly fired first); fixed the fixture, then 14/14.
- Parity: `python3 harness/parity.py --original harness/fixtures/mcpcap-tools-original.json --rebuild "stdio:node .../builds/pcapport/dist/cli.js mcp" --out builds/pcapport/parity-out`
  → `verdict=PASS parity_pct=100.0 original_tools=9 rebuild_tools=9 missing=[] extra=[] schema_diffs=[]`, exit 0.
- Honest checks: `node dist/cli.js analyze_capinfos '{"pcap_file":"/nonexistent/nope.pcap"}'`
  → stderr `error: Cannot read PCAP file '/nonexistent/nope.pcap': ENOENT: no such file or directory, open '/nonexistent/nope.pcap'`, exit 1.
  `node dist/cli.js --version` → `0.1.0`, exit 0.

## Lockfile (Route 3)

Only package.json copied into fresh /tmp/pcapport-lock, then
`npm install --package-lock-only --ignore-scripts --offline` → exit 0.
Verified: parses as JSON, name == @reneturcios/pcapport,
packages entry count = 128, lockfileVersion 3. Placed in build dir.
node_modules copied with `cp -a` from builds/clockport/node_modules
(ownership-preservation warnings on stderr are the known fleet norm;
contents complete — tsc/tsx run from it).

## Gaps

- Parser covers Ethernet/raw-IP IPv4 only — no IPv6, no pcapng, no
  TLS/SIP-over-TCP reassembly (SIP over TCP matched per segment).
- Anomaly/state heuristics are simpler than tshark-grade analysis
  (e.g. half-open = SYN with no SYN-ACK in the capture; retransmission
  = exact (directional tuple, seq, payload length) repeat).
- DNS answers are counted from the header, not fully decoded;
  questions after the first are decoded but aggregation is top 20.
- No live capture file tested beyond synthetic fixtures built in the
  test suite; no fragmented-IP L4 reassembly (non-first fragments
  are skipped).
