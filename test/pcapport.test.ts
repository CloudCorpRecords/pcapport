import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  analyzeCapinfos,
  analyzeDhcpPackets,
  analyzeDnsPackets,
  analyzeIcmpPackets,
  analyzeSipPackets,
  analyzeTcpAnomalies,
  analyzeTcpConnections,
  analyzeTcpRetransmissions,
  analyzeTrafficFlow,
  callPcapportTool,
  parsePcap,
  VERSION,
} from "../src/pcapport.js";
import type { CallDeps } from "../src/types.js";

// ---- synthetic frame builders ---------------------------------------------

function macBytes(mac: string): Buffer {
  return Buffer.from(mac.split(":").map((h) => parseInt(h, 16)));
}
function ipBytes(ip: string): Buffer {
  return Buffer.from(ip.split(".").map((n) => parseInt(n, 10)));
}
function checksum(buf: Buffer): number {
  let sum = 0;
  for (let i = 0; i + 1 < buf.length; i += 2) sum += buf.readUInt16BE(i);
  if (buf.length % 2) sum += buf[buf.length - 1] << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
}
function ethernet(src: string, dst: string, payload: Buffer, etherType = 0x0800): Buffer {
  const h = Buffer.alloc(14);
  macBytes(dst).copy(h, 0);
  macBytes(src).copy(h, 6);
  h.writeUInt16BE(etherType, 12);
  return Buffer.concat([h, payload]);
}
function ipv4(src: string, dst: string, protocol: number, payload: Buffer): Buffer {
  const h = Buffer.alloc(20);
  h[0] = 0x45;
  h.writeUInt16BE(20 + payload.length, 2);
  h.writeUInt16BE(1, 4);
  h[8] = 64;
  h[9] = protocol;
  ipBytes(src).copy(h, 12);
  ipBytes(dst).copy(h, 16);
  h.writeUInt16BE(checksum(h), 10);
  return Buffer.concat([h, payload]);
}
function udp(sport: number, dport: number, payload: Buffer): Buffer {
  const h = Buffer.alloc(8);
  h.writeUInt16BE(sport, 0);
  h.writeUInt16BE(dport, 2);
  h.writeUInt16BE(8 + payload.length, 4);
  return Buffer.concat([h, payload]);
}
const F = { FIN: 0x01, SYN: 0x02, RST: 0x04, PSH: 0x08, ACK: 0x10 };
function tcp(sport: number, dport: number, seq: number, ack: number, flags: number, window: number, payload: Buffer): Buffer {
  const h = Buffer.alloc(20);
  h.writeUInt16BE(sport, 0);
  h.writeUInt16BE(dport, 2);
  h.writeUInt32BE(seq >>> 0, 4);
  h.writeUInt32BE(ack >>> 0, 8);
  h[12] = 0x50;
  h[13] = flags;
  h.writeUInt16BE(window, 14);
  return Buffer.concat([h, payload]);
}
function icmp(type: number, code: number, rest: Buffer): Buffer {
  const h = Buffer.alloc(4);
  h[0] = type;
  h[1] = code;
  return Buffer.concat([h, rest]);
}
function dnsName(name: string): Buffer {
  const parts: Buffer[] = [];
  for (const label of name.split(".")) {
    parts.push(Buffer.from([label.length]), Buffer.from(label, "utf8"));
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}
function dnsPacket(isResponse: boolean, answerCount: number): Buffer {
  const h = Buffer.alloc(12);
  h.writeUInt16BE(0x1234, 0);
  h.writeUInt16BE(isResponse ? 0x8180 : 0x0100, 2);
  h.writeUInt16BE(1, 4);
  h.writeUInt16BE(answerCount, 6);
  const q = Buffer.concat([dnsName("example.com"), Buffer.from([0, 1, 0, 1])]);
  if (!isResponse) return Buffer.concat([h, q]);
  const ans = Buffer.alloc(16);
  ans.writeUInt16BE(0xc00c, 0);
  ans.writeUInt16BE(1, 2);
  ans.writeUInt16BE(1, 4);
  ans.writeUInt32BE(300, 6);
  ans.writeUInt16BE(4, 10);
  ipBytes("93.184.216.34").copy(ans, 12);
  return Buffer.concat([h, q, ans]);
}
function dhcpPacket(msgType: number, clientMac: string, serverIp: string, op: number): Buffer {
  const b = Buffer.alloc(240 + 4);
  b[0] = op;
  b[1] = 1;
  b[2] = 6;
  b.writeUInt32BE(0xabcd, 4);
  ipBytes(serverIp).copy(b, 20);
  macBytes(clientMac).copy(b, 28);
  b[236] = 0x63; b[237] = 0x82; b[238] = 0x53; b[239] = 0x63;
  b[240] = 53; b[241] = 1; b[242] = msgType; b[243] = 255;
  return b;
}
function sipInvite(): Buffer {
  const text =
    "INVITE sip:bob@10.0.0.5 SIP/2.0\r\n" +
    "Call-ID: call-123@10.0.0.2\r\n" +
    "From: <sip:alice@10.0.0.2>;tag=1\r\n" +
    "To: <sip:bob@10.0.0.5>\r\n" +
    "CSeq: 1 INVITE\r\n\r\n";
  return Buffer.from(text, "utf8");
}

const MAC_A = "aa:bb:cc:dd:ee:01";
const MAC_B = "aa:bb:cc:dd:ee:02";
const BCAST = "ff:ff:ff:ff:ff:ff";

function ethIp(srcMac: string, dstMac: string, src: string, dst: string, proto: number, l4: Buffer): Buffer {
  return ethernet(srcMac, dstMac, ipv4(src, dst, proto, l4));
}

interface Frame { ts: number; data: Buffer }
function pcap(frames: Frame[], linktype = 1): Buffer {
  const gh = Buffer.alloc(24);
  gh[0] = 0xd4; gh[1] = 0xc3; gh[2] = 0xb2; gh[3] = 0xa1; // LE micro
  gh.writeUInt16LE(2, 4);
  gh.writeUInt16LE(0, 6);
  gh.writeUInt32LE(65535, 16);
  gh.writeUInt32LE(linktype, 20);
  const parts: Buffer[] = [gh];
  for (const f of frames) {
    const ph = Buffer.alloc(16);
    ph.writeUInt32LE(Math.floor(f.ts), 0);
    ph.writeUInt32LE(Math.round((f.ts - Math.floor(f.ts)) * 1e6), 4);
    ph.writeUInt32LE(f.data.length, 8);
    ph.writeUInt32LE(f.data.length, 12);
    parts.push(ph, f.data);
  }
  return Buffer.concat(parts);
}

function depsFor(buf: Buffer): CallDeps {
  return { readFile: async () => buf };
}

// ---- frame sets ------------------------------------------------------------

function dnsFrames(): Frame[] {
  return [
    { ts: 1700000000, data: ethIp(MAC_A, MAC_B, "10.0.0.2", "8.8.8.8", 17, udp(53000, 53, dnsPacket(false, 0))) },
    { ts: 1700000000.05, data: ethIp(MAC_B, MAC_A, "8.8.8.8", "10.0.0.2", 17, udp(53, 53000, dnsPacket(true, 1))) },
  ];
}
function dhcpFrames(): Frame[] {
  return [
    { ts: 1700000001, data: ethIp(MAC_A, BCAST, "0.0.0.0", "255.255.255.255", 17, udp(68, 67, dhcpPacket(1, MAC_A, "0.0.0.0", 1))) },
    { ts: 1700000001.1, data: ethIp(MAC_B, MAC_A, "10.0.0.1", "10.0.0.2", 17, udp(67, 68, dhcpPacket(5, MAC_A, "10.0.0.1", 2))) },
  ];
}
function icmpFrames(): Frame[] {
  return [
    { ts: 1700000002, data: ethIp(MAC_A, MAC_B, "10.0.0.2", "10.0.0.1", 1, icmp(8, 0, Buffer.from([0, 1, 0, 1]))) },
    { ts: 1700000002.1, data: ethIp(MAC_B, MAC_A, "10.0.0.1", "10.0.0.2", 1, icmp(0, 0, Buffer.from([0, 1, 0, 1]))) },
  ];
}
function tcpDataFrames(): Frame[] {
  const c = "10.0.0.2", s = "10.0.0.5";
  return [
    { ts: 1700000003, data: ethIp(MAC_A, MAC_B, c, s, 6, tcp(40000, 80, 100, 0, F.SYN, 65535, Buffer.alloc(0))) },
    { ts: 1700000003.01, data: ethIp(MAC_B, MAC_A, s, c, 6, tcp(80, 40000, 500, 101, F.SYN | F.ACK, 65535, Buffer.alloc(0))) },
    { ts: 1700000003.02, data: ethIp(MAC_A, MAC_B, c, s, 6, tcp(40000, 80, 101, 501, F.ACK, 65535, Buffer.alloc(0))) },
    { ts: 1700000003.03, data: ethIp(MAC_A, MAC_B, c, s, 6, tcp(40000, 80, 101, 501, F.PSH | F.ACK, 65535, Buffer.from("hello"))) },
    { ts: 1700000003.04, data: ethIp(MAC_A, MAC_B, c, s, 6, tcp(40000, 80, 101, 501, F.PSH | F.ACK, 65535, Buffer.from("hello"))) },
    { ts: 1700000003.05, data: ethIp(MAC_A, MAC_B, c, s, 6, tcp(40000, 80, 106, 501, F.FIN | F.ACK, 65535, Buffer.alloc(0))) },
  ];
}
function sipFrames(): Frame[] {
  return [
    { ts: 1700000004, data: ethIp(MAC_A, MAC_B, "10.0.0.2", "10.0.0.5", 17, udp(5060, 5060, sipInvite())) },
  ];
}
function allFrames(): Frame[] {
  return [...dnsFrames(), ...dhcpFrames(), ...icmpFrames(), ...tcpDataFrames(), ...sipFrames()];
}

// ---- tests -----------------------------------------------------------------

describe("version and parser", () => {
  it("exposes version 0.1.0 and parses an Ethernet capture", () => {
    assert.equal(VERSION, "0.1.0");
    const cap = parsePcap(pcap(allFrames()));
    assert.equal(cap.packets.length, 13);
    assert.equal(cap.encapsulation, "Ethernet");
    assert.equal(cap.packets[0].srcIp, "10.0.0.2");
    assert.equal(cap.packets[0].dstPort, 53);
  });
  it("parses raw IP (linktype 101) captures", async () => {
    const raw = ipv4("10.0.0.2", "10.0.0.1", 1, icmp(8, 0, Buffer.from([0, 1, 0, 1])));
    const buf = pcap([{ ts: 1700000010, data: raw }], 101);
    const cap = parsePcap(buf);
    assert.equal(cap.encapsulation, "raw IP");
    assert.equal(cap.packets[0].icmpType, 8);
    const info = await analyzeCapinfos(depsFor(buf), { pcap_file: "raw.pcap" });
    assert.equal(info.encapsulation, "raw IP");
    assert.equal(info.packet_count, 1);
  });
  it("rejects bad magic and truncated files with named errors", async () => {
    assert.throws(() => parsePcap(Buffer.from("NOPE not a pcap file at all....")), /bad magic/);
    const good = pcap(dnsFrames());
    assert.throws(() => parsePcap(good.subarray(0, good.length - 3)), /Truncated/);
    const shortHeader = Buffer.alloc(10);
    shortHeader[0] = 0xd4; shortHeader[1] = 0xc3; shortHeader[2] = 0xb2; shortHeader[3] = 0xa1;
    assert.throws(() => parsePcap(shortHeader), /Truncated/);
    await assert.rejects(
      callPcapportTool({ readFile: async () => { throw new Error("ENOENT"); } }, "analyze_capinfos", { pcap_file: "x.pcap" }),
      /Cannot read PCAP file/,
    );
  });
  it("returns zeroed summaries for an empty capture", async () => {
    const empty = pcap([]);
    const info = await analyzeCapinfos(depsFor(empty), { pcap_file: "empty.pcap" });
    assert.equal(info.packet_count, 0);
    assert.equal(info.duration_s, 0);
    assert.equal(info.first_packet, null);
    const dns = await analyzeDnsPackets(depsFor(empty), { pcap_file: "empty.pcap" });
    assert.equal(dns.dns_packets, 0);
    assert.equal(dns.queries, 0);
    assert.deepEqual(dns.questions, []);
  });
});

describe("analyze_capinfos / dns / dhcp / icmp", () => {
  it("summarises the combined capture", async () => {
    const buf = pcap(allFrames());
    const info = await analyzeCapinfos(depsFor(buf), { pcap_file: "all.pcap" });
    assert.equal(info.packet_count, 13);
    assert.equal(info.capture_length_bytes, buf.length);
    assert.equal(info.data_bytes > 0, true);
    assert.ok(Math.abs(info.avg_packet_size - info.data_bytes / 13) < 1e-9);
    assert.equal(info.first_packet, new Date(1700000000 * 1000).toISOString());
  });
  it("counts DNS queries, responses, questions, and codes", async () => {
    const dns = await analyzeDnsPackets(depsFor(pcap(allFrames())), { pcap_file: "all.pcap" });
    assert.equal(dns.total_packets, 13);
    assert.equal(dns.dns_packets, 2);
    assert.equal(dns.queries, 1);
    assert.equal(dns.responses, 1);
    assert.deepEqual(dns.questions, [{ name: "example.com", type: "A", count: 2 }]);
    assert.deepEqual(dns.response_codes, { NoError: 1 });
  });
  it("counts DHCP message types, servers, and clients", async () => {
    const dhcp = await analyzeDhcpPackets(depsFor(pcap(allFrames())), { pcap_file: "all.pcap" });
    assert.equal(dhcp.total, 13);
    assert.equal(dhcp.dhcp_packets, 2);
    assert.deepEqual(dhcp.by_message_type, { discover: 1, ack: 1 });
    assert.deepEqual(dhcp.servers, ["10.0.0.1"]);
    assert.deepEqual(dhcp.clients, [MAC_A]);
  });
  it("counts ICMP echo traffic and talkers", async () => {
    const icmpR = await analyzeIcmpPackets(depsFor(pcap(allFrames())), { pcap_file: "all.pcap" });
    assert.equal(icmpR.icmp_packets, 2);
    assert.equal(icmpR.echo_requests, 1);
    assert.equal(icmpR.echo_replies, 1);
    assert.equal(icmpR.unreachable, 0);
    assert.deepEqual(icmpR.by_type, { "0": 1, "8": 1 });
    assert.equal(icmpR.top_talkers.length, 2);
  });
});

describe("tcp tools", () => {
  it("lists the connection with flag counts and closed state", async () => {
    const res = await analyzeTcpConnections(depsFor(pcap(tcpDataFrames())), { pcap_file: "t.pcap", detailed: true });
    assert.equal(res.connection_count, 1);
    const conn = res.connections[0] as Record<string, unknown>;
    assert.equal(conn.client, "10.0.0.2:40000");
    assert.equal(conn.server, "10.0.0.5:80");
    assert.equal(conn.packets, 6);
    assert.equal(conn.syn_count, 2);
    assert.equal(conn.fin_count, 1);
    assert.equal(conn.rst_count, 0);
    assert.equal(conn.state, "closed");
    const ts = conn.packet_timestamps as { count: number };
    assert.equal(ts.count, 6);
  });
  it("detects the retransmission and its rate", async () => {
    const res = await analyzeTcpRetransmissions(depsFor(pcap(tcpDataFrames())), { pcap_file: "t.pcap" });
    assert.equal(res.data_segments, 2);
    assert.equal(res.retransmissions, 1);
    assert.equal(res.rate, 0.5);
    assert.equal(res.exceeds_threshold, true);
    assert.equal(res.top_offending_connections.length, 1);
    assert.equal(res.top_offending_connections[0].retransmissions, 1);
  });
  it("detects reset, half-open, no-data, and zero-window anomalies", async () => {
    const c = "10.0.0.2", s = "10.0.0.5";
    const frames: Frame[] = [
      { ts: 1700000020, data: ethIp(MAC_A, MAC_B, c, s, 6, tcp(41000, 80, 1, 0, F.SYN, 1000, Buffer.alloc(0))) },
      { ts: 1700000020.01, data: ethIp(MAC_B, MAC_A, s, c, 6, tcp(80, 41000, 9, 2, F.SYN | F.ACK, 1000, Buffer.alloc(0))) },
      { ts: 1700000020.02, data: ethIp(MAC_A, MAC_B, c, s, 6, tcp(41000, 80, 2, 10, F.ACK, 0, Buffer.alloc(0))) },
      { ts: 1700000020.03, data: ethIp(MAC_B, MAC_A, s, c, 6, tcp(80, 41000, 10, 2, F.RST | F.ACK, 1000, Buffer.alloc(0))) },
      { ts: 1700000020.04, data: ethIp(MAC_A, MAC_B, "10.0.0.9", s, 6, tcp(42000, 80, 1, 0, F.SYN, 1000, Buffer.alloc(0))) },
    ];
    const res = await analyzeTcpAnomalies(depsFor(pcap(frames)), { pcap_file: "a.pcap" });
    assert.equal(res.rst_connections, 1);
    assert.equal(res.half_open, 1);
    assert.equal(res.connections_without_data, 2);
    assert.equal(res.zero_window_advertised, 1);
  });
  it("measures traffic flow to and from the server", async () => {
    const res = await analyzeTrafficFlow(depsFor(pcap(tcpDataFrames())), { pcap_file: "t.pcap", server_ip: "10.0.0.5", server_port: 80 });
    assert.equal(res.to_server.packets, 5);
    assert.equal(res.from_server.packets, 1);
    assert.equal(res.unique_clients, 1);
    assert.equal(res.top_clients[0].ip, "10.0.0.2");
    assert.ok(res.to_server.bytes > res.from_server.bytes);
  });
});

describe("sip and dispatch", () => {
  it("counts the SIP INVITE and its call", async () => {
    const sip = await analyzeSipPackets(depsFor(pcap(allFrames())), { pcap_file: "all.pcap" });
    assert.equal(sip.sip_packets, 1);
    assert.deepEqual(sip.requests, { INVITE: 1 });
    assert.deepEqual(sip.responses, {});
    assert.equal(sip.calls.length, 1);
    assert.equal(sip.calls[0].call_id, "call-123@10.0.0.2");
    assert.ok(sip.calls[0].from.includes("alice"));
    assert.ok(sip.calls[0].to.includes("bob"));
  });
  it("dispatches through callPcapportTool and rejects unknown tools", async () => {
    const deps = depsFor(pcap(dnsFrames()));
    const res = (await callPcapportTool(deps, "analyze_dns_packets", { pcap_file: "d.pcap" })) as { dns_packets: number };
    assert.equal(res.dns_packets, 2);
    await assert.rejects(callPcapportTool(deps, "nope", { pcap_file: "d.pcap" }), /Unknown tool/);
    await assert.rejects(callPcapportTool(deps, "analyze_traffic_flow", { pcap_file: "d.pcap" }), /server_ip/);
  });
});
