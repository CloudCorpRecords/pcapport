/**
 * pcapport core: an original minimal libpcap (classic PCAP) parser
 * and analysis engine, written clean-room from the documented tool
 * set of mcpcap/mcpcap.
 *
 * Supported: classic PCAP (big/little endian, micro/nanosecond),
 * linktype 1 (Ethernet, incl. a single 802.1Q VLAN tag) and 101
 * (raw IP). IPv4 only; other ethertypes / IP versions are counted
 * in total_packets but skipped for protocol analysis. TCP, UDP,
 * ICMP are decoded; DNS, DHCP, and SIP payloads are decoded from
 * UDP/TCP payloads. No network, no live capture, no side effects
 * beyond reading the capture file through the injected reader.
 */
import type { CallDeps } from "./types.js";

export const VERSION = "0.1.0";

export const TOOL_NAMES = [
  "analyze_dns_packets",
  "analyze_dhcp_packets",
  "analyze_icmp_packets",
  "analyze_tcp_connections",
  "analyze_tcp_anomalies",
  "analyze_tcp_retransmissions",
  "analyze_traffic_flow",
  "analyze_sip_packets",
  "analyze_capinfos",
] as const;
export type ToolName = (typeof TOOL_NAMES)[number];

// ---------------------------------------------------------------------------
// Parsed model
// ---------------------------------------------------------------------------

export interface TcpInfo {
  seq: number;
  ack: number;
  window: number;
  syn: boolean;
  ackFlag: boolean;
  fin: boolean;
  rst: boolean;
  psh: boolean;
  urg: boolean;
}

export interface ParsedPacket {
  index: number;
  timestamp: number; // epoch seconds (float)
  capLen: number;
  origLen: number;
  srcMac?: string;
  dstMac?: string;
  srcIp?: string;
  dstIp?: string;
  ipProtocol?: number;
  srcPort?: number;
  dstPort?: number;
  tcp?: TcpInfo;
  icmpType?: number;
  icmpCode?: number;
  payload: Buffer;
  payloadLen: number;
}

export interface ParsedCapture {
  linktype: number;
  encapsulation: string;
  packets: ParsedPacket[];
  totalBytes: number; // sum of captured lengths
}

function mac(buf: Buffer, off: number): string {
  return Array.from(buf.subarray(off, off + 6))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(":");
}
function ip4(buf: Buffer, off: number): string {
  return `${buf[off]}.${buf[off + 1]}.${buf[off + 2]}.${buf[off + 3]}`;
}

export function parsePcap(buf: Buffer): ParsedCapture {
  if (buf.length < 4) {
    throw new Error("Truncated PCAP file: too short to contain a PCAP magic number");
  }
  const b0 = buf[0], b1 = buf[1], b2 = buf[2], b3 = buf[3];
  let littleEndian: boolean;
  let nano: boolean;
  if (b0 === 0xa1 && b1 === 0xb2 && b2 === 0xc3 && b3 === 0xd4) { littleEndian = false; nano = false; }
  else if (b0 === 0xd4 && b1 === 0xc3 && b2 === 0xb2 && b3 === 0xa1) { littleEndian = true; nano = false; }
  else if (b0 === 0xa1 && b1 === 0xb2 && b2 === 0x3c && b3 === 0x4d) { littleEndian = false; nano = true; }
  else if (b0 === 0x4d && b1 === 0x3c && b2 === 0xb2 && b3 === 0xa1) { littleEndian = true; nano = true; }
  else {
    const hex = Array.from(buf.subarray(0, 4)).map((x) => x.toString(16).padStart(2, "0")).join(" ");
    throw new Error(`Invalid PCAP magic (${hex}): not a libpcap capture file (bad magic)`);
  }
  if (buf.length < 24) {
    throw new Error("Truncated PCAP file: global header incomplete (need 24 bytes)");
  }
  const u16 = (off: number) => (littleEndian ? buf.readUInt16LE(off) : buf.readUInt16BE(off));
  const u32 = (off: number) => (littleEndian ? buf.readUInt32LE(off) : buf.readUInt32BE(off));
  void u16;
  const linktype = u32(20);
  const encapsulation = linktype === 1 ? "Ethernet" : "raw IP";
  const packets: ParsedPacket[] = [];
  let offset = 24;
  let totalBytes = 0;
  let index = 0;
  while (offset < buf.length) {
    if (offset + 16 > buf.length) {
      throw new Error(`Truncated PCAP file: packet record header truncated at packet ${index}`);
    }
    const tsSec = u32(offset);
    const tsFrac = u32(offset + 4);
    const inclLen = u32(offset + 8);
    const origLen = u32(offset + 12);
    offset += 16;
    if (offset + inclLen > buf.length) {
      throw new Error(`Truncated PCAP file: packet data truncated at packet ${index} (need ${inclLen} bytes, have ${buf.length - offset})`);
    }
    const data = buf.subarray(offset, offset + inclLen);
    offset += inclLen;
    totalBytes += inclLen;
    const frac = nano ? tsFrac / 1e9 : tsFrac / 1e6;
    const pkt: ParsedPacket = {
      index, timestamp: tsSec + frac, capLen: inclLen, origLen,
      payload: Buffer.alloc(0), payloadLen: 0,
    };
    parsePacketData(data, linktype, pkt);
    packets.push(pkt);
    index++;
  }
  return { linktype, encapsulation, packets, totalBytes };
}

function parsePacketData(data: Buffer, linktype: number, pkt: ParsedPacket): void {
  let ipBuf: Buffer | null = null;
  let ipOffset = 0;
  if (linktype === 1) {
    if (data.length < 14) return;
    pkt.dstMac = mac(data, 0);
    pkt.srcMac = mac(data, 6);
    let etherType = data.readUInt16BE(12);
    let off = 14;
    if (etherType === 0x8100) {
      if (data.length < 18) return;
      etherType = data.readUInt16BE(16);
      off = 18;
    }
    if (etherType !== 0x0800) return; // non-IPv4: counted, not parsed
    ipBuf = data; ipOffset = off;
  } else {
    // raw IP (101) and any other linktype: treat payload as raw IP
    if (data.length < 1) return;
    if ((data[0] >> 4) !== 4) return;
    ipBuf = data; ipOffset = 0;
  }
  parseIpv4(ipBuf, ipOffset, pkt);
}

function parseIpv4(buf: Buffer, off: number, pkt: ParsedPacket): void {
  if (buf.length < off + 20) return;
  const version = buf[off] >> 4;
  if (version !== 4) return;
  const ihl = (buf[off] & 0x0f) * 4;
  if (ihl < 20 || buf.length < off + ihl) return;
  const totalLen = buf.readUInt16BE(off + 2);
  const flagsFrag = buf.readUInt16BE(off + 6);
  const fragOffset = flagsFrag & 0x1fff;
  const protocol = buf[off + 9];
  pkt.srcIp = ip4(buf, off + 12);
  pkt.dstIp = ip4(buf, off + 16);
  pkt.ipProtocol = protocol;
  const ipEnd = totalLen >= ihl ? Math.min(buf.length, off + totalLen) : buf.length;
  const payload = buf.subarray(off + ihl, ipEnd);
  if (fragOffset !== 0) return; // non-first fragment: no L4 header
  if (protocol === 17 && payload.length >= 8) {
    pkt.srcPort = payload.readUInt16BE(0);
    pkt.dstPort = payload.readUInt16BE(2);
    const udpLen = payload.readUInt16BE(4);
    const end = udpLen >= 8 ? Math.min(payload.length, udpLen) : payload.length;
    pkt.payload = payload.subarray(8, end);
    pkt.payloadLen = pkt.payload.length;
  } else if (protocol === 6 && payload.length >= 20) {
    pkt.srcPort = payload.readUInt16BE(0);
    pkt.dstPort = payload.readUInt16BE(2);
    const seq = payload.readUInt32BE(4);
    const ack = payload.readUInt32BE(8);
    const dataOff = (payload[12] >> 4) * 4;
    const flags = payload[13];
    const window = payload.readUInt16BE(14);
    pkt.tcp = {
      seq, ack, window,
      syn: !!(flags & 0x02), ackFlag: !!(flags & 0x10),
      fin: !!(flags & 0x01), rst: !!(flags & 0x04),
      psh: !!(flags & 0x08), urg: !!(flags & 0x20),
    };
    if (dataOff >= 20 && payload.length >= dataOff) {
      pkt.payload = payload.subarray(dataOff);
    } else {
      pkt.payload = Buffer.alloc(0);
    }
    pkt.payloadLen = pkt.payload.length;
  } else if (protocol === 1 && payload.length >= 4) {
    pkt.icmpType = payload[0];
    pkt.icmpCode = payload[1];
    pkt.payload = payload.subarray(4);
    pkt.payloadLen = pkt.payload.length;
  }
}

// ---------------------------------------------------------------------------
// Payload decoders
// ---------------------------------------------------------------------------

const DNS_TYPES: Record<number, string> = {
  1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
  16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS",
};
const RCODE_NAMES: Record<number, string> = {
  0: "NoError", 1: "FormErr", 2: "ServFail", 3: "NXDomain", 4: "NotImp", 5: "Refused",
};

interface DnsInfo {
  isResponse: boolean;
  rcode: number;
  questions: { name: string; type: string }[];
  answers: number;
}

function readDnsName(buf: Buffer, start: number): { name: string; next: number } | null {
  const labels: string[] = [];
  let off = start;
  let jumped = false;
  let next = start;
  let guard = 0;
  while (off < buf.length && guard++ < 128) {
    const len = buf[off];
    if (len === 0) { if (!jumped) next = off + 1; break; }
    if ((len & 0xc0) === 0xc0) {
      if (off + 1 >= buf.length) return null;
      const ptr = ((len & 0x3f) << 8) | buf[off + 1];
      if (!jumped) next = off + 2;
      jumped = true;
      off = ptr;
      continue;
    }
    if ((len & 0xc0) !== 0) return null;
    if (off + 1 + len > buf.length) return null;
    labels.push(buf.subarray(off + 1, off + 1 + len).toString("utf8"));
    off += 1 + len;
  }
  return { name: labels.join("."), next };
}

export function decodeDns(payload: Buffer): DnsInfo | null {
  if (payload.length < 12) return null;
  const flags = payload.readUInt16BE(2);
  const qd = payload.readUInt16BE(4);
  const an = payload.readUInt16BE(6);
  const questions: { name: string; type: string }[] = [];
  let off = 12;
  for (let i = 0; i < qd; i++) {
    const r = readDnsName(payload, off);
    if (!r) break;
    off = r.next;
    if (off + 4 > payload.length) break;
    const qtype = payload.readUInt16BE(off);
    questions.push({ name: r.name, type: DNS_TYPES[qtype] ?? `TYPE${qtype}` });
    off += 4;
  }
  return { isResponse: !!(flags & 0x8000), rcode: flags & 0x0f, questions, answers: an };
}

const DHCP_TYPES: Record<number, string> = {
  1: "discover", 2: "offer", 3: "request", 4: "decline",
  5: "ack", 6: "nak", 7: "release", 8: "inform",
};

interface DhcpInfo { messageType: string; serverIp?: string; clientMac: string; }

export function decodeDhcp(payload: Buffer): DhcpInfo | null {
  if (payload.length < 240) return null;
  if (!(payload[236] === 0x63 && payload[237] === 0x82 && payload[238] === 0x53 && payload[239] === 0x63)) return null;
  const clientMac = mac(payload, 28);
  const siaddr = ip4(payload, 20);
  let msgType: number | undefined;
  let serverId: string | undefined;
  let off = 240;
  while (off < payload.length) {
    const code = payload[off];
    if (code === 255) break;
    if (code === 0) { off++; continue; }
    if (off + 1 >= payload.length) break;
    const len = payload[off + 1];
    const val = payload.subarray(off + 2, off + 2 + len);
    if (code === 53 && len >= 1) msgType = val[0];
    if (code === 54 && len === 4) serverId = ip4(val, 0);
    off += 2 + len;
  }
  const serverIp = serverId ?? (siaddr !== "0.0.0.0" ? siaddr : undefined);
  return { messageType: msgType !== undefined ? (DHCP_TYPES[msgType] ?? `type${msgType}`) : "unknown", serverIp, clientMac };
}

const SIP_METHODS = ["INVITE", "ACK", "BYE", "CANCEL", "REGISTER", "OPTIONS", "PRACK", "SUBSCRIBE", "NOTIFY", "PUBLISH", "INFO", "REFER", "MESSAGE", "UPDATE"];

interface SipInfo {
  kind: "request" | "response";
  method?: string;
  statusCode?: number;
  statusClass?: string;
  callId?: string;
  from?: string;
  to?: string;
}

export function decodeSip(payload: Buffer): SipInfo | null {
  if (payload.length < 4) return null;
  const text = payload.toString("utf8");
  const firstLineEnd = text.indexOf("\r\n");
  const firstLine = (firstLineEnd >= 0 ? text.slice(0, firstLineEnd) : text.split("\n")[0] ?? "").trim();
  let info: SipInfo | null = null;
  if (firstLine.startsWith("SIP/2.0")) {
    const m = /^SIP\/2\.0\s+(\d{3})/.exec(firstLine);
    if (!m) return null;
    const code = parseInt(m[1], 10);
    info = { kind: "response", statusCode: code, statusClass: `${Math.floor(code / 100)}xx` };
  } else {
    const method = SIP_METHODS.find((mm) => firstLine.startsWith(`${mm} `));
    if (!method) return null;
    info = { kind: "request", method };
  }
  for (const line of text.split(/\r?\n/).slice(1)) {
    if (!line.trim()) break;
    const colon = line.indexOf(":");
    if (colon < 0) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (name === "call-id" || name === "i") info.callId = value;
    else if (name === "from" || name === "f") info.from = value;
    else if (name === "to" || name === "t") info.to = value;
  }
  return info;
}

function isDnsPacket(p: ParsedPacket): boolean {
  return p.srcPort === 53 || p.dstPort === 53;
}
function dnsPayload(p: ParsedPacket): Buffer {
  // TCP DNS carries a 2-byte length prefix
  if (p.ipProtocol === 6 && p.payload.length > 2) return p.payload.subarray(2);
  return p.payload;
}
function isDhcpPacket(p: ParsedPacket): boolean {
  return p.ipProtocol === 17 && ((p.srcPort === 67 && p.dstPort === 68) || (p.srcPort === 68 && p.dstPort === 67));
}
function isSipCandidate(p: ParsedPacket): boolean {
  if (p.payloadLen === 0) return false;
  if (p.srcPort === 5060 || p.dstPort === 5060) return true;
  const head = p.payload.subarray(0, 16).toString("utf8");
  return head.startsWith("SIP/2.0") || SIP_METHODS.some((m) => head.startsWith(`${m} `));
}

async function load(deps: CallDeps, file: string): Promise<{ capture: ParsedCapture; buf: Buffer }> {
  if (typeof file !== "string" || !file.trim()) throw new Error("pcap_file must be a non-empty string");
  let buf: Buffer;
  try {
    buf = await deps.readFile(file);
  } catch (err) {
    throw new Error(`Cannot read PCAP file '${file}': ${err instanceof Error ? err.message : String(err)}`);
  }
  return { capture: parsePcap(buf), buf };
}

function endpoint(p: ParsedPacket, side: "src" | "dst"): string {
  return side === "src" ? `${p.srcIp}:${p.srcPort}` : `${p.dstIp}:${p.dstPort}`;
}
function connKey(p: ParsedPacket): string {
  const a = endpoint(p, "src");
  const b = endpoint(p, "dst");
  return a < b ? `${a} <-> ${b}` : `${b} <-> ${a}`;
}
function matchServer(p: ParsedPacket, serverIp?: string, serverPort?: number): boolean {
  if (serverIp && p.srcIp !== serverIp && p.dstIp !== serverIp) return false;
  if (serverPort !== undefined && p.srcPort !== serverPort && p.dstPort !== serverPort) return false;
  return true;
}

interface ConnAgg {
  key: string;
  packets: number;
  bytes: number;
  syn: number;
  fin: number;
  rst: number;
  payloadBytes: number;
  synFrom?: string;
  synAckSeen: boolean;
  timestamps: number[];
  endpoints: [string, string];
}

function aggregateTcp(packets: ParsedPacket[]): Map<string, ConnAgg> {
  const map = new Map<string, ConnAgg>();
  for (const p of packets) {
    if (p.ipProtocol !== 6 || !p.tcp || p.srcIp === undefined || p.dstIp === undefined) continue;
    const key = connKey(p);
    let c = map.get(key);
    if (!c) {
      const a = endpoint(p, "src"); const b = endpoint(p, "dst");
      c = { key, packets: 0, bytes: 0, syn: 0, fin: 0, rst: 0, payloadBytes: 0, synAckSeen: false, timestamps: [], endpoints: a < b ? [a, b] : [b, a] };
      map.set(key, c);
    }
    c.packets++;
    c.bytes += p.capLen;
    c.payloadBytes += p.payloadLen;
    c.timestamps.push(p.timestamp);
    if (p.tcp.syn && !p.tcp.ackFlag && !c.synFrom) c.synFrom = endpoint(p, "src");
    if (p.tcp.syn && p.tcp.ackFlag) c.synAckSeen = true;
    if (p.tcp.syn) c.syn++;
    if (p.tcp.fin) c.fin++;
    if (p.tcp.rst) c.rst++;
  }
  return map;
}

function connClientServer(c: ConnAgg): { client: string; server: string } {
  if (c.synFrom) {
    const server = c.endpoints[0] === c.synFrom ? c.endpoints[1] : c.endpoints[0];
    return { client: c.synFrom, server };
  }
  return { client: c.endpoints[0], server: c.endpoints[1] };
}
function connState(c: ConnAgg): string {
  if (c.rst > 0) return "reset";
  if (c.fin > 0) return "closed";
  if (c.syn > 0 && !c.synAckSeen) return "half-open";
  return "established";
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

export async function analyzeDnsPackets(deps: CallDeps, args: { pcap_file: string }) {
  const { capture } = await load(deps, args.pcap_file);
  let dnsPackets = 0, queries = 0, responses = 0;
  const qAgg = new Map<string, { name: string; type: string; count: number }>();
  const responseCodes: Record<string, number> = {};
  for (const p of capture.packets) {
    if (!isDnsPacket(p)) continue;
    const info = decodeDns(dnsPayload(p));
    if (!info) continue;
    dnsPackets++;
    if (info.isResponse) {
      responses++;
      const name = RCODE_NAMES[info.rcode] ?? `RCODE${info.rcode}`;
      responseCodes[name] = (responseCodes[name] ?? 0) + 1;
    } else {
      queries++;
    }
    for (const q of info.questions) {
      const k = `${q.name}|${q.type}`;
      const e = qAgg.get(k) ?? { name: q.name, type: q.type, count: 0 };
      e.count++;
      qAgg.set(k, e);
    }
  }
  const questions = [...qAgg.values()].sort((a, b) => b.count - a.count || a.name.localeCompare(b.name)).slice(0, 20);
  return { file: args.pcap_file, total_packets: capture.packets.length, dns_packets: dnsPackets, queries, responses, questions, response_codes: responseCodes };
}

export async function analyzeDhcpPackets(deps: CallDeps, args: { pcap_file: string }) {
  const { capture } = await load(deps, args.pcap_file);
  let dhcpPackets = 0;
  const byType: Record<string, number> = {};
  const servers = new Set<string>();
  const clients = new Set<string>();
  for (const p of capture.packets) {
    if (!isDhcpPacket(p)) continue;
    const info = decodeDhcp(p.payload);
    if (!info) continue;
    dhcpPackets++;
    byType[info.messageType] = (byType[info.messageType] ?? 0) + 1;
    if (info.serverIp) servers.add(info.serverIp);
    clients.add(info.clientMac);
  }
  return { file: args.pcap_file, total: capture.packets.length, dhcp_packets: dhcpPackets, by_message_type: byType, servers: [...servers].sort(), clients: [...clients].sort() };
}

export async function analyzeIcmpPackets(deps: CallDeps, args: { pcap_file: string }) {
  const { capture } = await load(deps, args.pcap_file);
  let icmpPackets = 0, echoReq = 0, echoRep = 0, unreachable = 0;
  const byType: Record<string, number> = {};
  const talkers = new Map<string, number>();
  for (const p of capture.packets) {
    if (p.ipProtocol !== 1 || p.icmpType === undefined) continue;
    icmpPackets++;
    const k = String(p.icmpType);
    byType[k] = (byType[k] ?? 0) + 1;
    if (p.icmpType === 8) echoReq++;
    if (p.icmpType === 0) echoRep++;
    if (p.icmpType === 3) unreachable++;
    if (p.srcIp) talkers.set(p.srcIp, (talkers.get(p.srcIp) ?? 0) + 1);
  }
  const topTalkers = [...talkers.entries()].map(([ip, packets]) => ({ ip, packets }))
    .sort((a, b) => b.packets - a.packets || a.ip.localeCompare(b.ip)).slice(0, 10);
  return { file: args.pcap_file, total: capture.packets.length, icmp_packets: icmpPackets, by_type: byType, echo_requests: echoReq, echo_replies: echoRep, unreachable, top_talkers: topTalkers };
}

export async function analyzeTcpConnections(deps: CallDeps, args: { pcap_file: string; server_ip?: string; server_port?: number; detailed?: boolean }) {
  const { capture } = await load(deps, args.pcap_file);
  const filtered = capture.packets.filter((p) => matchServer(p, args.server_ip, args.server_port));
  const conns = aggregateTcp(filtered);
  const connections = [...conns.values()].sort((a, b) => a.key.localeCompare(b.key)).map((c) => {
    const { client, server } = connClientServer(c);
    const base: Record<string, unknown> = {
      client, server, packets: c.packets, bytes: c.bytes,
      syn_count: c.syn, fin_count: c.fin, rst_count: c.rst,
      state: connState(c),
    };
    if (args.detailed) {
      base.summary = `${client} -> ${server}: ${c.packets} packets, ${c.bytes} bytes, state ${connState(c)}, SYN ${c.syn}, FIN ${c.fin}, RST ${c.rst}`;
      base.packet_timestamps = {
        count: c.timestamps.length,
        first: c.timestamps.length ? new Date(Math.min(...c.timestamps) * 1000).toISOString() : null,
        last: c.timestamps.length ? new Date(Math.max(...c.timestamps) * 1000).toISOString() : null,
      };
    }
    return base;
  });
  return { file: args.pcap_file, total_packets: capture.packets.length, connection_count: connections.length, connections };
}

export async function analyzeTcpAnomalies(deps: CallDeps, args: { pcap_file: string; server_ip?: string; server_port?: number }) {
  const { capture } = await load(deps, args.pcap_file);
  const filtered = capture.packets.filter((p) => matchServer(p, args.server_ip, args.server_port));
  const conns = aggregateTcp(filtered);
  let rstConns = 0, halfOpen = 0, withoutData = 0, zeroWindow = 0;
  for (const c of conns.values()) {
    if (c.rst > 0) rstConns++;
    if (c.syn > 0 && !c.synAckSeen) halfOpen++;
    if (c.payloadBytes === 0) withoutData++;
  }
  for (const p of filtered) {
    if (p.ipProtocol === 6 && p.tcp && p.tcp.window === 0 && p.tcp.ackFlag) zeroWindow++;
  }
  const tcpPackets = filtered.filter((p) => p.ipProtocol === 6).length;
  return { file: args.pcap_file, total_packets: capture.packets.length, tcp_packets: tcpPackets, rst_connections: rstConns, half_open: halfOpen, connections_without_data: withoutData, zero_window: zeroWindow, zero_window_advertised: zeroWindow };
}

export async function analyzeTcpRetransmissions(deps: CallDeps, args: { pcap_file: string; server_ip?: string; threshold?: number }) {
  const threshold = args.threshold ?? 0.02;
  const { capture } = await load(deps, args.pcap_file);
  const filtered = capture.packets.filter((p) => p.ipProtocol === 6 && p.tcp && matchServer(p, args.server_ip, undefined));
  const seen = new Set<string>();
  let dataSegments = 0, retrans = 0;
  const perConn = new Map<string, number>();
  for (const p of filtered) {
    if (!p.tcp || p.payloadLen === 0) continue;
    dataSegments++;
    const dirKey = `${p.srcIp}:${p.srcPort}->${p.dstIp}:${p.dstPort}|${p.tcp.seq}|${p.payloadLen}`;
    if (seen.has(dirKey)) {
      retrans++;
      const ck = connKey(p);
      perConn.set(ck, (perConn.get(ck) ?? 0) + 1);
    } else {
      seen.add(dirKey);
    }
  }
  const rate = dataSegments ? retrans / dataSegments : 0;
  const top = [...perConn.entries()].map(([connection, retransmissions]) => ({ connection, retransmissions }))
    .sort((a, b) => b.retransmissions - a.retransmissions).slice(0, 10);
  return { file: args.pcap_file, total_packets: capture.packets.length, data_segments: dataSegments, retransmissions: retrans, rate, threshold, exceeds_threshold: rate > threshold, top_offending_connections: top };
}

export async function analyzeTrafficFlow(deps: CallDeps, args: { pcap_file: string; server_ip: string; server_port?: number }) {
  if (typeof args.server_ip !== "string" || !args.server_ip.trim()) throw new Error("server_ip must be a non-empty string");
  const { capture } = await load(deps, args.pcap_file);
  let toPackets = 0, toBytes = 0, fromPackets = 0, fromBytes = 0;
  const clientAgg = new Map<string, { ip: string; packets: number; bytes: number }>();
  for (const p of capture.packets) {
    if (p.dstIp === args.server_ip && (args.server_port === undefined || p.dstPort === args.server_port)) {
      toPackets++; toBytes += p.capLen;
      if (p.srcIp) {
        const e = clientAgg.get(p.srcIp) ?? { ip: p.srcIp, packets: 0, bytes: 0 };
        e.packets++; e.bytes += p.capLen; clientAgg.set(p.srcIp, e);
      }
    }
    if (p.srcIp === args.server_ip && (args.server_port === undefined || p.srcPort === args.server_port)) {
      fromPackets++; fromBytes += p.capLen;
      if (p.dstIp) {
        const e = clientAgg.get(p.dstIp) ?? { ip: p.dstIp, packets: 0, bytes: 0 };
        e.packets++; e.bytes += p.capLen; clientAgg.set(p.dstIp, e);
      }
    }
  }
  const topClients = [...clientAgg.values()].sort((a, b) => b.bytes - a.bytes || a.ip.localeCompare(b.ip)).slice(0, 10);
  return {
    file: args.pcap_file, total_packets: capture.packets.length,
    server_ip: args.server_ip, server_port: args.server_port ?? null,
    to_server: { packets: toPackets, bytes: toBytes },
    from_server: { packets: fromPackets, bytes: fromBytes },
    unique_clients: clientAgg.size,
    unique_client_ips: [...clientAgg.keys()].sort(),
    top_clients: topClients,
  };
}

export async function analyzeSipPackets(deps: CallDeps, args: { pcap_file: string }) {
  const { capture } = await load(deps, args.pcap_file);
  let sipPackets = 0;
  const requests: Record<string, number> = {};
  const responses: Record<string, number> = {};
  const callMap = new Map<string, { call_id: string; from: string; to: string }>();
  for (const p of capture.packets) {
    if (!isSipCandidate(p)) continue;
    const info = decodeSip(p.payload);
    if (!info) continue;
    sipPackets++;
    if (info.kind === "request" && info.method) requests[info.method] = (requests[info.method] ?? 0) + 1;
    if (info.kind === "response" && info.statusClass) responses[info.statusClass] = (responses[info.statusClass] ?? 0) + 1;
    if (info.callId && !callMap.has(info.callId)) {
      callMap.set(info.callId, { call_id: info.callId, from: info.from ?? "", to: info.to ?? "" });
    }
  }
  return { file: args.pcap_file, total_packets: capture.packets.length, sip_packets: sipPackets, requests, responses, calls: [...callMap.values()] };
}

export async function analyzeCapinfos(deps: CallDeps, args: { pcap_file: string }) {
  const { capture, buf } = await load(deps, args.pcap_file);
  const count = capture.packets.length;
  const first = count ? capture.packets[0].timestamp : null;
  const last = count ? capture.packets[count - 1].timestamp : null;
  const duration = first !== null && last !== null ? last - first : 0;
  return {
    file: args.pcap_file,
    packet_count: count,
    duration_s: duration,
    data_bytes: capture.totalBytes,
    avg_packet_size: count ? capture.totalBytes / count : 0,
    first_packet: first !== null ? new Date(first * 1000).toISOString() : null,
    last_packet: last !== null ? new Date(last * 1000).toISOString() : null,
    encapsulation: capture.encapsulation,
    capture_length_bytes: buf.length,
  };
}

function reqString(args: Record<string, unknown>, field: string): string {
  if (typeof args[field] !== "string" || !(args[field] as string).trim()) throw new Error(`${field} must be a non-empty string`);
  return args[field] as string;
}
function optString(args: Record<string, unknown>, field: string): string | undefined {
  if (args[field] === undefined) return undefined;
  return reqString(args, field);
}
function optPort(args: Record<string, unknown>): number | undefined {
  if (args.server_port === undefined) return undefined;
  if (typeof args.server_port !== "number" || !Number.isInteger(args.server_port) || args.server_port < 0 || args.server_port > 65535) {
    throw new Error("server_port must be an integer between 0 and 65535");
  }
  return args.server_port;
}

export async function callPcapportTool(deps: CallDeps, tool: string, args: Record<string, unknown>): Promise<unknown> {
  const a = args ?? {};
  switch (tool) {
    case "analyze_dns_packets": return analyzeDnsPackets(deps, { pcap_file: reqString(a, "pcap_file") });
    case "analyze_dhcp_packets": return analyzeDhcpPackets(deps, { pcap_file: reqString(a, "pcap_file") });
    case "analyze_icmp_packets": return analyzeIcmpPackets(deps, { pcap_file: reqString(a, "pcap_file") });
    case "analyze_tcp_connections": {
      if (a.detailed !== undefined && typeof a.detailed !== "boolean") throw new Error("detailed must be a boolean");
      return analyzeTcpConnections(deps, { pcap_file: reqString(a, "pcap_file"), server_ip: optString(a, "server_ip"), server_port: optPort(a), detailed: a.detailed as boolean | undefined });
    }
    case "analyze_tcp_anomalies": return analyzeTcpAnomalies(deps, { pcap_file: reqString(a, "pcap_file"), server_ip: optString(a, "server_ip"), server_port: optPort(a) });
    case "analyze_tcp_retransmissions": {
      if (a.threshold !== undefined && (typeof a.threshold !== "number" || Number.isNaN(a.threshold) || a.threshold < 0)) throw new Error("threshold must be a non-negative number");
      return analyzeTcpRetransmissions(deps, { pcap_file: reqString(a, "pcap_file"), server_ip: optString(a, "server_ip"), threshold: a.threshold as number | undefined });
    }
    case "analyze_traffic_flow": return analyzeTrafficFlow(deps, { pcap_file: reqString(a, "pcap_file"), server_ip: reqString(a, "server_ip"), server_port: optPort(a) });
    case "analyze_sip_packets": return analyzeSipPackets(deps, { pcap_file: reqString(a, "pcap_file") });
    case "analyze_capinfos": return analyzeCapinfos(deps, { pcap_file: reqString(a, "pcap_file") });
    default: throw new Error(`Unknown tool: ${tool}`);
  }
}
