/**
 * pcapport MCP server. Tools: analyze_dns_packets,
 * analyze_dhcp_packets, analyze_icmp_packets,
 * analyze_tcp_connections, analyze_tcp_anomalies,
 * analyze_tcp_retransmissions, analyze_traffic_flow,
 * analyze_sip_packets, analyze_capinfos.
 *
 * Low-level Server API with explicit schema literals matching the
 * documented fixture exactly; zod validates internally.
 * Local Tier A tool: no network, no API key. File reads go through
 * node:fs/promises behind the injectable reader in the core.
 */
import { readFile } from "node:fs/promises";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { callPcapportTool, VERSION } from "./pcapport.js";

const PcapOnly = z.object({ pcap_file: z.string() });
const TcpConnections = z.object({
  pcap_file: z.string(),
  server_ip: z.string().optional(),
  server_port: z.number().int().optional(),
  detailed: z.boolean().optional(),
});
const TcpAnomalies = z.object({
  pcap_file: z.string(),
  server_ip: z.string().optional(),
  server_port: z.number().int().optional(),
});
const TcpRetrans = z.object({
  pcap_file: z.string(),
  server_ip: z.string().optional(),
  threshold: z.number().optional(),
});
const TrafficFlow = z.object({
  pcap_file: z.string(),
  server_ip: z.string(),
  server_port: z.number().int().optional(),
});

const TOOLS = [
  {
    name: "analyze_dns_packets",
    description: "Analyze DNS packets in a PCAP file: query/response counts, top questions, and response codes.",
    inputSchema: {
      type: "object" as const,
      properties: { pcap_file: { type: "string", description: "Path to the packet capture file to read." } },
      required: ["pcap_file"],
    },
  },
  {
    name: "analyze_dhcp_packets",
    description: "Analyze DHCP packets in a PCAP file: message types, servers, and clients.",
    inputSchema: {
      type: "object" as const,
      properties: { pcap_file: { type: "string", description: "Path to the packet capture file to read." } },
      required: ["pcap_file"],
    },
  },
  {
    name: "analyze_icmp_packets",
    description: "Analyze ICMP packets in a PCAP file: types, echo traffic, unreachable, and top talkers.",
    inputSchema: {
      type: "object" as const,
      properties: { pcap_file: { type: "string", description: "Path to the packet capture file to read." } },
      required: ["pcap_file"],
    },
  },
  {
    name: "analyze_tcp_connections",
    description: "List TCP connections in a PCAP file with packet, byte, flag counts and state estimates.",
    inputSchema: {
      type: "object" as const,
      properties: {
        pcap_file: { type: "string", description: "Path to the packet capture file to read." },
        server_ip: { type: "string", description: "Server IP address to filter connections by." },
        server_port: { type: "integer", description: "Server port to filter connections by, between 0 and 65535." },
        detailed: { type: "boolean", description: "Whether to include a per-connection summary and packet timestamps." },
      },
      required: ["pcap_file"],
    },
  },
  {
    name: "analyze_tcp_anomalies",
    description: "Detect TCP anomalies in a PCAP file: resets, half-open connections, no-data connections, zero window.",
    inputSchema: {
      type: "object" as const,
      properties: {
        pcap_file: { type: "string", description: "Path to the packet capture file to read." },
        server_ip: { type: "string", description: "Server IP address to filter connections by." },
        server_port: { type: "integer", description: "Server port to filter connections by, between 0 and 65535." },
      },
      required: ["pcap_file"],
    },
  },
  {
    name: "analyze_tcp_retransmissions",
    description: "Detect TCP retransmissions in a PCAP file and compute the retransmission rate.",
    inputSchema: {
      type: "object" as const,
      properties: {
        pcap_file: { type: "string", description: "Path to the packet capture file to read." },
        server_ip: { type: "string", description: "Server IP address to filter connections by." },
        threshold: { type: "number", description: "Retransmission rate threshold to compare against, defaults to 0.02." },
      },
      required: ["pcap_file"],
    },
  },
  {
    name: "analyze_traffic_flow",
    description: "Analyze traffic flow to and from a server in a PCAP file.",
    inputSchema: {
      type: "object" as const,
      properties: {
        pcap_file: { type: "string", description: "Path to the packet capture file to read." },
        server_ip: { type: "string", description: "IP address of the server to analyze traffic flow for." },
        server_port: { type: "integer", description: "Server port to filter traffic by, between 0 and 65535." },
      },
      required: ["pcap_file", "server_ip"],
    },
  },
  {
    name: "analyze_sip_packets",
    description: "Analyze SIP packets in a PCAP file: methods, response classes, and calls.",
    inputSchema: {
      type: "object" as const,
      properties: { pcap_file: { type: "string", description: "Path to the packet capture file to read." } },
      required: ["pcap_file"],
    },
  },
  {
    name: "analyze_capinfos",
    description: "Summarize a PCAP file: packet count, duration, size, and encapsulation.",
    inputSchema: {
      type: "object" as const,
      properties: { pcap_file: { type: "string", description: "Path to the packet capture file to read." } },
      required: ["pcap_file"],
    },
  },
];

const SCHEMAS: Record<string, z.ZodTypeAny> = {
  analyze_dns_packets: PcapOnly,
  analyze_dhcp_packets: PcapOnly,
  analyze_icmp_packets: PcapOnly,
  analyze_tcp_connections: TcpConnections,
  analyze_tcp_anomalies: TcpAnomalies,
  analyze_tcp_retransmissions: TcpRetrans,
  analyze_traffic_flow: TrafficFlow,
  analyze_sip_packets: PcapOnly,
  analyze_capinfos: PcapOnly,
};

function textResult(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] };
}
function errorResult(err: unknown) {
  return {
    content: [{ type: "text" as const, text: err instanceof Error ? err.message : String(err) }],
    isError: true,
  };
}

const server = new Server(
  { name: "pcapport", version: VERSION },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const schema = SCHEMAS[name];
  if (!schema) throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
  try {
    const parsed = schema.parse(args ?? {}) as Record<string, unknown>;
    return textResult(await callPcapportTool({ readFile: (p) => readFile(p) }, name, parsed));
  } catch (err) {
    return errorResult(err);
  }
});

async function main(): Promise<void> {
  await server.connect(new StdioServerTransport());
}

void main();
