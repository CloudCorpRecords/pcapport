/**
 * pcapport types.
 *
 * Every tool takes a pcap_file path (plus a few optional filters) and
 * returns a plain JSON summary computed locally from the capture.
 * File access goes through an injectable reader so tests can supply
 * in-memory synthetic captures with no filesystem or network access.
 */

export type ReadFileFn = (path: string) => Promise<Buffer>;

export interface CallDeps {
  readFile: ReadFileFn;
}

export interface PcapFileArgs {
  pcap_file: string;
}

export interface TcpConnectionsArgs {
  pcap_file: string;
  server_ip?: string;
  server_port?: number;
  detailed?: boolean;
}

export interface TcpAnomaliesArgs {
  pcap_file: string;
  server_ip?: string;
  server_port?: number;
}

export interface TcpRetransmissionsArgs {
  pcap_file: string;
  server_ip?: string;
  threshold?: number;
}

export interface TrafficFlowArgs {
  pcap_file: string;
  server_ip: string;
  server_port?: number;
}
