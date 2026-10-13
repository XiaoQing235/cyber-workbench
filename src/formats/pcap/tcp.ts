import type { Bytes } from "../../core/bytes/ByteSource";
import { endpoint, TCP_ACK, TCP_SYN, type DecodedPacket } from "./decode";

export interface TcpPiece {
  fromClient: boolean;
  packet: number;
  /** Offset into the sender's reassembled data. */
  start: number;
  length: number;
}

export interface TcpStream {
  index: number;
  client: string;
  server: string;
  firstPacket: number;
  packets: number;
  clientData: Bytes;
  serverData: Bytes;
  /** Accepted data in capture order, for showing both directions as one conversation. */
  pieces: TcpPiece[];
  /** Sequence-space gaps: bytes never captured. */
  missingBytes: number;
}

interface Direction {
  isn: number | null;
  segments: { seq: number; payload: Bytes; packet: number }[];
}

function assemble(direction: Direction): { data: Bytes; pieces: Omit<TcpPiece, "fromClient">[]; missing: number } {
  const { segments } = direction;
  if (segments.length === 0) return { data: new Uint8Array(0), pieces: [], missing: 0 };
  const first = segments[0].seq;
  // Without a SYN, start from the lowest sequence number, allowing for 32-bit wrap-around.
  const base = direction.isn ?? (first + Math.min(...segments.map((s) => (s.seq - first) | 0))) >>> 0;
  const ordered = segments
    .map((segment) => ({ ...segment, offset: (segment.seq - base) >>> 0 }))
    .filter((segment) => segment.offset < 0x80000000)
    .sort((a, b) => a.offset - b.offset || a.packet - b.packet);
  const parts: Bytes[] = [];
  const pieces: Omit<TcpPiece, "fromClient">[] = [];
  let position = 0;
  let written = 0;
  let missing = 0;
  for (const segment of ordered) {
    const end = segment.offset + segment.payload.length;
    if (end <= position) continue;
    if (segment.offset > position) {
      missing += segment.offset - position;
      position = segment.offset;
    }
    const fresh = segment.payload.subarray(position - segment.offset);
    parts.push(fresh);
    pieces.push({ packet: segment.packet, start: written, length: fresh.length });
    written += fresh.length;
    position = end;
  }
  const data = new Uint8Array(written);
  let at = 0;
  for (const part of parts) {
    data.set(part, at);
    at += part.length;
  }
  return { data, pieces, missing };
}

/** Rebuilds each TCP conversation in sequence order, dropping retransmitted bytes. */
export function reassembleTcp(packets: readonly DecodedPacket[]): TcpStream[] {
  const conversations = new Map<string, { index: number; client: string; server: string; firstPacket: number; packets: number; client_: Direction; server_: Direction }>();
  for (const packet of packets) {
    const tcp = packet.tcp;
    if (!tcp || packet.src === undefined || packet.dst === undefined) continue;
    const from = endpoint(packet.src, tcp.srcPort);
    const to = endpoint(packet.dst, tcp.dstPort);
    const key = from < to ? `${from}|${to}` : `${to}|${from}`;
    let conversation = conversations.get(key);
    if (!conversation) {
      // The opener is whoever sent the first packet; a lone SYN-ACK first means the other side opened.
      const reversed = (tcp.flags & TCP_SYN) !== 0 && (tcp.flags & TCP_ACK) !== 0;
      conversation = {
        index: conversations.size,
        client: reversed ? to : from,
        server: reversed ? from : to,
        firstPacket: packet.index,
        packets: 0,
        client_: { isn: null, segments: [] },
        server_: { isn: null, segments: [] },
      };
      conversations.set(key, conversation);
    }
    conversation.packets++;
    const direction = from === conversation.client ? conversation.client_ : conversation.server_;
    if (tcp.flags & TCP_SYN) direction.isn = (tcp.seq + 1) >>> 0;
    if (tcp.payload.length > 0) direction.segments.push({ seq: tcp.seq, payload: tcp.payload, packet: packet.index });
  }
  return [...conversations.values()].map((conversation) => {
    const client = assemble(conversation.client_);
    const server = assemble(conversation.server_);
    // Each side stays in sequence order; the two sides interleave by when their data was captured.
    const pieces: TcpPiece[] = [];
    for (let i = 0, j = 0; i < client.pieces.length || j < server.pieces.length; ) {
      if (j >= server.pieces.length || (i < client.pieces.length && client.pieces[i].packet <= server.pieces[j].packet)) {
        pieces.push({ ...client.pieces[i++], fromClient: true });
      } else {
        pieces.push({ ...server.pieces[j++], fromClient: false });
      }
    }
    return {
      index: conversation.index,
      client: conversation.client,
      server: conversation.server,
      firstPacket: conversation.firstPacket,
      packets: conversation.packets,
      clientData: client.data,
      serverData: server.data,
      pieces,
      missingBytes: client.missing + server.missing,
    };
  });
}

/** Both directions interleaved in capture order, like "Follow TCP stream". */
export function conversationBytes(stream: TcpStream): Bytes {
  const out = new Uint8Array(stream.clientData.length + stream.serverData.length);
  let at = 0;
  for (const piece of stream.pieces) {
    const source = piece.fromClient ? stream.clientData : stream.serverData;
    out.set(source.subarray(piece.start, piece.start + piece.length), at);
    at += piece.length;
  }
  return out;
}
