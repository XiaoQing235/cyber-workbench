import type { Evidence, Finding } from "../../core/analysis/finding";
import type { Bytes } from "../../core/bytes/ByteSource";
import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation, type OperationContext } from "../../core/operation/types";
import type { Value } from "../../core/value";
import { bytesFrom, structuredValue, textValue } from "../../core/value";
import { CaptureError, parseCapture, type Capture } from "../../formats/pcap/capture";
import { decodePacket, type DecodedPacket } from "../../formats/pcap/decode";
import { parseDns, type DnsMessage } from "../../formats/pcap/dns";
import { headerValue, parseHttp, type HttpMessage } from "../../formats/pcap/http";
import { conversationBytes, reassembleTcp, type TcpStream } from "../../formats/pcap/tcp";
import { USB_LINK_TYPES } from "../../formats/usb";
import { bytesInput, MiB } from "../util";

const LIMITS = { maxInputBytes: 512 * MiB };
const COMMON = { runtime: "ts", deterministic: true, sideEffects: "none" } as const;
const CAPTURE_INPUT = [{ name: "data", type: "bytes" as const }];

interface Decoded {
  capture: Capture;
  packets: DecodedPacket[];
}

async function decode(inputs: Readonly<Record<string, Value>>, ctx: OperationContext): Promise<Decoded> {
  let capture: Capture;
  try {
    capture = parseCapture(await readAll(bytesInput(inputs)));
  } catch (error) {
    if (error instanceof CaptureError) throw new OperationError("INVALID_INPUT", error.message);
    throw error;
  }
  ctx.throwIfAborted();
  return { capture, packets: capture.packets.map(decodePacket) };
}

function dnsMessages(packets: readonly DecodedPacket[]): { packet: number; message: DnsMessage }[] {
  const found: { packet: number; message: DnsMessage }[] = [];
  for (const packet of packets) {
    const udp = packet.udp;
    if (!udp || (udp.srcPort !== 53 && udp.dstPort !== 53 && udp.srcPort !== 5353 && udp.dstPort !== 5353)) continue;
    const message = parseDns(udp.payload);
    if (message) found.push({ packet: packet.index, message });
  }
  return found;
}

/** Requests then responses of one stream; inspect reports and http-body use the same numbering. */
function httpMessages(stream: TcpStream): HttpMessage[] {
  return [...parseHttp(stream.clientData), ...parseHttp(stream.serverData)];
}

function preview(bytes: Bytes): string {
  const text = Array.from(bytes.subarray(0, 60), (byte) => (byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : ".")).join("");
  return text.replace(/\.{4,}/g, "…");
}

/** Names under one suffix with long, distinct, encoded-looking first labels: the usual DNS-tunnel shape. */
function dnsExfiltration(names: readonly string[]): { suffix: string; count: number; sample: string }[] {
  const groups = new Map<string, Set<string>>();
  for (const name of names) {
    const labels = name.toLowerCase().split(".");
    if (labels.length < 3) continue;
    const suffix = labels.slice(-2).join(".");
    const head = labels.slice(0, -2).join("");
    if (head.length >= 16 && /^[a-z0-9+/=_-]+$/i.test(head)) {
      groups.set(suffix, (groups.get(suffix) ?? new Set()).add(name));
    }
  }
  return [...groups].filter(([, set]) => set.size >= 3).map(([suffix, set]) => ({ suffix, count: set.size, sample: [...set][0] }));
}

export const pcapInspect = defineOperation<Record<string, never>>({
  spec: {
    ...COMMON,
    id: "pcap.inspect",
    version: "1.0.0",
    title: "Inspect capture (pcap)",
    category: "Network",
    description:
      "Read a pcap or pcapng capture: protocols, TCP conversations (reassembled), DNS queries, HTTP messages and ICMP data, with leads such as DNS tunnelling or data hidden in pings.",
    keywords: ["pcap", "pcapng", "wireshark", "tcpdump", "network", "dns", "http", "tcp", "follow stream"],
    inputs: CAPTURE_INPUT,
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    streaming: false,
    cost: "medium",
    limits: LIMITS,
  },
  async run(ctx, inputs) {
    const { capture, packets } = await decode(inputs, ctx);
    const streams = reassembleTcp(packets);
    const dns = dnsMessages(packets);
    const findings: Finding[] = capture.warnings.map((warning, index) => ({ id: `pcap.warning.${index}`, ruleId: "pcap.read", severity: "weak", message: warning }));
    const linkTypes: Record<string, number> = {};
    const protocols = { tcp: 0, udp: 0, icmp: 0, otherIp: 0, notIp: 0, fragments: 0 };
    for (const packet of packets) {
      linkTypes[packet.linkType] = (linkTypes[packet.linkType] ?? 0) + 1;
      if (packet.fragment) protocols.fragments++;
      if (packet.tcp) protocols.tcp++;
      else if (packet.udp) protocols.udp++;
      else if (packet.icmp) protocols.icmp++;
      else if (packet.ipVersion) protocols.otherIp++;
      else protocols.notIp++;
    }

    if (Object.keys(linkTypes).some((type) => USB_LINK_TYPES.has(Number(type)))) {
      findings.push({
        id: "pcap.usb",
        ruleId: "pcap.link-type",
        severity: "strong",
        message: "This is a USB capture: keystrokes or mouse movements may be recoverable",
        evidence: [{ kind: "structure", tier: "strong", detail: `Link types ${Object.keys(linkTypes).join(", ")} (189/220 usbmon, 249 USBPcap)` }],
        suggestion: { operationId: "usb.keyboard", label: "Decode keystrokes", then: [] },
      });
    }

    const httpRows: { stream: number; message: number; kind: string; startLine: string; host?: string; contentType?: string; bodyBytes: number }[] = [];
    for (const stream of streams) {
      httpMessages(stream).forEach((message, index) => {
        const host = headerValue(message, "host");
        const contentType = headerValue(message, "content-type");
        httpRows.push({ stream: stream.index, message: index, kind: message.kind, startLine: message.startLine, bodyBytes: message.body.length, ...(host ? { host } : {}), ...(contentType ? { contentType } : {}) });
      });
    }
    for (const row of httpRows.filter((row) => row.bodyBytes > 0).slice(0, 25)) {
      findings.push({
        id: `pcap.http.${row.stream}.${row.message}`,
        ruleId: "pcap.http",
        severity: "medium",
        message: `HTTP ${row.kind} body in stream ${row.stream}: ${row.startLine} (${row.contentType ?? "no content type"}, ${row.bodyBytes} bytes)`,
        evidence: [{ kind: "structure", tier: "strong", detail: `Parsed from the reassembled ${row.kind === "request" ? "client" : "server"} data of TCP stream ${row.stream}` }],
        suggestion: { operationId: "pcap.http-body", params: { stream: row.stream, message: row.message }, label: "Extract body", then: [] },
      });
    }

    for (const stream of streams.filter((s) => s.clientData.length + s.serverData.length > 0).slice(0, 25)) {
      const evidence: Evidence[] = [
        { kind: "structure", tier: "strong", detail: `${stream.packets} packets reassembled by sequence number; retransmitted bytes dropped` },
        ...(stream.missingBytes > 0 ? [{ kind: "integrity" as const, tier: "medium" as const, detail: `${stream.missingBytes} bytes were never captured (gaps in the sequence)` }] : []),
      ];
      findings.push({
        id: `pcap.stream.${stream.index}`,
        ruleId: "pcap.tcp",
        severity: "weak",
        message: `TCP stream ${stream.index}: ${stream.client} → ${stream.server}, ${stream.clientData.length} + ${stream.serverData.length} bytes: ${preview(stream.clientData.length > 0 ? stream.clientData : stream.serverData)}`,
        evidence,
        suggestion: { operationId: "pcap.tcp-stream", params: { stream: stream.index, direction: "both" }, label: "Follow stream", then: [] },
      });
    }

    const queries = dns.filter(({ message }) => !message.response).flatMap(({ message }) => message.questions.map((question) => question.name));
    for (const lead of dnsExfiltration(queries)) {
      findings.push({
        id: `pcap.dns-exfil.${lead.suffix}`,
        ruleId: "pcap.dns-tunnel",
        severity: "strong",
        message: `${lead.count} distinct long subdomains of ${lead.suffix}, e.g. ${lead.sample}: data may be smuggled in DNS queries`,
        evidence: [{ kind: "plausibility", tier: "medium", detail: "Long first labels made only of Base64/Base32/hex characters, all different, under one domain" }],
        suggestion: { operationId: "pcap.dns-names", params: { suffix: lead.suffix, part: "subdomain", join: "concatenate" }, label: "Collect the subdomains", then: [] },
      });
    }

    const echoes = packets.filter((packet) => packet.icmp?.echo && packet.icmp.payload.length > 0);
    const distinct = new Set(echoes.map((packet) => Array.from(packet.icmp!.payload).join(","))).size;
    if (echoes.length > 0 && distinct > 1) {
      findings.push({
        id: "pcap.icmp-data",
        ruleId: "pcap.icmp",
        severity: "medium",
        message: `${echoes.length} ICMP echo packets carry ${distinct} different payloads: pings may be carrying data`,
        evidence: [{ kind: "plausibility", tier: "medium", detail: "Ordinary ping tools send the same filler in every packet" }],
        suggestion: { operationId: "pcap.icmp-data", params: { type: "echo-request" }, label: "Collect ping payloads", then: [] },
      });
    }

    return {
      report: structuredValue({
        format: capture.format,
        packets: packets.length,
        duration: packets.length > 1 ? Math.round((packets[packets.length - 1].time - packets[0].time) * 1000) / 1000 : 0,
        linkTypes,
        protocols,
        tcpStreams: streams.slice(0, 500).map((stream) => ({
          index: stream.index,
          client: stream.client,
          server: stream.server,
          packets: stream.packets,
          clientBytes: stream.clientData.length,
          serverBytes: stream.serverData.length,
          missingBytes: stream.missingBytes,
        })),
        dns: dns.slice(0, 1000).map(({ packet, message }) => ({
          packet,
          response: message.response,
          questions: message.questions,
          answers: message.answers,
        })),
        http: httpRows.slice(0, 500),
        findings,
      }),
    };
  },
});

export const pcapTcpStream = defineOperation<{ stream: number; direction: "both" | "client" | "server" }>({
  spec: {
    ...COMMON,
    id: "pcap.tcp-stream",
    version: "1.0.0",
    title: "Follow TCP stream",
    category: "Network",
    description: "The reassembled bytes of one TCP conversation: both directions in capture order, or one side only.",
    keywords: ["follow", "tcp", "stream", "reassemble", "conversation"],
    inputs: CAPTURE_INPUT,
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: {
        stream: { type: "integer", title: "Stream number", minimum: 0, default: 0 },
        direction: { type: "string", title: "Direction", enum: ["both", "client", "server"], default: "both" },
      },
      required: ["stream", "direction"],
      additionalProperties: false,
    },
    streaming: false,
    cost: "medium",
    limits: LIMITS,
  },
  async run(ctx, inputs, params) {
    const streams = reassembleTcp((await decode(inputs, ctx)).packets);
    const stream = streams[params.stream];
    if (!stream) throw new OperationError("INVALID_INPUT", `There is no TCP stream ${params.stream} (the capture has ${streams.length})`);
    if (stream.missingBytes > 0) ctx.diagnostic(`${stream.missingBytes} bytes of this stream were never captured; the data has gaps.`);
    const data = params.direction === "client" ? stream.clientData : params.direction === "server" ? stream.serverData : conversationBytes(stream);
    return { data: bytesFrom(new Uint8Array(data)) };
  },
});

export const pcapHttpBody = defineOperation<{ stream: number; message: number }>({
  spec: {
    ...COMMON,
    id: "pcap.http-body",
    version: "1.0.0",
    title: "Extract HTTP body",
    category: "Network",
    description: "The body of one HTTP message in a TCP stream, with chunked transfer coding removed. Numbering matches the capture report (requests first, then responses).",
    keywords: ["http", "body", "download", "export objects", "file"],
    inputs: CAPTURE_INPUT,
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: {
        stream: { type: "integer", title: "Stream number", minimum: 0, default: 0 },
        message: { type: "integer", title: "Message number", minimum: 0, default: 0 },
      },
      required: ["stream", "message"],
      additionalProperties: false,
    },
    streaming: false,
    cost: "medium",
    limits: LIMITS,
  },
  async run(ctx, inputs, params) {
    const stream = reassembleTcp((await decode(inputs, ctx)).packets)[params.stream];
    if (!stream) throw new OperationError("INVALID_INPUT", `There is no TCP stream ${params.stream}`);
    const message = httpMessages(stream)[params.message];
    if (!message) throw new OperationError("INVALID_INPUT", `Stream ${params.stream} has no HTTP message ${params.message}`);
    const encoding = headerValue(message, "content-encoding");
    if (encoding && encoding !== "identity") ctx.diagnostic(`The body is ${encoding}-encoded; run "Decompress" (${encoding === "deflate" ? "zlib" : encoding}) on it.`);
    return { data: bytesFrom(new Uint8Array(message.body)) };
  },
});

export const pcapDnsNames = defineOperation<{ suffix: string; part: "name" | "subdomain"; join: "lines" | "concatenate"; unique: boolean }>({
  spec: {
    ...COMMON,
    id: "pcap.dns-names",
    version: "1.0.0",
    title: "Collect DNS query names",
    category: "Network",
    description: "Queried names in capture order, optionally only under one domain and with that domain removed: how data smuggled through DNS is put back together.",
    keywords: ["dns", "exfiltration", "tunnel", "subdomain", "query"],
    inputs: CAPTURE_INPUT,
    outputs: [{ name: "text", type: "text" }],
    parametersSchema: {
      type: "object",
      properties: {
        suffix: { type: "string", title: "Only names under (e.g. example.com; empty = all)", default: "" },
        part: { type: "string", title: "Keep", enum: ["name", "subdomain"], default: "name" },
        join: { type: "string", title: "Join with", enum: ["lines", "concatenate"], default: "lines" },
        unique: { type: "boolean", title: "Drop repeated names (retries)", default: true },
      },
      required: ["suffix", "part", "join", "unique"],
      additionalProperties: false,
    },
    streaming: false,
    cost: "medium",
    limits: LIMITS,
  },
  async run(ctx, inputs, params) {
    const suffix = params.suffix.toLowerCase().replace(/^\.+|\.+$/g, "");
    const seen = new Set<string>();
    const parts: string[] = [];
    for (const { message } of dnsMessages((await decode(inputs, ctx)).packets)) {
      if (message.response) continue;
      for (const { name } of message.questions) {
        const lower = name.toLowerCase();
        if (suffix && lower !== suffix && !lower.endsWith(`.${suffix}`)) continue;
        if (params.unique && seen.has(lower)) continue;
        seen.add(lower);
        const kept = params.part === "subdomain" && suffix ? name.slice(0, Math.max(0, name.length - suffix.length - 1)) : name;
        // Exfiltration tools split data over several labels; the dots are not part of it.
        parts.push(params.part === "subdomain" ? kept.replace(/\./g, "") : kept);
      }
    }
    if (parts.length === 0) ctx.diagnostic("No DNS queries matched.");
    return { text: textValue(parts.join(params.join === "lines" ? "\n" : "")) };
  },
});

export const pcapIcmpData = defineOperation<{ type: "echo-request" | "echo-reply" | "all" }>({
  spec: {
    ...COMMON,
    id: "pcap.icmp-data",
    version: "1.0.0",
    title: "Collect ICMP payloads",
    category: "Network",
    description: "Concatenate ICMP payloads in capture order (for echo packets, the data after the identifier and sequence number).",
    keywords: ["icmp", "ping", "exfiltration", "covert channel"],
    inputs: CAPTURE_INPUT,
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: { type: { type: "string", title: "Packets", enum: ["echo-request", "echo-reply", "all"], default: "echo-request" } },
      required: ["type"],
      additionalProperties: false,
    },
    streaming: false,
    cost: "medium",
    limits: LIMITS,
  },
  async run(ctx, inputs, params) {
    const payloads = (await decode(inputs, ctx)).packets
      .filter((packet) => {
        const icmp = packet.icmp;
        if (!icmp) return false;
        if (params.type === "all") return true;
        const request = icmp.type === 8 || icmp.type === 128;
        return icmp.echo && (params.type === "echo-request" ? request : !request);
      })
      .map((packet) => packet.icmp!.payload);
    if (payloads.length === 0) ctx.diagnostic("No matching ICMP packets.");
    const out = new Uint8Array(payloads.reduce((sum, payload) => sum + payload.length, 0));
    let at = 0;
    for (const payload of payloads) {
      out.set(payload, at);
      at += payload.length;
    }
    return { data: bytesFrom(out) };
  },
});
