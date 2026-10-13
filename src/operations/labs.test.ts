import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import type { ProtoTree } from "@goodtools/wiregasm";
import type { Finding } from "../core/analysis/finding";
import { writeZip } from "../core/archive/zip";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { OperationError } from "../core/operation/errors";
import type { Params } from "../core/operation/types";
import { bytesFrom, type Value } from "../core/value";
import { decodeImage } from "../formats/decode";
import { traceEngraverCapture } from "../formats/engraver";
import { plotStormPylons, readStormPylonText } from "../formats/pcap/storm";
import { concat, makePng } from "../formats/testing/fixtures";
import * as net from "../formats/testing/network";
import { projectTree } from "../runtimes/wiregasm/tree";
import { createDefaultRegistry } from "./index";

const freed = vi.fn();
const vector = <T>(items: T[]) => ({ size: () => items.length, get: (index: number) => items[index], delete: freed });
const treeNode = (label: string, filter: string, children: ProtoTree[] = []): ProtoTree => ({ label, filter,
  start: 0, length: 0, data_source_idx: 0, type: "proto", tree: vector(children) });
vi.mock("../runtimes/wiregasm", () => ({
  runDeepPcap: async (_input: Uint8Array, filter: string) => {
    if (filter !== "dns") throw new OperationError("INVALID_PARAMS", "Invalid display filter");
    return { filter, matched: 1, summary: { packet_count: 1, file_type: "pcap" }, frames: [{ number: 1, columns: ["DNS", "example.org"],
      tree: [{ label: "Domain Name System (query)", filter: "dns", children: [{ label: "example.org", filter: "dns.qry.name", children: [] }] }] }] };
  },
}));

const registry = createDefaultRegistry();
const ascii = (text: string) => new TextEncoder().encode(text);
const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

async function run(operationId: string, input: Value, params: Params = {}) {
  const port = registry.get(operationId).spec.inputs[0].name;
  const result = await executeOperation(registry, { operationId, inputs: { [port]: input }, params });
  expect(result.run.error, operationId).toBeUndefined();
  return { value: Object.values(result.outputs)[0], diagnostics: result.run.diagnostics };
}

async function bytesOf(value: Value): Promise<Uint8Array> {
  if (value.type !== "bytes") throw new Error(`expected bytes, got ${value.type}`);
  return readAll(value.source);
}

const findingsOf = (value: Value) => (value.type === "structured" ? (value.data as { findings: Finding[] }).findings : []);

const JPEG = Uint8Array.of(
  0xff, 0xd8,
  0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
  0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00,
  0x12, 0xff, 0x00, 0x34, 0xff, 0xd0, 0x56,
  0xff, 0xd9,
);
const GIF = concat(
  ascii("GIF89a"),
  Uint8Array.of(1, 0, 1, 0, 0x00, 0, 0, 0x21, 0xf9, 0x04, 0, 0, 0, 0, 0x00, 0x2c, 0, 0, 0, 0, 1, 0, 1, 0, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b),
);

describe("carving", () => {
  it("finds where each embedded file ends from its own structure", async () => {
    const png = await makePng({ width: 2, height: 2, colorType: 0, bitDepth: 8, pixels: Uint8Array.of(1, 2, 3, 4) });
    const zip = new Uint8Array(await (await writeZip([{ name: "flag.txt", data: new Blob([ascii("flag{carved}")]) }])).arrayBuffer());
    const polyglot = concat(png, JPEG, ascii("junk"), GIF, zip, ascii("TRAILER"));
    const { value } = await run("carve.scan", bytesFrom(polyglot));
    const items = (value.type === "structured" ? (value.data as { items: { type: string; offset: number; length: number | null }[] }).items : []).map(
      ({ type, offset, length }) => ({ type, offset, length }),
    );
    expect(items).toEqual([
      { type: "png", offset: 0, length: png.length },
      { type: "jpeg", offset: png.length, length: JPEG.length },
      { type: "gif", offset: png.length + JPEG.length + 4, length: GIF.length },
      { type: "zip", offset: png.length + JPEG.length + 4 + GIF.length, length: zip.length },
    ]);
    const findings = findingsOf(value);
    expect(findings[0]).toMatchObject({ id: "carve.trailing", suggestion: { params: { offset: png.length, length: -1 } } });
    for (const [component, finding] of [JPEG, GIF, zip].map((component, i) => [component, findings[i + 1]] as const)) {
      expect(finding.evidence?.[1]).toMatchObject({ kind: "structure", tier: "strong" });
      const { value: carved } = await run(finding.suggestion!.operationId, bytesFrom(polyglot), finding.suggestion!.params);
      expect(await bytesOf(carved)).toEqual(component);
    }
  });
});

const CLIENT = "10.0.0.1";
const SERVER = "10.0.0.2";
const tcpFrame = (fromClient: boolean, seq: number, ack: number, flags: number, payload?: Uint8Array) =>
  net.ethernet(
    net.ipv4(fromClient ? CLIENT : SERVER, fromClient ? SERVER : CLIENT, 6, net.tcp(fromClient ? 40000 : 80, fromClient ? 80 : 40000, seq, ack, flags, payload)),
  );
const REQUEST = ascii("GET /flag.txt HTTP/1.1\r\nHost: ctf.example\r\n\r\n");
const RESPONSE = ascii("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nflag{\r\n7\r\nchunked\r\n1\r\n}\r\n0\r\n\r\n");
const EXFIL = Array.from(ascii("flag{dns_tunnel_exfiltration_works}"), (b) => b.toString(16).padStart(2, "0")).join("");

function captureFrames(): Uint8Array[] {
  const dnsFrames = (EXFIL.match(/.{1,16}/g) ?? []).map((chunk, i) =>
    net.ethernet(net.ipv4(CLIENT, "8.8.8.8", 17, net.udp(5000 + i, 53, net.dns(i, `${chunk}.evil.com`)))),
  );
  return [
    tcpFrame(true, 1000, 0, 0x02),
    tcpFrame(false, 5000, 1001, 0x12),
    tcpFrame(true, 1001, 5001, 0x10),
    tcpFrame(true, 1011, 5001, 0x18, REQUEST.subarray(10)),
    tcpFrame(true, 1001, 5001, 0x18, REQUEST.subarray(0, 10)),
    tcpFrame(true, 1001, 5001, 0x18, REQUEST.subarray(0, 10)),
    tcpFrame(false, 5001, 1001 + REQUEST.length, 0x18, RESPONSE),
    ...dnsFrames,
    net.ethernet(net.ipv4("8.8.8.8", CLIENT, 17, net.udp(53, 5000, net.dns(0, "666c61677b646e735f74756e.evil.com", "1.2.3.4")))),
    ...["flag", "{icm", "p}"].map((part, i) => net.ethernet(net.ipv4(CLIENT, SERVER, 1, net.icmpEcho(8, 7, i, ascii(part))))),
    ...["flag", "{icm", "p}"].map((part, i) => net.ethernet(net.ipv4(SERVER, CLIENT, 1, net.icmpEcho(0, 7, i, ascii(part))))),
  ];
}

describe("network captures", () => {
  it("projects bounded Wiregasm DNS trees and releases native vectors", async () => {
    freed.mockClear();
    expect(projectTree(vector([treeNode("Domain Name System (query)", "dns", [treeNode("example.org", "dns.qry.name")])]), 0, { nodes: 2 }))
      .toMatchObject([{ label: "Domain Name System (query)", children: [{ label: "example.org" }] }]);
    expect(freed).toHaveBeenCalledTimes(3);
    const packet = net.ethernet(net.ipv4("192.0.2.10", "8.8.8.8", 17, net.udp(53000, 53, net.dns(0xbeef, "example.org"))));
    const input = bytesFrom(net.pcap(1, [packet]));
    const { value } = await run("pcap.deep-inspect", input, { filter: "dns", maxFrames: 1 });
    expect(value).toMatchObject({ type: "structured", data: { matched: 1, summary: { packet_count: 1 },
      frames: [{ number: 1, columns: ["DNS", "example.org"], tree: [{ label: "Domain Name System (query)", children: [{ label: "example.org" }] }] }] } });
    expect(freed).toHaveBeenCalledTimes(3);
    const invalidFilter = await executeOperation(registry, { operationId: "pcap.deep-inspect", inputs: { data: input }, params: { filter: "not a display filter", maxFrames: 1 } });
    expect(invalidFilter.run.error?.code).toBe("INVALID_PARAMS");
    const invalidCapture = await executeOperation(registry, { operationId: "pcap.deep-inspect", inputs: { data: bytesFrom(ascii("bad")) }, params: {} });
    expect(invalidCapture.run.error?.code).toBe("INVALID_INPUT");
  });
  it("reports streams, HTTP bodies, DNS tunnelling and ping data, in pcap and pcapng alike", async () => {
    for (const file of [net.pcap(1, captureFrames()), net.pcapng(1, captureFrames()), net.pcap(1, captureFrames(), { bigEndian: true, nano: true })]) {
      const { value } = await run("pcap.inspect", bytesFrom(file));
      const report = value.type === "structured" ? (value.data as { packets: number; tcpStreams: { client: string; clientBytes: number }[] }) : null;
      expect(report?.packets).toBe(captureFrames().length);
      expect(report?.tcpStreams[0]).toMatchObject({ client: "10.0.0.1:40000", clientBytes: REQUEST.length });
      const ids = findingsOf(value).map((finding) => finding.id);
      expect(ids).toEqual(expect.arrayContaining(["pcap.http.0.1", "pcap.stream.0", "pcap.dns-exfil.evil.com", "pcap.icmp-data"]));
    }
  });

  it("reconstructs the original 2019 StarCraft pylon bitmap from IPX packets", async () => {
    const original = readFileSync(new URL("../formats/testing/google-ctf-2019-sc.pcapng", import.meta.url));
    expect(createHash("sha256").update(original).digest("hex")).toBe("b40b193e219d78121b10aa1ce1ac1c0061fc4a4ac78f75c36c48a7b6768c2baa");
    const result = plotStormPylons(new Uint8Array(original));
    expect(result).toMatchObject({ packets: 16_827, matches: 62, uniquePoints: 61, outOfBounds: 0 });
    expect(result.clusters.map(({ left, right, points }) => ({ left, right, points }))).toEqual([
      { left: 114, right: 116, points: 4 },
      { left: 145, right: 155, points: 20 },
      { left: 161, right: 167, points: 12 },
      { left: 171, right: 186, points: 18 },
      { left: 198, right: 202, points: 7 },
    ]);
    expect(createHash("sha256").update(result.mask).digest("hex")).toBe("f3f77df0822913b0bf2ac1e520e25f2cd80b804355dee1b243f50b9117680965");
    expect(readStormPylonText(result.mask)).toEqual({ text: "6Pool", markerPoints: 4, unreadableGlyphs: 0 });
    const shifted = new Uint8Array(result.mask.length);
    for (let y = 0; y < 256; y++) for (let x = 0; x < 254; x++) shifted[x + 2 + y * 256] = result.mask[x + y * 256];
    expect(readStormPylonText(shifted).text).toBe("6Pool");
    const damaged = result.mask.slice();
    damaged[145 + 32 * 256] = 255;
    expect(readStormPylonText(damaged)).toMatchObject({ text: null, unreadableGlyphs: 1 });
    const incomplete = result.mask.slice();
    incomplete[147 + 32 * 256] = 0;
    expect(readStormPylonText(incomplete)).toMatchObject({ text: null, unreadableGlyphs: 1 });
    expect(() => readStormPylonText(new Uint8Array(256))).toThrow(/256x256/);
    const operation = await executeOperation(registry, { operationId: "pcap.storm-pylons", inputs: { data: bytesFrom(original) }, params: { buildingId: 156 } });
    expect(operation.run.status).toBe("success");
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: { packets: 16_827, matches: 62, uniquePoints: 61,
      glyphText: "6Pool", markerPoints: 4, unreadableGlyphs: 0, flagCandidate: "CTF{6Pool}", flagRecovered: false } });
    if (operation.outputs.image?.type !== "bytes") throw new Error("Expected plotted BMP image");
    const bmp = await readAll(operation.outputs.image.source);
    expect(Array.from(bmp.subarray(0, 2))).toEqual([0x42, 0x4d]);
    expect(new DataView(bmp.buffer, bmp.byteOffset, bmp.byteLength).getInt32(22, true)).toBe(-256);
    const wrongId = await executeOperation(registry, { operationId: "pcap.storm-pylons", inputs: { data: bytesFrom(original) }, params: { buildingId: 1 } });
    expect(wrongId.outputs.report).toMatchObject({ type: "structured", data: { matches: 0, uniquePoints: 0, glyphText: null, flagCandidate: null } });
  });

  it("bounds Storm map coordinates and requires 802.3 LLC/IPX framing", () => {
    const frame = new Uint8Array(73);
    frame[13] = 54;
    frame.set([0xe0, 0xe0, 0x03], 14);
    frame[59] = 0x37;
    frame[66] = 0x0c;
    frame[72] = 0x9c;
    frame[68] = 255;
    frame[70] = 255;
    const valid = plotStormPylons(net.pcapng(1, [frame]));
    expect(valid).toMatchObject({ packets: 1, matches: 1, uniquePoints: 1, outOfBounds: 0 });
    expect(valid.mask[256 * 256 - 1]).toBe(255);
    frame[69] = 1;
    expect(plotStormPylons(net.pcapng(1, [frame]))).toMatchObject({ matches: 1, uniquePoints: 0, outOfBounds: 1 });
    frame[14] = 0;
    expect(plotStormPylons(net.pcapng(1, [frame]))).toMatchObject({ matches: 0, uniquePoints: 0 });
  });

  it("reconstructs the original 2022 engraver USB servo timeline without inferring the flag", async () => {
    const original = readFileSync(new URL("../formats/testing/google-ctf-2022-engraver.pcapng", import.meta.url));
    expect(createHash("sha256").update(original).digest("hex")).toBe("7eff7c6c7aaed582054076e0cc1c8353b39d7135f881834ff3688afba35378b4");
    const trace = traceEngraverCapture(new Uint8Array(original));
    expect(trace).toMatchObject({ packets: 860, servoCounts: { 1: 76, 2: 118, 3: 95, 4: 43, 5: 43, 6: 43 },
      laserOnCommands: 30, laserOffCommands: 46, flagRecovered: false });
    expect(trace.commands).toHaveLength(418);
    expect(trace.strokes).toHaveLength(101);
    expect(trace.commands[0]).toMatchObject({ packet: 22, servo: 1, position: 2300, durationMs: 500, laserOn: false });
    expect(trace.commands[1]).toMatchObject({ packet: 24, servo: 2, position: 1300, durationMs: 1500 });
    const operation = await executeOperation(registry, { operationId: "hardware.usb.engraver-trace",
      inputs: { data: bytesFrom(new Uint8Array(original)) }, params: {} });
    expect(operation.run.status).toBe("success");
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: { packets: 860,
      laserOnCommands: 30, laserOffCommands: 46, flagRecovered: false } });
    if (operation.outputs.image?.type !== "bytes") throw new Error("Expected servo projection BMP");
    expect(Array.from((await readAll(operation.outputs.image.source)).subarray(0, 2))).toEqual([0x42, 0x4d]);
    expect(() => traceEngraverCapture(net.pcapng(1, [new Uint8Array(91)]))).toThrow(/No supported USBPcap/);
  });

  it("reassembles out-of-order and retransmitted TCP data and extracts a chunked HTTP body", async () => {
    const capture = bytesFrom(net.pcap(1, captureFrames()));
    expect(await bytesOf((await run("pcap.tcp-stream", capture, { stream: 0, direction: "client" })).value)).toEqual(REQUEST);
    expect(text(await bytesOf((await run("pcap.tcp-stream", capture, { stream: 0 })).value))).toBe(text(REQUEST) + text(RESPONSE));
    expect(text(await bytesOf((await run("pcap.http-body", capture, { stream: 0, message: 1 })).value))).toBe("flag{chunked}");
  });

  it("puts DNS-tunnelled data and ping payloads back together", async () => {
    const capture = bytesFrom(net.pcap(1, captureFrames()));
    const names = await run("pcap.dns-names", capture, { suffix: "evil.com", part: "subdomain", join: "concatenate" });
    expect(names.value).toEqual({ type: "text", text: EXFIL });
    const decoded = await run("hex.decode", names.value);
    expect(text(await bytesOf(decoded.value))).toBe("flag{dns_tunnel_exfiltration_works}");
    expect(text(await bytesOf((await run("pcap.icmp-data", capture)).value))).toBe("flag{icmp}");
  });

  it("rejects files that are not captures", async () => {
    const result = await executeOperation(registry, { operationId: "pcap.inspect", inputs: { data: bytesFrom(ascii("hello")) } });
    expect(result.run.error?.message).toMatch(/Too short|Not a pcap/);
  });
});

describe("USB HID", () => {
  const typed = "flag{usb_x\bKeys}";

  it("rebuilds typed text from usbmon, USBPcap and exported report lines", async () => {
    const reports = net.keyboardReports(typed);
    const usbmon = bytesFrom(net.pcap(220, reports.map(net.usbmon)));
    const usbpcap = bytesFrom(net.pcapng(249, reports.map(net.usbpcap)));
    const lines = bytesFrom(ascii(reports.map((r) => Array.from(r, (b) => b.toString(16).padStart(2, "0")).join(":")).join("\n")));
    for (const input of [usbmon, usbpcap, lines]) {
      expect((await run("usb.keyboard", input)).value).toEqual({ type: "text", text: "flag{usb_Keys}" });
    }
    expect((await run("usb.keyboard", usbmon, { applyBackspace: false })).value).toEqual({ type: "text", text: "flag{usb_x[BACKSPACE]Keys}" });
    const inspect = await run("pcap.inspect", usbmon);
    expect(findingsOf(inspect.value)[0]).toMatchObject({ id: "pcap.usb", suggestion: { operationId: "usb.keyboard" } });
  });

  it("draws mouse movements made with the button held", async () => {
    const reports = [
      ...Array.from({ length: 20 }, () => Uint8Array.of(0, 5, 5, 0)),
      ...Array.from({ length: 30 }, () => Uint8Array.of(1, 0, 2, 0)),
      ...Array.from({ length: 20 }, () => Uint8Array.of(1, 2, 0, 0)),
      ...Array.from({ length: 10 }, () => Uint8Array.of(0, -3 & 255, 0, 0)),
    ];
    const { value, diagnostics } = await run("usb.mouse", bytesFrom(net.pcap(220, reports.map(net.usbmon))));
    expect(diagnostics[0]).toMatch(/50 with the pen down in 1 stroke/);
    const { image } = await decodeImage(new MemorySource(new Uint8Array(await bytesOf(value))));
    expect([image.width, image.height]).toEqual([40 + 16, 58 + 16]);
    const dark = Array.from(image.samples).filter((sample, i) => i % 3 === 0 && sample < 128).length;
    expect(dark).toBeGreaterThan(100);
  });
});
