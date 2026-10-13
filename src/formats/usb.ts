import type { Bytes } from "../core/bytes/ByteSource";
import { isCapture, parseCapture } from "./pcap/capture";

export interface HidReport {
  packet: number;
  data: Bytes;
}

export const USB_LINK_TYPES = new Set([189, 220, 249]);

const u16le = (d: Uint8Array, o: number) => d[o] | (d[o + 1] << 8);
const u32le = (d: Uint8Array, o: number) => (d[o] | (d[o + 1] << 8) | (d[o + 2] << 16) | (d[o + 3] << 24)) >>> 0;

/** Interrupt transfers from device to host: what keyboards and mice send. */
export function hidReportsFromCapture(bytes: Bytes): HidReport[] {
  const reports: HidReport[] = [];
  for (const packet of parseCapture(bytes).packets) {
    const d = packet.data;
    if (packet.linkType === 220 || packet.linkType === 189) {
      // Linux usbmon: event 'C' (completion), transfer type 1 (interrupt), IN endpoint, captured length at 36.
      const header = packet.linkType === 220 ? 64 : 48;
      const captured = d.length >= header ? u32le(d, 36) : 0;
      if (d[8] === 0x43 && d[9] === 1 && d[10] & 0x80 && captured > 0) reports.push({ packet: packet.index, data: d.subarray(header, header + captured) });
    } else if (packet.linkType === 249 && d.length >= 27) {
      // USBPcap: info bit 0 = from the device, transfer type at 22, data length at 23.
      const header = u16le(d, 0);
      const length = u32le(d, 23);
      if (d[22] === 1 && d[16] & 1 && d[21] & 0x80 && length > 0) reports.push({ packet: packet.index, data: d.subarray(header, header + length) });
    }
  }
  return reports;
}

/** One report per line of hex, e.g. tshark's usb.capdata or usbhid.data export ("00:00:09:00:00:00:00:00"). */
export function hidReportsFromText(text: string): HidReport[] {
  const reports: HidReport[] = [];
  text.split(/\r?\n/).forEach((line, index) => {
    const hex = line.trim().replace(/[:\s-]/g, "");
    if (hex.length >= 4 && hex.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(hex)) {
      reports.push({ packet: index, data: Uint8Array.from(hex.match(/../g)!, (pair) => parseInt(pair, 16)) });
    }
  });
  return reports;
}

export function hidReports(bytes: Bytes): { reports: HidReport[]; from: "capture" | "text" } {
  return isCapture(bytes.subarray(0, 4))
    ? { reports: hidReportsFromCapture(bytes), from: "capture" }
    : { reports: hidReportsFromText(new TextDecoder("utf-8", { fatal: false }).decode(bytes)), from: "text" };
}

const NORMAL: Record<number, string> = {};
const SHIFTED: Record<number, string> = {};
for (let i = 0; i < 26; i++) {
  NORMAL[4 + i] = String.fromCharCode(97 + i);
  SHIFTED[4 + i] = String.fromCharCode(65 + i);
}
[..."1234567890"].forEach((c, i) => (NORMAL[30 + i] = c));
[..."!@#$%^&*()"].forEach((c, i) => (SHIFTED[30 + i] = c));
for (const [code, normal, shifted] of [
  [40, "\n", "\n"], [43, "\t", "\t"], [44, " ", " "], [45, "-", "_"], [46, "=", "+"], [47, "[", "{"], [48, "]", "}"],
  [49, "\\", "|"], [50, "#", "~"], [51, ";", ":"], [52, "'", '"'], [53, "`", "~"], [54, ",", "<"], [55, ".", ">"], [56, "/", "?"],
  [84, "/", "/"], [85, "*", "*"], [86, "-", "-"], [87, "+", "+"], [88, "\n", "\n"], [98, "0", "0"], [99, ".", "."],
] as const) {
  NORMAL[code] = normal;
  SHIFTED[code] = shifted;
}
for (let i = 0; i < 9; i++) NORMAL[89 + i] = SHIFTED[89 + i] = String(i + 1);
const SPECIAL: Record<number, string> = { 41: "[ESC]", 76: "[DEL]", 79: "[RIGHT]", 80: "[LEFT]", 81: "[DOWN]", 82: "[UP]" };
for (let i = 0; i < 12; i++) SPECIAL[58 + i] = `[F${i + 1}]`;

/** Reports from a device that numbers its reports start with a constant report-ID byte. */
function reportIdOffset(reports: readonly HidReport[], bootLength: number): number {
  const lengths = reports.map((report) => report.data.length);
  const first = reports[0]?.data[0];
  const constantId = first !== undefined && first !== 0 && reports.every((report) => report.data[0] === first);
  return constantId && lengths.every((length) => length === bootLength + 1) ? 1 : 0;
}

export function decodeKeyboard(reports: readonly HidReport[], applyBackspace: boolean): { text: string; keys: number; unknown: number[] } {
  const offset = reportIdOffset(reports, 8);
  const out: string[] = [];
  const unknown = new Set<number>();
  let previous = new Set<number>();
  let caps = false;
  let keys = 0;
  for (const report of reports) {
    const d = report.data.subarray(offset);
    if (d.length < 3) continue;
    const shift = (d[0] & 0x22) !== 0;
    // Codes 1–3 are rollover and error states, not keys.
    const pressed = new Set([...d.subarray(2, 8)].filter((code) => code > 3));
    for (const code of pressed) {
      if (previous.has(code)) continue;
      keys++;
      if (code === 57) {
        caps = !caps;
      } else if (code === 42) {
        if (applyBackspace) out.pop();
        else out.push("[BACKSPACE]");
      } else {
        const upper = code >= 4 && code <= 29 ? shift !== caps : shift;
        const char = (upper ? SHIFTED : NORMAL)[code] ?? SPECIAL[code];
        if (char === undefined) unknown.add(code);
        out.push(char ?? `[0x${code.toString(16)}]`);
      }
    }
    previous = pressed;
  }
  return { text: out.join(""), keys, unknown: [...unknown] };
}

export type MouseButton = "left" | "right" | "middle" | "any" | "always";
const BUTTON_MASK: Record<MouseButton, number> = { left: 1, right: 2, middle: 4, any: 7, always: 0 };

export interface MousePath {
  points: { x: number; y: number; pen: boolean }[];
  strokes: number;
}

export function decodeMouse(reports: readonly HidReport[], options: { button: MouseButton; reportId: boolean; wideDeltas: boolean }): MousePath {
  const offset = options.reportId ? 1 : 0;
  const points: MousePath["points"] = [];
  let x = 0;
  let y = 0;
  let strokes = 0;
  let wasPen = false;
  for (const report of reports) {
    const d = report.data.subarray(offset);
    if (d.length < (options.wideDeltas ? 5 : 3)) continue;
    const view = new DataView(d.buffer, d.byteOffset, d.byteLength);
    x += options.wideDeltas ? view.getInt16(1, true) : view.getInt8(1);
    y += options.wideDeltas ? view.getInt16(3, true) : view.getInt8(2);
    const pen = options.button === "always" || (d[0] & BUTTON_MASK[options.button]) !== 0;
    if (pen && !wasPen) strokes++;
    wasPen = pen;
    points.push({ x, y, pen });
  }
  return { points, strokes };
}

/** Black strokes on white, sized to the drawing (at most `maxSize` pixels across). */
export function renderPath(path: MousePath, lines: boolean, maxSize = 1600): { width: number; height: number; rgb: Uint8Array } {
  const drawn = path.points.filter((point) => point.pen);
  const box = drawn.length > 0 ? drawn : path.points;
  const margin = 8;
  let [minX, minY, maxX, maxY] = [0, 0, 0, 0];
  box.forEach((point, index) => {
    [minX, minY] = index === 0 ? [point.x, point.y] : [Math.min(minX, point.x), Math.min(minY, point.y)];
    [maxX, maxY] = index === 0 ? [point.x, point.y] : [Math.max(maxX, point.x), Math.max(maxY, point.y)];
  });
  const spanX = maxX - minX;
  const spanY = maxY - minY;
  const scale = Math.min(1, (maxSize - 2 * margin) / Math.max(spanX, spanY, 1));
  const width = Math.max(1, Math.ceil(spanX * scale) + 2 * margin);
  const height = Math.max(1, Math.ceil(spanY * scale) + 2 * margin);
  const rgb = new Uint8Array(width * height * 3).fill(255);
  const plot = (px: number, py: number) => {
    for (let dy = 0; dy < 2; dy++) {
      for (let dx = 0; dx < 2; dx++) {
        const cx = px + dx;
        const cy = py + dy;
        if (cx >= 0 && cy >= 0 && cx < width && cy < height) rgb.fill(0, (cy * width + cx) * 3, (cy * width + cx) * 3 + 3);
      }
    }
  };
  const at = (point: { x: number; y: number }) => [Math.round((point.x - minX) * scale) + margin, Math.round((point.y - minY) * scale) + margin];
  path.points.forEach((point, index) => {
    if (!point.pen) return;
    const [x1, y1] = at(point);
    const previous = path.points[index - 1];
    if (lines && previous?.pen) {
      const [x0, y0] = at(previous);
      const steps = Math.max(Math.abs(x1 - x0), Math.abs(y1 - y0), 1);
      for (let s = 0; s <= steps; s++) plot(Math.round(x0 + ((x1 - x0) * s) / steps), Math.round(y0 + ((y1 - y0) * s) / steps));
    } else {
      plot(x1, y1);
    }
  });
  return { width, height, rgb };
}
