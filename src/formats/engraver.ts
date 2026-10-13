import type { Bytes } from "../core/bytes/ByteSource";
import { parseCapture } from "./pcap/capture";

const MAX_CAPTURE_BYTES = 1024 * 1024;
const MAX_PACKETS = 10_000;
const MAX_COMMANDS = 2_000;
const PREFIX = [0x55, 0x55, 0x08, 0x03, 0x01];

export interface EngraverCommand {
  packet: number;
  servo: number;
  position: number;
  durationMs: number;
  laserOn: boolean;
}

export interface EngraverTrace {
  packets: number;
  commands: EngraverCommand[];
  servoCounts: Record<number, number>;
  laserOnCommands: number;
  laserOffCommands: number;
  strokes: { from: [number, number]; to: [number, number] }[];
  path: { x: number; y: number; pen: boolean }[];
  flagRecovered: false;
}

export function traceEngraverCapture(bytes: Bytes, signal?: AbortSignal): EngraverTrace {
  if (signal?.aborted) throw signal.reason;
  if (bytes.length < 32 || bytes.length > MAX_CAPTURE_BYTES) throw new Error("Engraver capture is truncated or exceeds 1 MiB");
  const capture = parseCapture(bytes, MAX_PACKETS);
  if (capture.warnings.length) throw new Error(`Engraver capture is incomplete: ${capture.warnings[0]}`);
  const commands: EngraverCommand[] = [];
  const servoCounts: Record<number, number> = {};
  const strokes: EngraverTrace["strokes"] = [];
  const path: EngraverTrace["path"] = [];
  const positions = new Map<number, number>();
  let laserOn = false;
  let laserOnCommands = 0;
  let laserOffCommands = 0;
  for (const packet of capture.packets) {
    if (signal?.aborted) throw signal.reason;
    const data = packet.data;
    if (packet.linkType !== 249 || data.length < 37) continue;
    const header = data[0] | data[1] << 8;
    const captured = (data[23] | data[24] << 8 | data[25] << 16 | data[26] << 24) >>> 0;
    if ((header !== 27 && header !== 28) || data[16] & 1 || data[21] !== 1 || data[22] !== 1 ||
      captured !== 64 || data.length < header + 64) continue;
    const command = data.subarray(header, header + 10);
    if (!PREFIX.every((byte, index) => command[index] === byte)) continue;
    const servo = command[7];
    const position = command[8] | command[9] << 8;
    if (servo < 1 || servo > 6 || position > 3_000) throw new Error("Engraver servo command is outside the supported range");
    if (commands.length >= MAX_COMMANDS) throw new Error("Engraver command count exceeds 2,000");
    const durationMs = command[5] | command[6] << 8;
    const fromX = positions.get(2), fromY = positions.get(3);
    if (servo === 1) {
      if (position === 2_400) { laserOn = true; laserOnCommands++; }
      else if (position === 2_300) { laserOn = false; laserOffCommands++; }
      else laserOn = false;
      if (fromX !== undefined && fromY !== undefined && !laserOn) path.push({ x: fromX, y: fromY, pen: false });
    }
    positions.set(servo, position);
    if (laserOn && (servo === 2 || servo === 3) && fromX !== undefined && fromY !== undefined) {
      const toX = positions.get(2)!, toY = positions.get(3)!;
      strokes.push({ from: [fromX, fromY], to: [toX, toY] });
      path.push({ x: fromX, y: fromY, pen: true }, { x: toX, y: toY, pen: true });
    }
    servoCounts[servo] = (servoCounts[servo] ?? 0) + 1;
    commands.push({ packet: packet.index, servo, position, durationMs, laserOn });
  }
  if (!commands.length) throw new Error("No supported USBPcap engraver servo commands were found");
  return { packets: capture.packets.length, commands, servoCounts, laserOnCommands, laserOffCommands,
    strokes, path, flagRecovered: false };
}