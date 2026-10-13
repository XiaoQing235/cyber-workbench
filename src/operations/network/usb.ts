import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, textValue } from "../../core/value";
import { encodeBmp24 } from "../../formats/bmp/encode";
import { CaptureError } from "../../formats/pcap/capture";
import { decodeKeyboard, decodeMouse, hidReports, renderPath, type HidReport, type MouseButton } from "../../formats/usb";
import { bytesInput, MiB } from "../util";

const COMMON = { runtime: "ts", deterministic: true, sideEffects: "none", streaming: false, cost: "medium" } as const;

async function reportsOf(source: Parameters<typeof readAll>[0]): Promise<{ reports: HidReport[]; from: string }> {
  try {
    const result = hidReports(await readAll(source));
    if (result.reports.length === 0) {
      throw new OperationError(
        "INVALID_INPUT",
        result.from === "capture"
          ? "No USB interrupt data from a device in this capture"
          : "Not a USB capture, and no lines of hex reports (e.g. 00:00:09:00:00:00:00:00) found",
      );
    }
    return result;
  } catch (error) {
    if (error instanceof CaptureError) throw new OperationError("INVALID_INPUT", error.message);
    throw error;
  }
}

export const usbKeyboard = defineOperation<{ applyBackspace: boolean }>({
  spec: {
    ...COMMON,
    id: "usb.keyboard",
    version: "1.0.0",
    title: "USB keyboard: keystrokes",
    category: "USB",
    description:
      "Rebuild typed text from a USB capture (usbmon or USBPcap) or from exported HID report lines, handling Shift, Caps Lock and held keys.",
    keywords: ["usb", "hid", "keyboard", "keystroke", "keylogger", "usbhid", "capdata", "leftover"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "text", type: "text" }],
    parametersSchema: {
      type: "object",
      properties: { applyBackspace: { type: "boolean", title: "Apply Backspace (otherwise show [BACKSPACE])", default: true } },
      required: ["applyBackspace"],
      additionalProperties: false,
    },
    limits: { maxInputBytes: 512 * MiB },
  },
  async run(ctx, inputs, params) {
    const { reports, from } = await reportsOf(bytesInput(inputs));
    const result = decodeKeyboard(reports, params.applyBackspace);
    ctx.diagnostic(`${result.keys} key presses from ${reports.length} reports (${from === "capture" ? "capture" : "hex lines"}).`);
    if (result.unknown.length > 0) ctx.diagnostic(`Unmapped key codes: ${result.unknown.map((code) => `0x${code.toString(16)}`).join(", ")}.`);
    return { text: textValue(result.text) };
  },
});

export const usbMouse = defineOperation<{ button: MouseButton; lines: boolean; reportId: boolean; wideDeltas: boolean }>({
  spec: {
    ...COMMON,
    id: "usb.mouse",
    version: "1.0.0",
    title: "USB mouse: draw movements",
    category: "USB",
    description:
      "Replay mouse movements from a USB capture or exported HID report lines and draw where the pointer moved while a button was held, as an image.",
    keywords: ["usb", "hid", "mouse", "draw", "movement", "plot", "usbhid", "capdata"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "image", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: {
        button: { type: "string", title: "Draw while", enum: ["left", "right", "middle", "any", "always"], default: "left" },
        lines: { type: "boolean", title: "Join points with lines", default: true },
        reportId: { type: "boolean", title: "Reports start with a report ID byte", default: false },
        wideDeltas: { type: "boolean", title: "16-bit movement fields", default: false },
      },
      required: ["button", "lines", "reportId", "wideDeltas"],
      additionalProperties: false,
    },
    limits: { maxInputBytes: 512 * MiB },
  },
  async run(ctx, inputs, params) {
    const { reports } = await reportsOf(bytesInput(inputs));
    const path = decodeMouse(reports, params);
    const drawn = path.points.filter((point) => point.pen).length;
    ctx.diagnostic(`${path.points.length} movements, ${drawn} with the pen down in ${path.strokes} stroke(s).`);
    if (drawn === 0) ctx.diagnostic('Nothing was drawn with that button; try "any" or "always".');
    const { width, height, rgb } = renderPath(path, params.lines);
    return { image: bytesFrom(encodeBmp24(width, height, rgb)) };
  },
});
