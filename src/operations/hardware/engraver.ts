import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { encodeBmp24 } from "../../formats/bmp/encode";
import { traceEngraverCapture } from "../../formats/engraver";
import { renderPath } from "../../formats/usb";
import { bytesInput, MiB } from "../util";

export const engraverServoTrace = defineOperation<Record<string, never>>({
  spec: {
    id: "hardware.usb.engraver-trace", version: "1.0.0", title: "Plot USB engraver servo trace", category: "Hardware",
    description: "Read bounded USBPcap LewanSoul servo commands, list six-axis positions and plot the 2D servo-2/3 motion while servo 1 enables the laser. This is a projection, not a reconstruction of the arm geometry or flag.",
    keywords: ["usb", "usbpcap", "engraver", "servo", "laser", "robot", "pcapng"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "image", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MiB },
  },
  async run(ctx, inputs) {
    const source = bytesInput(inputs);
    if (source.size > MiB) throw new OperationError("INPUT_TOO_LARGE", "Engraver capture exceeds 1 MiB");
    try {
      ctx.throwIfAborted();
      const trace = traceEngraverCapture(await readAll(source), ctx.signal);
      const projection = renderPath({ points: trace.path, strokes: trace.laserOnCommands }, true);
      ctx.diagnostic(`Recovered ${trace.commands.length} USB servo write(s) and ${trace.strokes.length} laser-on motion segment(s); 2D projection does not verify a flag.`);
      return { image: bytesFrom(encodeBmp24(projection.width, projection.height, projection.rgb)),
        report: structuredValue({ packets: trace.packets, commands: trace.commands, servoCounts: trace.servoCounts,
          laserOnCommands: trace.laserOnCommands, laserOffCommands: trace.laserOffCommands,
          strokes: trace.strokes, width: projection.width, height: projection.height, flagRecovered: false }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});