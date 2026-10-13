import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { encodeBmp24 } from "../../formats/bmp/encode";
import { plotStormPylons, readStormPylonText } from "../../formats/pcap/storm";
import { bytesInput, MiB } from "../util";

export const stormPylonMap = defineOperation<{ buildingId: number }>({
  spec: {
    id: "pcap.storm-pylons", version: "1.2.0", title: "Plot Storm build packets", category: "Network",
    description: "Plot selected StarCraft Storm build coordinates from bounded 802.3 LLC/IPX pcap/pcapng packets and read exact sparse glyph shapes. A CTF{...} wrapper is a convention-based candidate, not independently encoded in the capture.",
    keywords: ["pcap", "pcapng", "ipx", "starcraft", "storm", "pylon", "packet", "plot"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "image", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      buildingId: { type: "integer", title: "Building ID", minimum: 0, maximum: 255, default: 156 },
    }, required: ["buildingId"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 8 * MiB },
  },
  async run(ctx, inputs, params) {
    const source = bytesInput(inputs);
    if (source.size > 8 * MiB) throw new OperationError("INPUT_TOO_LARGE", "Storm capture exceeds 8 MiB");
    try {
      ctx.throwIfAborted();
      const result = plotStormPylons(await readAll(source), params.buildingId, ctx.signal);
      const reading = readStormPylonText(result.mask);
      const rgb = new Uint8Array(256 * 256 * 3);
      for (let index = 0; index < result.mask.length; index++) rgb.fill(result.mask[index], index * 3, index * 3 + 3);
      ctx.diagnostic(`${result.matches} matching Storm build packet(s), ${result.uniquePoints} unique pixel(s) from ${result.packets} captured packet(s).`);
      return {
        image: bytesFrom(encodeBmp24(256, 256, rgb)),
        report: structuredValue({ packets: result.packets, matches: result.matches, uniquePoints: result.uniquePoints,
           outOfBounds: result.outOfBounds, clusters: result.clusters, width: 256, height: 256, buildingId: params.buildingId,
           glyphText: reading.text, markerPoints: reading.markerPoints, unreadableGlyphs: reading.unreadableGlyphs,
           flagCandidate: reading.text && reading.markerPoints === 4 ? `CTF{${reading.text}}` : null, flagRecovered: false }),
      };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
