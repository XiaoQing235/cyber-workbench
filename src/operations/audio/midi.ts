import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { extractMidiNoteBytes, inspectMidi, MAX_MIDI_BYTES } from "../../formats/midi";
import { bytesInput } from "../util";

export const midiInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "audio.midi.inspect", version: "1.0.0", title: "Inspect MIDI events", category: "Audio",
    description: "Inspect bounded Standard MIDI tracks, note-on ticks, tempo, running status, and text metadata without rendering or playing the file.",
    keywords: ["midi", "smf", "notes", "tempo", "lyrics", "text", "stego"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_MIDI_BYTES },
  },
  async run(ctx, inputs) {
    try {
      return { report: structuredValue(await inspectMidi(bytesInput(inputs), ctx.signal)) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const midiNoteBytes = defineOperation<{ trackIndex: number; channel: number; field: "pitch" | "velocity"; maxNotes: number }>({
  spec: {
    id: "audio.midi.note-bytes", version: "1.0.0", title: "Extract MIDI note bytes", category: "Audio",
    description: "Export bounded note-on pitches or velocities as bytes, with optional track and channel filters. Zero-velocity note-on events are treated as note-off.",
    keywords: ["midi", "note", "pitch", "velocity", "bytes", "stego", "ascii"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: {
        trackIndex: { type: "integer", title: "Track (-1 = all)", minimum: -1, maximum: 63, default: -1 },
        channel: { type: "integer", title: "Channel (-1 = all)", minimum: -1, maximum: 15, default: -1 },
        field: { type: "string", title: "Note field", enum: ["pitch", "velocity"], default: "pitch" },
        maxNotes: { type: "integer", title: "Maximum notes", minimum: 1, maximum: 10_000, default: 10_000 },
      },
      required: ["trackIndex", "channel", "field", "maxNotes"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_MIDI_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const parsed = await inspectMidi(bytesInput(inputs), ctx.signal);
      const extracted = extractMidiNoteBytes(parsed, params.trackIndex, params.channel, params.field, params.maxNotes);
      ctx.diagnostic(`Extracted ${extracted.selected} MIDI ${params.field} byte(s).${extracted.truncated ? " Note limit reached." : ""}`);
      return { data: bytesFrom(extracted.bytes), report: structuredValue({ selected: extracted.selected, truncated: extracted.truncated, trackIndex: params.trackIndex, channel: params.channel, field: params.field }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});