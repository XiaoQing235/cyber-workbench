import { describe, expect, it } from "vitest";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractMidiNoteBytes, inspectMidi } from "./midi";

const MIDI = Uint8Array.from(atob("TVRoZAAAAAYAAQACAeBNVHJrAAAAGAD/AwlDb25kdWN0b3IA/1EDB6EgAP8vAE1UcmsAAAA4AP8DA0NURgD/ARFoaWRkZW4gaW4gcGl0Y2hlcwCQQ1p4gENAAJBUWniAVEAAkEZaeIBGQAD/LwA="), (character) => character.charCodeAt(0));
const RUNNING_MIDI = Uint8Array.from(atob("TVRoZAAAAAYAAAABAGBNVHJrAAAAEQCQQ1AYVFAYRlAYQwAA/y8A"), (character) => character.charCodeAt(0));

describe("MIDI event forensics", () => {
  it("inspects a real two-track file and extracts CTF from note pitches", async () => {
    const report = await inspectMidi(new MemorySource(MIDI));
    expect(report).toMatchObject({ format: 1, ticksPerBeat: 480, trackCount: 2, maxTick: 360 });
    expect(report.tempo).toEqual([{ track: 0, tick: 0, microsecondsPerBeat: 500_000 }]);
    expect(report.text).toEqual(expect.arrayContaining([{ track: 1, tick: 0, type: "text", value: "hidden in pitches" }]));
    expect(report.notes.map((note) => [note.pitch, note.tick])).toEqual([[67, 0], [84, 120], [70, 240]]);
    expect(new TextDecoder().decode(extractMidiNoteBytes(report, 1, 0, "pitch", 10).bytes)).toBe("CTF");
    expect(Array.from(extractMidiNoteBytes(report, -1, -1, "velocity", 2).bytes)).toEqual([90, 90]);
    expect(extractMidiNoteBytes(report, -1, -1, "velocity", 2).truncated).toBe(true);
  });

  it("rejects invalid headers and missing note selections", async () => {
    const damaged = MIDI.slice();
    damaged[0] = 0;
    await expect(inspectMidi(new MemorySource(damaged))).rejects.toThrow(/standard 6-byte MIDI header/);
    const report = await inspectMidi(new MemorySource(MIDI));
    expect(() => extractMidiNoteBytes(report, 0, 0, "pitch", 10)).toThrow(/no note-on events/);
  });

  it("handles running status and excludes a zero-velocity note-on", async () => {
    const report = await inspectMidi(new MemorySource(RUNNING_MIDI));
    expect(report).toMatchObject({ format: 0, trackCount: 1, ticksPerBeat: 96, maxTick: 72 });
    expect(report.notes.map((note) => [note.pitch, note.running])).toEqual([[67, false], [84, true], [70, true]]);
    expect(new TextDecoder().decode(extractMidiNoteBytes(report, 0, 0, "pitch", 10).bytes)).toBe("CTF");
  });

  it("makes pitch bytes available to the registry as a downstream artifact", async () => {
    const registry = createDefaultRegistry();
    const inspection = await executeOperation(registry, { operationId: "audio.midi.inspect", inputs: { data: bytesFrom(MIDI) }, params: {} });
    expect(inspection.run.error).toBeUndefined();
    expect((inspection.outputs.report as { data: object }).data).toMatchObject({ trackCount: 2, ticksPerBeat: 480 });
    const extracted = await executeOperation(registry, {
      operationId: "audio.midi.note-bytes", inputs: { data: bytesFrom(MIDI) }, params: { trackIndex: 1, channel: 0, field: "pitch", maxNotes: 10 },
    });
    expect(extracted.run.error).toBeUndefined();
    expect(new TextDecoder().decode(await readAll((extracted.outputs.data as { source: Parameters<typeof readAll>[0] }).source))).toBe("CTF");
    expect(extracted.run.diagnostics).toEqual(["Extracted 3 MIDI pitch byte(s)."]);
  });
});