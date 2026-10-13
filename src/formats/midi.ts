import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { readAll } from "../core/bytes/sources";

export const MAX_MIDI_BYTES = 256 * 1024;

export interface MidiNote {
  track: number;
  tick: number;
  channel: number;
  pitch: number;
  velocity: number;
  running: boolean;
}

export interface MidiReport {
  format: 0 | 1;
  ticksPerBeat: number;
  trackCount: number;
  eventCount: number;
  maxTick: number;
  tempo: { track: number; tick: number; microsecondsPerBeat: number }[];
  text: { track: number; tick: number; type: string; value: string }[];
  notes: MidiNote[];
}

export async function inspectMidi(source: ByteSource, signal?: AbortSignal): Promise<MidiReport> {
  if (signal?.aborted) throw signal.reason;
  const bytes = await readAll(source, MAX_MIDI_BYTES);
  if (bytes.length < 14 || bytes[0] !== 0x4d || bytes[1] !== 0x54 || bytes[2] !== 0x68 || bytes[3] !== 0x64 || new DataView(bytes.buffer).getUint32(4) !== 6) throw new Error("Input is not a standard 6-byte MIDI header");
  const { parseMidi } = await import("midi-file");
  const midi = parseMidi(bytes);
  if ((midi.header.format !== 0 && midi.header.format !== 1) || midi.tracks.length < 1 || midi.tracks.length > 64 || midi.header.numTracks !== midi.tracks.length) throw new Error("MIDI format or track count is unsupported");
  const ticksPerBeat = midi.header.ticksPerBeat;
  if (!ticksPerBeat || ticksPerBeat > 32767) throw new Error("MIDI SMPTE timing or ticks-per-beat value is unsupported");
  const notes: MidiNote[] = [];
  const tempo: MidiReport["tempo"] = [];
  const text: MidiReport["text"] = [];
  let eventCount = 0;
  let maxTick = 0;
  let totalText = 0;
  for (const [track, events] of midi.tracks.entries()) {
    let tick = 0;
    for (const event of events) {
      tick += event.deltaTime;
      eventCount++;
      if (!Number.isSafeInteger(tick) || tick > 1_000_000_000 || eventCount > 50_000) throw new Error("MIDI event count or tick position exceeds the budget");
      if (event.type === "noteOn" && event.velocity > 0) {
        if (notes.length >= 10_000) throw new Error("MIDI note count exceeds 10,000");
        notes.push({ track, tick, channel: event.channel, pitch: event.noteNumber, velocity: event.velocity, running: event.running === true });
      } else if (event.type === "setTempo") {
        if (tempo.length >= 128 || event.microsecondsPerBeat < 1) throw new Error("MIDI tempo events are invalid or exceed the budget");
        tempo.push({ track, tick, microsecondsPerBeat: event.microsecondsPerBeat });
      } else if ("text" in event && typeof event.text === "string") {
        totalText += event.text.length;
        if (event.text.length > 1_024 || totalText > 16_384 || text.length >= 128) throw new Error("MIDI text metadata exceeds the budget");
        text.push({ track, tick, type: event.type, value: event.text });
      }
      if (eventCount % 1_024 === 0 && signal?.aborted) throw signal.reason;
    }
    maxTick = Math.max(maxTick, tick);
  }
  return { format: midi.header.format, ticksPerBeat, trackCount: midi.tracks.length, eventCount, maxTick, tempo, text, notes };
}

export function extractMidiNoteBytes(report: MidiReport, trackIndex: number, channel: number, field: "pitch" | "velocity", maxNotes: number): { bytes: Bytes; selected: number; truncated: boolean } {
  if (!Number.isSafeInteger(trackIndex) || trackIndex < -1 || trackIndex >= report.trackCount || !Number.isSafeInteger(channel) || channel < -1 || channel > 15 || !Number.isSafeInteger(maxNotes) || maxNotes < 1 || maxNotes > 10_000) throw new Error("MIDI note selection parameters are invalid");
  const selected = report.notes.filter((note) => (trackIndex === -1 || note.track === trackIndex) && (channel === -1 || note.channel === channel));
  if (selected.length === 0) throw new Error("MIDI selection contains no note-on events");
  return { bytes: Uint8Array.from(selected.slice(0, maxNotes), (note) => note[field]), selected: Math.min(maxNotes, selected.length), truncated: selected.length > maxNotes };
}