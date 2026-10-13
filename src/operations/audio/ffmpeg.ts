import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { importPack } from "../../runtimes/files";
import { bytesInput, MiB } from "../util";

const MAX_INPUT = 16 * MiB;
const MAX_OUTPUT = 8 * MiB;

export const ffmpegAudioWav = defineOperation<{ sampleRate: number; channels: number }>({
  spec: {
    id: "audio.ffmpeg.wav", version: "1.0.0", title: "Extract media audio as WAV (FFmpeg)", category: "Audio",
    description: "Extract the first 30 seconds of audio from a bounded media file as PCM16 WAV. Uses the optional threaded FFmpeg pack; requires cross-origin isolation.",
    keywords: ["ffmpeg", "video", "audio", "transcode", "extract", "wav", "pcm"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "audio", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: {
      type: "object", properties: {
        sampleRate: { type: "integer", title: "Output sample rate (Hz)", minimum: 8_000, maximum: 48_000, default: 8_000 },
        channels: { type: "integer", title: "Output channels", minimum: 1, maximum: 2, default: 1 },
      }, required: ["sampleRate", "channels"], additionalProperties: false,
    },
    runtime: "wasm", deterministic: true, streaming: false, sideEffects: "none", cost: "high",
    limits: { maxInputBytes: MAX_INPUT },
  },
  async run(ctx, inputs, params) {
    const input = await readAll(bytesInput(inputs), MAX_INPUT);
    if (input.length === 0) throw new OperationError("INVALID_INPUT", "Media input is empty");
    const inputBytes = input.length;
    ctx.throwIfAborted();
    const { loadFFmpeg } = await importPack("FFmpeg", () => import("../../runtimes/ffmpeg"));
    const { ffmpeg, dispose } = await loadFFmpeg(ctx.signal);
    try {
      await ffmpeg.writeFile("input.media", input, { signal: ctx.signal });
      const code = await ffmpeg.exec(["-hide_banner", "-loglevel", "error", "-i", "input.media", "-vn", "-t", "30",
        "-ac", String(params.channels), "-ar", String(params.sampleRate), "-c:a", "pcm_s16le", "-f", "wav", "audio.wav"], 15_000, { signal: ctx.signal });
      ctx.throwIfAborted();
      if (code !== 0) throw new OperationError("INVALID_INPUT", `FFmpeg could not decode audio (exit code ${code})`);
      const audio = await ffmpeg.readFile("audio.wav", "binary", { signal: ctx.signal });
      if (typeof audio === "string" || audio.length > MAX_OUTPUT) throw new OperationError("INVALID_INPUT", "Decoded WAV exceeds the 8 MiB output limit");
      ctx.diagnostic(`Extracted ${audio.length} PCM16 WAV bytes at ${params.sampleRate} Hz, ${params.channels} channel(s).`);
      const owned = new Uint8Array(audio.length);
      owned.set(audio);
      return { audio: bytesFrom(owned), report: structuredValue({ inputBytes, outputBytes: audio.length, sampleRate: params.sampleRate, channels: params.channels, durationLimitSeconds: 30 }) };
    } finally {
      dispose();
    }
  },
});