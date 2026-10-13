import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { decodeVcdCan, decodeVcdI2c, decodeVcdManchester, decodeVcdNrz, decodeVcdSpi, decodeVcdUart, inspectVcd } from "../../formats/vcd";
import { bytesInput, MiB } from "../util";

export const vcdInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "hardware.vcd.inspect", version: "1.0.0", title: "Inspect VCD signals", category: "Hardware",
    description: "Inspect bounded scalar digital changes, timescale and signal identifiers in a VCD waveform. Vector-bus contents are not decoded.",
    keywords: ["vcd", "verilog", "waveform", "digital", "signal", "hardware"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: 2 * MiB },
  },
  async run(ctx, inputs) {
    try {
      const report = await inspectVcd(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`Read ${report.signals.length} VCD signal(s) and ${report.scalarTransitions} scalar change(s) through tick ${report.lastTick}.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const vcdUartDecode = defineOperation<{ signal: string; bitTicks: number; maxBytes: number }>({
  spec: {
    id: "hardware.vcd.uart", version: "1.0.0", title: "Decode VCD UART bytes", category: "Hardware",
    description: "Sample one idle-high VCD signal as 8-N-1 UART using a specified ticks-per-bit value. Return bounded decoded bytes and framing errors; parity and inverted serial lines are unsupported.",
    keywords: ["vcd", "uart", "serial", "waveform", "decode", "hardware"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: {
      type: "object", properties: {
        signal: { type: "string", title: "Signal ID or name (blank = only scalar)", maxLength: 256, default: "" },
        bitTicks: { type: "integer", title: "Ticks per bit", minimum: 2, maximum: 1_000_000, default: 10 },
        maxBytes: { type: "integer", title: "Maximum decoded bytes", minimum: 1, maximum: 4_096, default: 256 },
      }, required: ["signal", "bitTicks", "maxBytes"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 2 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      const report = await decodeVcdUart(bytesInput(inputs), params.signal, params.bitTicks, params.maxBytes, ctx.signal);
      ctx.diagnostic(`Decoded ${report.bytes.length} UART byte(s) on ${report.signal}; ${report.framingErrors} framing error(s).${report.sampledBeyondLastTick ? " Stop sampling extended past the last recorded transition." : ""}`);
      return { data: bytesFrom(Uint8Array.from(report.bytes)), report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const vcdCanDecode = defineOperation<{ signal: string; bitTicks: number; maxFrames: number; startTick: number }>({
  spec: {
    id: "hardware.vcd.can", version: "1.0.0", title: "Decode VCD CAN frames", category: "Hardware",
    description: "Sample idle-high classical 11-bit CAN data frames from a scalar VCD line. Remove bit stuffing and validate CRC-15, ACK and EOF. Extended, remote and CAN FD frames are not decoded.",
    keywords: ["vcd", "can", "controller area network", "bus", "crc15", "hardware"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      signal: { type: "string", title: "Signal ID or name (blank = only scalar)", maxLength: 256, default: "" },
      bitTicks: { type: "integer", title: "Ticks per bit", minimum: 2, maximum: 1_000_000, default: 10 },
      maxFrames: { type: "integer", title: "Maximum frames", minimum: 1, maximum: 64, default: 32 },
      startTick: { type: "integer", title: "Earliest frame start tick", minimum: 0, default: 0 },
    }, required: ["signal", "bitTicks", "maxFrames", "startTick"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 2 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      const report = await decodeVcdCan(bytesInput(inputs), params.signal, params.bitTicks, params.maxFrames, params.startTick, ctx.signal);
      ctx.diagnostic(`Decoded ${report.frames.length} CRC-verified CAN data frame(s).${report.limitReached ? " Frame limit reached." : ""}`);
      return { data: bytesFrom(Uint8Array.from(report.frames.flatMap((frame) => frame.data))), report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const vcdSpiDecode = defineOperation<{ clock: string; data: string; select: string; maxBytes: number }>({
  spec: {
    id: "hardware.vcd.spi", version: "1.0.0", title: "Decode VCD SPI bytes", category: "Hardware",
    description: "Decode bounded SPI mode-0 MOSI bytes from explicit scalar clock, data and active-low chip-select signals. Sample rising edges MSB-first; other modes and MISO are not inferred.",
    keywords: ["vcd", "spi", "mosi", "clock", "chip select", "hardware"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: {
      type: "object", properties: {
        clock: { type: "string", title: "Clock signal ID or name", minLength: 1, maxLength: 256, default: "" },
        data: { type: "string", title: "MOSI signal ID or name", minLength: 1, maxLength: 256, default: "" },
        select: { type: "string", title: "Active-low select ID or name", minLength: 1, maxLength: 256, default: "" },
        maxBytes: { type: "integer", title: "Maximum decoded bytes", minimum: 1, maximum: 4_096, default: 256 },
      }, required: ["clock", "data", "select", "maxBytes"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 2 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      const report = await decodeVcdSpi(bytesInput(inputs), params.clock, params.data, params.select, params.maxBytes, ctx.signal);
      ctx.diagnostic(`Sampled ${report.sampledEdges} selected SPI clock edge(s), decoded ${report.bytes.length} byte(s); ${report.incompleteBits} partial bit(s) remain.`);
      return { data: bytesFrom(Uint8Array.from(report.bytes)), report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const vcdI2cDecode = defineOperation<{ clock: string; data: string; maxMessages: number; maxBytes: number }>({
  spec: {
    id: "hardware.vcd.i2c", version: "1.0.0", title: "Decode VCD I²C messages", category: "Hardware",
    description: "Decode 7-bit I²C START/repeated START/STOP, address and read/write bits, data bytes and ACK/NACK from explicit scalar SCL/SDA signals. Simultaneous edges and unknown values are rejected.",
    keywords: ["vcd", "i2c", "i²c", "scl", "sda", "hardware"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: {
      type: "object", properties: {
        clock: { type: "string", title: "SCL signal ID or name", minLength: 1, maxLength: 256, default: "" },
        data: { type: "string", title: "SDA signal ID or name", minLength: 1, maxLength: 256, default: "" },
        maxMessages: { type: "integer", title: "Maximum messages", minimum: 1, maximum: 64, default: 32 },
        maxBytes: { type: "integer", title: "Maximum decoded data bytes", minimum: 1, maximum: 4_096, default: 256 },
      }, required: ["clock", "data", "maxMessages", "maxBytes"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 2 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      const report = await decodeVcdI2c(bytesInput(inputs), params.clock, params.data, params.maxMessages, params.maxBytes, ctx.signal);
      const payload = report.messages.flatMap((message) => message.data);
      ctx.diagnostic(`Decoded ${report.messages.length} I²C message(s) and ${payload.length} data byte(s) from ${report.sampledEdges} SCL rising edges.`);
      return { data: bytesFrom(Uint8Array.from(payload)), report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const vcdManchesterDecode = defineOperation<{ signal: string; startTick: number; bitTicks: number; maxBytes: number; convention: "ieee" | "inverted" }>({
  spec: {
    id: "hardware.vcd.manchester", version: "1.0.0", title: "Decode VCD Manchester bytes", category: "Hardware",
    description: "Sample explicit scalar VCD half-bits as IEEE (low-to-high = 1) or inverted Manchester, MSB-first. Requires a known bit width and start tick; rejects bits without a midpoint transition.",
    keywords: ["vcd", "manchester", "line code", "digital", "hardware", "bits"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: {
      type: "object", properties: {
        signal: { type: "string", title: "Signal ID or name", minLength: 1, maxLength: 256, default: "" },
        startTick: { type: "integer", title: "First bit start tick", minimum: 0, default: 0 },
        bitTicks: { type: "integer", title: "Ticks per bit", minimum: 4, maximum: 1_000_000, default: 10 },
        maxBytes: { type: "integer", title: "Maximum decoded bytes", minimum: 1, maximum: 4_096, default: 256 },
        convention: { type: "string", title: "Bit convention", enum: ["ieee", "inverted"], default: "ieee" },
      }, required: ["signal", "startTick", "bitTicks", "maxBytes", "convention"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 2 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      const report = await decodeVcdManchester(bytesInput(inputs), params.signal, params.startTick, params.bitTicks, params.maxBytes, params.convention, ctx.signal);
      ctx.diagnostic(`Decoded ${report.bytes.length} Manchester byte(s) from ${report.sampledBits} bit(s).${report.truncated ? " Byte limit reached." : ""}`);
      return { data: bytesFrom(Uint8Array.from(report.bytes)), report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const vcdNrzDecode = defineOperation<{ signal: string; startTick: number; bitTicks: number; maxBytes: number; inverted: boolean }>({
  spec: {
    id: "hardware.vcd.nrz", version: "1.0.0", title: "Decode VCD NRZ bytes", category: "Hardware",
    description: "Sample a scalar digital VCD signal at explicit NRZ bit centres, optionally inverting levels, then pack MSB-first bytes. Unknown levels and missing start samples are rejected; partial final bits remain in the report.",
    keywords: ["vcd", "nrz", "line code", "digital", "hardware", "bits"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      signal: { type: "string", title: "Signal ID or name", minLength: 1, maxLength: 256, default: "" },
      startTick: { type: "integer", title: "First bit start tick", minimum: 0, default: 0 },
      bitTicks: { type: "integer", title: "Ticks per bit", minimum: 2, maximum: 1_000_000, default: 10 },
      maxBytes: { type: "integer", title: "Maximum decoded bytes", minimum: 1, maximum: 4096, default: 256 },
      inverted: { type: "boolean", title: "Invert levels", default: false },
    }, required: ["signal", "startTick", "bitTicks", "maxBytes", "inverted"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 2 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      const report = await decodeVcdNrz(bytesInput(inputs), params.signal, params.startTick, params.bitTicks, params.maxBytes, params.inverted, ctx.signal);
      ctx.diagnostic(`Sampled ${report.sampledBits} NRZ bit(s), producing ${report.bytes.length} complete byte(s).`);
      return { data: bytesFrom(Uint8Array.from(report.bytes)), report: structuredValue(report) };
    } catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
