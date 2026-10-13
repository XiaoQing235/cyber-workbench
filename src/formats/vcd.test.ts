import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { saleaeDigitalCsvToVcd } from "./saleaeCsv";
import { decodeVcdCan, decodeVcdI2c, decodeVcdManchester, decodeVcdNrz, decodeVcdSpi, decodeVcdUart, inspectVcd } from "./vcd";
import canPyVcd from "./testing/can-standard-pyvcd.vcd?raw";

const VCD = `$date fixture $end
$timescale 1 us $end
$scope module serial $end
$var wire 1 ! tx $end
$upscope $end
$enddefinitions $end
#0
$dumpvars
1!
$end
#10
0!
#50
1!
#60
0!
#80
1!
#90
0!
#100
1!
#120
0!
#130
1!
#140
0!
#160
1!
#170
0!
#190
1!
#200
0!
#210
1!
`;
const source = (input = VCD) => new MemorySource(new TextEncoder().encode(input));
const SPI = `$date fixture $end
$timescale 1 us $end
$scope module spi $end
$var wire 1 ! clk $end
$var wire 1 " mosi $end
$var wire 1 # cs $end
$upscope $end
$enddefinitions $end
#0
$dumpvars
0!
0"
1#
$end
#10
0#
#11
1"
#15
1!
#20
0!
#21
0"
#25
1!
#30
0!
#31
1"
#35
1!
#40
0!
#41
0"
#45
1!
#50
0!
#55
1!
#60
0!
#61
1"
#65
1!
#70
0!
#71
0"
#75
1!
#80
0!
#81
1"
#85
1!
#90
0!
#100
1#
`;

function i2cFixture(addressWrite = 0xa0): string {
  const lines = ["$timescale 1 us $end", "$scope module i2c $end", "$var wire 1 ! scl $end", '$var wire 1 " sda $end', "$upscope $end", "$enddefinitions $end", "#0", "$dumpvars", "1!", '1"', "$end"];
  let clock = "1";
  let data = "1";
  const change = (tick: number, wire: "clock" | "data", value: string) => {
    if (wire === "clock" ? clock === value : data === value) return;
    lines.push(`#${tick}`, `${value}${wire === "clock" ? "!" : '"'}`);
    if (wire === "clock") clock = value;
    else data = value;
  };
  const send = (value: number, ack: number, start: number) => {
    for (const [index, bit] of [...Array.from({ length: 8 }, (_, shift) => (value >> (7 - shift)) & 1), ack].entries()) {
      const tick = start + index * 10;
      change(tick, "clock", "0");
      change(tick + 1, "data", String(bit));
      change(tick + 5, "clock", "1");
    }
    change(start + 90, "clock", "0");
    return start + 90;
  };
  change(10, "data", "0");
  let tick = send(addressWrite, 0, 20);
  tick = send(0xa5, 0, tick);
  change(tick + 1, "data", "1");
  change(tick + 5, "clock", "1");
  change(tick + 10, "data", "0");
  tick = send(0xa1, 0, tick + 20);
  tick = send(0x5a, 1, tick);
  change(tick + 1, "data", "0");
  change(tick + 5, "clock", "1");
  change(tick + 10, "data", "1");
  return `${lines.join("\n")}\n`;
}

function manchesterFixture(): string {
  const lines = ["$timescale 1 us $end", "$scope module linecode $end", "$var wire 1 ! rx $end", '$var wire 1 " end $end', "$upscope $end", "$enddefinitions $end", "#0", "$dumpvars", "1!", '0"', "$end"];
  let previous = "1";
  const bits = [0x48, 0x49].flatMap((byte) => Array.from({ length: 8 }, (_, shift) => (byte >> (7 - shift)) & 1));
  for (const [index, bit] of bits.entries()) {
    for (const [offset, value] of [[0, bit ? "0" : "1"], [5, bit ? "1" : "0"]] as const) {
      if (value !== previous) lines.push(`#${index * 10 + offset}`, `${value}!`);
      previous = value;
    }
  }
  lines.push("#160", '1"');
  return `${lines.join("\n")}\n`;
}

describe("VCD digital waveform evidence", () => {
  it("samples explicit NRZ bits as bytes and refuses unknown gaps", async () => {
    const bits = "01001000";
    const lines = ["$timescale 1 ns $end", "$scope module line $end", "$var wire 1 ! rx $end", "$upscope $end", "$enddefinitions $end"];
    bits.split("").forEach((bit, index) => lines.push(`#${index * 10}`, `${bit}!`));
    lines.push("#80");
    const waveform = source(lines.join("\n"));
    expect(await decodeVcdNrz(waveform, "line.rx", 0, 10, 2, false)).toMatchObject({ bytes: [0x48], sampledBits: 8, incompleteBits: 0 });
    expect((await decodeVcdNrz(waveform, "!", 0, 10, 2, true)).bytes).toEqual([0xb7]);
    await expect(decodeVcdNrz(source(lines.join("\n").replace("0!", "x!")), "!", 0, 10, 2, false)).rejects.toThrow(/unknown/);
    const result = await executeOperation(createDefaultRegistry(), { operationId: "hardware.vcd.nrz", inputs: { data: bytesValue(waveform) },
      params: { signal: "line.rx", startTick: 0, bitTicks: 10, maxBytes: 2, inverted: false } });
    expect(result.run.status).toBe("success");
    if (result.outputs.data?.type !== "bytes") throw new Error("Expected NRZ output");
    expect(await readAll(result.outputs.data.source)).toEqual(Uint8Array.of(0x48));
  });
  it("converts Saleae digital transitions into VCD without changing PyVCD UART HI bytes", async () => {
    const rows = Array.from(VCD.matchAll(/^#(\d+)\n([01])!$/gm), (match) => `${(Number(match[1]) / 1e6).toFixed(9)},${match[2]},X`);
    const csv = `Time [s],"Serial TX","Spare channel"\n0.000000000,1,X\n${rows.join("\n")}\n`;
    const converted = await saleaeDigitalCsvToVcd(source(csv));
    expect(converted.report).toMatchObject({ timescale: "1 ns", rows: rows.length + 1, transitions: rows.length + 2, lastTick: 210_000,
      channels: [{ original: "Serial TX", signal: "saleae.Serial_TX" }, { original: "Spare channel", signal: "saleae.Spare_channel" }] });
    expect(await inspectVcd(new MemorySource(converted.vcd))).toMatchObject({ timescale: "1 ns", lastTick: 210_000 });
    expect(await decodeVcdUart(new MemorySource(converted.vcd), "saleae.Serial_TX", 10_000, 16)).toMatchObject({ bytes: [72, 73], startTicks: [10_000, 120_000] });
    const result = await executeOperation(createDefaultRegistry(), { operationId: "hardware.saleae.digital-import", inputs: { data: bytesValue(source(csv)) }, params: {} });
    expect(result.run.error).toBeUndefined();
    if (result.outputs.data?.type !== "bytes") throw new Error("Expected VCD from Saleae digital CSV");
    expect(await readAll(result.outputs.data.source)).toEqual(converted.vcd);
  });

  it("retains Saleae X gaps and refuses lossy timing or non-digital CSV", async () => {
    const rows = Array.from(VCD.matchAll(/^#(\d+)\n([01])!$/gm), (match) => `${(Number(match[1]) / 1e6).toFixed(9)},${match[2]}`);
    const csv = `Time [s],Serial TX\n0.000000000,1\n${rows.join("\n")}\n`;
    const gapped = csv.replace("0.000060000,0", "0.000060000,X");
    const { vcd } = await saleaeDigitalCsvToVcd(source(gapped));
    expect(new TextDecoder().decode(vcd)).toContain("#60000\nx!");
    expect((await decodeVcdUart(new MemorySource(vcd), "saleae.Serial_TX", 10_000, 16)).bytes).toEqual([73]);
    await expect(saleaeDigitalCsvToVcd(source(csv.replace("0.000060000", "0.0000600005")))).rejects.toThrow(/1 ns resolution/);
    await expect(saleaeDigitalCsvToVcd(source(csv.replace("0.000050000,1", "0.000005000,1")))).rejects.toThrow(/out of order/);
    await expect(saleaeDigitalCsvToVcd(source(csv.replace("0.000060000,0", "0.000060000,Z")))).rejects.toThrow(/invalid digital value/);
    await expect(saleaeDigitalCsvToVcd(source("Trigger [s],Time [s],Voltage\n0,0,1.2\n"))).rejects.toThrow(/Time \[s\]/);
    const aliases = await saleaeDigitalCsvToVcd(source("Time [s],A,A_1,A\n0,1,0,X\n"));
    expect(aliases.report.channels.map((channel) => channel.signal)).toEqual(["saleae.A", "saleae.A_1", "saleae.A_2"]);
  });

  it("preserves bounded digital transitions for reproducibly generated Saleae exports", async () => {
    await fc.assert(fc.asyncProperty(
      fc.integer({ min: 1, max: 3 }),
      fc.array(fc.tuple(fc.integer({ min: 1, max: 500 }),
        fc.constantFrom("0", "1", "X"), fc.constantFrom("0", "1", "X"), fc.constantFrom("0", "1", "X")), { minLength: 1, maxLength: 64 }),
      async (channelCount, events) => {
        const names = ["A", "B", "C"].slice(0, channelCount);
        const lines = [`Time [s],${names.join(",")}`];
        const changes = Array(channelCount).fill(0) as number[];
        let previous: string[] = [];
        let lastTick = 0;
        for (const [delta, ...levels] of events) {
          lastTick += delta;
          const current = levels.slice(0, channelCount).map((value) => value.toLowerCase());
          for (let index = 0; index < channelCount; index++) {
            if (current[index] !== previous[index]) changes[index]++;
          }
          lines.push(`${(lastTick / 1e9).toFixed(9)},${levels.slice(0, channelCount).join(",")}`);
          previous = current;
        }
        const { vcd, report } = await saleaeDigitalCsvToVcd(source(lines.join("\n")));
        const parsed = await inspectVcd(new MemorySource(vcd));
        expect(report).toMatchObject({ timescale: "1 ns", rows: events.length, lastTick, transitions: changes.reduce((sum, count) => sum + count, 0) });
        expect(parsed).toMatchObject({ timescale: "1 ns", lastTick, scalarTransitions: report.transitions });
        expect(parsed.signals.map((item) => item.changes)).toEqual(changes);
      },
    ), { seed: 20261012, numRuns: 75 });
  });

  it("decodes independently generated stuffed classical CAN data frames with checked CRC-15", async () => {
    const report = await decodeVcdCan(source(canPyVcd), "can.bus", 10, 4, 0);
    expect(report).toMatchObject({ signal: "can.bus", bitTicks: 10, limitReached: false, frames: [
      { startTick: 50, identifier: 0x123, data: [0x11, 0x22], crc15: "0x04b7", crcValid: true, acknowledged: true, stuffedBits: 2 },
      { startTick: 700, identifier: 0x7df, data: [0xff, 0x00], crc15: "0x5bb7", crcValid: true, acknowledged: true, stuffedBits: 5 },
    ] });
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "hardware.vcd.can", inputs: { data: bytesValue(source(canPyVcd)) },
      params: { signal: "can.bus", bitTicks: 10, maxFrames: 4, startTick: 0 },
    });
    expect(result.run.status).toBe("success");
    if (result.outputs.data?.type !== "bytes") throw new Error("Expected CAN payload bytes");
    expect(await readAll(result.outputs.data.source)).toEqual(Uint8Array.of(0x11, 0x22, 0xff, 0x00));
  });

  it("rejects corrupt CAN bits and incomplete captures while bounding decoded frames", async () => {
    await expect(decodeVcdCan(source(canPyVcd.replace("#280\n1!", "#270\n1!")), "can.bus", 10, 4, 0)).rejects.toThrow(/CRC-15/);
    await expect(decodeVcdCan(source(canPyVcd.replace("#760\n0!", "#760\n1!")), "can.bus", 10, 4, 0)).rejects.toThrow(/bit stuffing/);
    await expect(decodeVcdCan(source(canPyVcd.replace('#1410\n1"', "")), "can.bus", 10, 4, 0)).rejects.toThrow(/beyond the recorded waveform/);
    expect(await decodeVcdCan(source(canPyVcd), "can.bus", 10, 1, 0)).toMatchObject({ limitReached: true, frames: [{ identifier: 0x123 }] });
    expect(await decodeVcdCan(source(canPyVcd), "can.bus", 10, 4, 680)).toMatchObject({ limitReached: false, frames: [{ identifier: 0x7df }] });
    await expect(decodeVcdCan(source(canPyVcd), "", 10, 4, 0)).rejects.toThrow(/valid scalar signal/);
  });

  it("samples IEEE Manchester half-bits as ASCII HI and enforces the byte budget", async () => {
    const sourceFile = source(manchesterFixture());
    expect(await decodeVcdManchester(sourceFile, "linecode.rx", 0, 10, 8, "ieee")).toMatchObject({ sampledBits: 16, bytes: [0x48, 0x49], incompleteBits: 0, truncated: false });
    expect(await decodeVcdManchester(sourceFile, "!", 0, 10, 1, "inverted")).toMatchObject({ bytes: [0xb7], sampledBits: 8, truncated: true });
    await expect(decodeVcdManchester(source(manchesterFixture().replace("#5\n0!", "#5\n1!")), "!", 0, 10, 8, "ieee")).rejects.toThrow(/midpoint transition/);
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "hardware.vcd.manchester", inputs: { data: bytesValue(source(manchesterFixture())) }, params: { signal: "linecode.rx" },
    });
    expect(result.run.status).toBe("success");
    if (result.outputs.data?.type !== "bytes") throw new Error("Expected Manchester bytes");
    expect(await readAll(result.outputs.data.source)).toEqual(Uint8Array.of(0x48, 0x49));
  });
  it("decodes 7-bit I2C write, repeated-start read and ACK/NACK bits", async () => {
    const report = await decodeVcdI2c(source(i2cFixture()), "i2c.scl", "i2c.sda", 4, 8);
    expect(report).toMatchObject({ clock: "i2c.scl", data: "i2c.sda", sampledEdges: 36 });
    expect(report.messages[0]).toMatchObject({ address: 0x50, read: false, addressAck: true, data: [0xa5], dataAcks: [true], incompleteBits: 0, stopTick: null });
    expect(report.messages[1]).toMatchObject({ address: 0x50, read: true, addressAck: true, data: [0x5a], dataAcks: [false], incompleteBits: 0 });
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "hardware.vcd.i2c", inputs: { data: bytesValue(source(i2cFixture())) },
      params: { clock: "i2c.scl", data: "i2c.sda" },
    });
    expect(result.run.status).toBe("success");
    if (result.outputs.data?.type !== "bytes") throw new Error("Expected I2C payload bytes");
    expect(await readAll(result.outputs.data.source)).toEqual(Uint8Array.of(0xa5, 0x5a));
  });

  it("rejects ambiguous I2C edges, unknown SDA and data budgets", async () => {
    const fixture = i2cFixture();
    await expect(decodeVcdI2c(source(fixture.replace('#21\n1"', '#20\n1"')), "i2c.scl", "i2c.sda", 4, 8)).rejects.toThrow(/simultaneous/);
    await expect(decodeVcdI2c(source(fixture.replace('#21\n1"', '#21\nx"')), "i2c.scl", "i2c.sda", 4, 8)).rejects.toThrow(/unknown/);
    await expect(decodeVcdI2c(source(fixture), "i2c.scl", "i2c.sda", 4, 1)).rejects.toThrow(/byte budget/);
    await expect(decodeVcdI2c(source(i2cFixture(0xf0)), "i2c.scl", "i2c.sda", 4, 8)).rejects.toThrow(/10-bit addresses/);
    await expect(decodeVcdI2c(source(fixture), "i2c.sda", "i2c.sda", 4, 8)).rejects.toThrow(/selection/);
  });

  it("matches the independent PyVCD signal inventory and decodes LSB-first UART HI", async () => {
    expect(await inspectVcd(source())).toMatchObject({ timescale: "1 us", lastTick: 210, signals: [{ id: "!", name: "serial.tx", width: 1 }] });
    expect(await decodeVcdUart(source(), "serial.tx", 10, 16)).toMatchObject({ signal: "serial.tx", bytes: [72, 73], startTicks: [10, 120], framingErrors: 0 });
  });

  it("rejects backward timestamps and bad UART selection", async () => {
    await expect(inspectVcd(source(VCD.replace("#210\n1!", "#90\n1!")))).rejects.toThrow(/monotonically increasing/);
    await expect(decodeVcdUart(source(), "missing", 10, 16)).rejects.toThrow(/valid scalar signal/);
  });

  it("exposes VCD inventory and UART HI through registered Hardware operations", async () => {
    const registry = createDefaultRegistry();
    const data = bytesValue(source());
    const inspected = await executeOperation(registry, { operationId: "hardware.vcd.inspect", inputs: { data }, params: {} });
    expect(inspected.outputs.report).toMatchObject({ type: "structured", data: { lastTick: 210 } });
    const uart = await executeOperation(registry, { operationId: "hardware.vcd.uart", inputs: { data }, params: {} });
    expect(uart.run.status).toBe("success");
    if (uart.outputs.data?.type !== "bytes") throw new Error("Expected UART bytes");
    expect(new TextDecoder().decode(await readAll(uart.outputs.data.source))).toBe("HI");
    expect(uart.outputs.report).toMatchObject({ type: "structured", data: { framingErrors: 0, bitTicks: 10 } });
  });

  it("decodes PyVCD SPI mode-0 selected rising edges MSB-first", async () => {
    expect(await decodeVcdSpi(source(SPI), "spi.clk", "spi.mosi", "spi.cs", 16)).toMatchObject({ mode: 0,
      bitOrder: "msb", sampledEdges: 8, bytes: [0xa5], incompleteBits: 0, selectActiveLow: true });
    await expect(decodeVcdSpi(source(SPI.replace('#11\n1"', '#11\nx"')), "spi.clk", "spi.mosi", "spi.cs", 16)).rejects.toThrow(/unknown/);
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "hardware.vcd.spi", inputs: { data: bytesValue(source(SPI)) },
      params: { clock: "spi.clk", data: "spi.mosi", select: "spi.cs" },
    });
    expect(result.run.status).toBe("success");
    if (result.outputs.data?.type !== "bytes") throw new Error("Expected SPI bytes");
    expect(await readAll(result.outputs.data.source)).toEqual(Uint8Array.of(0xa5));
  });
});
