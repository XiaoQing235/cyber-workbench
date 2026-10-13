import { describe, expect, it } from "vitest";
import { MemorySource } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { inspectDex } from "./dex";

const NATIVE = `ZGV4CjAzNQCUc/nQWyTgB+h56Xf3NCz63IziH5KVRMLQAgAAcAAAAHhWNBIAAAAAAAAAAEgCAAAKAAAA
cAAAAAQAAACYAAAAAgAAAKgAAAAAAAAAAAAAAAMAAADAAAAAAQAAANgAAADYAQAA+AAAADABAAA4AQAA
RAEAAEcBAABQAQAAZAEAAHgBAAB7AQAAhQEAAJgBAAADAAAABAAAAAUAAAAGAAAAAgAAAAIAAAAAAAAA
BgAAAAMAAAAAAAAAAAABAAAAAAAAAAAABwAAAAEAAQAAAAAAAAAAAAEAAAABAAAAAAAAAAEAAAAAAAAA
NwIAAAAAAAABAAAAAAAAACgBAAADAAAAGgAIABEAAAABAAEAAQAAACwBAAAEAAAAcBACAAAADgADAA4A
AQAOAAY8aW5pdD4ACkhlbGxvLmphdmEAAUwAB0xIZWxsbzsAEkxqYXZhL2xhbmcvT2JqZWN0OwASTGph
dmEvbGFuZy9TdHJpbmc7AAFWAAhncmVldGluZwARaGVsbG8gamFyIGZpeHR1cmUAnAF+fkQ4eyJiYWNr
ZW5kIjoiZGV4IiwiY29tcGlsYXRpb24tbW9kZSI6ImRlYnVnIiwiaGFzLWNoZWNrc3VtcyI6ZmFsc2Us
Im1pbi1hcGkiOjIxLCJzaGEtMSI6ImFiYWFiNDY5YjVlYmQ0ZGQyYmI5MWJhMGVkNmY0NTI3N2ZhYWU0
Y2EiLCJ2ZXJzaW9uIjoiOC42LjItZGV2In0AAAACAACBgASQAgEJ+AEAAAALAAAAAAAAAAEAAAAAAAAA
AQAAAAoAAABwAAAAAgAAAAQAAACYAAAAAwAAAAIAAACoAAAABQAAAAMAAADAAAAABgAAAAEAAADYAAAA
ASAAAAIAAAD4AAAAAyAAAAIAAAAoAQAAAiAAAAoAAAAwAQAAACAAAAEAAAA3AgAAABAAAAEAAABIAgAA`;
const fixture = () => new MemorySource(Uint8Array.from(atob(NATIVE.replace(/\s/g, "")), (character) => character.charCodeAt(0)));

describe("Android DEX 035 header", () => {
  it("matches independent D8 and dexdump checksums, class and method counts", async () => {
    expect(await inspectDex(fixture())).toMatchObject({ version: "035", bytes: 720, firstClassDescriptor: "LHello;", classes: 1,
      methods: 3, strings: 10, adler32Valid: true, sha1Valid: true, executed: false });
  });

  it("rejects changed data and bad table geometry", async () => {
    const changed = fixture().bytes.slice();
    changed[116] ^= 1;
    await expect(inspectDex(new MemorySource(changed))).rejects.toThrow(/Adler-32/);
    const malformed = fixture().bytes.slice();
    new DataView(malformed.buffer).setUint32(36, 64, true);
    await expect(inspectDex(new MemorySource(malformed))).rejects.toThrow(/header geometry/);
  });

  it("registers checksum-verified DEX inspection without running bytecode", async () => {
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "reverse.android.dex.inspect", inputs: { data: bytesValue(fixture()) }, params: {},
    });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { firstClassDescriptor: "LHello;", sha1Valid: true, executed: false } });
  });
});