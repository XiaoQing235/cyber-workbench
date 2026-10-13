import { describe, expect, it } from "vitest";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom, textValue } from "../core/value";
import { createDefaultRegistry } from "./index";

const registry = createDefaultRegistry();

describe("offline EVM primitives", () => {
  it("matches ERC-20 transfer's function selector", async () => {
    const result = await executeOperation(registry, {
      operationId: "crypto.evm.selector", inputs: { text: textValue("transfer(address,uint256)") }, params: {},
    });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { digest: "0xa9059cbb", rpcUsed: false } });
  });

  it("matches EIP-1014's zero-deployer zero-salt 0x00 init-code address", async () => {
    const result = await executeOperation(registry, {
      operationId: "crypto.evm.create2", inputs: { data: bytesFrom(Uint8Array.of(0)) }, params: {},
    });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { address: "0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38", rpcUsed: false } });
  });

  it("RLP-encodes a pair of byte strings and rejects unsafe item shapes", async () => {
    const good = await executeOperation(registry, { operationId: "crypto.evm.rlp-encode", inputs: { text: textValue('["0x01","0x02"]') }, params: {} });
    expect(good.run.status).toBe("success");
    expect(good.outputs.text).toMatchObject({ type: "text", text: "0xc20102" });
    const bad = await executeOperation(registry, { operationId: "crypto.evm.rlp-encode", inputs: { text: textValue('["0x01", {"danger": true}]') }, params: {} });
    expect(bad.run.error?.code).toBe("INVALID_INPUT");
  });

  it("encodes and decodes ERC-20-style scalar ABI parameters losslessly", async () => {
    const address = "0x000000000000000000000000000000000000dEaD";
    const encoded = `0x${"0".repeat(60)}dead${"0".repeat(61)}3e8`;
    const request = { types: "address,uint256", values: [address, "1000"] };
    const result = await executeOperation(registry, {
      operationId: "crypto.evm.abi-parameters", inputs: { text: textValue(JSON.stringify(request)) }, params: {},
    });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { mode: "encode", encoded, rpcUsed: false } });
    const decoded = await executeOperation(registry, {
      operationId: "crypto.evm.abi-parameters", inputs: { text: textValue(JSON.stringify({ types: request.types, data: encoded })) }, params: { mode: "decode" },
    });
    expect(decoded.outputs.report).toMatchObject({ type: "structured", data: { mode: "decode", values: [address, "1000"] } });
  });

  it("hashes the canonical Ether Mail EIP-712 data without returning message values", async () => {
    const person = [{ name: "name", type: "string" }, { name: "wallet", type: "address" }];
    const data = {
      domain: { name: "Ether Mail", version: "1", chainId: 1, verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC" },
      types: { Person: person, Mail: [{ name: "from", type: "Person" }, { name: "to", type: "Person" }, { name: "contents", type: "string" }] },
      primaryType: "Mail", message: {
        from: { name: "Cow", wallet: "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826" },
        to: { name: "Bob", wallet: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB" }, contents: "Hello, Bob!",
      },
    };
    const result = await executeOperation(registry, { operationId: "crypto.evm.eip712-hash", inputs: { text: textValue(JSON.stringify(data)) }, params: {} });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { primaryType: "Mail", digest: "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2", signed: false, rpcUsed: false } });
    expect(JSON.stringify(result.outputs)).not.toContain("Hello, Bob!");
  });

  it("computes the canonical key-zero slot-zero mapping and decodes RLP bytes", async () => {
    const slot = await executeOperation(registry, {
      operationId: "crypto.evm.mapping-slot", inputs: { data: bytesFrom(new Uint8Array(32)) }, params: {},
    });
    expect(slot.run.status).toBe("success");
    expect(slot.outputs.report).toMatchObject({ type: "structured", data: { slotHash: "0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5", rpcUsed: false } });
    const decoded = await executeOperation(registry, {
      operationId: "crypto.evm.rlp-decode", inputs: { data: bytesFrom(Uint8Array.of(0xc2, 1, 2)) }, params: {},
    });
    expect(decoded.outputs.report).toMatchObject({ type: "structured", data: { decoded: ["0x01", "0x02"], rpcUsed: false } });
    const invalid = await executeOperation(registry, {
      operationId: "crypto.evm.mapping-slot", inputs: { data: bytesFrom(new Uint8Array(20)) }, params: {},
    });
    expect(invalid.run.error?.code).toBe("INVALID_INPUT");
  });
});