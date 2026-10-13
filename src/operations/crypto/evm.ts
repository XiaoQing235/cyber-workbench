import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue, textValue } from "../../core/value";
import { bytesInput, textInput } from "../util";

const ZERO_ADDRESS = `0x${"00".repeat(20)}`;
const ZERO_SALT = `0x${"00".repeat(32)}`;

export const evmSelector = defineOperation<{ kind: "function" | "event" }>({
  spec: {
    id: "crypto.evm.selector", version: "1.0.0", title: "Compute EVM selector", category: "Crypto",
    description: "Compute an offline Keccak-based function selector or event topic from an ABI signature. No RPC or wallet is used.",
    keywords: ["evm", "abi", "selector", "event", "keccak", "ethereum"],
    inputs: [{ name: "text", type: "text" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: {
      type: "object", properties: { kind: { type: "string", title: "Signature kind", enum: ["function", "event"], default: "function" } },
      required: ["kind"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs, params) {
    try {
      const signature = textInput(inputs).trim();
      if (signature.length < 3 || signature.length > 512) throw new Error("EVM signature must be 3 to 512 characters");
      const { toFunctionSelector, toEventSelector } = await import("viem");
      ctx.throwIfAborted();
      const digest = params.kind === "function" ? toFunctionSelector(signature) : toEventSelector(signature);
      ctx.diagnostic(`${params.kind} ${params.kind === "function" ? "selector" : "topic"} calculated locally.`);
      return { report: structuredValue({ kind: params.kind, signature, digest, rpcUsed: false }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const evmCreate2 = defineOperation<{ deployer: string; salt: string }>({
  spec: {
    id: "crypto.evm.create2", version: "1.0.0", title: "Compute CREATE2 address", category: "Crypto",
    description: "Compute an EIP-1014 CREATE2 address from raw init-code bytes, a deployer address and a 32-byte salt. No deployment or RPC occurs.",
    keywords: ["evm", "create2", "ethereum", "address", "salt", "offline"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: {
      type: "object", properties: {
        deployer: { type: "string", title: "Deployer address", minLength: 42, maxLength: 42, default: ZERO_ADDRESS },
        salt: { type: "string", title: "32-byte salt (hex)", minLength: 66, maxLength: 66, default: ZERO_SALT },
      }, required: ["deployer", "salt"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: 256 * 1024 },
  },
  async run(ctx, inputs, params) {
    try {
      if (!/^0x[0-9a-fA-F]{40}$/.test(params.deployer) || !/^0x[0-9a-fA-F]{64}$/.test(params.salt)) throw new Error("CREATE2 needs a 20-byte deployer and 32-byte salt");
      ctx.throwIfAborted();
      const code = await readAll(bytesInput(inputs), 256 * 1024);
      const { getCreate2Address, keccak256, toHex } = await import("viem");
      const bytecode = toHex(code);
      const address = getCreate2Address({ from: params.deployer as `0x${string}`, salt: params.salt as `0x${string}`, bytecode });
      ctx.throwIfAborted();
      ctx.diagnostic(`Computed CREATE2 address for ${code.length} init-code byte(s) without RPC.`);
      return { report: structuredValue({ address, initCodeHash: keccak256(bytecode), rpcUsed: false }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const evmRlpEncode = defineOperation<Record<string, never>>({
  spec: {
    id: "crypto.evm.rlp-encode", version: "1.0.0", title: "Encode EVM RLP", category: "Crypto",
    description: "Encode an offline JSON array of hex-byte strings or nested arrays as Recursive Length Prefix bytes; input is bounded and never sent to a network.",
    keywords: ["evm", "ethereum", "rlp", "encode", "offline"],
    inputs: [{ name: "text", type: "text" }], outputs: [{ name: "text", type: "text" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs) {
    try {
      const input = textInput(inputs);
      if (input.length > 256 * 1024) throw new Error("EVM RLP JSON exceeds 256 KiB");
      const values: unknown = JSON.parse(input);
      let items = 0;
      let bytes = 0;
      const check = (item: unknown, depth: number): void => {
        if (++items > 1_024 || depth > 8) throw new Error("EVM RLP nesting or item count exceeds the budget");
        if (Array.isArray(item)) { for (const value of item) check(value, depth + 1); return; }
        if (typeof item !== "string" || !/^0x(?:[0-9a-fA-F]{2})*$/.test(item)) throw new Error("EVM RLP items must be hex byte strings");
        bytes += (item.length - 2) / 2;
        if (bytes > 64 * 1024) throw new Error("EVM RLP data exceeds 64 KiB");
      };
      if (!Array.isArray(values)) throw new Error("EVM RLP input must be a JSON array");
      check(values, 0);
      const { toRlp } = await import("viem");
      ctx.throwIfAborted();
      const encoded = toRlp(values as Parameters<typeof toRlp>[0]);
      ctx.diagnostic(`Encoded ${items} RLP value(s), ${bytes} input byte(s), without RPC.`);
      return { text: textValue(encoded) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const evmAbiParameters = defineOperation<{ mode: "encode" | "decode" }>({
  spec: {
    id: "crypto.evm.abi-parameters", version: "1.0.0", title: "Encode or decode EVM ABI", category: "Crypto",
    description: "Encode or decode bounded scalar ABI parameters offline. Supply types plus decimal-string integers and values for encoding, or types plus hex data for decoding. Arrays/tuples are deliberately unsupported.",
    keywords: ["evm", "abi", "encode", "decode", "uint256", "ethereum"],
    inputs: [{ name: "text", type: "text" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: {
      type: "object", properties: { mode: { type: "string", title: "Mode", enum: ["encode", "decode"], default: "encode" } },
      required: ["mode"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs, params) {
    try {
      const input = textInput(inputs);
      if (input.length > 128 * 1024) throw new Error("EVM ABI JSON exceeds 128 KiB");
      const request: unknown = JSON.parse(input);
      if (!request || typeof request !== "object" || Array.isArray(request)) throw new Error("EVM ABI request must be a JSON object");
      const { types, values, data } = request as Record<string, unknown>;
      if (typeof types !== "string" || types.length < 1 || types.length > 512) throw new Error("EVM ABI types must be bounded text");
      const { parseAbiParameters, encodeAbiParameters, decodeAbiParameters } = await import("viem");
      const parsed = parseAbiParameters(types);
      if (parsed.length < 1 || parsed.length > 16 || parsed.some((parameter) => !/^(?:u?int(?:[0-9]+)?|address|bool|string|bytes(?:[1-9]|[12][0-9]|3[0-2])?)$/.test(parameter.type))) throw new Error("EVM ABI supports 1 to 16 scalar parameters only");
      ctx.throwIfAborted();
      if (params.mode === "decode") {
        if (typeof data !== "string" || !/^0x(?:[0-9a-fA-F]{2})*$/.test(data) || data.length > 256 * 1024) throw new Error("EVM ABI data must be bounded hex bytes");
        const decoded = decodeAbiParameters(parsed, data as `0x${string}`);
        return { report: structuredValue({ mode: "decode", types, values: decoded.map((value) => typeof value === "bigint" ? value.toString() : value), rpcUsed: false }) };
      }
      if (!Array.isArray(values) || values.length !== parsed.length) throw new Error("EVM ABI values must match the parameter count");
      const converted = parsed.map((parameter, index) => {
        const value = values[index];
        if (/^u?int/.test(parameter.type)) {
          if (typeof value !== "string" || !/^-?\d{1,78}$/.test(value)) throw new Error(`EVM ABI integer ${index} must be a decimal string`);
          return BigInt(value);
        }
        if (parameter.type === "bool") {
          if (typeof value !== "boolean") throw new Error(`EVM ABI bool ${index} must be true or false`);
          return value;
        }
        if (parameter.type === "string") {
          if (typeof value !== "string" || value.length > 4_096) throw new Error(`EVM ABI string ${index} exceeds the budget`);
          return value;
        }
        if (typeof value !== "string" || !/^0x(?:[0-9a-fA-F]{2})+$/.test(value)) throw new Error(`EVM ABI address/bytes ${index} must be hex bytes`);
        return value;
      });
      const encoded = encodeAbiParameters(parsed, converted as Parameters<typeof encodeAbiParameters>[1]);
      return { report: structuredValue({ mode: "encode", types, encoded, rpcUsed: false }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const evmTypedDataHash = defineOperation<Record<string, never>>({
  spec: {
    id: "crypto.evm.eip712-hash", version: "1.0.0", title: "Hash EIP-712 typed data", category: "Crypto",
    description: "Hash bounded EIP-712 domain, types and message JSON offline. Returns only the digest and primary type; never signs or contacts a wallet or RPC endpoint.",
    keywords: ["evm", "eip712", "typed data", "hash", "ethereum", "offline"],
    inputs: [{ name: "text", type: "text" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
  },
  async run(ctx, inputs) {
    try {
      const text = textInput(inputs);
      if (new TextEncoder().encode(text).length > 64 * 1024) throw new Error("EIP-712 typed data exceeds 64 KiB");
      const parsed: unknown = JSON.parse(text);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("EIP-712 input must be an object");
      const { domain, types, primaryType, message } = parsed as Record<string, unknown>;
      if (!domain || typeof domain !== "object" || Array.isArray(domain) || !types || typeof types !== "object" || Array.isArray(types) ||
        !message || typeof message !== "object" || Array.isArray(message) || typeof primaryType !== "string" || !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(primaryType)) throw new Error("EIP-712 needs domain, types, primaryType and message objects");
      const definitions = Object.entries(types);
      if (definitions.length < 1 || definitions.length > 32 || definitions.some(([name, fields]) => !/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(name) || !Array.isArray(fields) || fields.length > 64 || fields.some((field) => !field || typeof field !== "object" || typeof field.name !== "string" || typeof field.type !== "string" || field.name.length > 64 || field.type.length > 64))) throw new Error("EIP-712 type definitions exceed the supported schema budget");
      const { hashTypedData } = await import("viem");
      ctx.throwIfAborted();
      const digest = hashTypedData(parsed as Parameters<typeof hashTypedData>[0]);
      ctx.diagnostic(`Hashed EIP-712 ${primaryType} locally; no wallet, signature or RPC was used.`);
      return { report: structuredValue({ primaryType, digest, signed: false, rpcUsed: false }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const evmStorageSlot = defineOperation<{ keyType: "uint256" | "address"; slot: string }>({
  spec: {
    id: "crypto.evm.mapping-slot", version: "1.0.0", title: "Compute mapping storage slot", category: "Crypto",
    description: "Compute keccak256(abi.encode(key, slot)) for a uint256 or address mapping key and a decimal slot number. Accepts a 32-byte or 20-byte key; returns only the derived slot hash.",
    keywords: ["evm", "solidity", "storage", "mapping", "keccak", "offline"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: {
      type: "object", properties: {
        keyType: { type: "string", title: "Mapping key type", enum: ["uint256", "address"], default: "uint256" },
        slot: { type: "string", title: "Storage slot (decimal)", minLength: 1, maxLength: 78, default: "0" },
      }, required: ["keyType", "slot"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: 32 },
  },
  async run(ctx, inputs, params) {
    try {
      if (!/^\d{1,78}$/.test(params.slot)) throw new Error("EVM storage slot must be a decimal uint256");
      const key = await readAll(bytesInput(inputs), 32);
      if (key.length !== (params.keyType === "address" ? 20 : 32)) throw new Error("EVM mapping key length does not match its type");
      const { encodeAbiParameters, parseAbiParameters, keccak256, toHex } = await import("viem");
      const slot = BigInt(params.slot);
      const encoded = params.keyType === "address"
        ? encodeAbiParameters(parseAbiParameters("address,uint256"), [toHex(key), slot])
        : encodeAbiParameters(parseAbiParameters("uint256,uint256"), [BigInt(toHex(key)), slot]);
      ctx.throwIfAborted();
      ctx.diagnostic("Derived mapping slot from ABI-encoded key and declared slot; no RPC used.");
      return { report: structuredValue({ keyType: params.keyType, slot: params.slot, slotHash: keccak256(encoded), rpcUsed: false }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const evmRlpDecode = defineOperation<Record<string, never>>({
  spec: {
    id: "crypto.evm.rlp-decode", version: "1.0.0", title: "Decode EVM RLP", category: "Crypto",
    description: "Decode bounded Recursive Length Prefix bytes to nested hex byte strings offline. Arbitrary decoded bytes are returned only when the operation is explicitly run.",
    keywords: ["evm", "ethereum", "rlp", "decode", "offline"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: 64 * 1024 },
  },
  async run(ctx, inputs) {
    try {
      const bytes = await readAll(bytesInput(inputs), 64 * 1024);
      const { fromRlp, toHex } = await import("viem");
      const decoded = fromRlp(toHex(bytes));
      let count = 0;
      const check = (item: unknown, depth: number): void => {
        if (++count > 1_024 || depth > 8) throw new Error("EVM decoded RLP nesting or item count exceeds the budget");
        if (Array.isArray(item)) for (const child of item) check(child, depth + 1);
        else if (typeof item !== "string" || !/^0x(?:[0-9a-fA-F]{2})*$/.test(item)) throw new Error("EVM decoded RLP item is not hex bytes");
      };
      check(decoded, 0);
      ctx.throwIfAborted();
      ctx.diagnostic(`Decoded ${count} RLP item(s) from ${bytes.length} byte(s) offline.`);
      return { report: structuredValue({ decoded, rpcUsed: false }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});