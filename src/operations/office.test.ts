import * as CFB from "cfb";
import { describe, expect, it } from "vitest";
import { MissingSource } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom, bytesValue } from "../core/value";
import { MAX_OFFICE_BYTES } from "../formats/officeEncryption";
import { createDefaultRegistry } from "./index";

const registry = createDefaultRegistry();
const SALT = "d45830de88e393364e6f47aa785f465d";
const VERIFIER = "f8920519ed092e7a39928bf702102deb";
const VERIFIER_HASH = "1816e7a49f884fd975547d011a0f6ab8daf97111a27445575e9886654a03bb10";
const OFFICE_HASH = `$office$*2013*100000*256*16*${SALT}*${VERIFIER}*${VERIFIER_HASH}`;
const PASSWORD_URI = "http://schemas.microsoft.com/office/2006/keyEncryptor/password";
const STANDARD_INFO = [
  "AwACACQAAACMAAAAJAAAAAAAAAAOZgAABIAAAIAAAAAYAAAAAAAAAAAAAABNAGkAYwByAG8Ac",
  "wBvAGYAdAAgAEUAbgBoAGEAbgBjAGUAZAAgAFIAUwBBACAAYQBuAGQAIABBAEUAUwAgAEMAcgB5AHAAd",
  "ABvAGcAcgBhAHAAaABpAGMAIABQAHIAbwB2AGkAZABlAHIAAAAQAAAA6IJmSQxb0e69K0OU4/gw71Fvc",
  "y6Wb6wXscXX2Mw2ySgUAAAAK2Fo2r4pEa0r03wXRnRcFNPPG7FApI9Obz0jiAhysWo=",
].join("");
const STANDARD_HASH = "$office$*2007*20*128*16*e88266490c5bd1eebd2b4394e3f830ef*516f732e966fac17b1c5d7d8cc36c928*2b6168dabe2911ad2bd37c1746745c14d3cf1bb1";

function base64(hex: string): string {
  return btoa(String.fromCharCode(...Uint8Array.from(hex.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16))));
}

function metadataXml(): string {
  const shared = 'saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512"';
  return `<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption" xmlns:p="${PASSWORD_URI}"><keyData ${shared} saltValue="${base64(SALT)}"/><keyEncryptors><keyEncryptor uri="${PASSWORD_URI}"><p:encryptedKey spinCount="100000" ${shared} saltValue="${base64(SALT)}" encryptedVerifierHashInput="${base64(VERIFIER)}" encryptedVerifierHashValue="${base64(VERIFIER_HASH + "aa".repeat(32))}"/></keyEncryptor></keyEncryptors></encryption>`;
}

function encryptedOffice(xml = metadataXml(), flags = 0x40, packagePresent = true): Uint8Array<ArrayBuffer> {
  const container = CFB.utils.cfb_new();
  const info = new Uint8Array(8 + new TextEncoder().encode(xml).length);
  const view = new DataView(info.buffer);
  view.setUint16(0, 4, true);
  view.setUint16(2, 4, true);
  view.setUint32(4, flags, true);
  info.set(new TextEncoder().encode(xml), 8);
  CFB.utils.cfb_add(container, "EncryptionInfo", info);
  if (packagePresent) CFB.utils.cfb_add(container, "EncryptedPackage", new Uint8Array(16));
  return Uint8Array.from(CFB.write(container, { type: "array" }));
}

function standardOffice(change?: (info: Uint8Array<ArrayBuffer>) => void): Uint8Array<ArrayBuffer> {
  const container = CFB.utils.cfb_new();
  const info = Uint8Array.from(atob(STANDARD_INFO), (character) => character.charCodeAt(0));
  change?.(info);
  CFB.utils.cfb_add(container, "EncryptionInfo", info);
  CFB.utils.cfb_add(container, "EncryptedPackage", new Uint8Array(16));
  return Uint8Array.from(CFB.write(container, { type: "array" }));
}

async function run(operationId: string, bytes: Uint8Array<ArrayBuffer>) {
  return executeOperation(registry, { operationId, inputs: { data: bytesFrom(bytes) }, params: {} });
}

describe("Office Agile password material", () => {
  it("exports Office 2007 Standard material verified by John and Hashcat 9400", async () => {
    const exported = await run("document.office.hash-export", standardOffice());
    expect(exported.run.error).toBeUndefined();
    expect((exported.outputs.hash as { text: string }).text).toBe(STANDARD_HASH);
    expect(exported.run.diagnostics).toEqual(["Exported Office Standard (2007) password material for Hashcat mode 9400 and John the Ripper."]);
    const inspected = await run("document.office.encryption-inspect", standardOffice());
    expect((inspected.outputs.report as { data: object }).data).toEqual({
      format: "Office Standard (2007)", container: "OLE Compound File", cipher: "AES-128-CBC", hashAlgorithm: "SHA1",
      spinCount: 50_000, saltBytes: 16, encryptedPackageBytes: 16,
    });
  });

  it("rejects unsupported Standard cipher IDs and invalid verifier sizes", async () => {
    const cipher = await run("document.office.hash-export", standardOffice((info) => new DataView(info.buffer).setUint32(20, 0x660f, true)));
    expect(cipher.run.error?.message).toMatch(/cipher or hash parameters are unsupported/);
    const invalidSize = await run("document.office.hash-export", standardOffice((info) => new DataView(info.buffer).setUint32(188, 0, true)));
    expect(invalidSize.run.error?.message).toMatch(/provider or verifier fields are invalid/);
  });

  it("exports the canonical Office 2013 line from office2john", async () => {
    const result = await run("document.office.hash-export", encryptedOffice());
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.hash as { text: string }).text).toBe(OFFICE_HASH);
    expect(result.run.diagnostics).toEqual(["Exported Office Agile (2013) password material for Hashcat mode 9600 and John the Ripper."]);
  });

  it("inspects encryption metadata without embedding the password hash", async () => {
    const result = await run("document.office.encryption-inspect", encryptedOffice());
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.report as { data: object }).data).toEqual({
      format: "Office Agile (2013)", container: "OLE Compound File", cipher: "AES-256-CBC", hashAlgorithm: "SHA512",
      spinCount: 100000, saltBytes: 16, encryptedPackageBytes: 16,
    });
  });

  it("rejects non-OLE input, missing encrypted payload, and non-Agile flags", async () => {
    const plain = await run("document.office.hash-export", new TextEncoder().encode("PK ZIP"));
    expect(plain.run.error?.message).toMatch(/not an encrypted Office compound file/);
    const missing = await run("document.office.hash-export", encryptedOffice(metadataXml(), 0x40, false));
    expect(missing.run.error?.message).toMatch(/EncryptedPackage stream is missing/);
    const standard = await run("document.office.hash-export", encryptedOffice(metadataXml(), 0x20));
    expect(standard.run.error?.message).toMatch(/only Agile 4\.4/);
  });

  it("rejects XML entities and conflicting keyData parameters", async () => {
    const entity = await run("document.office.hash-export", encryptedOffice(`<!DOCTYPE encryption [<!ENTITY secret "x">]>${metadataXml()}`));
    expect(entity.run.error?.message).toMatch(/XML is unsafe or malformed/);
    const inconsistent = await run("document.office.hash-export", encryptedOffice(metadataXml().replace('hashAlgorithm="SHA512"', 'hashAlgorithm="SHA1"')));
    expect(inconsistent.run.error?.message).toMatch(/hashAlgorithm disagrees with keyData/);
  });

  it("rejects duplicate password keys and malformed verifier bytes", async () => {
    const duplicate = metadataXml().replace("<keyEncryptors>", `<keyEncryptors><keyEncryptor uri="${PASSWORD_URI}"/>`);
    const ambiguous = await run("document.office.hash-export", encryptedOffice(duplicate));
    expect(ambiguous.run.error?.message).toMatch(/exactly one password key encryptor/);
    const malformed = await run("document.office.hash-export", encryptedOffice(metadataXml().replace(base64(VERIFIER), "@@@=")));
    expect(malformed.run.error?.message).toMatch(/encryptedVerifierHashInput has invalid base64/);
  });

  it("rejects inputs above the declared memory bound before parsing", async () => {
    const result = await executeOperation(registry, {
      operationId: "document.office.hash-export",
      inputs: { data: bytesValue(new MissingSource(MAX_OFFICE_BYTES + 1)) }, params: {},
    });
    expect(result.run.error?.code).toBe("INPUT_TOO_LARGE");
  });
});