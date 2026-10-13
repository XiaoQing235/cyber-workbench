import { describe, expect, it } from "vitest";
import { bytesFrom } from "../core/value";
import { executeOperation } from "../core/operation/execute";
import { createDefaultRegistry } from "../operations";
import { encodeBase64 } from "../operations/encoding/base64";
import { exportOpenSshJohn, inspectSshPrivateKey } from "./sshPrivateKey";

const encoder = new TextEncoder();
const registry = createDefaultRegistry();

function uint32(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const bytes = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) { bytes.set(part, offset); offset += part.length; }
  return bytes;
}

function sshString(value: string | Uint8Array): Uint8Array {
  const bytes = typeof value === "string" ? encoder.encode(value) : value;
  return concat(uint32(bytes.length), bytes);
}

function hexBytes(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
}

function bytesHex(value: Uint8Array): string {
  return [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function base64Bytes(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

function openSshKey(
  encrypted: boolean,
  cipher = encrypted ? "aes256-ctr" : "none",
  kdf = encrypted ? "bcrypt" : "none",
  options: { publicKey?: Uint8Array; privateDataBytes?: number; authTagBytes?: number; rounds?: number } = {},
): Uint8Array {
  const publicKey = options.publicKey ?? concat(sshString("ssh-ed25519"), sshString(Uint8Array.from({ length: 32 }, (_, index) => index)));
  const kdfOptions = encrypted ? concat(sshString(Uint8Array.from({ length: 16 }, (_, index) => index + 1)), uint32(options.rounds ?? 32)) : new Uint8Array();
  const privateDataBytes = options.privateDataBytes ?? (encrypted ? 160 : 152);
  const authTagBytes = options.authTagBytes ?? (/gcm@openssh\.com$|^chacha20-poly1305@/.test(cipher) ? 16 : 0);
  return concat(
    encoder.encode("openssh-key-v1\0"),
    sshString(cipher),
    sshString(kdf),
    sshString(kdfOptions),
    uint32(1),
    sshString(publicKey),
    sshString(Uint8Array.from({ length: privateDataBytes }, () => 0xaa)),
    Uint8Array.from({ length: authTagBytes }, () => 0xbb),
  );
}

function pem(label: string, body: Uint8Array, headers: string[] = []): Uint8Array {
  const encoded = encodeBase64(body, "standard", true).match(/.{1,64}/g)?.join("\n") ?? "";
  const prefix = headers.length ? `${headers.join("\n")}\n\n` : "";
  return encoder.encode(`-----BEGIN ${label}-----\n${prefix}${encoded}\n-----END ${label}-----\n`);
}

describe("SSH private-key inspection", () => {
  it("reads encrypted OpenSSH bcrypt metadata without exposing salt or payload", () => {
    const report = inspectSshPrivateKey(pem("OPENSSH PRIVATE KEY", openSshKey(true)));
    expect(report).toEqual({
      container: "OpenSSH v1",
      pemLabel: "OPENSSH PRIVATE KEY",
      encrypted: true,
      cipher: "aes256-ctr",
      kdf: "bcrypt",
      bcrypt: { saltBytes: 16, rounds: 32 },
      keyCount: 1,
      keyTypes: ["ssh-ed25519"],
      privateDataBytes: 160,
      issues: [],
    });
    expect(JSON.stringify(report)).not.toMatch(/0102030405060708|aa{8}/i);
  });

  it("reads an unencrypted raw OpenSSH envelope", () => {
    expect(inspectSshPrivateKey(openSshKey(false))).toMatchObject({ encrypted: false, cipher: "none", kdf: "none", bcrypt: null, keyTypes: ["ssh-ed25519"] });
  });

  it("validates authenticated-cipher framing", () => {
    expect(inspectSshPrivateKey(openSshKey(true, "aes256-gcm@openssh.com"))).toMatchObject({
      cipher: "aes256-gcm@openssh.com",
      privateDataBytes: 160,
    });
    expect(() => inspectSshPrivateKey(openSshKey(true, "aes256-gcm@openssh.com", "bcrypt", { authTagBytes: 0 }))).toThrow(/exactly 16 authentication-tag bytes/);
    expect(() => inspectSshPrivateKey(openSshKey(true, "aes256-ctr", "bcrypt", { authTagBytes: 1 }))).toThrow(/exactly 0 authentication-tag bytes/);
    expect(() => inspectSshPrivateKey(openSshKey(true, "chacha20-poly1305@openssh.com", "bcrypt", { privateDataBytes: 1 }))).toThrow(/8-byte cipher block size/);
  });

  it("accepts every declared OpenSSH private-key cipher framing", () => {
    const ciphers = [
      "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
      "aes128-ctr", "aes192-ctr", "aes256-ctr",
      "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
      "chacha20-poly1305@openssh.com",
    ];
    for (const cipher of ciphers) expect(inspectSshPrivateKey(openSshKey(true, cipher)).cipher).toBe(cipher);
    expect(inspectSshPrivateKey(openSshKey(true, undefined, undefined, { rounds: 0xffff_ffff })).bcrypt?.rounds).toBe(0xffff_ffff);
  });

  it("rejects noncanonical RSA values and invalid ECDSA points", () => {
    const noncanonicalRsa = concat(sshString("ssh-rsa"), sshString(Uint8Array.of(0, 1)), sshString(Uint8Array.of(1)));
    expect(() => inspectSshPrivateKey(openSshKey(true, undefined, undefined, { publicKey: noncanonicalRsa }))).toThrow(/not canonically encoded/);

    const p256Generator = hexBytes(
      "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
      "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    );
    const validEcdsa = concat(sshString("ecdsa-sha2-nistp256"), sshString("nistp256"), sshString(p256Generator));
    expect(inspectSshPrivateKey(openSshKey(true, undefined, undefined, { publicKey: validEcdsa })).keyTypes).toEqual(["ecdsa-sha2-nistp256"]);
    p256Generator[p256Generator.length - 1] ^= 1;
    const invalidEcdsa = concat(sshString("ecdsa-sha2-nistp256"), sshString("nistp256"), sshString(p256Generator));
    expect(() => inspectSshPrivateKey(openSshKey(true, undefined, undefined, { publicKey: invalidEcdsa }))).toThrow(/not on the named curve/);
  });

  it("reads OpenSSH security-key public blobs", () => {
    const ed25519 = concat(sshString("sk-ssh-ed25519@openssh.com"), sshString(new Uint8Array(32)), sshString("ssh:test"));
    expect(inspectSshPrivateKey(openSshKey(true, undefined, undefined, { publicKey: ed25519 })).keyTypes).toEqual(["sk-ssh-ed25519@openssh.com"]);

    const p256Generator = hexBytes(
      "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
      "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    );
    const ecdsa = concat(sshString("sk-ecdsa-sha2-nistp256@openssh.com"), sshString("nistp256"), sshString(p256Generator), sshString("ssh:test"));
    expect(inspectSshPrivateKey(openSshKey(true, undefined, undefined, { publicKey: ecdsa })).keyTypes).toEqual(["sk-ecdsa-sha2-nistp256@openssh.com"]);
  });

  it("exports John $sshng$ material with exact cipher metadata and offsets", () => {
    for (const [cipher, johnCipher] of [["aes256-cbc", "2"], ["aes256-ctr", "6"]] as const) {
      const decoded = openSshKey(true, cipher);
      const fields = exportOpenSshJohn(pem("OPENSSH PRIVATE KEY", decoded)).split("$");
      expect(fields).toEqual([
        "", "sshng", johnCipher, "16", "0102030405060708090a0b0c0d0e0f10",
        String(decoded.length), bytesHex(decoded), "32", String(decoded.indexOf(0xaa)),
      ]);
    }
  });

  it("matches current ssh2john output for real ssh-keygen CTR and CBC keys", () => {
    const vectors = [
      {
        cipher: "6",
        salt: "d4978c325f1f2019385ed3da494dcd3f",
        body: "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDUl4wyXx8gGThe09pJTc0/AAAAJQAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIEtbvFamARgLKIRPk5JCl35W2nL8G3Csa/SVOwOY4FZ8AAAAoLocCbSwfGyLqebzSvaAh20Z1LzY9mvvGkXhCEnxTifRZvxVNiQnadfA7mBeJsiK22cOss570a8oe0EyKHydfEHLw1erUpk5Rmbl2om6CgO0EI0iApw5at3hWSg5IcxPxO+mPlRBKfyeQMuiZI7H5TrMkL5XFHa4hIGMkfvQpsshtFIHqXajNH91TM2Tb+IOCtPhljLbHiZaJ/UcVg1bfM0=",
      },
      {
        cipher: "2",
        salt: "1a81850984f2b13251017ddb5eef8fb5",
        body: "b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABAagYUJhPKxMlEBfdte74+1AAAAJQAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIP79dqMhE99xIYFRRKdBEDmQCtK341LSExCuZRJ1LrPOAAAAoJbH/rqt0+o9RCVX/NSq5+3fV8XTKhpX3U4PcnrcsFBgU/6evuYyALuz+Xc7jzncqTjOVCbNAEeM4Km1f7mhCpW3Z143bhKQ3hZ/zLT+TuRpT1Avligw31syVmBGHg7V4uqIz4s8+YUd4ZJ4m+y9Scy30YhHL1BecTAR/aw3BKWEl988K8RCU1nskzTEA9zWN4JeJyYIfEXavlIIK4v4dfs=",
      },
    ];
    for (const vector of vectors) {
      const decoded = base64Bytes(vector.body);
      expect(exportOpenSshJohn(decoded)).toBe(`$sshng$${vector.cipher}$16$${vector.salt}$290$${bytesHex(decoded)}$37$130`);
    }
  });

  it("exports compatible envelopes independently of strict public-key inspection", () => {
    const dsaPublicBlob = concat(sshString("ssh-dss"), Uint8Array.of(1, 2, 3, 4));
    const key = openSshKey(true, undefined, undefined, { publicKey: dsaPublicBlob });
    expect(() => inspectSshPrivateKey(key)).toThrow(/Unsupported OpenSSH public key type/);
    expect(exportOpenSshJohn(key)).toMatch(/^\$sshng\$6\$16\$/);
  });

  it("rejects OpenSSH keys that John cannot consume", () => {
    expect(() => exportOpenSshJohn(openSshKey(false))).toThrow(/not password encrypted/);
    expect(() => exportOpenSshJohn(openSshKey(true, "aes256-gcm@openssh.com"))).toThrow(/does not support/);
    expect(() => exportOpenSshJohn(openSshKey(true, "aes128-cbc"))).toThrow(/does not support/);
    expect(exportOpenSshJohn(openSshKey(true, "aes256-ctr", "bcrypt", { privateDataBytes: 16 }))).toMatch(/\$146\$/);
    expect(exportOpenSshJohn(openSshKey(true, "aes256-ctr", "bcrypt", { privateDataBytes: 8048 }))).toMatch(/\$8178\$/);
    expect(() => exportOpenSshJohn(openSshKey(true, "aes256-ctr", "bcrypt", { privateDataBytes: 8064 }))).toThrow(/between 128 and 8192 bytes/);
  });

  it("rejects unsupported PEM types, contradictory encryption markers, and truncated fields", () => {
    expect(() => inspectSshPrivateKey(pem("PUBLIC KEY", Uint8Array.of(1)))).toThrow(/not an OpenSSH v1/);
    expect(() => inspectSshPrivateKey(pem("PRIVATE KEY", Uint8Array.of(1, 2, 3)))).toThrow(/not an OpenSSH v1/);
    expect(() => inspectSshPrivateKey(openSshKey(true, "none", "bcrypt"))).toThrow(/none cipher requires/);
    expect(() => inspectSshPrivateKey(openSshKey(true, "made-up-cipher", "bcrypt"))).toThrow(/supported cipher/);
    expect(() => inspectSshPrivateKey(encoder.encode("-----BEGIN PRIVATE KEY-----\nAQ==\n-----END RSA PRIVATE KEY-----\n"))).toThrow(/end marker is missing/);
    expect(() => inspectSshPrivateKey(encoder.encode("-----BEGIN OPENSSH PRIVATE KEY-----\nAQ==-----END OPENSSH PRIVATE KEY-----\n"))).toThrow(/end marker is missing/);
    expect(() => inspectSshPrivateKey(openSshKey(true).subarray(0, 40))).toThrow(/truncated|bounds/);
  });

  it("runs through the public operation registry", async () => {
    const result = await executeOperation(registry, { operationId: "credential.ssh-private-key.inspect", inputs: { data: bytesFrom(new Uint8Array(openSshKey(true))) }, params: {} });
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.report as { data: unknown }).data).toMatchObject({ encrypted: true, bcrypt: { saltBytes: 16, rounds: 32 } });

    const exported = await executeOperation(registry, { operationId: "credential.ssh-private-key.john-export", inputs: { data: bytesFrom(new Uint8Array(openSshKey(true))) }, params: {} });
    expect(exported.run.error).toBeUndefined();
    expect(exported.outputs.hash).toMatchObject({ type: "text", text: expect.stringMatching(/^\$sshng\$6\$16\$/) });
  });
});