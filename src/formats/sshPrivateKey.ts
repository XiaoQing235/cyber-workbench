const OPENSSH_MAGIC = "openssh-key-v1\0";
const MAX_FIELD_BYTES = 1024 * 1024;
const MAX_KEY_BYTES = 2 * 1024 * 1024;
const OPENSSH_CIPHERS = new Map<string, { blockSize: number; authLength: number }>([
  ["none", { blockSize: 8, authLength: 0 }],
  ["3des-cbc", { blockSize: 8, authLength: 0 }],
  ["aes128-cbc", { blockSize: 16, authLength: 0 }],
  ["aes192-cbc", { blockSize: 16, authLength: 0 }],
  ["aes256-cbc", { blockSize: 16, authLength: 0 }],
  ["aes128-ctr", { blockSize: 16, authLength: 0 }],
  ["aes192-ctr", { blockSize: 16, authLength: 0 }],
  ["aes256-ctr", { blockSize: 16, authLength: 0 }],
  ["aes128-gcm@openssh.com", { blockSize: 16, authLength: 16 }],
  ["aes256-gcm@openssh.com", { blockSize: 16, authLength: 16 }],
  ["chacha20-poly1305@openssh.com", { blockSize: 8, authLength: 16 }],
]);

const NIST_CURVES = {
  nistp256: {
    coordinateBytes: 32,
    prime: BigInt("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
    b: BigInt("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
  },
  nistp384: {
    coordinateBytes: 48,
    prime: BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
    b: BigInt("0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
  },
  nistp521: {
    coordinateBytes: 66,
    prime: (1n << 521n) - 1n,
    b: BigInt("0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00"),
  },
} as const;

export interface SshPrivateKeyReport {
  container: "OpenSSH v1";
  pemLabel: string | null;
  encrypted: boolean;
  cipher: string;
  kdf: string;
  bcrypt: { saltBytes: number; rounds: number } | null;
  keyCount: number | null;
  keyTypes: string[];
  privateDataBytes: number | null;
  issues: string[];
}

class SshReader {
  private offset = 0;

  constructor(private readonly bytes: Uint8Array) {}

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  get position(): number {
    return this.offset;
  }

  readBytes(length: number, label: string): Uint8Array {
    if (length > MAX_FIELD_BYTES) {
      throw new Error(`${label} exceeds the ${MAX_FIELD_BYTES}-byte field limit.`);
    }
    if (length > this.remaining) throw new Error(`${label} exceeds the container bounds`);
    const value = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  readUint32(): number {
    if (this.remaining < 4) throw new Error("OpenSSH field is truncated");
    const value = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.offset, 4).getUint32(0, false);
    this.offset += 4;
    return value;
  }

  readString(): Uint8Array {
    const length = this.readUint32();
    if (length > MAX_FIELD_BYTES) throw new Error(`OpenSSH field exceeds the ${MAX_FIELD_BYTES}-byte limit`);
    if (length > this.remaining) throw new Error("OpenSSH string exceeds the container bounds");
    const value = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }
}

function ascii(bytes: Uint8Array, field: string): string {
  if (bytes.length > 256) throw new Error(`${field} exceeds 256 bytes`);
  if (bytes.some((byte) => byte < 0x20 || byte > 0x7e)) throw new Error(`${field} is not printable ASCII`);
  return String.fromCharCode(...bytes);
}

function decodePem(bytes: Uint8Array): { label: string; headers: Map<string, string>; body: Uint8Array } | null {
  if (bytes.some((byte) => byte !== 0x09 && byte !== 0x0a && byte !== 0x0d && (byte < 0x20 || byte > 0x7e))) return null;
  const text = new TextDecoder().decode(bytes).replace(/\r/g, "");
  const begin = /^-----BEGIN ([A-Z0-9 ]+)-----$/m.exec(text);
  if (!begin) return null;
  if (text.slice(0, begin.index).trim() !== "") throw new Error("PEM container has leading non-whitespace data");
  const bodyStart = begin.index + begin[0].length;
  if (text[bodyStart] !== "\n") throw new Error("PEM begin marker must occupy a complete line");
  const endMarker = `-----END ${begin[1]}-----`;
  const endStart = text.indexOf(`\n${endMarker}`, bodyStart + 1);
  if (endStart < 0) throw new Error(`PEM ${begin[1]} end marker is missing`);
  if (text.slice(endStart + 1 + endMarker.length).trim() !== "") throw new Error("PEM container has trailing non-whitespace data");
  const bodyText = text.slice(bodyStart + 1, endStart);
  const headers = new Map<string, string>();
  if (bodyText.includes(":")) headers.set("unsupported", "legacy PEM header");
  const encoded = bodyText.replace(/\n/g, "");
  if (encoded.length > Math.ceil(MAX_KEY_BYTES / 3) * 4) throw new Error(`PEM body exceeds the ${MAX_KEY_BYTES}-byte decoded input limit`);
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(encoded) || encoded.length === 0 || encoded.length % 4 !== 0) throw new Error("PEM body is not valid padded Base64");
  try {
    return { label: begin[1], headers, body: Uint8Array.from(atob(encoded), (character) => character.charCodeAt(0)) };
  } catch {
    throw new Error("PEM body could not be decoded as Base64");
  }
}

function validateRsaMpint(value: Uint8Array, label: string): void {
  if (value.length === 0 || (value[0] & 0x80) !== 0) throw new Error(`OpenSSH RSA ${label} must be a positive mpint`);
  if (value[0] === 0 && (value.length === 1 || (value[1] & 0x80) === 0)) throw new Error(`OpenSSH RSA ${label} is not canonically encoded`);
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function validateEcdsaPoint(curveName: keyof typeof NIST_CURVES, point: Uint8Array): void {
  const curve = NIST_CURVES[curveName];
  if (point.length !== 1 + (2 * curve.coordinateBytes) || point[0] !== 0x04) {
    throw new Error(`OpenSSH ECDSA ${curveName} point is not uncompressed SEC1 data of the expected length`);
  }
  const x = bytesToBigInt(point.subarray(1, 1 + curve.coordinateBytes));
  const y = bytesToBigInt(point.subarray(1 + curve.coordinateBytes));
  if (x >= curve.prime || y >= curve.prime) throw new Error(`OpenSSH ECDSA ${curveName} point coordinate is out of range`);
  const left = (y * y) % curve.prime;
  const right = (((x * x % curve.prime) * x) - (3n * x) + curve.b + (3n * curve.prime)) % curve.prime;
  if (left !== right) throw new Error(`OpenSSH ECDSA ${curveName} point is not on the named curve`);
}

function publicKeyType(blob: Uint8Array): string {
  const reader = new SshReader(blob);
  const type = ascii(reader.readString(), "OpenSSH public key type");
  if (type === "ssh-ed25519") {
    if (reader.readString().length !== 32) throw new Error("OpenSSH Ed25519 public key is not 32 bytes");
  } else if (type === "sk-ssh-ed25519@openssh.com") {
    if (reader.readString().length !== 32) throw new Error("OpenSSH security-key Ed25519 public key is not 32 bytes");
    reader.readString();
  } else if (type === "ssh-rsa") {
    validateRsaMpint(reader.readString(), "exponent");
    validateRsaMpint(reader.readString(), "modulus");
  } else if (type === "sk-ecdsa-sha2-nistp256@openssh.com") {
    const curve = ascii(reader.readString(), "OpenSSH security-key ECDSA curve");
    if (curve !== "nistp256") throw new Error("OpenSSH security-key ECDSA public key has inconsistent curve metadata");
    validateEcdsaPoint("nistp256", reader.readString());
    reader.readString();
  } else if (/^ecdsa-sha2-nistp(?:256|384|521)$/.test(type)) {
    const curve = ascii(reader.readString(), "OpenSSH ECDSA curve");
    if (!(curve in NIST_CURVES) || type !== `ecdsa-sha2-${curve}`) throw new Error("OpenSSH ECDSA public key has inconsistent curve metadata");
    validateEcdsaPoint(curve as keyof typeof NIST_CURVES, reader.readString());
  } else {
    throw new Error(`Unsupported OpenSSH public key type: ${type}`);
  }
  if (reader.remaining !== 0) throw new Error(`OpenSSH ${type} public key has trailing data`);
  return type;
}

function publicKeyTypeForExport(blob: Uint8Array): string {
  const type = ascii(new SshReader(blob).readString(), "OpenSSH public key type");
  if (type.length === 0) throw new Error("OpenSSH public key type is empty");
  return type;
}

interface ParsedOpenSsh {
  bytes: Uint8Array;
  report: SshPrivateKeyReport;
  bcryptSalt: Uint8Array | null;
  ciphertextOffset: number;
}

function parseOpenSsh(bytes: Uint8Array, pemLabel: string | null, validatePublicKeys: boolean): ParsedOpenSsh {
  const magic = Uint8Array.from(OPENSSH_MAGIC, (character) => character.charCodeAt(0));
  if (bytes.length < magic.length || !magic.every((byte, index) => bytes[index] === byte)) throw new Error("OpenSSH key magic is missing");
  const reader = new SshReader(bytes.subarray(magic.length));
  const cipher = ascii(reader.readString(), "OpenSSH cipher name");
  const kdf = ascii(reader.readString(), "OpenSSH KDF name");
  const kdfOptions = reader.readString();
  const keyCount = reader.readUint32();
  if (keyCount === 0) throw new Error("OpenSSH container has no keys");
  if (keyCount > 1024) throw new Error("OpenSSH key count exceeds 1,024");
  const keyTypes: string[] = [];
  for (let index = 0; index < keyCount; index++) {
    const publicBlob = reader.readString();
    keyTypes.push(validatePublicKeys ? publicKeyType(publicBlob) : publicKeyTypeForExport(publicBlob));
  }
  let bcrypt: SshPrivateKeyReport["bcrypt"] = null;
  let bcryptSalt: Uint8Array | null = null;
  if (kdf === "bcrypt") {
    const options = new SshReader(kdfOptions);
    const salt = options.readString();
    const rounds = options.readUint32();
    if (options.remaining !== 0) throw new Error("OpenSSH bcrypt options contain trailing data");
    if (salt.length === 0 || rounds === 0) throw new Error("OpenSSH bcrypt options contain an empty salt or zero rounds");
    bcryptSalt = salt;
    bcrypt = { saltBytes: salt.length, rounds };
  }

  const encrypted = cipher !== "none";
  const cipherMetadata = OPENSSH_CIPHERS.get(cipher);
  if (!cipherMetadata) throw new Error(`Encrypted OpenSSH keys require a supported cipher; received ${cipher}`);
  if (!encrypted && (kdf !== "none" || kdfOptions.length !== 0)) throw new Error("OpenSSH none cipher requires the none KDF with empty options");
  if (encrypted && (kdf !== "bcrypt" || !bcrypt)) throw new Error("Encrypted OpenSSH keys require a supported cipher and bcrypt KDF");
  const privateDataLength = reader.readUint32();
  const ciphertextOffset = OPENSSH_MAGIC.length + reader.position;
  const privateData = reader.readBytes(privateDataLength, "OpenSSH private-key payload");
  if (privateDataLength < cipherMetadata.blockSize || privateDataLength % cipherMetadata.blockSize !== 0) {
    throw new Error(`OpenSSH private-key payload must be a positive multiple of the ${cipherMetadata.blockSize}-byte cipher block size`);
  }
  if (reader.remaining !== cipherMetadata.authLength) {
    throw new Error(`OpenSSH ${cipher} payload requires exactly ${cipherMetadata.authLength} authentication-tag bytes`);
  }
  reader.readBytes(cipherMetadata.authLength, "OpenSSH authentication tag");
  return {
    bytes,
    bcryptSalt,
    ciphertextOffset,
    report: { container: "OpenSSH v1", pemLabel, encrypted, cipher, kdf, bcrypt, keyCount, keyTypes, privateDataBytes: privateData.length, issues: [] },
  };
}

function parseSshPrivateKey(bytes: Uint8Array, validatePublicKeys: boolean): ParsedOpenSsh {
  if (bytes.length > MAX_KEY_BYTES) throw new Error(`SSH private key exceeds the ${MAX_KEY_BYTES}-byte limit`);
  const pem = decodePem(bytes);
  if (!pem) return parseOpenSsh(bytes, null, validatePublicKeys);
  if (pem.label !== "OPENSSH PRIVATE KEY") throw new Error(`PEM label ${pem.label} is not an OpenSSH v1 private-key container`);
  if (pem.headers.size !== 0) throw new Error("OpenSSH v1 PEM must not contain legacy encryption headers");
  return parseOpenSsh(pem.body, pem.label, validatePublicKeys);
}

function toHex(bytes: Uint8Array): string {
  let output = "";
  for (const byte of bytes) output += byte.toString(16).padStart(2, "0");
  return output;
}

export function inspectSshPrivateKey(bytes: Uint8Array): SshPrivateKeyReport {
  return parseSshPrivateKey(bytes, true).report;
}

export function exportOpenSshJohn(bytes: Uint8Array): string {
  const parsed = parseSshPrivateKey(bytes, false);
  const { bcrypt, cipher, encrypted } = parsed.report;
  if (!encrypted || !bcrypt || !parsed.bcryptSalt) throw new Error("OpenSSH key is not password encrypted with bcrypt");
  const johnCipher = cipher === "aes256-cbc" ? 2 : cipher === "aes256-ctr" ? 6 : null;
  if (johnCipher === null) throw new Error(`John the Ripper SSH export does not support OpenSSH cipher ${cipher}`);
  if (parsed.bcryptSalt.length !== 16) throw new Error("John the Ripper SSH export requires a 16-byte bcrypt salt");
  if (parsed.bytes.length < 128 || parsed.bytes.length > 8192) throw new Error("John the Ripper SSH export requires a decoded key blob between 128 and 8192 bytes");
  if (parsed.ciphertextOffset > parsed.bytes.length - 16) throw new Error("OpenSSH ciphertext offset leaves fewer than 16 encrypted bytes");
  return `$sshng$${johnCipher}$16$${toHex(parsed.bcryptSalt)}$${parsed.bytes.length}$${toHex(parsed.bytes)}$${bcrypt.rounds}$${parsed.ciphertextOffset}`;
}