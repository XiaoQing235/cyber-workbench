export const MAX_RSA_PUBLIC_PEM_BYTES = 12_000;

export interface RsaPublicKeyReport {
  format: "SPKI";
  modulus: string;
  modulusBits: number;
  publicExponent: string;
}

function base64UrlInteger(encoded: string): bigint {
  if (!/^[A-Za-z0-9_-]{1,1400}$/.test(encoded)) throw new Error("RSA public JWK integer is malformed");
  const decoded = atob(encoded.replace(/-/g, "+").replace(/_/g, "/"));
  const hex = Array.from(decoded, (byte) => byte.charCodeAt(0).toString(16).padStart(2, "0")).join("");
  return BigInt(`0x${hex}`);
}

export async function inspectRsaPublicKey(pem: string, signal?: AbortSignal): Promise<RsaPublicKeyReport> {
  if (signal?.aborted) throw signal.reason;
  if (pem.length > MAX_RSA_PUBLIC_PEM_BYTES) throw new Error("RSA public PEM exceeds 12,000 characters");
  const match = /^-----BEGIN PUBLIC KEY-----\r?\n([A-Za-z0-9+/=\r\n]+)\r?\n-----END PUBLIC KEY-----$/.exec(pem.trim());
  if (!match) throw new Error("Expected an unencrypted SPKI RSA PUBLIC KEY PEM");
  const base64 = match[1].replace(/[\r\n]/g, "");
  if (base64.length > 11_000 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64)) {
    throw new Error("RSA public PEM base64 is malformed or exceeds its budget");
  }
  const der = Uint8Array.from(atob(base64), (byte) => byte.charCodeAt(0));
  if (der.length < 32 || der.length > 8_192) throw new Error("RSA public DER size is unsupported");
  const key = await crypto.subtle.importKey("spki", der, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
  if (signal?.aborted) throw signal.reason;
  const jwk = await crypto.subtle.exportKey("jwk", key);
  if (jwk.kty !== "RSA" || !jwk.n || !jwk.e) throw new Error("SPKI key did not export as a public RSA key");
  const modulus = base64UrlInteger(jwk.n);
  const exponent = base64UrlInteger(jwk.e);
  if (modulus < 2n || exponent < 3n || exponent % 2n === 0n) throw new Error("RSA public key modulus or exponent is invalid");
  return { format: "SPKI", modulus: modulus.toString(), modulusBits: modulus.toString(2).length, publicExponent: exponent.toString() };
}