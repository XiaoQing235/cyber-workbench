import type { ByteSource } from "../core/bytes/ByteSource";
import { MemorySource, readAll } from "../core/bytes/sources";

export const MAX_MAIL_BYTES = 8 * 1024 * 1024;

export interface MailReport {
  subject: string | null;
  messageId: string | null;
  dateUtc: string | null;
  from: string | null;
  to: string[];
  received: string[];
  routing: { index: number; from: string | null; by: string | null; utc: string | null; reportedOnly: true }[];
  routingAnomalies: { newerIndex: number; olderIndex: number; kind: "older-hop-after-newer-hop" }[];
  authentication: { server: string; method: "spf" | "dkim" | "dmarc"; result: string; reportedOnly: true }[];
  dkimSignaturePresent: boolean;
  textCharacters: number;
  htmlCharacters: number;
  attachments: { index: number; filename: string | null; mimeType: string; bytes: number; sha256: string }[];
  iocs: { hosts: string[]; ipv4: string[] };
}

type ParsedMail = Awaited<ReturnType<typeof import("postal-mime")["default"]["parse"]>>;

function bounded(value: string | undefined | null, label: string, limit: number): string | null {
  if (value === undefined || value === null || value === "") return null;
  if (value.length > limit || /[\0-\x08\x0e-\x1f\x7f]/.test(value)) throw new Error(`Mail ${label} exceeds the bounded header format`);
  return value;
}

async function parseMail(source: ByteSource): Promise<ParsedMail> {
  const { default: PostalMime } = await import("postal-mime");
  if (!Number.isSafeInteger(source.size) || source.size < 1 || source.size > MAX_MAIL_BYTES) throw new Error("Mail input exceeds the 8 MiB budget");
  return PostalMime.parse(await readAll(source, MAX_MAIL_BYTES), {
    attachmentEncoding: "arraybuffer", maxNestingDepth: 32, maxHeadersSize: 256 * 1024,
    maxPartCount: 256, maxRfc822NestingDepth: 2,
  });
}

function addresses(values: ParsedMail["to"]): string[] {
  const result: string[] = [];
  for (const item of values ?? []) {
    if (item.address) result.push(bounded(item.address, "recipient", 320)!);
    for (const member of item.group ?? []) result.push(bounded(member.address, "recipient", 320)!);
  }
  if (result.length > 128) throw new Error("Mail has too many recipients");
  return result;
}

function authSegments(value: string): string[] {
  const result: string[] = [];
  let section = "";
  let quoted = false;
  let escaped = false;
  let commentDepth = 0;
  for (const character of value) {
    if (escaped) { escaped = false; section += character; continue; }
    if (character === "\\") { escaped = true; section += character; continue; }
    if (!quoted && character === "(") commentDepth++;
    if (!quoted && character === ")") commentDepth--;
    if (commentDepth < 0 || commentDepth > 8) throw new Error("Mail authentication-results comments are malformed");
    if (commentDepth === 0 && character === '"') quoted = !quoted;
    if (character === ";" && !quoted && commentDepth === 0) { result.push(section.trim()); section = ""; }
    else section += character;
  }
  if (quoted || commentDepth !== 0) throw new Error("Mail authentication-results quoting is incomplete");
  result.push(section.trim());
  return result;
}

function iocs(mail: ParsedMail, recipients: string[], received: string[]): MailReport["iocs"] {
  const hosts = new Set<string>();
  const ipv4 = new Set<string>();
  const body = `${mail.text ?? ""}\n${mail.html ?? ""}`;
  for (const match of body.matchAll(/https?:\/\/[^\s<>"']+/gi)) {
    try {
      const host = new URL(match[0].replace(/[.,;!?)]*$/, "")).hostname.toLowerCase();
      if (host.length <= 253) hosts.add(host);
    } catch { continue; }
  }
  for (const match of body.matchAll(/[\w.%+-]+@([a-z0-9.-]+\.[a-z]{2,})/gi)) hosts.add(match[1].toLowerCase());
  for (const email of [mail.from?.address, ...recipients]) {
    const host = email?.split("@").at(-1)?.toLowerCase();
    if (host && host.length <= 253) hosts.add(host);
  }
  for (const match of `${body}\n${received.join("\n")}`.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) {
    if (match[0].split(".").every((part) => Number(part) <= 255)) ipv4.add(match[0]);
  }
  return { hosts: [...hosts].sort().slice(0, 128), ipv4: [...ipv4].sort().slice(0, 128) };
}

/** Received fields are sender-supplied claims. Parse only simple from/by tokens and the final date. */
function routing(received: string[]): Pick<MailReport, "routing" | "routingAnomalies"> {
  const hops: MailReport["routing"] = received.map((value, index) => {
    const semicolon = value.lastIndexOf(";");
    const claimed = semicolon < 0 ? value : value.slice(0, semicolon);
    const token = (keyword: "from" | "by") => {
      const match = new RegExp(`(?:^|\\s)${keyword}\\s+([a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)\\b`, "i").exec(claimed);
      return match?.[1].toLowerCase() ?? null;
    };
    let utc: string | null = null;
    if (semicolon >= 0) {
      const date = value.slice(semicolon + 1).trim();
      // Reject Date.parse's permissive interpretation of unzoned dates and timezone abbreviations.
      if (/^(?:[A-Za-z]{3},?\s+)?\d{1,2}\s+[A-Za-z]{3}\s+\d{4}\s+\d{2}:\d{2}(?::\d{2})?\s+(?:[+-](?:0\d|1[0-4])[0-5]\d|(?:UT|UTC|GMT))$/i.test(date)) {
        const millis = Date.parse(date);
        if (Number.isFinite(millis)) utc = new Date(millis).toISOString();
      }
    }
    return { index, from: token("from"), by: token("by"), utc, reportedOnly: true };
  });
  const routingAnomalies: MailReport["routingAnomalies"] = [];
  for (let index = 0; index + 1 < hops.length; index++) {
    const newer = hops[index].utc;
    const older = hops[index + 1].utc;
    // Received headers appear in reverse chronological order. Allow equality and skip unknown times.
    if (newer && older && Date.parse(older) > Date.parse(newer)) {
      routingAnomalies.push({ newerIndex: index, olderIndex: index + 1, kind: "older-hop-after-newer-hop" });
    }
  }
  return { routing: hops, routingAnomalies };
}

export async function inspectMail(source: ByteSource): Promise<MailReport> {
  const mail = await parseMail(source);
  if (mail.headers.length > 1_024 || mail.attachments.length > 256) throw new Error("Mail exceeds the header or attachment budget");
  const received = mail.headers.filter((header) => header.key === "received").map((header) => bounded(header.value, "Received hop", 2_048)!);
  if (received.length > 64) throw new Error("Mail exceeds the 64-hop routing budget");
  const authentication: MailReport["authentication"] = [];
  for (const header of mail.headers.filter((item) => item.key === "authentication-results")) {
    const segments = authSegments(bounded(header.value, "authentication-results", 4_096)!);
    const server = /^[a-z0-9.-]{1,253}$/i.test(segments[0]) ? segments[0] : "unknown";
    for (const segment of segments.slice(1)) {
      const match = /^(spf|dkim|dmarc)\s*=\s*([a-z][a-z0-9_-]{0,31})(?:\s|$)/i.exec(segment);
      if (match) authentication.push({ server, method: match[1].toLowerCase() as "spf" | "dkim" | "dmarc", result: match[2].toLowerCase(), reportedOnly: true });
    }
  }
  if (authentication.length > 128) throw new Error("Mail exceeds the authentication-result budget");
  const attachments: MailReport["attachments"] = [];
  for (const [index, attachment] of mail.attachments.entries()) {
    if (!(attachment.content instanceof ArrayBuffer)) throw new Error("Mail attachment was not decoded as bytes");
    const digest = await crypto.subtle.digest("SHA-256", attachment.content);
    attachments.push({ index, filename: bounded(attachment.filename, "attachment name", 512),
      mimeType: bounded(attachment.mimeType, "attachment MIME type", 256) ?? "application/octet-stream",
      bytes: attachment.content.byteLength,
      sha256: Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("") });
  }
  const recipients = addresses(mail.to);
  const from = bounded(mail.from?.address, "sender", 320);
  const date = mail.date && /^\d{4}-\d{2}-\d{2}T.*Z$/.test(mail.date) ? mail.date : null;
  return {
    subject: bounded(mail.subject, "subject", 512), messageId: bounded(mail.messageId, "message ID", 512), dateUtc: date,
    from, to: recipients, received, ...routing(received), authentication,
    dkimSignaturePresent: mail.headers.some((header) => header.key === "dkim-signature"),
    textCharacters: mail.text?.length ?? 0, htmlCharacters: mail.html?.length ?? 0, attachments,
    iocs: iocs(mail, recipients, received),
  };
}

export async function extractMailAttachment(source: ByteSource, index: number): Promise<{ filename: string | null; data: ByteSource }> {
  const mail = await parseMail(source);
  if (!Number.isSafeInteger(index) || index < 0 || index >= mail.attachments.length) throw new Error("Mail attachment index is out of range");
  const attachment = mail.attachments[index];
  if (!(attachment.content instanceof ArrayBuffer)) throw new Error("Mail attachment was not decoded as bytes");
  return { filename: bounded(attachment.filename, "attachment name", 512), data: new MemorySource(new Uint8Array(attachment.content)) };
}
