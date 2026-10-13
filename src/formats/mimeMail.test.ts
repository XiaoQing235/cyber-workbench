import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractMailAttachment, inspectMail } from "./mimeMail";

const BOUNDARY = "===============6529724477734351114==";
const EML = [
  "From: Alice <alice@example.com>",
  "To: Bob <bob@example.net>",
  "Subject: Fixture invoice",
  "Date: Sun, 11 Oct 2026 21:10:00 +1100",
  "Message-ID: <fixture-001@example.com>",
  "Received: from relay.example.com by mx.example.net with ESMTPS; Sun, 11 Oct 2026 21:10:00 +1100",
  "Received: from sender.example.com by relay.example.com with ESMTP; Sun, 11 Oct 2026 21:09:00 +1100",
  "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=example.com; dkim=fail header.d=evil.example; dmarc=fail header.from=example.com",
  "MIME-Version: 1.0",
  `Content-Type: multipart/mixed; boundary="${BOUNDARY}"`,
  "",
  `--${BOUNDARY}`,
  'Content-Type: text/plain; charset="utf-8"',
  "Content-Transfer-Encoding: quoted-printable",
  "",
  "Review https://audit.example.org/report?token=3DFAKE-HIDDEN-QUERY-123. Contact analyst@example.org.",
  `--${BOUNDARY}`,
  "Content-Type: application/octet-stream",
  "Content-Transfer-Encoding: base64",
  'Content-Disposition: attachment; filename="evidence.bin"',
  "",
  "ZmxhZ3ttaW1lX2F0dGFjaG1lbnRfZml4dHVyZX0K",
  `--${BOUNDARY}--`,
  "",
].join("\r\n");

const source = () => new MemorySource(new TextEncoder().encode(EML));

describe("offline MIME evidence", () => {
  it("reports hops, asserted SPF/DKIM/DMARC and IOC hosts without leaking body or attachment values", async () => {
    const report = await inspectMail(source());
    expect(report).toMatchObject({
      subject: "Fixture invoice", dateUtc: "2026-10-11T10:10:00.000Z", from: "alice@example.com", to: ["bob@example.net"],
      authentication: [
        { server: "mx.example.net", method: "spf", result: "pass", reportedOnly: true },
        { server: "mx.example.net", method: "dkim", result: "fail", reportedOnly: true },
        { server: "mx.example.net", method: "dmarc", result: "fail", reportedOnly: true },
      ],
      attachments: [{ index: 0, filename: "evidence.bin", bytes: 30, sha256: "827a8d6f1179308dce9fe353f532d5547260e1467813264970b2678820adeca8" }],
    });
    expect(report.received).toHaveLength(2);
    expect(report.routing).toEqual([
      { index: 0, from: "relay.example.com", by: "mx.example.net", utc: "2026-10-11T10:10:00.000Z", reportedOnly: true },
      { index: 1, from: "sender.example.com", by: "relay.example.com", utc: "2026-10-11T10:09:00.000Z", reportedOnly: true },
    ]);
    expect(report.routingAnomalies).toEqual([]);
    expect(report.iocs.hosts).toContain("audit.example.org");
    expect(JSON.stringify(report)).not.toContain("FAKE-HIDDEN-QUERY-123");
    expect(JSON.stringify(report)).not.toContain("flag{mime_attachment_fixture}");
  });

  it("extracts the same decoded attachment as the independent Python fixture", async () => {
    const attachment = await extractMailAttachment(source(), 0);
    expect(attachment.filename).toBe("evidence.bin");
    expect(new TextDecoder().decode(await readAll(attachment.data))).toBe("flag{mime_attachment_fixture}\n");
    await expect(extractMailAttachment(source(), 1)).rejects.toThrow(/out of range/);
  });

  it("keeps MIME content out of registered reports and exports bytes explicitly", async () => {
    const registry = createDefaultRegistry();
    const data = bytesFrom(new TextEncoder().encode(EML));
    const inspected = await executeOperation(registry, { operationId: "forensics.mail.inspect", inputs: { data }, params: {} });
    expect(inspected.run.status).toBe("success");
    expect(JSON.stringify(inspected.outputs)).not.toContain("FAKE-HIDDEN-QUERY-123");
    expect(inspected.outputs.report).toMatchObject({ type: "structured", data: { received: [expect.any(String), expect.any(String)] } });
    const extracted = await executeOperation(registry, { operationId: "forensics.mail.attachment-extract", inputs: { data }, params: {} });
    expect(extracted.run.status).toBe("success");
    if (extracted.outputs.data?.type !== "bytes") throw new Error("Expected mail attachment bytes");
    expect(new TextDecoder().decode(await readAll(extracted.outputs.data.source))).toBe("flag{mime_attachment_fixture}\n");
  });

  it("does not treat auth-method text in a parenthesized comment as a DKIM verdict", async () => {
    const commented = EML.replace("mx.example.net; spf=pass", "mx.example.net (note; dkim=pass); spf=pass");
    const report = await inspectMail(new MemorySource(new TextEncoder().encode(commented)));
    expect(report.authentication.find((entry) => entry.method === "dkim")?.result).toBe("fail");
  });

  it("flags inconsistent claimed hop order without interpreting ambiguous timestamps", async () => {
    const later = EML.replace("21:09:00 +1100", "21:11:00 +1100");
    expect((await inspectMail(new MemorySource(new TextEncoder().encode(later)))).routingAnomalies)
      .toEqual([{ newerIndex: 0, olderIndex: 1, kind: "older-hop-after-newer-hop" }]);
    const unzoned = EML.replace("21:09:00 +1100", "21:09:00 PST");
    const report = await inspectMail(new MemorySource(new TextEncoder().encode(unzoned)));
    expect(report.routing[1].utc).toBeNull();
    expect(report.routingAnomalies).toEqual([]);
  });

  it("parses the independently published postal-mime nested multipart vector through the mail operation", async () => {
    // MIT-licensed postal-mime test/fixtures/mixed.eml, published by Andris Reinman.
    const bytes = new Uint8Array(readFileSync(new URL("./testing/postal-mime-mixed.eml", import.meta.url)));
    expect(createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex"))
      .toBe("3718c9b1cd67b57896d83dd08fc838fee8642562");
    const report = await inspectMail(new MemorySource(bytes));
    expect(report).toMatchObject({ received: [], routing: [], routingAnomalies: [], attachments: [], authentication: [] });
    expect(report.textCharacters).toBeGreaterThan(80);
    expect(report.htmlCharacters).toBeGreaterThan(80);
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "forensics.mail.inspect",
      inputs: { data: bytesFrom(bytes) }, params: {} });
    expect(operation.run.status).toBe("success");
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: {
      textCharacters: report.textCharacters, htmlCharacters: report.htmlCharacters, attachments: [],
    } });
  });

  it("summarizes routing and claimed authentication in the published multi-hop bounce", async () => {
    const bytes = new Uint8Array(readFileSync(new URL("./testing/postal-mime-bounce.eml", import.meta.url)));
    expect(createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex"))
      .toBe("ab82052f236146b037143af73ab734d11ec89d83");
    const report = await inspectMail(new MemorySource(bytes));
    expect(report.subject).toBe("Undelivered Mail Returned to Sender");
    expect(report.received.length).toBeGreaterThan(3);
    expect(report.routing[0]).toMatchObject({ from: "compute1.internal", by: "sloti52n10", utc: "2022-10-10T05:37:22.000Z", reportedOnly: true });
    expect(report.authentication).toEqual(expect.arrayContaining([
      { server: "mx4.messagingengine.com", method: "dkim", result: "none", reportedOnly: true },
      { server: "mx4.messagingengine.com", method: "dmarc", result: "pass", reportedOnly: true },
      { server: "mx4.messagingengine.com", method: "spf", result: "pass", reportedOnly: true },
    ]));
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "forensics.mail.inspect",
      inputs: { data: bytesFrom(bytes) }, params: {} });
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: {
      routing: report.routing, routingAnomalies: report.routingAnomalies,
    } });
  });
});
