import { describe, expect, it } from "vitest";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "./index";

const registry = createDefaultRegistry();
const encoder = new TextEncoder();

const ID = "93dbe988558d4077255ec55c8e868fe6";
const U = "edead21945abc7b8b15622427910ba21ea010b2200ca574bccc71ddc496a0279bd8b512a8df0616b1c673dd25ca62f15";
const O = "8658b311ec45836ec2adfcdbcdb49064e10f34433564a1b76f77423b5b3d665faafc9b4ac3806b3b1de7271234256e88";
const OE = "f8a8db696db8e7300cd05508e04c850f2b6d35002e1dd40b4c0ff9296ddadbd8";
const UE = "55992594fe468a86a639275b49da37980bcffa5546f41c99e03e651198565ffd";
const PERMS = "5722c5a0eb0642b2b6c1a1c1ff0d7353";
const R6_HASH = `$pdf$5*6*256*-4*1*16*${ID}*48*${U}*48*${O}*32*${OE}*32*${UE}`;

function classicPdf(dictionary: string, trailerExtra = ""): Uint8Array<ArrayBuffer> {
  const header = "%PDF-1.7\n";
  const object = `3 0 obj\n<< ${dictionary} >>\nendobj\n`;
  const objectOffset = encoder.encode(header).length;
  const xrefOffset = objectOffset + encoder.encode(object).length;
  return encoder.encode(`${header}${object}xref\n0 4\n0000000000 65535 f \n0000000000 00000 f \n0000000000 00000 f \n${String(objectOffset).padStart(10, "0")} 00000 n \ntrailer\n<< /Size 4 /ID [<${ID}><${ID}>] /Encrypt 3 0 R ${trailerExtra}>>\nstartxref\n${xrefOffset}\n%%EOF\n`);
}

function crossingObjectPdf(dictionary: string): Uint8Array<ArrayBuffer> {
  const header = "%PDF-1.7\n";
  const encryptionObject = `3 0 obj\n<< ${dictionary} >>\n`;
  const nextObject = "4 0 obj\nnull\nendobj\n";
  const encryptionOffset = encoder.encode(header).length;
  const nextOffset = encryptionOffset + encoder.encode(encryptionObject).length;
  const xrefOffset = nextOffset + encoder.encode(nextObject).length;
  return encoder.encode(`${header}${encryptionObject}${nextObject}xref\n0 5\n0000000000 65535 f \n0000000000 00000 f \n0000000000 00000 f \n${String(encryptionOffset).padStart(10, "0")} 00000 n \n${String(nextOffset).padStart(10, "0")} 00000 n \ntrailer\n<< /Size 5 /ID [<${ID}><${ID}>] /Encrypt 3 0 R >>\nstartxref\n${xrefOffset}\n%%EOF\n`);
}

const r6Dictionary = `/CF << /StdCF << /CFM /AESV3 /Length 32 >> >> /Filter /Standard /Length 256 /O <${O}> /OE <${OE}> /P -4 /Perms <${PERMS}> /R 6 /U <${U}> /UE <${UE}> /V 5`;

async function run(operationId: string, bytes: Uint8Array<ArrayBuffer>) {
  return executeOperation(registry, { operationId, inputs: { data: bytesFrom(bytes) }, params: {} });
}

describe("PDF password material", () => {
  it("matches current pdf2john output for a qpdf R6 fixture", async () => {
    const result = await run("document.pdf.hash-export", classicPdf(r6Dictionary));
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.hash as { text: string }).text).toBe(R6_HASH);
    expect(result.run.diagnostics).toEqual(["Exported a PDF Standard security revision 6 hash for Hashcat and John the Ripper."]);
  });

  it("reports encryption parameters without exposing a duplicate hash field", async () => {
    const result = await run("document.pdf.encryption-inspect", classicPdf(r6Dictionary));
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.report as { data: object }).data).toEqual({
      version: "1.7",
      algorithm: 5,
      revision: 6,
      keyBits: 256,
      permissions: -4,
      encryptMetadata: true,
      documentId: ID,
      userEntryBytes: 48,
      ownerEntryBytes: 48,
      userKeyBytes: 32,
      ownerKeyBytes: 32,
    });
  });

  it("exports legacy standard-security fields", async () => {
    const user = "00".repeat(32);
    const owner = "11".repeat(32);
    const result = await run("document.pdf.hash-export", classicPdf(`/Filter /Standard /V 4 /R 4 /Length 128 /P -44 /EncryptMetadata false /U <${user}> /O <${owner}>`));
    expect((result.outputs.hash as { text: string }).text).toBe(`$pdf$4*4*128*-44*0*16*${ID}*32*${user}*32*${owner}`);
  });

  it.each([
    { revision: 2, dictionary: `/Filter /Standard /V 1 /R 2 /P -4 /U <${"22".repeat(32)}> /O <${"33".repeat(32)}>`, prefix: "$pdf$1*2*40" },
    { revision: 3, dictionary: `/Filter /Standard /V 2 /R 3 /Length 128 /P -4 /U <${"44".repeat(32)}> /O <${"55".repeat(32)}>`, prefix: "$pdf$2*3*128" },
    { revision: 5, dictionary: r6Dictionary.replace("/R 6", "/R 5"), prefix: "$pdf$5*5*256" },
  ])("supports Standard security revision $revision", async ({ dictionary, prefix }) => {
    const result = await run("document.pdf.hash-export", classicPdf(dictionary));
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.hash as { text: string }).text.startsWith(prefix)).toBe(true);
  });

  it("rejects incremental trailers, duplicate fields, and truncated R6 keys", async () => {
    const incremental = await run("document.pdf.hash-export", classicPdf(r6Dictionary, "/Prev 10 "));
    expect(incremental.run.error).toMatchObject({ code: "INVALID_INPUT", message: "PDF export does not support incremental xref chains" });

    const duplicate = await run("document.pdf.hash-export", classicPdf(`${r6Dictionary} /R 6`));
    expect(duplicate.run.error).toMatchObject({ code: "INVALID_INPUT", message: "PDF encryption dictionary contains duplicate /R entries" });

    const truncated = await run("document.pdf.hash-export", classicPdf(r6Dictionary.replace(OE, "00")));
    expect(truncated.run.error).toMatchObject({ code: "INVALID_INPUT", message: "PDF owner or user encryption-key entry is invalid" });
  });

  it("rejects xref streams and mismatched encryption-object references", async () => {
    const xrefStream = encoder.encode("%PDF-1.7\n5 0 obj\n<< /Type /XRef >>\nendobj\nstartxref\n9\n%%EOF\n");
    const streamResult = await run("document.pdf.hash-export", xrefStream);
    expect(streamResult.run.error?.message).toMatch(/classic xref tables/);

    const mismatched = classicPdf(r6Dictionary);
    const text = new TextDecoder().decode(mismatched).replace("/Encrypt 3 0 R", "/Encrypt 2 0 R");
    const referenceResult = await run("document.pdf.hash-export", encoder.encode(text));
    expect(referenceResult.run.error).toMatchObject({ code: "INVALID_INPUT", message: "PDF encryption object has no matching xref entry" });
  });

  it("rejects hybrid xrefs, trailing payloads, and overlapping xref subsections", async () => {
    const hybrid = await run("document.pdf.hash-export", classicPdf(r6Dictionary, "/XRefStm 9 "));
    expect(hybrid.run.error?.message).toMatch(/hybrid xref streams/);

    const trailing = encoder.encode(`${new TextDecoder().decode(classicPdf(r6Dictionary))}payload`);
    const trailingResult = await run("document.pdf.hash-export", trailing);
    expect(trailingResult.run.error?.message).toMatch(/data after its final %%EOF/);

    const normal = new TextDecoder().decode(classicPdf(r6Dictionary));
    const objectEntry = `${String("%PDF-1.7\n".length).padStart(10, "0")} 00000 n \n`;
    const overlapping = encoder.encode(normal.replace(objectEntry, `${objectEntry}0 1\n0000000000 65535 f \n`));
    const overlapResult = await run("document.pdf.hash-export", overlapping);
    expect(overlapResult.run.error?.message).toMatch(/overlapping subsections/);
  });

  it("rejects malformed security values instead of normalizing them", async () => {
    const unsupportedV3 = await run("document.pdf.hash-export", classicPdf(`/Filter /Standard /V 3 /R 3 /Length 128 /P -4 /U <${"00".repeat(32)}> /O <${"11".repeat(32)}>`));
    expect(unsupportedV3.run.error?.message).toMatch(/V=3, R=3/);

    const unsignedPermissions = await run("document.pdf.hash-export", classicPdf(r6Dictionary.replace("/P -4", "/P 4294967292")));
    expect(unsignedPermissions.run.error?.message).toMatch(/signed 32-bit range/);

    const malformedMetadata = await run("document.pdf.hash-export", classicPdf(`${r6Dictionary} /EncryptMetadata 0`));
    expect(malformedMetadata.run.error?.message).toMatch(/must be a boolean/);

    const oversizedUser = await run("document.pdf.hash-export", classicPdf(r6Dictionary.replace(`/U <${U}>`, `/U <${U}00>`)));
    expect(oversizedUser.run.error?.message).toMatch(/exactly 48 bytes/);

    const missingPerms = await run("document.pdf.hash-export", classicPdf(r6Dictionary.replace(`/Perms <${PERMS}>`, "")));
    expect(missingPerms.run.error?.message).toMatch(/no \/Perms entry/);
  });

  it.each([
    ["U", U, `${U}00`, /exactly 48 bytes/],
    ["O", O, O.slice(2), /exactly 48 bytes/],
    ["OE", OE, OE.slice(2), /encryption-key entry is invalid/],
    ["UE", UE, `${UE}00`, /encryption-key entry is invalid/],
    ["Perms", PERMS, PERMS.slice(2), /exactly 16 bytes/],
  ])("rejects an invalid /%s field length", async (name, valid, invalid, message) => {
    const result = await run("document.pdf.hash-export", classicPdf(r6Dictionary.replace(`/${name} <${valid}>`, `/${name} <${invalid}>`)));
    expect(result.run.error?.message).toMatch(message as RegExp);
  });

  it("ignores nested and commented field-like text", async () => {
    const dictionary = r6Dictionary
      .replace("/StdCF <<", "/Fake << /R 2 /Length 40 >> /StdCF <<")
      .replace("/Filter /Standard", "% /R 2 /U <00>\n/Filter /Standard");
    const result = await run("document.pdf.hash-export", classicPdf(dictionary));
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.hash as { text: string }).text).toBe(R6_HASH);
  });

  it("rejects stray top-level dictionary tokens", async () => {
    const result = await run("document.pdf.hash-export", classicPdf(r6Dictionary.replace("/P -4", "/P -4 0")));
    expect(result.run.error?.message).toMatch(/unexpected top-level number token/);
  });

  it("ignores field-like text inside literal strings", async () => {
    const result = await run("document.pdf.hash-export", classicPdf(`${r6Dictionary} /Note (/R 2 /U <00> /Length 40)`));
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.hash as { text: string }).text).toBe(R6_HASH);
  });

  it("does not consume an endobj marker from the next xref object", async () => {
    const result = await run("document.pdf.hash-export", crossingObjectPdf(r6Dictionary));
    expect(result.run.error?.message).toMatch(/data outside its direct dictionary/);
  });
});