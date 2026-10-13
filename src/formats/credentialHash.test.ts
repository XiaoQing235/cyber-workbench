import { describe, expect, it } from "vitest";
import { identifyCredentialHashes } from "./credentialHash";

describe("credential hash identification", () => {
  it("distinguishes NetNTLMv1 and NetNTLMv2 by field shape", async () => {
    const v1 = `alice::LAB:${"11".repeat(24)}:${"22".repeat(24)}:${"33".repeat(8)}`;
    const v2 = `bob::LAB:${"44".repeat(8)}:${"55".repeat(16)}:0101000000000000${"66".repeat(16)}0000000000000000`;
    expect((await identifyCredentialHashes(`${v1}\n${v2}`, 10)).matches).toMatchObject([
      { format: "NetNTLMv1", hashcatModes: [5500], johnFormats: ["netntlm"] },
      { format: "NetNTLMv2", hashcatModes: [5600], johnFormats: ["netntlmv2"] },
    ]);
  });

  it("identifies pwdump and valid Unix shadow formats without retaining identities", async () => {
    const lines = [
      `Administrator:500:${"a".repeat(32)}:${"b".repeat(32)}:::`,
      `service:$1$salt$${"C".repeat(22)}`,
      `builder:$5$salt$${"D".repeat(43)}`,
      `root:$6$salt$${"A".repeat(86)}`,
      `$2x$12$${"B".repeat(53)}`,
    ];
    const report = await identifyCredentialHashes(lines.join("\n"), 10);
    expect(report.matches).toMatchObject([
      { format: "Windows pwdump (LM + NTLM)", hashcatModes: [3000, 1000], johnFormats: ["LM", "NT"] },
      { format: "Unix md5crypt", hashcatModes: [500] },
      { format: "Unix sha256crypt", hashcatModes: [7400] },
      { format: "Unix sha512crypt", hashcatModes: [1800] },
      { format: "bcrypt", hashcatModes: [3200] },
    ]);
    expect(JSON.stringify(report)).not.toMatch(/Administrator|service|builder|root|a{32}|b{32}|C{22}|D{43}|A{86}|B{53}/);
  });

  it("parses full Unix shadow aging fields without retaining the account", async () => {
    const line = `example-user:$6$salt$${"A".repeat(86)}:19344:0:99999:7:::`;
    const report = await identifyCredentialHashes(line, 10);
    expect(report.matches).toMatchObject([{ format: "Unix sha512crypt", hashcatModes: [1800], johnFormats: ["sha512crypt"] }]);
    expect(JSON.stringify(report)).not.toMatch(/example-user|19344|A{86}/);
    const malformed = await identifyCredentialHashes(`example-user:$6$salt$${"A".repeat(86)}:not-aging:0:1:7:::`, 10);
    expect(malformed.matches).toEqual([]);
  });

  it("classifies Kerberos etype-23 AS-REP and TGS-REP without retaining identities", async () => {
    const asrep = `$krb5asrep$23$alice@LAB.EXAMPLE:${"11".repeat(16)}$${"22".repeat(64)}`;
    const tgs = `$krb5tgs$23$*bob$LAB.EXAMPLE$HTTP/server.lab.example*$${"33".repeat(16)}$${"44".repeat(64)}`;
    const report = await identifyCredentialHashes(`${asrep}\n${tgs}`, 10);
    expect(report.matches).toMatchObject([
      { format: "Kerberos 5 AS-REP (etype 23)", hashcatModes: [18200], johnFormats: ["krb5asrep"] },
      { format: "Kerberos 5 TGS-REP (etype 23)", hashcatModes: [13100], johnFormats: ["krb5tgs"] },
    ]);
    expect(JSON.stringify(report)).not.toMatch(/alice|bob|LAB.EXAMPLE|HTTP\/server|1{32}|2{128}/);
  });

  it("rejects truncated, odd-length, and wrong-etype Kerberos records", async () => {
    const invalid = [
      `$krb5asrep$23$alice@LAB:${"11".repeat(15)}$${"22".repeat(64)}`,
      `$krb5asrep$23$alice@LAB:${"11".repeat(16)}$${"22".repeat(32)}f`,
      `$krb5tgs$23$*bob$LAB$HTTP/service*$${"33".repeat(16)}$${"44".repeat(31)}`,
      `$krb5tgs$18$*bob$LAB$HTTP/service*$${"33".repeat(16)}$${"44".repeat(64)}`,
    ];
    const report = await identifyCredentialHashes(invalid.join("\n"), 10);
    expect(report.matches).toEqual([]);
    expect(report.unrecognised).toHaveLength(invalid.length);
  });

  it("validates NTLMv2 AV pairs and rejects malformed lengths or missing terminators", async () => {
    const prefix = `bob::LAB:${"44".repeat(8)}:${"55".repeat(16)}:0101000000000000${"66".repeat(16)}00000000`;
    const valid = `${prefix}02000400aabbccdd00000000`;
    const badLength = `${prefix}02000800aabb00000000`;
    const noTerminator = `${prefix}02000400aabbccdd`;
    const report = await identifyCredentialHashes([valid, badLength, noTerminator].join("\n"), 10);
    expect(report.matches).toMatchObject([{ format: "NetNTLMv2", hashcatModes: [5600] }]);
    expect(report.unrecognised).toHaveLength(2);
  });

  it("keeps raw 32-hex material ambiguous and preserves unknown line metadata", async () => {
    const report = await identifyCredentialHashes(`${"f".repeat(32)}\nnot-a-hash`, 10);
    expect(report.matches[0]).toMatchObject({ confidence: "ambiguous", hashcatModes: [0, 1000] });
    expect(report.matches[0].notes[0]).toMatch(/cannot distinguish MD5 from NTLM/);
    expect(report.matches[0].johnFormats).toEqual(["Raw-MD5", "NT"]);
    expect(report.unrecognised).toEqual([{ line: 2, length: 10 }]);
  });

  it("rejects unsupported tags, malformed crypt, and malformed NetNTLMv2 material", async () => {
    const invalid = ["$7z$", "$keepass$garbage", "$RAR3$*0*", "$krb5asrep$23$bad", "$y$j9T$salt$digest", "$2b$invalid", "$6$x$y", `bob::LAB:${"44".repeat(8)}:${"55".repeat(16)}:${"66".repeat(32)}`];
    const report = await identifyCredentialHashes(invalid.join("\n"), 10);
    expect(report.matches).toEqual([]);
    expect(report.unrecognised).toHaveLength(invalid.length);
  });

  it("bounds processing by non-empty lines while retaining source line numbers", async () => {
    const report = await identifyCredentialHashes(`\n${"1".repeat(32)}\n\n${"2".repeat(32)}`, 1);
    expect(report).toMatchObject({ truncated: true, matches: [{ line: 2 }] });
  });

  it("yields while scanning long input", async () => {
    let yields = 0;
    await identifyCredentialHashes("x".repeat(40_000), 10, async () => { yields++; });
    expect(yields).toBeGreaterThanOrEqual(2);
  });

  it("propagates cancellation from a yield boundary", async () => {
    await expect(identifyCredentialHashes("x".repeat(40_000), 10, async () => { throw new DOMException("cancelled", "AbortError"); })).rejects.toMatchObject({ name: "AbortError" });
  });
});