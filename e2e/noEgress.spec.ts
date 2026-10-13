import { createPublicKey, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { expect, test, type Page } from "@playwright/test";

test("private text and files never leave the browser during local operations", async ({ page, context, baseURL }) => {
  const origin = new URL(baseURL!).origin;
  const secret = `m6-private-${randomUUID()}`;
  const encoded = Buffer.from(secret).toString("base64");
  const forbidden: string[] = [];
  const packFiles: string[] = [];
  await context.routeWebSocket("**/*", async (route) => {
    forbidden.push(`WebSocket ${route.url()}`);
    await route.close();
  });
  await context.route("**/*", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const body = request.postData() ?? "";
    const headers = JSON.stringify(request.headers());
    if (url.origin !== origin || request.method() !== "GET" ||
      [request.url(), body, headers].some((value) => value.includes(secret) || value.includes(encoded))) {
      forbidden.push(`${request.method()} ${url.origin}${url.pathname}`);
      await route.abort();
      return;
    }
    if (url.pathname.includes("/assets/pack-")) packFiles.push(url.pathname);
    await route.continue();
  });

  await page.goto("/");
  await page.getByPlaceholder("Type or paste text…").fill(encoded);
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Hash (SHA family)" }).click();
  await page.getByRole("button", { name: "File / artifact" }).click();
  await page.locator('main input[type="file"]').setInputFiles({
    name: "private.bin", mimeType: "application/octet-stream", buffer: Buffer.from(secret),
  });
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();

  expect(forbidden).toEqual([]);
  expect(packFiles).toEqual([]);
});

test("seccomp and format-string plans run offline as local operations without a runtime pack", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Inspect seccomp filter" }).click();
  await page.getByRole("button", { name: "File / artifact" }).click();
  await page.locator('main input[type="file"]').setInputFiles({
    name: "filter.bpf", mimeType: "application/octet-stream",
    buffer: Buffer.from("200000000000000015000000010000000600000000000500060000000000ff7f", "hex"),
  });
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const filterReport = JSON.parse(await page.locator("main pre").last().innerText()) as { sample: { action: string; trace: number[] } };
  expect(filterReport.sample).toMatchObject({ action: "ERRNO", trace: [0, 1, 2] });

  await page.getByRole("button", { name: "Plan format-string byte writes" }).click();
  await page.getByRole("textbox", { name: "First write address (hex)" }).fill("0x404040");
  await page.getByRole("textbox", { name: "Little-endian value (hex)" }).fill("0x10");
  await page.getByRole("spinbutton", { name: "Bytes to write" }).fill("1");
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const plan = JSON.parse(await page.locator("main pre").last().innerText()) as { format: string; addressesEmbedded: boolean };
  expect(plan).toMatchObject({ format: "%1$16c%2$hhn", addressesEmbedded: false });
  await page.getByRole("spinbutton", { name: "Bytes to write" }).fill("2");
  await page.getByRole("spinbutton", { name: "Bytes per write (1 = hhn, 2 = hn)" }).fill("2");
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByRole("button", { name: "Run", exact: true })).toBeVisible();
  const halfword = JSON.parse(await page.locator("main pre").last().innerText()) as { format: string; writeWidthBytes: number };
  expect(halfword).toMatchObject({ format: "%1$16c%2$hn", writeWidthBytes: 2 });
  expect(packFiles).toEqual([]);
});

test("Burp XML comparison stays local and returns no request payload", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  const xml = `<?xml version="1.0"?><items>
    <item><url>https://api.example.org/check?token=PRIVATE&amp;cb=1</url><method>GET</method><status>200</status><request base64="true">UFJJVkFURQ==</request><response base64="true">UFJJVkFURQ==</response></item>
    <item><url>https://api.example.org/check?token=SECRET&amp;cb=2</url><method>GET</method><status>403</status><request base64="true">U0VDUkVU</request><response base64="true">U0VDUkVU</response></item>
  </items>`;
  await page.goto("/");
  await page.getByRole("button", { name: "Compare Burp requests" }).click();
  await page.getByRole("button", { name: "File / artifact" }).click();
  await page.locator('main input[type="file"]').setInputFiles({ name: "capture.xml", mimeType: "application/xml", buffer: Buffer.from(xml) });
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const report = JSON.parse(await page.locator("main pre").last().innerText()) as { changed: { request: string; baselineStatus: number; candidateStatus: number }[] };
  expect(report.changed).toMatchObject([{ request: "GET https://api.example.org/check?token", baselineStatus: 200, candidateStatus: 403 }]);
  expect(JSON.stringify(report)).not.toMatch(/PRIVATE|SECRET|UFJJVkFURQ|U0VDUkVU/);

  const headerRequest = (headers: string) => Buffer.from(`GET /check HTTP/1.1\r\nHost: api.example.org\r\nAuthorization: PRIVATE\r\n${headers}\r\n`).toString("base64");
  const headerXml = `<?xml version="1.0"?><items>
    <item><url>https://api.example.org/check</url><method>GET</method><request base64="true">${headerRequest("X-Test: one\r\nX-Test: two\r\n")}</request><response base64="true">UFJJVkFURQ==</response></item>
    <item><url>https://api.example.org/check</url><method>GET</method><request base64="true">${headerRequest("X-Test: SECRET\r\n")}</request><response base64="true">U0VDUkVU</response></item>
  </items>`;
  await page.getByRole("button", { name: "Compare Burp headers" }).click();
  await page.locator('main input[type="file"]').setInputFiles({ name: "headers.xml", mimeType: "application/xml", buffer: Buffer.from(headerXml) });
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const headerReport = JSON.parse(await page.locator("main pre").last().innerText()) as { changed: { header: string; baselineValues: number; candidateValues: number }[] };
  expect(headerReport.changed).toMatchObject([{ header: "x-test", baselineValues: 2, candidateValues: 1 }]);
  expect(JSON.stringify(headerReport)).not.toMatch(/PRIVATE|SECRET|UFJJVkFURQ|U0VDUkVU/);
  const response = (headers: string) => Buffer.from(`HTTP/1.1 200 OK\r\nSet-Cookie: PRIVATE\r\n${headers}\r\nSECRET BODY`).toString("base64");
  const responseXml = `<?xml version="1.0"?><items>
    <item><url>https://api.example.org/check</url><method>GET</method><response base64="true">${response("X-Trace: one\r\nX-Trace: two\r\n")}</response></item>
    <item><url>https://api.example.org/check</url><method>GET</method><response base64="true">${response("X-Trace: SECRET\r\n")}</response></item>
  </items>`;
  await page.locator('main input[type="file"]').setInputFiles({ name: "responses.xml", mimeType: "application/xml", buffer: Buffer.from(responseXml) });
  await page.getByRole("combobox", { name: "Headers from" }).selectOption("response");
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByRole("button", { name: "Running…" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Run", exact: true })).toBeVisible();
  const responseReport = JSON.parse(await page.locator("main pre").last().innerText()) as { changed: { header: string; baselineValues: number; candidateValues: number }[] };
  expect(responseReport.changed).toMatchObject([{ header: "x-trace", baselineValues: 2, candidateValues: 1 }]);
  expect(JSON.stringify(responseReport)).not.toMatch(/PRIVATE|SECRET|200 OK/);
  expect(packFiles).toEqual([]);
});

test("licensed OTP image pair, subset and full set improve their shared permutation without a pack", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Improve shared pixel permutation" }).click();
  await page.getByRole("button", { name: "File / artifact" }).click();
  await page.locator('main input[type="file"][multiple]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/google-ctf-2024-otp-pair.zip", import.meta.url)));
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const report = JSON.parse(await page.locator("main pre").last().innerText()) as { initialScore: number; finalScore: number; flagRecovered: boolean };
  expect(report.initialScore).toBe(323_017_296);
  expect(report.finalScore).toBeLessThan(report.initialScore);
  expect(report.flagRecovered).toBe(false);
  await page.locator('main input[type="file"][multiple]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/google-ctf-2024-otp-24.zip", import.meta.url)));
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByRole("button", { name: "Run", exact: true })).toBeVisible();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const full = JSON.parse(await page.locator("main pre").last().innerText()) as {
    images: string[]; initialScore: number; finalScore: number; flagRecovered: boolean;
  };
  expect(full.images).toHaveLength(24);
  expect(full.finalScore).toBeLessThan(full.initialScore);
  expect(full.flagRecovered).toBe(false);
  await expect(page.locator("main")).toContainText("mapping");
  await expect(page.locator("main")).toContainText("[0,");
  await page.getByRole("spinbutton", { name: "Candidate image index (zero-based)" }).fill("1");
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByRole("button", { name: "Run", exact: true })).toBeVisible();
  const selected = JSON.parse(await page.locator("main pre").last().innerText()) as { selectedImage: string; finalScore: number };
  expect(selected).toMatchObject({ selectedImage: "2nd01.png", finalScore: full.finalScore });
  await page.getByRole("spinbutton", { name: "Candidate image index (zero-based)" }).fill("0");
  await page.getByRole("spinbutton", { name: "Maximum swaps" }).fill("1000");
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByRole("button", { name: "Run", exact: true })).toBeVisible();
  const partial = JSON.parse(await page.locator("main pre").last().innerText()) as { finalScore: number };
  const mapText = await page.locator('main textarea').last().inputValue();
  await page.getByRole("textbox", { name: "Previous position map JSON (blank = new search)" }).fill(mapText);
  await page.getByRole("spinbutton", { name: "Swaps attempted before this batch" }).fill("1000");
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByRole("button", { name: "Run", exact: true })).toBeVisible();
  const resumed = JSON.parse(await page.locator("main pre").last().innerText()) as { initialScore: number; finalScore: number };
  expect(resumed.initialScore).toBe(partial.finalScore);
  expect(resumed.finalScore).toBe(full.finalScore);
  await page.locator('main input[type="file"][multiple]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/google-ctf-2024-otp-64.zip", import.meta.url)));
  await page.getByRole("textbox", { name: "Previous position map JSON (blank = new search)" }).fill("");
  await page.getByRole("spinbutton", { name: "Swaps attempted before this batch" }).fill("0");
  await page.getByRole("spinbutton", { name: "Candidate image index (zero-based)" }).fill("63");
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByRole("button", { name: "Run", exact: true })).toBeVisible();
  const all = JSON.parse(await page.locator("main pre").last().innerText()) as { images: string[]; selectedImage: string; initialScore: number; finalScore: number };
  expect(all.images).toHaveLength(64);
  expect(all.selectedImage).toBe("2nd63.png");
  expect(all.finalScore).toBeLessThan(all.initialScore);
  expect(packFiles).toEqual([]);
});

test("licensed Numerology package recovers its candidate flag locally", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Recover one-quarter-round stream" }).click();
  await page.getByRole("button", { name: "File / artifact" }).click();
  await page.locator('main input[type="file"]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/google-ctf-2025-numerology.json", import.meta.url)));
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const report = JSON.parse(await page.locator("main pre").last().innerText()) as { counter: number; utf8Candidate: string; verified: boolean };
  expect(report.counter).toBe(32279);
  expect(report.utf8Candidate).toBe("CTF{w3_aRe_g0Nn@_ge7_MY_FuncKee_monkey_!!}");
  expect(report.verified).toBe(false);
  expect(packFiles).toEqual([]);
});

test("original Primes attachment recovers its re-encoded flag offline", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  const script = readFileSync(fileURLToPath(new URL("../src/formats/testing/google-ctf-2023-primes-chal.sage", import.meta.url)), "utf8");
  const message = script.match(/^m = b"([^"]+)"$/m)?.[1];
  const q = script.match(/^# q = (0x[0-9a-f]+)$/im)?.[1];
  const x = script.match(/^# x = (0x[0-9a-f]+)$/im)?.[1];
  if (!message || !q || !x) throw new Error("Original Primes attachment is incomplete");
  await page.goto("/");
  await page.getByRole("button", { name: "Recover indexed-prime message" }).click();
  await page.locator("main textarea").first().fill(JSON.stringify({ message, q, x }));
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const report = JSON.parse(await page.locator("main pre").last().innerText()) as { candidate: string; verifiedEncoding: boolean; correctedBits: number };
  expect(report).toMatchObject({ candidate: "I have a sweet flag for you: CTF{w0W_c0Nt1nUed_fr4Ct10ns_suR3_Ar3_fUn_Huh}",
    verifiedEncoding: true, correctedBits: 135 });
  expect(packFiles).toEqual([]);
});

test("original Auxin2 ROM checks the published payload's static constraints locally", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  const payload = "efef3921212fefefefa5a5a53a3a3a3a3a3a3a3a840494cfcf1a01190505152194cfcfcf8484011a011a1a1a011a1a0da528058509442babd41d99850a1d0a0a1a85adbcd41dbcd41d3c090999851d1c85158509241d992504f50505050505056b71616c";
  await page.goto("/");
  await page.getByRole("button", { name: "Inspect Auxin2 Uxn constraints" }).click();
  await page.getByRole("button", { name: "File / artifact" }).click();
  await page.locator('main input[type="file"]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/google-ctf-2024-auxin2.rom", import.meta.url)));
  await page.getByRole("textbox", { name: "Payload bytes (lowercase hex, optional)" }).fill(payload);
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const report = JSON.parse(await page.locator("main pre").last().innerText()) as { rom: { shellcodeAddress: string; executingRom: boolean }; payload: { bytes: number; acceptedByStaticFilter: boolean; executed: boolean } };
  expect(report).toMatchObject({ rom: { shellcodeAddress: "0x01d0", executingRom: false }, payload: {
    bytes: 100, acceptedByStaticFilter: true, executed: false,
  } });
  expect(packFiles).toEqual([]);
});

test("original Symatrix PNG yields its complete mirrored-pixel candidate locally", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Decode mirrored Symatrix pixels" }).click();
  await page.getByRole("button", { name: "File / artifact" }).click();
  await page.locator('main input[type="file"]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/google-ctf-2023-symatrix.png", import.meta.url)));
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const result = JSON.parse(await page.locator("main pre").last().innerText()) as { candidate: string; bits: number; verifiedFlag: boolean };
  expect(result).toMatchObject({ candidate: "CTF{W4ke_Up_Ne0+Th1s_I5_Th3_Fl4g!}", bits: 272, verifiedFlag: false });
  expect(packFiles).toEqual([]);
});

test("original NPC hint verifies only a supplied graph-valid password candidate locally", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  const input = readFileSync(fileURLToPath(new URL("../src/formats/testing/google-ctf-2023-npc-hint.dot", import.meta.url)), "utf8");
  await page.goto("/");
  await page.getByRole("button", { name: "Verify labeled NPC hint path" }).click();
  await page.locator("main textarea").first().fill(input);
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const result = JSON.parse(await page.locator("main pre").last().innerText()) as { nodes: number; statesExplored: number; graphValid: boolean; passwordVerified: boolean };
  expect(result).toMatchObject({ nodes: 28, statesExplored: 53, graphValid: true, passwordVerified: false });
  expect(packFiles).toEqual([]);
});

test("original NPC graph and full word list discover password candidates locally", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  const hint = readFileSync(fileURLToPath(new URL("../src/formats/testing/google-ctf-2023-npc-hint.dot", import.meta.url)), "utf8");
  const dictionary = readFileSync(fileURLToPath(new URL("../src/formats/testing/google-ctf-2023-npc-USACONST.TXT", import.meta.url)), "latin1");
  await page.goto("/");
  await page.getByRole("button", { name: "Search NPC graph dictionary" }).click();
  await page.locator("main textarea").first().fill(JSON.stringify({ hint, dictionary }));
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible({ timeout: 30_000 });
  const report = JSON.parse(await page.locator("main pre").last().innerText()) as { dictionaryWords: number; candidates: string[]; truncated: boolean };
  expect(report.dictionaryWords).toBe(1_087);
  expect(report.candidates).toContain("standardwatersigngivenchosen");
  expect(report.truncated).toBe(true);
  expect(packFiles).toEqual([]);
});

test("original NPC graph and age file recover the flag in one local run", async ({ page, context }) => {
  test.setTimeout(90_000);
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  const hint = readFileSync(fileURLToPath(new URL("../src/formats/testing/google-ctf-2023-npc-hint.dot", import.meta.url)), "utf8");
  const dictionary = readFileSync(fileURLToPath(new URL("../src/formats/testing/google-ctf-2023-npc-USACONST.TXT", import.meta.url)), "latin1");
  const ageCiphertextHex = readFileSync(fileURLToPath(new URL("../src/formats/testing/google-ctf-2023-npc-secret.age", import.meta.url))).toString("hex");
  await page.goto("/");
  await page.getByRole("button", { name: "Search NPC graph dictionary" }).click();
  await page.locator("main textarea").first().fill(JSON.stringify({ hint, dictionary, ageCiphertextHex }));
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible({ timeout: 70_000 });
  const report = JSON.parse(await page.locator("main pre").last().innerText()) as { truncated: boolean; flagVerified: boolean;
    age: { authenticated: boolean; attempts: number; passphrase: string; utf8Candidate: string } };
  expect(report.truncated).toBe(true);
  expect(report.age.authenticated).toBe(true);
  expect(report.age.attempts).toBeLessThanOrEqual(16);
  expect(report.age.passphrase).toBe("standardwatersigngivenchosen");
  expect(report.age.utf8Candidate).toBe("CTF{S3vEn_bR1dg35_0f_K0eN1g5BeRg}");
  expect(report.flagVerified).toBe(false);
  expect(packFiles).toEqual([]);
});

test("original NPC age file decrypts with the published passphrase locally", async ({ page, context }) => {
  test.setTimeout(90_000);
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Decrypt age passphrase file" }).click();
  await page.getByRole("textbox", { name: "Age passphrase" }).fill("standardwatersigngivenchosen");
  await page.getByRole("button", { name: "File / artifact" }).click();
  await page.locator('main input[type="file"]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/google-ctf-2023-npc-secret.age", import.meta.url)));
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible({ timeout: 60_000 });
  const report = JSON.parse(await page.locator("main pre").last().innerText()) as { authenticated: boolean; workFactor: number; utf8Candidate: string; flagVerified: boolean };
  expect(report).toMatchObject({ authenticated: true, workFactor: 19,
    utf8Candidate: "CTF{S3vEn_bR1dg35_0f_K0eN1g5BeRg}", flagVerified: false });
  expect(packFiles).toEqual([]);
});

test("PNG2 reconstructed pixels yield a local colour-isolated prefix", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Decode PNG2 image" }).click();
  await page.getByRole("button", { name: "File / artifact" }).click();
  await page.locator('main input[type="file"]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/google-ctf-2023-reproduced.png2", import.meta.url)));
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByRole("button", { name: "Run", exact: true })).toBeVisible();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: /Decode PNG2 image → data bytes/ }).click();
  await page.getByRole("button", { name: "Isolate coloured image region" }).click();
  await page.getByRole("spinbutton", { name: "Left pixel" }).fill("320");
  await page.getByRole("spinbutton", { name: "Top pixel" }).fill("215");
  await page.getByRole("spinbutton", { name: "Crop width" }).fill("390");
  await page.getByRole("spinbutton", { name: "Crop height" }).fill("180");
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByRole("button", { name: "Run", exact: true })).toBeVisible();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const report = JSON.parse(await page.locator("main pre").last().innerText()) as { width: number; height: number; coloredPixels: number; textRecovered: boolean };
  expect(report).toMatchObject({ width: 390, height: 180, textRecovered: false });
  expect(report.coloredPixels).toBeGreaterThan(1_000);
  expect(packFiles).toEqual([]);
});

test("original StarCraft capture yields its sparse glyphs locally", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Plot Storm build packets" }).click();
  await page.getByRole("button", { name: "File / artifact" }).click();
  await page.locator('main input[type="file"]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/google-ctf-2019-sc.pcapng", import.meta.url)));
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const report = JSON.parse(await page.locator("main pre").last().innerText()) as { packets: number; matches: number; uniquePoints: number; glyphText: string; flagCandidate: string; flagRecovered: boolean };
  expect(report).toMatchObject({ packets: 16_827, matches: 62, uniquePoints: 61, glyphText: "6Pool", flagCandidate: "CTF{6Pool}", flagRecovered: false });
  expect(packFiles).toEqual([]);
});

test("original laser engraver capture exposes its servo timeline locally", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Plot USB engraver servo trace" }).click();
  await page.getByRole("button", { name: "File / artifact" }).click();
  await page.locator('main input[type="file"]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/google-ctf-2022-engraver.pcapng", import.meta.url)));
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const report = JSON.parse(await page.locator("main pre").last().innerText()) as { packets: number; commands: unknown[]; strokes: unknown[];
    servoCounts: Record<string, number>; laserOnCommands: number; laserOffCommands: number; flagRecovered: boolean };
  expect(report).toMatchObject({ packets: 860, servoCounts: { 1: 76, 2: 118, 3: 95, 4: 43, 5: 43, 6: 43 },
    laserOnCommands: 30, laserOffCommands: 46, flagRecovered: false });
  expect(report.commands).toHaveLength(418);
  expect(report.strokes).toHaveLength(101);
  expect(packFiles).toEqual([]);
});

test("original Polyglot ZIP inputs yield CRC-verified entries locally", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  for (const [archive, name, bytes] of [["first", "header.txt", 24], ["second", "arepa.txt", 32_768]] as const) {
    await page.goto("/");
    await page.getByRole("button", { name: "Extract unencrypted ZIP entry" }).click();
    await page.getByRole("button", { name: "File / artifact" }).click();
    await page.locator('main input[type="file"]').setInputFiles(fileURLToPath(new URL(`../src/formats/testing/google-ctf-2018-polyglot-${archive}.zip`, import.meta.url)));
    await page.getByRole("button", { name: "Run", exact: true }).click();
    await expect(page.getByText("success", { exact: true })).toBeVisible();
    const report = JSON.parse(await page.locator("main pre").last().innerText()) as { name: string; bytes: number; verified: boolean };
    expect(report).toMatchObject({ name, bytes, verified: true });
  }
  expect(packFiles).toEqual([]);
});

test("original Polyglot ZIP pair composes the reference archive locally", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Compose ZIP polyglot" }).click();
  await page.getByRole("button", { name: "File / artifact" }).click();
  await page.locator('main input[type="file"]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/google-ctf-2018-polyglot-pair.zip", import.meta.url)));
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const report = JSON.parse(await page.locator("main pre").last().innerText()) as { bytes: number; independentExtractorValidationRequired: boolean; flagRecovered: boolean };
  expect(report).toMatchObject({ bytes: 131_881, independentExtractorValidationRequired: true, flagRecovered: false });
  expect(packFiles).toEqual([]);
});

test("7-Zip Copy archive extracts verified bytes without a runtime pack", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Extract 7z Copy file" }).click();
  await page.getByRole("button", { name: "File / artifact" }).click();
  await page.locator('main input[type="file"]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/7zip-26-copy.7z", import.meta.url)));
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  await expect(page.locator("main")).toContainText("bytes · 930 B");
  await page.locator('main input[type="file"]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/7zip-26-two-copy.7z", import.meta.url)));
  await page.getByRole("spinbutton", { name: "File index (zero-based)" }).fill("1");
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  await expect(page.locator("main")).toContainText("bytes · 795 B");
  expect(packFiles).toEqual([]);
});

test("original EVTX exports selected BinXML bytes without a runtime pack", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Extract EVTX BinXML bytes" }).click();
  await page.getByRole("button", { name: "File / artifact" }).click();
  await page.locator('main input[type="file"]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/plaso-system.evtx", import.meta.url)));
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  await expect(page.locator("main")).toContainText("0f 01 01 00");
  await page.getByRole("button", { name: "Inspect EVTX substitutions" }).click();
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const values = JSON.parse(await page.locator("main pre").last().innerText()) as { fieldsMapped: boolean; substitutions: { index: number; value: string | null }[] };
  expect(values.fieldsMapped).toBe(false);
  expect(values.substitutions[2]).toMatchObject({ index: 2, value: "105" });
  expect(values.substitutions[10]).toMatchObject({ index: 10, value: "12049" });
  await page.getByRole("button", { name: "Inspect EVTX inline names" }).click();
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByRole("button", { name: "Run", exact: true })).toBeVisible();
  const names = JSON.parse(await page.locator("main pre").last().innerText()) as {
    candidateNames: boolean; fieldsMapped: boolean; names: { name: string }[];
  };
  expect(names).toMatchObject({ candidateNames: true, fieldsMapped: false });
  expect(names.names.map((item) => item.name)).toContain("EventID");
  await page.getByRole("button", { name: "Extract EVTX substitution bytes" }).click();
  await page.getByRole("spinbutton", { name: "Substitution index (zero-based)" }).fill("19");
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByRole("button", { name: "Run", exact: true })).toBeVisible();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  await expect(page.locator("main")).toContainText("bytes · 597 B");
  await page.getByRole("button", { name: "Inspect nested EVTX substitutions" }).click();
  await page.getByRole("spinbutton", { name: "Nested substitution index (zero-based)" }).fill("19");
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByRole("button", { name: "Run", exact: true })).toBeVisible();
  const nested = JSON.parse(await page.locator("main pre").last().innerText()) as { fieldsMapped: boolean; substitutions: { value: string }[] };
  expect(nested).toMatchObject({ fieldsMapped: false, substitutions: [{ value: "System" },
    { value: "C:\\Windows\\System32\\Winevt\\Logs\\Archive-System-2012-03-14-04-17-39-932.evtx" }] });
  await page.getByRole("spinbutton", { name: "Record index within chunk (zero-based)" }).fill("1");
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByRole("button", { name: "Run", exact: true })).toBeVisible();
  const second = JSON.parse(await page.locator("main pre").last().innerText()) as { substitutions: { value: string | null }[] };
  expect(second.substitutions).toMatchObject([{ value: "Windows Modules Installer" }, { value: "stopped" }, { value: "38" }, { value: null }]);
  await page.getByRole("button", { name: "Extract nested EVTX value" }).click();
  await page.getByRole("spinbutton", { name: "Record index within chunk (zero-based)" }).fill("1");
  await page.getByRole("spinbutton", { name: "Nested value index (zero-based)" }).fill("3");
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByRole("button", { name: "Run", exact: true })).toBeVisible();
  await expect(page.locator("main")).toContainText("bytes · 38 B");
  expect(packFiles).toEqual([]);
});

test("published RAR4 stored file extracts locally without a runtime pack", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Extract RAR4 stored file" }).click();
  await page.getByRole("button", { name: "File / artifact" }).click();
  await page.locator('main input[type="file"]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/libarchive-rar4-store.rar", import.meta.url)));
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  await expect(page.locator("main")).toContainText("bytes · 20 B");
  await page.getByRole("button", { name: "Extract RAR5 stored file" }).click();
  await page.getByRole("button", { name: "File / artifact" }).click();
  await page.locator('main input[type="file"]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/libarchive-rar5-store.rar", import.meta.url)));
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  await expect(page.locator("main")).toContainText("bytes · 29 B");
  expect(packFiles).toEqual([]);
});

test("published Hayabusa JSONL imports and exports explicit entities without a runtime pack", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  const input = readFileSync(fileURLToPath(new URL("../src/formats/testing/hayabusa-upstream-test.jsonl", import.meta.url)), "utf-8");
  await page.goto("/");
  await page.getByRole("button", { name: "Import forensic timeline" }).click();
  await page.locator("main textarea").first().fill(input);
  await page.getByRole("combobox", { name: "Input format" }).selectOption("hayabusa-jsonl");
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const timeline = JSON.parse(await page.locator("main pre").last().innerText()) as { total: number; events: { host: string }[] };
  expect(timeline).toMatchObject({ total: 2, events: [{ host: "test.local" }, { host: "test2.local" }] });
  await page.getByRole("button", { name: "Export timeline entities" }).click();
  await page.locator("main textarea").first().fill(input);
  await page.getByRole("combobox", { name: "Input format" }).selectOption("hayabusa-jsonl");
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  await expect(page.locator("main")).toContainText("lastalive1.dat");
  expect(packFiles).toEqual([]);
});

test("attributed AWS incident excerpt imports as local CloudTrail JSONL", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  const input = readFileSync(fileURLToPath(new URL("../src/formats/testing/otrf-cloud-breach-excerpt.jsonl", import.meta.url)), "utf8");
  await page.goto("/");
  await page.getByRole("button", { name: "Inspect CloudTrail events" }).click();
  await page.locator("main textarea").first().fill(input);
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const report = JSON.parse(await page.locator("main pre").last().innerText()) as { total: number; events: { eventName: string }[] };
  expect(report.total).toBe(3);
  expect(report.events.map((event) => event.eventName)).toEqual(["AssumeRole", "GetObject", "GetObject"]);
  expect(packFiles).toEqual([]);
});

test("deflated sigrok digital session imports as VCD without a runtime pack", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Import sigrok session" }).click();
  await page.getByRole("button", { name: "File / artifact" }).click();
  await page.locator('main input[type="file"]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/sigrok-deflated-logic.sr", import.meta.url)));
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const report = JSON.parse(await page.locator("main pre").last().innerText()) as { samples: number; probes: number; transitions: number };
  expect(report).toMatchObject({ samples: 32, probes: 2 });
  expect(report.transitions).toBeGreaterThan(2);
  expect(packFiles).toEqual([]);
});

test("original AppNote ZIP recovers its hidden end-record flag locally", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Recover ZIP end-record chain" }).click();
  await page.getByRole("button", { name: "File / artifact" }).click();
  await page.locator('main input[type="file"]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/google-ctf-2022-appnote.zip", import.meta.url)));
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const report = JSON.parse(await page.locator("main pre").last().innerText()) as { records: unknown[]; candidateText: string; verified: boolean };
  expect(report.records).toHaveLength(21);
  expect(report.candidateText).toBe("CTF{p0s7m0d3rn_z1p}");
  expect(report.verified).toBe(false);
  expect(packFiles).toEqual([]);
});

test("original Google CTF RSA PEM is inspectable without a pack", async ({ page, context }) => {
  const pem = readFileSync(fileURLToPath(new URL("../src/formats/testing/google-ctf-2023-lcg-public.pem", import.meta.url)), "utf8");
  const key = createPublicKey(pem).export({ format: "jwk" });
  const publicModulus = BigInt(`0x${Buffer.from(key.n!, "base64url").toString("hex")}`).toString();
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Inspect RSA public key" }).click();
  await page.getByPlaceholder("Type or paste text…").fill(pem);
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const report = JSON.parse(await page.locator("main pre").last().innerText()) as { modulus: string; modulusBits: number; publicExponent: string };
  expect(report).toMatchObject({ modulus: publicModulus, modulusBits: 4090, publicExponent: "65537" });
  expect(packFiles).toEqual([]);
});

test("Lua 5.4 bytecode inspector runs locally without a pack", async ({ page, context }) => {
  const packFiles: string[] = [];
  await context.route("**/assets/pack-*", async (route) => {
    packFiles.push(route.request().url());
    await route.abort();
  });
  const hex = [
    "1b4c7561540019930d0a1a0a0408087856000000000000000000000028774000",
    "80818101000486cf000000000101008001000045010200460100004701010080",
    "808180818101000284950000862f008606c8000200c700010080808080808080",
    "80808080",
  ].join("");
  await page.goto("/");
  await page.getByRole("button", { name: "Inspect Lua 5.4 bytecode" }).click();
  await page.getByRole("button", { name: "File / artifact" }).click();
  await page.locator('main input[type="file"]').setInputFiles({
    name: "nested.luac", mimeType: "application/octet-stream", buffer: Buffer.from(hex, "hex"),
  });
  await page.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page.getByText("success", { exact: true })).toBeVisible();
  const report = JSON.parse(await page.locator("main pre").last().innerText()) as { totalInstructions: number; prototypes: { path: string }[]; executed: boolean };
  expect(report.totalInstructions).toBe(10);
  expect(report.prototypes.map((prototype) => prototype.path)).toEqual(["main", "main/0"]);
  expect(report.executed).toBe(false);
  expect(packFiles).toEqual([]);
});

async function cachePack(page: Page, packId: string, title: string): Promise<void> {
    await page.goto("/");
    try {
      await page.waitForFunction(() => navigator.serviceWorker.controller !== null, undefined, { timeout: 12_000 });
    } catch (error) {
      if (!(error instanceof Error) || error.name !== "TimeoutError") throw error;
      await page.reload();
      await page.waitForFunction(() => navigator.serviceWorker.controller !== null, undefined, { timeout: 20_000 });
    }
    await page.getByText("Runtime packs", { exact: true }).click();
  const item = page.locator("li").filter({ has: page.getByText(title, { exact: true }) });
    await item.getByRole("button", { name: "Download for offline" }).click();
  await expect(item.getByText("Available offline")).toBeVisible({ timeout: 60_000 });
    const cache = await page.evaluate(async (id) => {
      const manifest = await (await fetch("/packs.json")).json() as { packs: Record<string, { files: string[] }> };
      const assets = await caches.open("ctf-packs");
      return Promise.all(manifest.packs[id].files.map(async (file) => Boolean(await assets.match(new URL(file, location.href), { ignoreVary: true }))));
    }, packId);
    expect(cache.length).toBeGreaterThan(0);
    expect(cache.every(Boolean)).toBe(true);
}

test.describe("offline cached runtime packs", () => {
  test.use({ serviceWorkers: "allow" });

  test("SQLite download caches every manifest asset", async ({ page }) => {
    await cachePack(page, "sqlite", "SQLite");
  });

  test("Capstone download caches every manifest asset", async ({ page }) => {
    await cachePack(page, "capstone", "Capstone disassembler");
  });

  test("Python download caches every manifest asset", async ({ page }) => {
    test.setTimeout(45_000);
    await cachePack(page, "python", "Python (Pyodide)");
  });

  test("OCR download caches every manifest asset", async ({ page }) => {
    test.setTimeout(45_000);
    await cachePack(page, "ocr", "OCR (Tesseract, English)");
  });

  test("FFmpeg download caches every manifest asset", async ({ page }) => {
    test.setTimeout(90_000);
    await cachePack(page, "ffmpeg", "FFmpeg (threaded)");
  });

  test("bkcrack download caches every manifest asset", async ({ page }) => {
    await cachePack(page, "bkcrack", "bkcrack");
  });

  test("Wiregasm download caches every manifest asset", async ({ page }) => {
    test.setTimeout(120_000);
    await cachePack(page, "wiregasm", "Wiregasm (Wireshark)");
  });

  test("SQLite stays usable after an offline reload", async ({ page, context, browserName }) => {
    test.skip(browserName === "webkit", "Playwright WebKit offline emulation fails even for a precached core asset");
    test.setTimeout(45_000);
    await cachePack(page, "sqlite", "SQLite");

    await context.setOffline(true);
    await page.reload();
    await page.getByRole("button", { name: "Inspect SQLite database" }).click();
    await page.getByRole("button", { name: "File / artifact" }).click();
    await page.locator('main input[type="file"]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/offline-pack.sqlite", import.meta.url)));
    await page.getByRole("button", { name: "Run", exact: true }).click();
    await expect(page.getByText("success", { exact: true })).toBeVisible();
    await expect(page.locator("main")).toContainText("offline_items");
  });

  test("Capstone stays usable after a pack download and offline reload", async ({ page, context, browserName }) => {
    test.skip(browserName === "webkit", "Playwright WebKit offline emulation fails even for a precached core asset");
    test.setTimeout(45_000);
    await cachePack(page, "capstone", "Capstone disassembler");
    await context.setOffline(true);
    await page.reload();
    await page.getByRole("button", { name: "Disassemble", exact: true }).click();
    await page.getByRole("button", { name: "File / artifact" }).click();
    await page.locator('main input[type="file"]').setInputFiles({ name: "raw-x86.bin", mimeType: "application/octet-stream", buffer: Buffer.from([0x90, 0xc3]) });
    await page.getByRole("combobox", { name: "Architecture" }).selectOption("x86-64");
    await page.getByRole("button", { name: "Run", exact: true }).click();
    await expect(page.getByText("success", { exact: true })).toBeVisible();
    await expect(page.locator("main")).toContainText("nop");
    await expect(page.locator("main")).toContainText("ret");
  });

  test("Python stays usable after a pack download and offline reload", async ({ page, context, browserName }) => {
    test.skip(browserName === "webkit", "Playwright WebKit offline emulation fails even for a precached core asset");
    test.setTimeout(120_000);
    await cachePack(page, "python", "Python (Pyodide)");
    await context.setOffline(true);
    await page.reload();
    await page.getByRole("button", { name: "Run Python script" }).click();
    await page.getByRole("button", { name: "File / artifact" }).click();
    await page.locator('main input[type="file"][multiple]').setInputFiles({ name: "script-input.bin", mimeType: "application/octet-stream", buffer: Buffer.from("M6PY") });
    await page.getByRole("textbox", { name: "Python script" }).fill("result = data[::-1]");
    await page.getByRole("button", { name: "Run", exact: true }).click();
    await expect(page.getByText("success", { exact: true })).toBeVisible({ timeout: 90_000 });
    await expect(page.locator("main")).toContainText("YP6M");
  });

  test("OCR stays usable after a pack download and offline reload", async ({ page, context, browserName }) => {
    test.skip(browserName === "webkit", "Playwright WebKit offline emulation fails even for a precached core asset");
    test.setTimeout(120_000);
    await cachePack(page, "ocr", "OCR (Tesseract, English)");
    await context.setOffline(true);
    await page.reload();
    await page.getByRole("button", { name: "Recognise text (OCR)" }).click();
    await page.getByRole("button", { name: "File / artifact" }).click();
    await page.locator('main input[type="file"][multiple]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/ocr-text.png", import.meta.url)));
    await page.getByRole("button", { name: "Run", exact: true }).click();
    await expect(page.getByText("success", { exact: true })).toBeVisible({ timeout: 90_000 });
    await expect(page.locator("main")).toContainText("Hello CTF Workbench");
  });

  test("FFmpeg stays usable after a pack download and offline reload", async ({ page, context, browserName }) => {
    test.skip(browserName === "webkit", "Playwright WebKit offline emulation fails even for a precached core asset");
    test.setTimeout(150_000);
    await cachePack(page, "ffmpeg", "FFmpeg (threaded)");
    await context.setOffline(true);
    await page.reload();
    await page.getByRole("button", { name: "Extract media audio as WAV (FFmpeg)" }).click();
    await page.getByRole("button", { name: "File / artifact" }).click();
    await page.locator('main input[type="file"][multiple]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/sstv-robot36-vis.wav", import.meta.url)));
    await page.getByRole("button", { name: "Run", exact: true }).click();
    await expect(page.getByText("success", { exact: true })).toBeVisible({ timeout: 120_000 });
    await expect(page.locator("main")).toContainText("PCM16 WAV bytes at 8000 Hz");
  });

  test("bkcrack stays usable after a pack download and offline reload", async ({ page, context, browserName }) => {
    test.skip(browserName === "webkit", "Playwright WebKit offline emulation fails even for a precached core asset");
    test.setTimeout(90_000);
    await cachePack(page, "bkcrack", "bkcrack");
    await context.setOffline(true);
    await page.reload();
    await page.getByRole("button", { name: "Recover ZipCrypto keys" }).click();
    await page.getByRole("button", { name: "File / artifact" }).click();
    await page.locator('main input[type="file"][multiple]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/offline-pack.zip", import.meta.url)));
    await page.getByRole("textbox", { name: "Known compressed-stream bytes" }).fill("offline-know");
    await page.getByRole("combobox", { name: "Known-byte encoding" }).selectOption("utf8");
    await page.getByRole("spinbutton", { name: "Maximum reduced states to test" }).fill("1");
    await page.getByRole("button", { name: "Run", exact: true }).click();
    await expect(page.getByText("success", { exact: true })).toBeVisible({ timeout: 60_000 });
    await expect(page.locator("main")).toContainText('"knownPlaintextBytes": 12');
    await page.getByRole("textbox", { name: "Known compressed-stream bytes" }).fill("offline-known-plaintext-fixture");
    await page.getByRole("button", { name: "Run", exact: true }).click();
    await expect(page.getByText("success", { exact: true })).toBeVisible({ timeout: 15_000 });
    await expect(page.locator("main")).toContainText('"knownPlaintextBytes": 31');
    await page.getByRole("textbox", { name: "Known compressed-stream bytes" }).fill("offline-known-plaintext-fixture\n");
    await page.getByRole("button", { name: "Run", exact: true }).click();
    await expect(page.locator("main")).toContainText("Known plaintext extends past the 31-byte compressed stream");
  });

  test("Wiregasm stays usable after a pack download and offline reload", async ({ page, context, browserName }) => {
    test.skip(browserName === "webkit", "Playwright WebKit offline emulation fails even for a precached core asset");
    test.setTimeout(180_000);
    await cachePack(page, "wiregasm", "Wiregasm (Wireshark)");
    await context.setOffline(true);
    await page.reload();
    await page.getByRole("button", { name: "Dissect capture with Wiregasm" }).click();
    await page.getByRole("button", { name: "File / artifact" }).click();
    await page.locator('main input[type="file"][multiple]').setInputFiles(fileURLToPath(new URL("../src/formats/testing/offline-pack.pcap", import.meta.url)));
    await page.getByRole("button", { name: "Run", exact: true }).click();
    await expect(page.getByText("success", { exact: true })).toBeVisible({ timeout: 150_000 });
    await expect(page.locator("main")).toContainText("Wiregasm matched 1 of 1 packet(s)");
  });
});
