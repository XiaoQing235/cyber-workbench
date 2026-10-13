import { describe, expect, it } from "vitest";
import repoDataUrl from "../formats/testing/repo.tar?inline";
import { writeZip } from "../core/archive/zip";
import type { Finding } from "../core/analysis/finding";
import { readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import type { Params } from "../core/operation/types";
import { bytesFrom, type Value } from "../core/value";
import { readArchive } from "../formats/archive";
import { applyDelta } from "../formats/git";
import { createDefaultRegistry } from "./index";

const registry = createDefaultRegistry();
// A real repository made by git (see the commit that added it): a secret committed then deleted,
// a branch deleted after a commit, and a stash; `git gc` packed it, so objects include deltas.
const REPO = Uint8Array.from(atob(repoDataUrl.slice(repoDataUrl.indexOf(",") + 1)), (char) => char.charCodeAt(0));

async function run(operationId: string, input: Value, params: Params = {}) {
  const result = await executeOperation(registry, { operationId, inputs: { data: input }, params });
  expect(result.run.error, operationId).toBeUndefined();
  return Object.values(result.outputs)[0];
}

const text = async (value: Value) => (value.type === "text" ? value.text : value.type === "bytes" ? new TextDecoder().decode(await readAll(value.source)) : "");

describe("git forensics", () => {
  it("finds the deleted secret, the deleted branch and the stash in a packed repository", async () => {
    const report = await run("git.inspect", bytesFrom(REPO));
    const data = report.type === "structured" ? (report.data as { objects: Record<string, number>; packs: number; findings: Finding[] }) : null;
    expect(data?.packs).toBe(1);
    expect(data?.objects).toMatchObject({ commit: 6, blob: 6, tree: 5 });
    const messages = data!.findings.map((finding) => finding.message);
    expect(messages).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/"feature work" is not on any branch \(only in the reflog\)/),
        expect.stringMatching(/^A stash exists/),
        expect.stringMatching(/^secret\.txt was deleted in commit .* "remove secret"/),
        expect.stringMatching(/contains flag\{git_never_forgets\}/),
        expect.stringMatching(/contains flag\{deleted_branch\}/),
        expect.stringMatching(/contains flag\{stashed_away\}/),
      ]),
    );
    const deleted = data!.findings.find((finding) => finding.message.startsWith("secret.txt"))!;
    expect(await text(await run("git.cat", bytesFrom(REPO), deleted.suggestion!.params))).toBe("flag{git_never_forgets}\n");
    const feature = data!.findings.find((finding) => finding.message.includes("feature work"))!;
    const shown = await text(await run("git.show", bytesFrom(REPO), feature.suggestion!.params));
    expect(shown).toMatch(/feature work/);
    expect(shown).toMatch(/^A {2}f\.txt {2}\(blob [0-9a-f]{40}\)$/m);
  });

  it("reads the same repository from a ZIP, resolves short ids and rejects other files", async () => {
    const files = await readArchive(new Blob([REPO]));
    const zip = await writeZip(await Promise.all(files.map(async (file) => ({ name: file.path, data: await file.read() }))));
    const zipped = bytesFrom(new Uint8Array(await zip.arrayBuffer()));
    const report = await run("git.inspect", zipped);
    const commits = report.type === "structured" ? (report.data as { commits: { id: string; subject: string }[] }).commits : [];
    const initial = commits.find((commit) => commit.subject === "initial")!;
    expect(await text(await run("git.show", zipped, { commit: initial.id.slice(0, 8) }))).toMatch(/^A {2}notes\.txt/m);
    const bad = await executeOperation(registry, { operationId: "git.inspect", inputs: { data: bytesFrom(new TextEncoder().encode("not a repo")) } });
    expect(bad.run.error?.code).toBe("INVALID_INPUT");
  });

  it("rejects a tampered tar header rather than trusting declared members", async () => {
    const damaged = REPO.slice();
    damaged[0] ^= 1;
    await expect(readArchive(new Blob([damaged]))).rejects.toThrow(/checksum/);
  });

  it("applies copy and insert delta instructions", () => {
    const base = new TextEncoder().encode("hello world");
    const delta = Uint8Array.of(11, 12, 0x90, 5, 2, 0x2c, 0x20, 0x91, 6, 5);
    expect(new TextDecoder().decode(applyDelta(base, delta))).toBe("hello, world");
  });
});
