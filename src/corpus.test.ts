import { existsSync, readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import YAML from "yaml";
import { createDefaultRegistry } from "./operations";

const root = fileURLToPath(new URL("..", import.meta.url));
const corpus = fileURLToPath(new URL("../corpus/", import.meta.url));

function safeFixturePath(path: string): boolean {
  const segments = path.split("/");
  return segments.length > 1 && (segments[0] === "src" || segments[0] === "corpus") &&
    segments.every((segment) => segment !== "" && segment !== "." && segment !== ".." && /^[a-zA-Z0-9_.-]+$/.test(segment));
}

describe("sourced CTF operation corpus", () => {
  it("rejects fixture paths that leave the repository or contain empty segments", () => {
    expect(safeFixturePath("src/formats/testing/original.png")).toBe(true);
    expect(safeFixturePath("src/../outside.txt")).toBe(false);
    expect(safeFixturePath("corpus/../outside.txt")).toBe(false);
    expect(safeFixturePath("src//fixture.png")).toBe(false);
    expect(safeFixturePath("/tmp/fixture.png")).toBe(false);
  });

  it("keeps unique attributed records and real operation references in ordered steps", () => {
    const registry = createDefaultRegistry();
    const ids = new Set<string>();
    const sources = new Set<string>();
    const files = readdirSync(corpus, { withFileTypes: true }).filter((entry) => entry.isDirectory()).flatMap((folder) =>
      readdirSync(`${corpus}/${folder.name}`).filter((name) => name.endsWith(".yaml")).map((name) => `${corpus}/${folder.name}/${name}`));
    expect(files.length).toBeGreaterThan(0);
    for (const file of files) {
      const document = YAML.parseDocument(readFileSync(file, "utf8"), { uniqueKeys: true });
      expect(document.errors, file).toEqual([]);
      const record = document.toJS() as Record<string, unknown>;
      expect(record.id, file).toMatch(/^[a-z0-9]+(?:-[a-z0-9]+)+$/);
      expect(ids.has(record.id as string), file).toBe(false);
      ids.add(record.id as string);
      expect(record.title, file).toEqual(expect.any(String));
      expect(record.event, file).toEqual(expect.any(String));
      expect(record.category, file).toEqual(expect.any(String));
      expect(record.sourceUrl, file).toMatch(/^https:\/\//);
      const source = new URL(record.sourceUrl as string).href.replace(/\/$/, "");
      expect(sources.has(source), file).toBe(false);
      sources.add(source);
      expect(record.author, file).toEqual(expect.any(String));
      expect(record.inputFormats, file).toEqual(expect.arrayContaining([expect.any(String)]));
      const steps = record.steps as Record<string, unknown>[];
      expect(steps.length, file).toBeGreaterThan(0);
      for (const step of steps) {
        expect(step, file).toMatchObject({ originalTool: expect.any(String), originalCommand: expect.any(String),
          inputs: expect.arrayContaining([expect.any(String)]), outputs: expect.arrayContaining([expect.any(String)]) });
        expect(step.operationId === null || typeof step.operationId === "string", file).toBe(true);
        if (step.operationId !== null) expect(registry.has(step.operationId as string), file).toBe(true);
      }
      const verification = record.verification as Record<string, unknown>;
      expect(() => new RegExp(verification.pattern as string), file).not.toThrow();
      expect(verification.intermediate, file).toEqual(expect.arrayContaining([expect.any(String)]));
      const fixture = record.fixture as Record<string, unknown>;
      expect(typeof fixture.usable, file).toBe("boolean");
      if (fixture.usable) {
        expect(fixture.license, file).toEqual(expect.any(String));
        expect(fixture.attribution, file).toEqual(expect.any(String));
        for (const path of [...(fixture.inputs as string[]), fixture.test as string, fixture.licenseFile as string]) {
          expect(safeFixturePath(path), `${file}: ${path}`).toBe(true);
          expect(existsSync(`${root}/${path}`), `${file}: ${path}`).toBe(true);
        }
      } else expect(fixture.reason, file).toEqual(expect.any(String));
    }
  });
});