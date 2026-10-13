import type { Finding } from "../../core/analysis/finding";
import { toBlob } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import type { Value } from "../../core/value";
import { bytesFrom, structuredValue, textValue } from "../../core/value";
import { ArchiveError, readArchive } from "../../formats/archive";
import { GitError, GitRepository, type Commit } from "../../formats/git";
import { DEFAULT_FLAG_PATTERN } from "../analysis/autoDecode";
import { bytesInput, MiB } from "../util";

const COMMON = { runtime: "ts", deterministic: true, sideEffects: "none", streaming: false, cost: "medium" } as const;
const INPUT = [{ name: "data", type: "bytes" as const }];
const LIMITS = { maxInputBytes: 1024 * MiB };
const MAX_SCANNED_BLOB = 4 * MiB;
const MAX_SCANNED_TOTAL = 64 * MiB;

async function open(inputs: Readonly<Record<string, Value>>): Promise<GitRepository> {
  try {
    return await GitRepository.open(await readArchive(await toBlob(bytesInput(inputs))));
  } catch (error) {
    if (error instanceof ArchiveError || error instanceof GitError) throw new OperationError("INVALID_INPUT", error.message);
    throw error;
  }
}

async function guard<T>(work: () => Promise<T>): Promise<T> {
  try {
    return await work();
  } catch (error) {
    if (error instanceof GitError) throw new OperationError("INVALID_INPUT", error.message);
    throw error;
  }
}

const short = (id: string) => id.slice(0, 10);
const subject = (commit: Commit) => commit.message.split("\n")[0];

/** Commits reachable from `starts` through parent links (stashes reach their index commit the same way). */
async function reachable(repository: GitRepository, starts: Iterable<string>): Promise<Map<string, Commit>> {
  const found = new Map<string, Commit>();
  const queue = [...starts];
  while (queue.length > 0) {
    const id = queue.pop()!;
    if (found.has(id)) continue;
    try {
      const commit = await repository.commit(id);
      found.set(id, commit);
      queue.push(...commit.parents);
    } catch {
      // Missing or non-commit objects (e.g. refs to tags of blobs) end the walk here.
    }
  }
  return found;
}

export const gitInspect = defineOperation<Record<string, never>>({
  spec: {
    ...COMMON,
    id: "git.inspect",
    version: "1.0.0",
    title: "Inspect git repository",
    category: "Forensics",
    description:
      "Read a .git directory uploaded as .zip or .tar (loose objects and packs): branches, history, the reflog, stashes, commits no longer on any branch, deleted files and blobs that match a flag pattern.",
    keywords: ["git", "repository", "commit", "reflog", "stash", "dangling", "deleted", "history", "forensics"],
    inputs: INPUT,
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    limits: LIMITS,
  },
  async run(ctx, inputs) {
    const repository = await open(inputs);
    return guard(async () => {
      const refs = await repository.refs();
      const reflog = await repository.reflog();
      const onBranches = await reachable(repository, refs.values());
      const viaReflog = await reachable(repository, reflog.flatMap((entry) => [entry.from, entry.to]).filter((id) => !/^0+$/.test(id)));
      const types = new Map<string, string>();
      for (const id of repository.objectIds) {
        ctx.throwIfAborted();
        types.set(id, await repository.typeOf(id).catch(() => "damaged"));
      }
      const allCommits = await reachable(repository, [...types].filter(([, type]) => type === "commit").map(([id]) => id));
      const status = (id: string) => (onBranches.has(id) ? "on a branch" : viaReflog.has(id) ? "only in the reflog" : "dangling");
      const findings: Finding[] = [];

      for (const commit of allCommits.values()) {
        if (onBranches.has(commit.id)) continue;
        findings.push({
          id: `git.unreachable.${commit.id}`,
          ruleId: "git.reachability",
          severity: "strong",
          message: `Commit ${short(commit.id)} "${subject(commit)}" is not on any branch (${status(commit.id)})`,
          evidence: [{ kind: "structure", tier: "strong", detail: `Not reachable from ${refs.size} ref(s); ${viaReflog.has(commit.id) ? "still listed in the reflog" : "not even in the reflog"}` }],
          suggestion: { operationId: "git.show", params: { commit: commit.id }, label: "Show commit", then: [] },
        });
      }
      const stash = refs.get("refs/stash");
      if (stash && allCommits.has(stash)) {
        findings.push({
          id: "git.stash",
          ruleId: "git.refs",
          severity: "strong",
          message: `A stash exists: "${subject(allCommits.get(stash)!)}"`,
          evidence: [{ kind: "structure", tier: "strong", detail: "refs/stash points to a stash commit: uncommitted work that was put aside" }],
          suggestion: { operationId: "git.show", params: { commit: stash }, label: "Show the stash", then: [] },
        });
      }

      const pathOf = new Map<string, string>();
      for (const commit of allCommits.values()) {
        ctx.throwIfAborted();
        const files = await repository.listFiles(commit.tree);
        for (const [path, id] of files) if (!pathOf.has(id)) pathOf.set(id, path);
        const parent = commit.parents[0] ? allCommits.get(commit.parents[0]) : undefined;
        if (!parent) continue;
        for (const [path, id] of await repository.listFiles(parent.tree)) {
          if (files.has(path)) continue;
          findings.push({
            id: `git.deleted.${commit.id}.${path}`,
            ruleId: "git.history",
            severity: "medium",
            message: `${path} was deleted in commit ${short(commit.id)} "${subject(commit)}"`,
            evidence: [{ kind: "consistency", tier: "strong", detail: `Present in the parent ${short(parent.id)} as blob ${short(id)}, absent afterwards; the blob is still stored` }],
            suggestion: { operationId: "git.cat", params: { object: id }, label: "Recover the file", then: [] },
          });
        }
      }

      const pattern = new RegExp(DEFAULT_FLAG_PATTERN);
      let scanned = 0;
      const decoder = new TextDecoder("utf-8", { fatal: false });
      for (const [id, type] of types) {
        if (type !== "blob" || scanned > MAX_SCANNED_TOTAL) continue;
        const { content } = await repository.read(id);
        if (content.length > MAX_SCANNED_BLOB) continue;
        scanned += content.length;
        const match = pattern.exec(decoder.decode(content));
        if (!match) continue;
        findings.push({
          id: `git.flag.${id}`,
          ruleId: "git.content",
          severity: "strong",
          message: `Blob ${short(id)}${pathOf.has(id) ? ` (${pathOf.get(id)})` : " (not in any commit)"} contains ${match[0]} (unverified)`,
          evidence: [{ kind: "targetMatch", tier: "strong", detail: "Flag pattern matches the blob's content. A pattern match is not proof the flag is correct." }],
          suggestion: { operationId: "git.cat", params: { object: id }, label: "Extract the blob", then: [] },
        });
      }

      const counts: Record<string, number> = {};
      for (const type of types.values()) counts[type] = (counts[type] ?? 0) + 1;
      const order = [...allCommits.values()].sort((a, b) => b.time - a.time);
      return {
        report: structuredValue({
          objects: counts,
          packs: repository.packCount,
          refs: Object.fromEntries(refs),
          commits: order.slice(0, 500).map((commit) => ({
            id: commit.id,
            subject: subject(commit),
            author: commit.author,
            time: new Date(commit.time * 1000).toISOString(),
            parents: commit.parents,
            status: status(commit.id),
          })),
          reflog: reflog.slice(-200),
          findings: findings.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === "strong" ? -1 : b.severity === "strong" ? 1 : 0)),
        }),
      };
    });
  },
});

export const gitShow = defineOperation<{ commit: string }>({
  spec: {
    ...COMMON,
    id: "git.show",
    version: "1.0.0",
    title: "Show git commit",
    category: "Forensics",
    description: "A commit's author, date, message and the files it added, deleted or changed (with blob ids to extract).",
    keywords: ["git", "show", "commit", "diff", "changes"],
    inputs: INPUT,
    outputs: [{ name: "text", type: "text" }],
    parametersSchema: {
      type: "object",
      properties: { commit: { type: "string", title: "Commit id (or unique prefix)", minLength: 4, default: "" } },
      required: ["commit"],
      additionalProperties: false,
    },
    limits: LIMITS,
  },
  async run(_ctx, inputs, params) {
    const repository = await open(inputs);
    return guard(async () => {
      const commit = await repository.commit(repository.resolve(params.commit));
      const files = await repository.listFiles(commit.tree);
      const before = commit.parents[0] ? await repository.listFiles((await repository.commit(commit.parents[0])).tree) : new Map<string, string>();
      const changes: string[] = [];
      for (const [path, id] of files) {
        if (!before.has(path)) changes.push(`A  ${path}  (blob ${id})`);
        else if (before.get(path) !== id) changes.push(`M  ${path}  (blob ${before.get(path)} → ${id})`);
      }
      for (const [path, id] of before) if (!files.has(path)) changes.push(`D  ${path}  (was blob ${id})`);
      const lines = [
        `commit ${commit.id}`,
        ...commit.parents.map((parent) => `parent ${parent}`),
        `Author: ${commit.author}`,
        `Date:   ${new Date(commit.time * 1000).toISOString()}`,
        "",
        ...commit.message.split("\n").map((line) => `    ${line}`),
        "",
        ...(changes.length > 0 ? changes.sort((a, b) => a.slice(3).localeCompare(b.slice(3))) : ["(no file changes)"]),
      ];
      return { text: textValue(lines.join("\n")) };
    });
  },
});

export const gitCat = defineOperation<{ object: string }>({
  spec: {
    ...COMMON,
    id: "git.cat",
    version: "1.0.0",
    title: "Extract git object",
    category: "Forensics",
    description: "The content of any object by id, including deleted and dangling ones: a file's bytes for a blob, the text of a commit or tag, a listing for a tree.",
    keywords: ["git", "cat-file", "blob", "object", "recover", "extract"],
    inputs: INPUT,
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: { object: { type: "string", title: "Object id (or unique prefix)", minLength: 4, default: "" } },
      required: ["object"],
      additionalProperties: false,
    },
    limits: LIMITS,
  },
  async run(ctx, inputs, params) {
    const repository = await open(inputs);
    return guard(async () => {
      const id = repository.resolve(params.object);
      const object = await repository.read(id);
      ctx.diagnostic(`${object.type} ${id}, ${object.content.length} bytes`);
      if (object.type !== "tree") return { data: bytesFrom(new Uint8Array(object.content)) };
      const listing = (await repository.tree(id)).map((entry) => `${entry.mode.padStart(6, "0")} ${entry.mode === "40000" ? "tree" : "blob"} ${entry.id}\t${entry.name}`);
      return { data: bytesFrom(new TextEncoder().encode(listing.join("\n"))) };
    });
  },
});
