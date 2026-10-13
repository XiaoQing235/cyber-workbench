import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue } from "../../core/value";
import { extractVisibleOciFile, inspectOciImage, inspectOciLayer } from "../../formats/ociLayer";
import { bytesInput, MiB } from "../util";

export const ociLayerInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "forensics.oci.layer.inspect", version: "1.0.0", title: "Inspect OCI tar layer", category: "Forensics",
    description: "Inspect up to 64 MiB of uncompressed OCI tar metadata: regular files, .wh.* deletions and opaque-directory markers. Symlinks and directory headers are not listed; decompress .tar.gz first.",
    keywords: ["oci", "docker", "container", "tar", "whiteout", "opaque", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: 64 * MiB },
  },
  async run(ctx, inputs) {
    try {
      const report = await inspectOciLayer(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`OCI layer: ${report.files} regular file(s), ${report.whiteouts} deletion marker(s), ${report.opaqueDirectories} opaque director${report.opaqueDirectories === 1 ? "y" : "ies"}. Directories and symlinks are not listed.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const ociImageInspect = defineOperation<{ manifestIndex: number }>({
  spec: {
    id: "forensics.oci.image.inspect", version: "1.0.0", title: "Inspect Docker-save image layers", category: "Forensics",
    description: "Merge up to 32 uncompressed tar layers from a Docker-save-style image archive (128 MiB max). Report visible regular files and the prior files hidden by whiteouts or opaque markers. Directory and symlink metadata is not merged.",
    keywords: ["oci", "docker", "container", "image", "layers", "whiteout", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: { manifestIndex: { type: "integer", title: "Manifest image index", minimum: 0, maximum: 15, default: 0 } },
      required: ["manifestIndex"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 128 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      const report = await inspectOciImage(bytesInput(inputs), params.manifestIndex, ctx.signal);
      ctx.diagnostic(`Applied ${report.layers} OCI layer(s): ${report.visible.length} visible regular file(s), ${report.hidden.length} prior file(s) hidden. Directory and symlink metadata is not merged.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const ociImageExtract = defineOperation<{ manifestIndex: number; path: string }>({
  spec: {
    id: "forensics.oci.image.extract", version: "1.0.0", title: "Extract visible image file", category: "Forensics",
    description: "Extract a regular file still visible after applying ordered Docker-save image layers. Whiteout-hidden, opaque-hidden, unsafe and non-regular paths are refused.",
    keywords: ["oci", "docker", "container", "image", "layers", "extract", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: {
        manifestIndex: { type: "integer", title: "Manifest image index", minimum: 0, maximum: 15, default: 0 },
        path: { type: "string", title: "Visible file path", minLength: 1, maxLength: 1_024, default: "" },
      },
      required: ["manifestIndex", "path"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 128 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      const data = await extractVisibleOciFile(bytesInput(inputs), params.path, params.manifestIndex, ctx.signal);
      ctx.diagnostic(`Extracted ${params.path} (${data.size} bytes) from the visible Docker-save layer stack.`);
      return { data: bytesValue(data) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});