import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue } from "../../core/value";
import { extractMailAttachment, inspectMail, MAX_MAIL_BYTES } from "../../formats/mimeMail";
import { bytesInput } from "../util";

export const mailInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "forensics.mail.inspect", version: "1.0.0", title: "Inspect MIME e-mail", category: "Forensics",
    description: "Inspect bounded offline EML headers, Received hops, attachments and IOC hosts. SPF/DKIM/DMARC results are reported header claims, not verified signatures or DNS checks. Body, URL query and attachment contents are not returned.",
    keywords: ["email", "eml", "mime", "spf", "dkim", "dmarc", "attachment", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_MAIL_BYTES },
  },
  async run(ctx, inputs) {
    try {
      ctx.throwIfAborted();
      const report = await inspectMail(bytesInput(inputs));
      ctx.throwIfAborted();
      ctx.diagnostic(`Read ${report.received.length} Received hop(s), ${report.authentication.length} reported authentication result(s), and ${report.attachments.length} attachment(s). Authentication is not independently verified.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const mailAttachmentExtract = defineOperation<{ attachmentIndex: number }>({
  spec: {
    id: "forensics.mail.attachment-extract", version: "1.0.0", title: "Extract MIME attachment", category: "Forensics",
    description: "Extract one decoded attachment from a bounded offline EML file by its zero-based report index. No e-mail content leaves the browser.",
    keywords: ["email", "eml", "mime", "attachment", "extract", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: { attachmentIndex: { type: "integer", title: "Attachment index (zero-based)", minimum: 0, maximum: 255, default: 0 } },
      required: ["attachmentIndex"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_MAIL_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      ctx.throwIfAborted();
      const attachment = await extractMailAttachment(bytesInput(inputs), params.attachmentIndex);
      ctx.throwIfAborted();
      ctx.diagnostic(`Extracted ${attachment.filename ?? `attachment ${params.attachmentIndex}`} (${attachment.data.size} bytes) from the EML input.`);
      return { data: bytesValue(attachment.data) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});