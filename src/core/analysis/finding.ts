import type { SourceSpan } from "../bytes/span";

export type FindingSeverity = "strong" | "medium" | "weak";

export type EvidenceKind = "signature" | "structure" | "integrity" | "decode" | "plausibility" | "targetMatch" | "consistency";

/** One observed fact behind a finding or candidate. Spans refer to the analysed artifact only. */
export interface Evidence {
  kind: EvidenceKind;
  tier: FindingSeverity;
  detail: string;
  span?: SourceSpan;
}

export interface SuggestedStep {
  operationId: string;
  /** Pins a version (recipes do); otherwise the latest registered version runs. */
  operationVersion?: string;
  params?: Record<string, unknown>;
}

export interface Suggestion extends SuggestedStep {
  label: string;
  /** When present (even empty), this is a complete recipe: it runs at once, each step on the previous output. */
  then?: SuggestedStep[];
}

/**
 * An observation about data, kept separate from any conclusion drawn from it. For example,
 * "CRC mismatch in IHDR" is a finding; "the height was altered" is only a hypothesis.
 */
export interface Finding {
  id: string;
  /** The rule or detector that produced it. */
  ruleId?: string;
  severity: FindingSeverity;
  message: string;
  span?: SourceSpan;
  evidence?: Evidence[];
  /** Operation the user can run next to test or act on this finding. */
  suggestion?: Suggestion;
}
