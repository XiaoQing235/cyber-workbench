/** A byte range inside the artifact being analysed, used to link findings to the Hex view. */
export interface SourceSpan {
  offset: number;
  length: number;
}
