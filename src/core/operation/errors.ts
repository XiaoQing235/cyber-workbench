export type OperationErrorCode =
  | "UNKNOWN_OPERATION"
  | "INPUT_MISSING"
  | "INPUT_TYPE"
  | "INPUT_TOO_LARGE"
  | "INVALID_PARAMS"
  | "INVALID_INPUT"
  | "OUTPUT_CONTRACT"
  | "CANCELLED"
  | "UNAVAILABLE"
  | "INTERNAL";

/** Expected failure of an operation. Anything else thrown is reported as INTERNAL. */
export class OperationError extends Error {
  readonly code: OperationErrorCode;

  constructor(code: OperationErrorCode, message: string) {
    super(message);
    this.name = "OperationError";
    this.code = code;
  }
}
