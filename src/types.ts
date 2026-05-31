export type Severity = "critical" | "high" | "medium" | "low" | "review";

export const SEVERITY_ORDER: Record<Severity, number> = { low: 0, review: 1, medium: 2, high: 3, critical: 4 };

export interface SourceFile {
  path: string;
  rel: string;
  content: string;
}

export interface Finding {
  ruleId: string;
  severity: Severity;
  file: string;
  line: number;
  col: number;
  message: string;
  snippet: string;
  remediation: string;
}

export class VibecheckError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VibecheckError";
  }
}
