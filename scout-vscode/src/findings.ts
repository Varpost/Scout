/**
 * Pure mapping from Scout's `--format json` output to diagnostic shapes.
 * No vscode imports — this module is unit-tested with plain Node.
 */

export interface ScoutFinding {
  id: string;
  scanner: string;
  file: string;
  line: number;
  severity: string;
  title: string;
  explanation: string;
  fix_guidance?: string;
  reachable?: boolean | null;
}

export interface MappedDiagnostic {
  /** Absolute path the diagnostic belongs to. */
  path: string;
  /** Zero-based line. */
  line: number;
  /** 0 = Error, 1 = Warning, 2 = Information (vscode.DiagnosticSeverity). */
  severity: number;
  message: string;
  /** Finding id, e.g. "injection/innerhtml_assignment". */
  code: string;
}

const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 0,
  MEDIUM: 1,
  LOW: 2,
};

export function parseScoutJson(stdout: string): ScoutFinding[] {
  const doc = JSON.parse(stdout);
  if (typeof doc !== "object" || doc === null || !Array.isArray(doc.findings)) {
    throw new Error("unexpected Scout JSON shape (no findings array)");
  }
  return doc.findings.filter(
    (f: unknown): f is ScoutFinding =>
      typeof f === "object" && f !== null && typeof (f as ScoutFinding).line === "number",
  );
}

/**
 * Map findings to diagnostics.
 *
 * @param findings Parsed Scout findings.
 * @param scanRoot Directory the scan ran over (absolute).
 * @param singleFilePath When the scan targeted one file, every finding
 *   belongs to it — Scout reports "." as the file in that mode.
 */
export function toDiagnostics(
  findings: ScoutFinding[],
  scanRoot: string,
  singleFilePath?: string,
): MappedDiagnostic[] {
  const sep = scanRoot.includes("\\") ? "\\" : "/";
  const results: MappedDiagnostic[] = [];
  for (const finding of findings) {
    let path: string;
    if (singleFilePath) {
      path = singleFilePath;
    } else if (finding.file === "." || finding.file === "") {
      continue; // project-level finding with no real location — not inline material
    } else if (finding.file.includes(":") || finding.file.startsWith("/")) {
      path = finding.file; // already absolute (windows drive or posix)
    } else {
      path = scanRoot + sep + finding.file;
    }
    const reachable = finding.reachable === true ? " [reachable from user input]" : "";
    results.push({
      path,
      line: Math.max(0, finding.line - 1),
      severity: SEVERITY_RANK[finding.severity] ?? 1,
      message: `${finding.title}${reachable} — ${finding.explanation}`,
      code: finding.id,
    });
  }
  return results;
}
