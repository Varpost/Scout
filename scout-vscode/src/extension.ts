import * as vscode from "vscode";
import { execFile } from "node:child_process";
import { dirname } from "node:path";
import { parseScoutJson, toDiagnostics, MappedDiagnostic } from "./findings";

const SCAN_TIMEOUT_MS = 60_000;
// JSON on stdout can be large on a big workspace scan.
const MAX_BUFFER = 32 * 1024 * 1024;

let diagnostics: vscode.DiagnosticCollection;
let output: vscode.OutputChannel;
// Latest-wins: a save can outrun the previous scan of the same file.
const generations = new Map<string, number>();

function config<T>(key: string, fallback: T): T {
  return vscode.workspace.getConfiguration("scout").get<T>(key) ?? fallback;
}

function runScout(args: string[], cwd: string): Promise<string> {
  const exe = config("executable", "scoutsec");
  return new Promise((resolve, reject) => {
    execFile(
      exe,
      ["scan", ...args, "--no-ai", "--format", "json", "--fail-on", "never"],
      { cwd, timeout: SCAN_TIMEOUT_MS, maxBuffer: MAX_BUFFER },
      (error, stdout, stderr) => {
        // Scout prints JSON even alongside stderr notes; a spawn failure
        // (executable missing) has no stdout at all.
        if (stdout) {
          resolve(stdout);
        } else {
          reject(new Error(`${exe}: ${error?.message ?? stderr}`));
        }
      },
    );
  });
}

function publish(mapped: MappedDiagnostic[], clearFirst?: vscode.Uri): void {
  if (clearFirst) {
    diagnostics.delete(clearFirst);
  } else {
    diagnostics.clear();
  }
  const byFile = new Map<string, vscode.Diagnostic[]>();
  for (const item of mapped) {
    const range = new vscode.Range(item.line, 0, item.line, 1000);
    const diagnostic = new vscode.Diagnostic(range, item.message, item.severity);
    diagnostic.source = "scout";
    diagnostic.code = item.code;
    const list = byFile.get(item.path) ?? [];
    list.push(diagnostic);
    byFile.set(item.path, list);
  }
  for (const [path, list] of byFile) {
    diagnostics.set(vscode.Uri.file(path), list);
  }
}

async function scanFile(document: vscode.TextDocument): Promise<void> {
  const path = document.uri.fsPath;
  const generation = (generations.get(path) ?? 0) + 1;
  generations.set(path, generation);
  const folder = vscode.workspace.getWorkspaceFolder(document.uri);
  const cwd = folder ? folder.uri.fsPath : dirname(path);
  try {
    const stdout = await runScout([path], cwd);
    if (generations.get(path) !== generation) {
      return; // a newer save already superseded this scan
    }
    publish(toDiagnostics(parseScoutJson(stdout), cwd, path), document.uri);
  } catch (error) {
    output.appendLine(`scan failed for ${path}: ${error}`);
  }
}

async function scanWorkspace(): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    void vscode.window.showWarningMessage("Scout: open a folder to scan a workspace.");
    return;
  }
  const root = folder.uri.fsPath;
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Window, title: "Scout: scanning workspace…" },
    async () => {
      try {
        const stdout = await runScout([root], root);
        publish(toDiagnostics(parseScoutJson(stdout), root));
      } catch (error) {
        output.appendLine(`workspace scan failed: ${error}`);
        void vscode.window.showErrorMessage(
          "Scout scan failed — is scout-security installed? (pip install scout-security). See the Scout output channel.",
        );
      }
    },
  );
}

const SCANNABLE = new Set(["python", "javascript", "javascriptreact", "typescript", "typescriptreact"]);

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection("scout");
  output = vscode.window.createOutputChannel("Scout");
  context.subscriptions.push(
    diagnostics,
    output,
    vscode.commands.registerCommand("scout.scanWorkspace", scanWorkspace),
    vscode.commands.registerCommand("scout.scanFile", () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        void scanFile(editor.document);
      }
    }),
    vscode.workspace.onDidSaveTextDocument((document) => {
      if (config("scanOnSave", true) && SCANNABLE.has(document.languageId)) {
        void scanFile(document);
      }
    }),
  );
}

export function deactivate(): void {
  // subscriptions dispose the collection and channel
}
