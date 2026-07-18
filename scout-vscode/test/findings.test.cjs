"use strict";
// Unit tests for the pure finding→diagnostic mapper (no vscode needed).
const test = require("node:test");
const assert = require("node:assert/strict");
const { parseScoutJson, toDiagnostics } = require("../out/findings.js");

const SAMPLE = JSON.stringify({
  findings: [
    {
      id: "injection/innerhtml_assignment",
      scanner: "injection",
      file: ".",
      line: 2,
      severity: "HIGH",
      title: "innerHTML assignment",
      explanation: "Dynamic innerHTML is XSS.",
      reachable: true,
    },
    {
      id: "secrets/aws_key",
      scanner: "secrets",
      file: "src/config.js",
      line: 5,
      severity: "CRITICAL",
      title: "AWS key",
      explanation: "Hardcoded key.",
      reachable: null,
    },
    {
      id: "headers/csrf",
      scanner: "headers",
      file: ".",
      line: 1,
      severity: "LOW",
      title: "CSRF",
      explanation: "App-wide, no real line.",
    },
  ],
});

test("parse rejects garbage", () => {
  assert.throws(() => parseScoutJson("not json"));
  assert.throws(() => parseScoutJson("[]"));
});

test("single-file scan maps every finding to that file", () => {
  const mapped = toDiagnostics(parseScoutJson(SAMPLE), "C:\\proj", "C:\\proj\\app.js");
  assert.equal(mapped.length, 3);
  assert.ok(mapped.every((d) => d.path === "C:\\proj\\app.js"));
});

test("workspace scan resolves relative paths and drops locationless findings", () => {
  const mapped = toDiagnostics(parseScoutJson(SAMPLE), "C:\\proj");
  assert.equal(mapped.length, 1);
  assert.equal(mapped[0].path, "C:\\proj\\src/config.js");
  assert.equal(mapped[0].severity, 0); // CRITICAL → Error
  assert.equal(mapped[0].line, 4); // 1-based → 0-based
});

test("reachable taint verdict is surfaced in the message", () => {
  const mapped = toDiagnostics(parseScoutJson(SAMPLE), "C:\\proj", "C:\\proj\\app.js");
  assert.match(mapped[0].message, /\[reachable from user input\]/);
  assert.doesNotMatch(mapped[1].message, /reachable/);
});

test("severity ranks map to vscode DiagnosticSeverity values", () => {
  const doc = (severity) =>
    JSON.stringify({
      findings: [{ id: "x", scanner: "s", file: "a.js", line: 1, severity, title: "t", explanation: "e" }],
    });
  assert.equal(toDiagnostics(parseScoutJson(doc("HIGH")), "/r")[0].severity, 0);
  assert.equal(toDiagnostics(parseScoutJson(doc("MEDIUM")), "/r")[0].severity, 1);
  assert.equal(toDiagnostics(parseScoutJson(doc("LOW")), "/r")[0].severity, 2);
  assert.equal(toDiagnostics(parseScoutJson(doc("MYSTERY")), "/r")[0].severity, 1);
});
