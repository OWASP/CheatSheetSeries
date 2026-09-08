const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const repoRoot = path.resolve(__dirname, "../..");
const realChecker = path.join(
  repoRoot,
  "node_modules",
  ".bin",
  "markdown-link-check",
);

function runLinkCheck(t, { checker = realChecker, files }) {
  const fixtureRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "cheatsheet-link-check-"),
  );
  const targetDir = path.join(fixtureRoot, "cheatsheets");
  const config = path.join(fixtureRoot, "markdown-link-check-config.json");
  const log = path.join(fixtureRoot, "log");

  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));
  fs.mkdirSync(targetDir);
  fs.writeFileSync(config, "{}\n");
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(targetDir, name), content);
  }

  const result = spawnSync("npm", ["run", "link-check", "--silent"], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      MARKDOWN_LINK_CHECK_BIN: checker,
      MARKDOWN_LINK_CHECK_CONFIG: config,
      MARKDOWN_LINK_CHECK_LOG: log,
      MARKDOWN_LINK_CHECK_TARGET: targetDir,
    },
  });

  return {
    ...result,
    log: fs.existsSync(log) ? fs.readFileSync(log, "utf8") : "",
    targetDir,
  };
}

function createFailingChecker(t) {
  const fixtureRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "cheatsheet-failing-checker-"),
  );
  const checker = path.join(fixtureRoot, "markdown-link-check");
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));
  fs.writeFileSync(
    checker,
    [
      "#!/bin/bash",
      'printf \'FILE: %s\\n\' "$3"',
      'if [[ "$3" == *failing.md ]]; then',
      '  printf \'checker crashed for %s\\n\' "$3" >&2',
      "  exit 42",
      "fi",
      'printf \'[✓] local fixture\\n\'',
      "",
    ].join("\n"),
    { mode: 0o755 },
  );
  return checker;
}

test("a valid local-link fixture exits zero", (t) => {
  const result = runLinkCheck(t, {
    files: {
      "target.md": "# Target\n",
      "valid.md": "# Valid\n\n[Existing target](target.md)\n",
    },
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /No error found by the link validator/);
  assert.match(result.log, /FILE: .*valid\.md/);
});

test("a broken local link exits nonzero and leaves workflow diagnostics", (t) => {
  const result = runLinkCheck(t, {
    files: {
      "broken.md": "# Broken\n\n[Missing target](missing.md)\n",
    },
  });

  assert.notEqual(result.status, 0);
  assert.doesNotMatch(result.stdout, /All good/);
  assert.match(result.log, /FILE: .*broken\.md/);
  assert.match(result.log, /ERROR:/);
  assert.match(result.log, /\[✖\] missing\.md/);
});

test("a missing checker exits nonzero and cannot report success", (t) => {
  const result = runLinkCheck(t, {
    checker: path.join(os.tmpdir(), "missing-markdown-link-check"),
    files: { "valid.md": "# Valid\n" },
  });

  assert.notEqual(result.status, 0);
  assert.doesNotMatch(result.stdout, /All good/);
  assert.match(result.stderr, /Link checker executable is unavailable/);
  assert.match(result.log, /Link checker executable is unavailable/);
});

test("any failing per-file invocation makes the command fail", (t) => {
  const checker = createFailingChecker(t);
  const result = runLinkCheck(t, {
    checker,
    files: {
      "failing.md": "# Failing\n",
      "valid.md": "# Valid\n",
    },
  });

  assert.notEqual(result.status, 0);
  assert.doesNotMatch(result.stdout, /All good/);
  assert.match(result.log, /checker crashed for .*failing\.md/);
  assert.match(result.log, /FILE: .*valid\.md/);
});
