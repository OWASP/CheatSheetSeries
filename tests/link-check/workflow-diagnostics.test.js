const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const repoRoot = path.resolve(__dirname, "../..");
const prepareScript = path.join(
  repoRoot,
  "scripts",
  "Prepare_Link_Check_Diagnostics.js",
);

function runPrepare(
  t,
  {
    eventName = "pull_request",
    headRepository = "contributor/CheatSheetSeries",
    known = "## Known\n\n    [known] old.example\n",
    outcome = "failure",
    repository = "OWASP/CheatSheetSeries",
    unexpected = "## Unexpected\n\n    FILE: cheatsheets/example.md\n      [✖] new.example → Status: 404\n",
  } = {},
) {
  const fixtureRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "cheatsheet-workflow-diagnostics-"),
  );
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));
  const knownPath = path.join(fixtureRoot, "known.md");
  const unexpectedPath = path.join(fixtureRoot, "unexpected.md");
  const summaryPath = path.join(fixtureRoot, "summary.md");
  const outputPath = path.join(fixtureRoot, "output");
  fs.writeFileSync(knownPath, known);
  fs.writeFileSync(unexpectedPath, unexpected);
  fs.writeFileSync(summaryPath, "");
  fs.writeFileSync(outputPath, "");

  const result = spawnSync(process.execPath, [prepareScript], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      GITHUB_OUTPUT: outputPath,
      GITHUB_STEP_SUMMARY: summaryPath,
      LINK_CHECK_EVENT_NAME: eventName,
      LINK_CHECK_HEAD_REPOSITORY: headRepository,
      LINK_CHECK_OUTCOME: outcome,
      LINK_CHECK_REPOSITORY: repository,
      MARKDOWN_LINK_CHECK_KNOWN: knownPath,
      MARKDOWN_LINK_CHECK_UNEXPECTED: unexpectedPath,
    },
  });

  return {
    ...result,
    output: fs.readFileSync(outputPath, "utf8"),
    summary: fs.readFileSync(summaryPath, "utf8"),
  };
}

test("a fork failure writes unexpected diagnostics to the summary and skips comment", (t) => {
  const result = runPrepare(t);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.summary, /FILE: cheatsheets\/example\.md/);
  assert.match(result.summary, /new\.example/);
  assert.doesNotMatch(result.summary, /old\.example/);
  assert.match(result.output, /^should_comment=false$/m);
});

test("a same-repository failure enables a comment containing only unexpected output", (t) => {
  const result = runPrepare(t, {
    headRepository: "OWASP/CheatSheetSeries",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.output, /^should_comment=true$/m);
  assert.doesNotMatch(result.summary, /old\.example/);
});

test("an internal failure without recovered diagnostics produces a generic summary", (t) => {
  const result = runPrepare(t, {
    headRepository: "OWASP/CheatSheetSeries",
    unexpected: "",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.summary, /failed before actionable diagnostics could be recovered/);
  assert.match(result.summary, /link-check-diagnostics/);
  assert.match(result.output, /^should_comment=false$/m);
});

test("a successful run reports known and recovered counts without a comment", (t) => {
  const result = runPrepare(t, {
    known: [
      "## Known",
      "",
      "    [known] first.example",
      "    [known] second.example",
      "    [recovered] third.example",
      "    [transient] fourth.example",
      "",
    ].join("\n"),
    outcome: "success",
    unexpected: "",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.summary, /2 exact known-failure tuple\(s\) remain/);
  assert.match(result.summary, /1 baseline row\(s\) are recovered or stale/);
  assert.match(
    result.summary,
    /1 unbaselined network failure\(s\) were not persistent across every observation/,
  );
  assert.match(result.output, /^should_comment=false$/m);
});

test("the workflow keeps fork execution unprivileged and comments only unexpected rows", () => {
  const workflow = fs.readFileSync(
    path.join(repoRoot, ".github", "workflows", "md-link-check.yml"),
    "utf8",
  );
  assert.match(workflow, /^\s*pull_request:\s*$/m);
  assert.doesNotMatch(workflow, /pull_request_target/);
  assert.doesNotMatch(workflow, /secrets\./);
  assert.doesNotMatch(workflow, /GITHUB_TOKEN/);
  assert.match(workflow, /github-token:\s*\$\{\{ github\.token \}\}/);
  assert.match(
    workflow,
    /steps\.link_check_diagnostics\.outputs\.should_comment == 'true'/,
  );
  const commentStep = workflow.split("- name: Send comment with unexpected broken links")[1];
  assert.ok(commentStep);
  assert.match(commentStep, /file-path:\s*\.link-check\/unexpected\.md/);
  // The pinned action ignores file-path when message is nonempty.
  assert.doesNotMatch(commentStep, /^\s*message:/m);
  assert.doesNotMatch(commentStep, /file-path:\s*\.link-check\/known\.md/);

  const artifactStep = workflow
    .split("- name: Preserve link check diagnostics")[1]
    .split("- name:")[0];
  assert.match(artifactStep, /if:\s*always\(\)/);
  assert.match(artifactStep, /uses:\s*actions\/upload-artifact@[0-9a-f]{40}/);
  assert.match(artifactStep, /name:\s*link-check-diagnostics/);
  assert.match(artifactStep, /path:\s*\.link-check\//);
  assert.match(artifactStep, /include-hidden-files:\s*true/);
});

test("default diagnostics survive checker-then-lint without entering Git", (t) => {
  const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), "link-check-lint-"));
  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));
  fs.mkdirSync(path.join(fixtureRoot, "scripts"));
  fs.mkdirSync(path.join(fixtureRoot, "cheatsheets"));
  for (const file of [
    "scripts/Check_Markdown_Links.js",
    "scripts/Prepare_Link_Check_Diagnostics.js",
    ".gitignore",
    ".markdownlintignore",
    ".markdownlint.json",
    "link-check-known-failures.json",
  ]) {
    fs.copyFileSync(path.join(repoRoot, file), path.join(fixtureRoot, file));
  }
  fs.writeFileSync(path.join(fixtureRoot, "markdown-link-check-config.json"), "{}\n");
  fs.writeFileSync(path.join(fixtureRoot, "cheatsheets", "broken.md"),
    "# Broken\n\n[Missing](missing.md)\n");
  const env = { ...process.env };
  for (const key of Object.keys(env)) {
    if (key.startsWith("MARKDOWN_LINK_CHECK_")) delete env[key];
  }
  env.MARKDOWN_LINK_CHECK_BIN = path.join(repoRoot, "node_modules", "markdown-link-check", "markdown-link-check");
  const checked = spawnSync(process.execPath, ["scripts/Check_Markdown_Links.js"], {
    cwd: fixtureRoot, env, encoding: "utf8",
  });
  assert.equal(checked.status, 1, checked.stderr);
  const reportPath = path.join(fixtureRoot, ".link-check", "unexpected.md");
  const report = fs.readFileSync(reportPath, "utf8");
  assert.match(report, /FILE: cheatsheets\/broken\.md/);
  assert.match(report, /missing\.md/);
  assert.match(fs.readFileSync(path.join(fixtureRoot, ".link-check", "raw.log"), "utf8"), /dead link/);

  const summaryPath = path.join(fixtureRoot, "summary.txt");
  const outputPath = path.join(fixtureRoot, "output.txt");
  const prepared = spawnSync(process.execPath, ["scripts/Prepare_Link_Check_Diagnostics.js"], {
    cwd: fixtureRoot, encoding: "utf8",
    env: {
      ...env,
      GITHUB_STEP_SUMMARY: summaryPath,
      GITHUB_OUTPUT: outputPath,
      LINK_CHECK_OUTCOME: "failure",
      LINK_CHECK_EVENT_NAME: "pull_request",
      LINK_CHECK_HEAD_REPOSITORY: "OWASP/CheatSheetSeries",
      LINK_CHECK_REPOSITORY: "OWASP/CheatSheetSeries",
    },
  });
  assert.equal(prepared.status, 0, prepared.stderr);
  assert.match(fs.readFileSync(outputPath, "utf8"), /^should_comment=true$/m);
  assert.ok(fs.readFileSync(summaryPath, "utf8").includes(report));

  const linted = spawnSync(process.execPath, [
    path.join(repoRoot, "node_modules", "markdownlint-cli", "markdownlint.js"),
    "./", "-c", ".markdownlint.json", "--ignore", "node_modules", "--ignore", "cheatsheets_excluded",
  ], { cwd: fixtureRoot, encoding: "utf8" });
  assert.equal(linted.status, 0, linted.stderr);

  const initialized = spawnSync("git", ["init", "--quiet"], { cwd: fixtureRoot, encoding: "utf8" });
  assert.equal(initialized.status, 0, initialized.stderr);
  const ignored = spawnSync("git", ["check-ignore", ".link-check/raw.log", ".link-check/known.md", ".link-check/unexpected.md"], {
    cwd: fixtureRoot, encoding: "utf8",
  });
  assert.equal(ignored.status, 0, ignored.stderr);
  assert.equal(ignored.stdout.trim().split(/\r?\n/).length, 3);
});

test("the package test command uses explicit Windows-cmd-portable file paths", () => {
  const packageJson = JSON.parse(
    fs.readFileSync(path.join(repoRoot, "package.json"), "utf8"),
  );
  assert.equal(
    packageJson.scripts["test:link-check"],
    "node --test tests/link-check/apply-link-check.test.js tests/link-check/workflow-diagnostics.test.js",
  );
  assert.doesNotMatch(packageJson.scripts["test:link-check"], /[*?\[\]]/);
});
