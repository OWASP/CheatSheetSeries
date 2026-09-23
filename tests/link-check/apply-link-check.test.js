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
  "markdown-link-check",
  "markdown-link-check",
);
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const provenance = {
  attemptCount: 1,
  checkedHead: "daae48ab4c94803f0250ff9beb5e4f815091e259",
  contentBaseCommit: "e5420b90672011aa84d3e5de3c3e38f704a5033d",
  workflowRunId: 34185231643,
  workflowJobId: 101932122278,
  workflowUrl:
    "https://github.com/OWASP/CheatSheetSeries/actions/runs/34185231643/job/101932122278",
};
const supplementalProvenance = {
  attemptCount: 3,
  checkedHead: "47a37a9226052e03a516a536e9431813e23878b9",
  contentBaseCommit: "e5420b90672011aa84d3e5de3c3e38f704a5033d",
  workflowRunId: 34228838406,
  workflowJobId: 102069549060,
  workflowUrl:
    "https://github.com/OWASP/CheatSheetSeries/actions/runs/34228838406/job/102069549060",
};

function baseline(failures = []) {
  return {
    schemaVersion: 2,
    batches: [{ generatedFrom: provenance, failures }],
  };
}

function writeFiles(root, files) {
  for (const [name, contents] of Object.entries(files)) {
    const file = path.join(root, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, contents);
  }
}

function createChecker(t, source) {
  const checkerRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "cheatsheet-fake-checker-"),
  );
  const checker = path.join(checkerRoot, "checker.js");
  t.after(() => fs.rmSync(checkerRoot, { recursive: true, force: true }));
  fs.writeFileSync(checker, source);
  return checker;
}

function canonicalChecker(t) {
  return createChecker(
    t,
    [
      'const fs = require("node:fs");',
      'const path = require("node:path");',
      "const file = process.argv.at(-1);",
      "let attemptIndex = 0;",
      "if (process.env.FAKE_CHECKER_INVOCATIONS) {",
      "  const previous = fs.existsSync(process.env.FAKE_CHECKER_INVOCATIONS)",
      '    ? fs.readFileSync(process.env.FAKE_CHECKER_INVOCATIONS, "utf8").split(/\\r?\\n/)',
      "    : [];",
      "  attemptIndex = previous.filter((entry) => entry === file).length;",
      '  fs.appendFileSync(process.env.FAKE_CHECKER_INVOCATIONS, `${file}\\n`);',
      "}",
      'const byFile = JSON.parse(process.env.FAKE_CHECKER_FAILURES || "{}");',
      'const attemptsByFile = JSON.parse(process.env.FAKE_CHECKER_ATTEMPTS || "{}");',
      "const attempts = attemptsByFile[path.basename(file)];",
      "const attempt = Array.isArray(attempts) && attempts.length > 0",
      "  ? attempts[Math.min(attemptIndex, attempts.length - 1)]",
      "  : null;",
      'if (attempt && attempt.internal === "crash") {',
      '  process.stderr.write("planned checker crash\\n");',
      "  process.exit(42);",
      "}",
      "const failures = Array.isArray(attempt) ? attempt : (byFile[path.basename(file)] || []);",
      'console.log(`FILE: ${file}`);',
      "for (const failure of failures) {",
      '  console.log(`  [✖] ${failure.url}`);',
      "}",
      'console.log(`\\n  ${failures.length} links checked.\\n`);',
      "if (failures.length > 0) {",
      '  console.log(`  ERROR: ${failures.length} dead link${failures.length === 1 ? "" : "s"} found!`);',
      "  for (const failure of failures) {",
      '    console.log(`  [✖] ${failure.url} → Status: ${failure.status}`);',
      "  }",
      "  process.exitCode = 1;",
      "}",
      "",
    ].join("\n"),
  );
}

function runLinkCheck(
  t,
  {
    baselineContents = JSON.stringify(baseline()),
    checker = realChecker,
    configContents = "{}\n",
    env = {},
    files = { "valid.md": "# Valid\n" },
    missingBaseline = false,
    missingConfig = false,
  } = {},
) {
  const fixtureRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "cheatsheet-link-check-"),
  );
  const targetDir = path.join(fixtureRoot, "cheatsheets");
  const config = path.join(fixtureRoot, "markdown-link-check-config.json");
  const baselinePath = path.join(fixtureRoot, "link-check-known-failures.json");
  const raw = path.join(fixtureRoot, "raw.log");
  const known = path.join(fixtureRoot, "known.md");
  const unexpected = path.join(fixtureRoot, "unexpected.md");

  t.after(() => fs.rmSync(fixtureRoot, { recursive: true, force: true }));
  fs.mkdirSync(targetDir);
  writeFiles(targetDir, files);
  if (!missingConfig) {
    fs.writeFileSync(config, configContents);
  }
  if (!missingBaseline) {
    fs.writeFileSync(baselinePath, `${baselineContents}\n`);
  }

  const result = spawnSync(npmCommand, ["run", "link-check", "--silent"], {
    cwd: repoRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      ...env,
      MARKDOWN_LINK_CHECK_BASELINE: baselinePath,
      MARKDOWN_LINK_CHECK_BIN: checker,
      MARKDOWN_LINK_CHECK_CONFIG: config,
      MARKDOWN_LINK_CHECK_KNOWN: known,
      MARKDOWN_LINK_CHECK_LOG: raw,
      MARKDOWN_LINK_CHECK_TARGET: targetDir,
      MARKDOWN_LINK_CHECK_UNEXPECTED: unexpected,
    },
  });

  const read = (file) => (fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "");
  return {
    ...result,
    baselinePath,
    known: read(known),
    raw: read(raw),
    targetDir,
    unexpected: read(unexpected),
  };
}

test("the committed baseline has exact reviewed provenance and tuples", () => {
  const value = JSON.parse(
    fs.readFileSync(path.join(repoRoot, "link-check-known-failures.json"), "utf8"),
  );
  assert.equal(value.schemaVersion, 2);
  assert.equal(value.batches.length, 2);
  assert.deepEqual(value.batches[0].generatedFrom, provenance);
  assert.deepEqual(value.batches[1].generatedFrom, supplementalProvenance);
  assert.equal(value.batches[0].failures.length, 168);
  assert.equal(value.batches[1].failures.length, 7);
  const failures = value.batches.flatMap((batch) => batch.failures);
  assert.equal(failures.length, 175);
  assert.equal(new Set(failures.map(({ file }) => file)).size, 64);
  assert.equal(
    new Set(failures.map(({ file, url }) => `${file}\0${url}`)).size,
    175,
  );
  assert.ok(
    value.batches[1].failures.every(
      ({ observedStatuses }) =>
        observedStatuses.length === 3 && observedStatuses.every(Number.isInteger),
    ),
  );
  for (const inconsistentUrl of [
    "https://github.com/jdereg/json-io/blob/master/user-guide.md#non-typed-usage",
    "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x06g-Testing-Network-Communication.md",
    "https://azure.microsoft.com/nl-nl/services/key-vault/",
  ]) {
    assert.equal(failures.some(({ url }) => url === inconsistentUrl), false);
  }
});

test("a valid local-link fixture exits zero", (t) => {
  const result = runLinkCheck(t, {
    files: {
      "target.md": "# Target\n",
      "valid.md": "# Valid\n\n[Existing target](target.md)\n",
    },
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /No unexpected link failures/);
  assert.match(result.raw, /FILE: .*valid\.md/);
  assert.equal(result.unexpected, "");
});

test("a broken local link exits nonzero with only unexpected diagnostics", (t) => {
  const result = runLinkCheck(t, {
    files: { "broken.md": "# Broken\n\n[Missing target](missing.md)\n" },
  });

  assert.notEqual(result.status, 0);
  assert.doesNotMatch(result.stdout, /All good/);
  assert.match(result.raw, /ERROR:/);
  assert.equal(result.known, "");
  assert.match(result.unexpected, /FILE: cheatsheets\/broken\.md/);
  assert.match(result.unexpected, /\[✖\] missing\.md → Status: 400/);
});

test("an unbaselined non-network failure is not retried", (t) => {
  const checker = canonicalChecker(t);
  const invocationLog = path.join(
    os.tmpdir(),
    `link-check-local-${process.pid}-${Date.now()}`,
  );
  t.after(() => fs.rmSync(invocationLog, { force: true }));
  const result = runLinkCheck(t, {
    checker,
    env: {
      FAKE_CHECKER_FAILURES: JSON.stringify({
        "local.md": [{ url: "missing.md", status: 400 }],
      }),
      FAKE_CHECKER_INVOCATIONS: invocationLog,
    },
    files: { "local.md": "# Local\n" },
  });

  assert.notEqual(result.status, 0);
  assert.equal(fs.readFileSync(invocationLog, "utf8").trim().split(/\r?\n/).length, 1);
  assert.match(result.raw, /attempt 1\/3/);
  assert.doesNotMatch(result.raw, /attempt 2\/3/);
});

test("an exact known tuple is nonblocking and separately reported", (t) => {
  const result = runLinkCheck(t, {
    baselineContents: JSON.stringify(
      baseline([
        {
          file: "cheatsheets/known.md",
          url: "missing.md",
          observedStatus: 404,
        },
      ]),
    ),
    files: { "known.md": "# Known\n\n[Missing target](missing.md)\n" },
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.known, /\[known\] missing\.md → Status: 400; baseline observed 404/);
  assert.equal(result.unexpected, "");
  assert.deepEqual(
    JSON.parse(fs.readFileSync(result.baselinePath, "utf8")).batches[0].failures,
    [
      {
        file: "cheatsheets/known.md",
        url: "missing.md",
        observedStatus: 404,
      },
    ],
  );
});

test("an exact tuple from a multi-observation evidence batch is known", (t) => {
  const result = runLinkCheck(t, {
    baselineContents: JSON.stringify({
      schemaVersion: 2,
      batches: [
        {
          generatedFrom: supplementalProvenance,
          failures: [
            {
              file: "cheatsheets/known.md",
              url: "missing.md",
              observedStatuses: [404, 404, 404],
            },
          ],
        },
      ],
    }),
    files: { "known.md": "# Known\n\n[Missing target](missing.md)\n" },
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.known, /\[known\] missing\.md → Status: 400; baseline observed 404/);
  assert.equal(result.unexpected, "");
});

test("the same URL in a different file remains fatal", (t) => {
  const result = runLinkCheck(t, {
    baselineContents: JSON.stringify(
      baseline([
        {
          file: "cheatsheets/known.md",
          url: "missing.md",
          observedStatus: 400,
        },
      ]),
    ),
    files: { "different.md": "# Different\n\n[Missing target](missing.md)\n" },
  });

  assert.notEqual(result.status, 0);
  assert.match(result.unexpected, /FILE: cheatsheets\/different\.md/);
  assert.doesNotMatch(result.known, /\[recovered\] missing\.md/);
});

test("an exact baseline row is recovered only after its file is assessed", (t) => {
  const result = runLinkCheck(t, {
    baselineContents: JSON.stringify(
      baseline([
        {
          file: "cheatsheets/assessed.md",
          url: "missing.md",
          observedStatus: 400,
        },
      ]),
    ),
    files: { "assessed.md": "# Assessed\n" },
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.known, /\[recovered\] missing\.md/);
  assert.match(result.known, /Status: not failing/);
});

test("a different URL on a known domain remains fatal", (t) => {
  const checker = canonicalChecker(t);
  const result = runLinkCheck(t, {
    checker,
    baselineContents: JSON.stringify(
      baseline([
        {
          file: "cheatsheets/domain.md",
          url: "https://example.invalid/old",
          observedStatus: 404,
        },
      ]),
    ),
    env: {
      FAKE_CHECKER_FAILURES: JSON.stringify({
        "domain.md": [{ url: "https://example.invalid/new", status: 404 }],
      }),
    },
    files: { "domain.md": "# Domain\n" },
  });

  assert.notEqual(result.status, 0);
  assert.match(result.unexpected, /https:\/\/example\.invalid\/new/);
  assert.doesNotMatch(result.unexpected, /example\.invalid\/old/);
});

for (const status of [0, 403, 404, 429, 500]) {
  test(`a new status ${status} failure remains fatal`, (t) => {
    const checker = canonicalChecker(t);
    const url = `https://status.invalid/${status}`;
    const result = runLinkCheck(t, {
      checker,
      env: {
        FAKE_CHECKER_FAILURES: JSON.stringify({
          "status.md": [{ url, status }],
        }),
      },
      files: { "status.md": "# Status\n" },
    });

    assert.notEqual(result.status, 0);
    assert.match(result.unexpected, new RegExp(`Status: ${status}`));
  });
}

test("a transient unbaselined network tuple is confirmed, visible, and nonfatal", (t) => {
  const checker = canonicalChecker(t);
  const invocationLog = path.join(
    os.tmpdir(),
    `link-check-transient-${process.pid}-${Date.now()}`,
  );
  t.after(() => fs.rmSync(invocationLog, { force: true }));
  const url = "https://transient.invalid/flaky";
  const result = runLinkCheck(t, {
    checker,
    env: {
      FAKE_CHECKER_ATTEMPTS: JSON.stringify({
        "transient.md": [[{ url, status: 429 }], []],
      }),
      FAKE_CHECKER_INVOCATIONS: invocationLog,
    },
    files: { "transient.md": "# Transient\n" },
  });

  assert.equal(result.status, 0, result.stderr);
  assert.equal(fs.readFileSync(invocationLog, "utf8").trim().split(/\r?\n/).length, 2);
  assert.match(result.raw, /attempt 1\/3/);
  assert.match(result.raw, /attempt 2\/3/);
  assert.match(result.known, /\[transient\].*transient\.invalid\/flaky/);
  assert.match(result.known, /attempts: 1=429, 2=recovered/);
  assert.equal(result.unexpected, "");
});

test("a network tuple failing only on the final observation is transient", (t) => {
  const checker = canonicalChecker(t);
  const invocationLog = path.join(
    os.tmpdir(),
    `link-check-late-${process.pid}-${Date.now()}`,
  );
  t.after(() => fs.rmSync(invocationLog, { force: true }));
  const persistentUrl = "https://persistent.invalid/trigger";
  const lateUrl = "https://transient.invalid/late";
  const result = runLinkCheck(t, {
    checker,
    env: {
      FAKE_CHECKER_INVOCATIONS: invocationLog,
      FAKE_CHECKER_ATTEMPTS: JSON.stringify({
        "late.md": [
          [{ url: persistentUrl, status: 503 }],
          [{ url: persistentUrl, status: 503 }],
          [
            { url: persistentUrl, status: 503 },
            { url: lateUrl, status: 429 },
          ],
        ],
      }),
    },
    files: { "late.md": "# Late\n" },
  });

  assert.notEqual(result.status, 0);
  assert.equal(fs.readFileSync(invocationLog, "utf8").trim().split(/\r?\n/).length, 3);
  assert.match(result.known, /\[transient\].*transient\.invalid\/late/);
  assert.match(result.known, /attempts: 1=not failing, 2=not failing, 3=429/);
  assert.doesNotMatch(result.unexpected, /transient\.invalid\/late/);
  assert.match(result.unexpected, /persistent\.invalid\/trigger/);
});

test("a network tuple that fails, recovers, and fails is transient", (t) => {
  const checker = canonicalChecker(t);
  const invocationLog = path.join(
    os.tmpdir(),
    `link-check-intermittent-${process.pid}-${Date.now()}`,
  );
  t.after(() => fs.rmSync(invocationLog, { force: true }));
  const persistentUrl = "https://persistent.invalid/trigger";
  const flakyUrl = "https://transient.invalid/intermittent";
  const result = runLinkCheck(t, {
    checker,
    env: {
      FAKE_CHECKER_INVOCATIONS: invocationLog,
      FAKE_CHECKER_ATTEMPTS: JSON.stringify({
        "intermittent.md": [
          [
            { url: persistentUrl, status: 503 },
            { url: flakyUrl, status: 429 },
          ],
          [{ url: persistentUrl, status: 503 }],
          [
            { url: persistentUrl, status: 503 },
            { url: flakyUrl, status: 500 },
          ],
        ],
      }),
    },
    files: { "intermittent.md": "# Intermittent\n" },
  });

  assert.notEqual(result.status, 0);
  assert.equal(fs.readFileSync(invocationLog, "utf8").trim().split(/\r?\n/).length, 3);
  assert.match(result.known, /\[transient\].*transient\.invalid\/intermittent/);
  assert.match(result.known, /attempts: 1=429, 2=recovered, 3=500/);
  assert.doesNotMatch(result.unexpected, /transient\.invalid\/intermittent/);
  assert.match(result.unexpected, /persistent\.invalid\/trigger/);
});

test("a persistent unbaselined network tuple remains fatal after bounded attempts", (t) => {
  const checker = canonicalChecker(t);
  const invocationLog = path.join(
    os.tmpdir(),
    `link-check-persistent-${process.pid}-${Date.now()}`,
  );
  t.after(() => fs.rmSync(invocationLog, { force: true }));
  const url = "https://persistent.invalid/failing";
  const result = runLinkCheck(t, {
    checker,
    env: {
      FAKE_CHECKER_ATTEMPTS: JSON.stringify({
        "persistent.md": [
          [{ url, status: 503 }],
          [{ url, status: 429 }],
          [{ url, status: 502 }],
        ],
      }),
      FAKE_CHECKER_INVOCATIONS: invocationLog,
    },
    files: { "persistent.md": "# Persistent\n" },
  });

  assert.notEqual(result.status, 0);
  assert.equal(fs.readFileSync(invocationLog, "utf8").trim().split(/\r?\n/).length, 3);
  assert.match(result.raw, /attempt 1\/3/);
  assert.match(result.raw, /attempt 2\/3/);
  assert.match(result.raw, /attempt 3\/3/);
  assert.match(result.unexpected, /persistent\.invalid\/failing/);
  assert.match(result.unexpected, /attempts: 1=503, 2=429, 3=502/);
});

test("a missing baseline is fatal before checker invocation", (t) => {
  const result = runLinkCheck(t, { missingBaseline: true });
  assert.notEqual(result.status, 0);
  assert.match(result.raw, /Known-failure baseline is unavailable/);
  assert.equal(result.unexpected, "");
});

test("a malformed baseline is fatal", async (t) => {
  await t.test("invalid JSON", (subtest) => {
    const result = runLinkCheck(subtest, { baselineContents: "{not json" });
    assert.notEqual(result.status, 0);
    assert.match(result.raw, /Known-failure baseline is malformed/);
    assert.equal(result.unexpected, "");
  });
  await t.test("invalid schema", (subtest) => {
    const result = runLinkCheck(subtest, {
      baselineContents: JSON.stringify({ ...baseline(), extra: true }),
    });
    assert.notEqual(result.status, 0);
    assert.match(
      result.raw,
      /baseline must contain only schemaVersion and batches/,
    );
    assert.equal(result.unexpected, "");
  });
  await t.test("batch without provenance", (subtest) => {
    const result = runLinkCheck(subtest, {
      baselineContents: JSON.stringify({
        schemaVersion: 2,
        batches: [
          {
            failures: [
              {
                file: "cheatsheets/valid.md",
                url: "https://example.invalid/missing-source",
                observedStatus: 404,
              },
            ],
          },
        ],
      }),
    });
    assert.notEqual(result.status, 0);
    assert.match(result.raw, /baseline batch 0 has an invalid shape/);
    assert.equal(result.unexpected, "");
  });
  await t.test("malformed provenance", (subtest) => {
    const result = runLinkCheck(subtest, {
      baselineContents: JSON.stringify({
        schemaVersion: 2,
        batches: [
          {
            generatedFrom: { ...provenance, checkedHead: "unknown" },
            failures: [
              {
                file: "cheatsheets/valid.md",
                url: "https://example.invalid/bad-source",
                observedStatus: 404,
              },
            ],
          },
        ],
      }),
    });
    assert.notEqual(result.status, 0);
    assert.match(result.raw, /baseline batch 0 provenance is malformed/);
    assert.equal(result.unexpected, "");
  });
  await t.test("duplicate tuple across evidence batches", (subtest) => {
    const failure = {
      file: "cheatsheets/valid.md",
      url: "https://example.invalid/duplicate",
      observedStatus: 404,
    };
    const result = runLinkCheck(subtest, {
      baselineContents: JSON.stringify({
        schemaVersion: 2,
        batches: [
          { generatedFrom: provenance, failures: [failure] },
          { generatedFrom: provenance, failures: [failure] },
        ],
      }),
    });
    assert.notEqual(result.status, 0);
    assert.match(result.raw, /baseline contains a duplicate tuple/);
    assert.equal(result.unexpected, "");
  });
});

test("a missing or malformed config is fatal", async (t) => {
  await t.test("missing", (subtest) => {
    const result = runLinkCheck(subtest, { missingConfig: true });
    assert.notEqual(result.status, 0);
    assert.match(result.raw, /Link checker configuration is unavailable/);
    assert.equal(result.unexpected, "");
  });
  await t.test("malformed", (subtest) => {
    const result = runLinkCheck(subtest, { configContents: "{not json" });
    assert.notEqual(result.status, 0);
    assert.match(result.raw, /Link checker configuration is malformed/);
    assert.equal(result.unexpected, "");
  });
});

test("a missing checker remains fatal even when its tuple is baselined", (t) => {
  const result = runLinkCheck(t, {
    baselineContents: JSON.stringify(
      baseline([
        {
          file: "cheatsheets/valid.md",
          url: "missing.md",
          observedStatus: 400,
        },
      ]),
    ),
    checker: path.join(os.tmpdir(), "missing-markdown-link-check.js"),
  });
  assert.notEqual(result.status, 0);
  assert.match(result.raw, /Link checker executable is unavailable/);
  assert.equal(result.unexpected, "");
});

test("a crashing checker without canonical diagnostics is fatal", (t) => {
  const checker = createChecker(t, 'process.stderr.write("crash\\n"); process.exit(42);\n');
  const result = runLinkCheck(t, {
    checker,
    baselineContents: JSON.stringify(
      baseline([
        {
          file: "cheatsheets/valid.md",
          url: "missing.md",
          observedStatus: 400,
        },
      ]),
    ),
  });

  assert.notEqual(result.status, 0);
  assert.match(result.raw, /crash/);
  assert.match(result.raw, /checker exited with unexpected status 42/);
  assert.doesNotMatch(result.known, /\[recovered\]/);
  assert.doesNotMatch(result.known, /Status: not failing/);
  assert.equal(result.unexpected, "");
});

test("a crashing checker with canonical-looking output is still internal and is not retried", (t) => {
  const checker = createChecker(
    t,
    [
      "const file = process.argv.at(-1);",
      "console.log(`FILE: ${file}`);",
      'console.log("  1 link checked.");',
      'console.error("  ERROR: 1 dead link found!");',
      'console.log("  [✖] https://crash.invalid/failure → Status: 503");',
      "process.exit(42);",
      "",
    ].join("\n"),
  );
  const result = runLinkCheck(t, { checker });

  assert.notEqual(result.status, 0);
  assert.match(result.raw, /attempt 1\/3/);
  assert.doesNotMatch(result.raw, /attempt 2\/3/);
  assert.match(result.raw, /checker exited with unexpected status 42/);
  assert.doesNotMatch(result.known, /\[transient\]/);
  assert.equal(result.unexpected, "");
});

test("an internal retry failure cannot turn a network failure into success", (t) => {
  const checker = canonicalChecker(t);
  const invocationLog = path.join(
    os.tmpdir(),
    `link-check-internal-retry-${process.pid}-${Date.now()}`,
  );
  t.after(() => fs.rmSync(invocationLog, { force: true }));
  const url = "https://transient.invalid/then-crash";
  const result = runLinkCheck(t, {
    baselineContents: JSON.stringify(
      baseline([
        {
          file: "cheatsheets/internal.md",
          url: "https://known.invalid/unassessed",
          observedStatus: 404,
        },
      ]),
    ),
    checker,
    env: {
      FAKE_CHECKER_ATTEMPTS: JSON.stringify({
        "internal.md": [[{ url, status: 429 }], { internal: "crash" }, []],
      }),
      FAKE_CHECKER_INVOCATIONS: invocationLog,
    },
    files: { "internal.md": "# Internal\n" },
  });

  assert.notEqual(result.status, 0);
  assert.equal(fs.readFileSync(invocationLog, "utf8").trim().split(/\r?\n/).length, 2);
  assert.match(result.raw, /attempt 1\/3/);
  assert.match(result.raw, /attempt 2\/3/);
  assert.doesNotMatch(result.raw, /attempt 3\/3/);
  assert.match(result.raw, /planned checker crash/);
  assert.doesNotMatch(result.known, /\[transient\]/);
  assert.doesNotMatch(result.known, /\[recovered\]/);
  assert.equal(result.unexpected, "");
});

test("a silent zero-exit checker is fatal", (t) => {
  const checker = createChecker(t, "process.exit(0);\n");
  const result = runLinkCheck(t, { checker });

  assert.notEqual(result.status, 0);
  assert.match(result.raw, /successful checker result lacks the expected FILE header/);
  assert.equal(result.unexpected, "");
});

test("every enumerated Markdown fixture is invoked", (t) => {
  const checker = canonicalChecker(t);
  const invocationLog = path.join(
    os.tmpdir(),
    `link-check-invocations-${process.pid}-${Date.now()}`,
  );
  t.after(() => fs.rmSync(invocationLog, { force: true }));
  const result = runLinkCheck(t, {
    checker,
    env: { FAKE_CHECKER_INVOCATIONS: invocationLog },
    files: {
      "a.md": "# A\n",
      "nested/b.md": "# B\n",
      "nested/c.md": "# C\n",
      "nested/ignored.txt": "not Markdown\n",
    },
  });

  assert.equal(result.status, 0, result.stderr);
  const invoked = fs
    .readFileSync(invocationLog, "utf8")
    .trim()
    .split(/\r?\n/)
    .map((file) => path.relative(result.targetDir, file).split(path.sep).join("/"))
    .sort();
  assert.deepEqual(invoked, ["a.md", "nested/b.md", "nested/c.md"]);
});

test("unexpected output excludes exact known rows in a mixed failure", (t) => {
  const checker = canonicalChecker(t);
  const knownUrl = "https://mixed.invalid/known";
  const newUrl = "https://mixed.invalid/new";
  const result = runLinkCheck(t, {
    checker,
    baselineContents: JSON.stringify(
      baseline([
        {
          file: "cheatsheets/mixed.md",
          url: knownUrl,
          observedStatus: 403,
        },
      ]),
    ),
    env: {
      FAKE_CHECKER_FAILURES: JSON.stringify({
        "mixed.md": [
          { url: knownUrl, status: 500 },
          { url: newUrl, status: 429 },
        ],
      }),
    },
    files: { "mixed.md": "# Mixed\n" },
  });

  assert.notEqual(result.status, 0);
  assert.match(result.known, /mixed\.invalid\/known/);
  assert.doesNotMatch(result.unexpected, /mixed\.invalid\/known/);
  assert.match(result.unexpected, /mixed\.invalid\/new/);
});
