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
// npm supplies its JavaScript entry point, which also works on Windows.
// Direct node --test invocations exercise the driver without requiring npm.
const linkCheckArgs = process.env.npm_execpath
  ? [process.env.npm_execpath, "run", "link-check", "--silent"]
  : [path.join(repoRoot, "scripts", "Check_Markdown_Links.js")];
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
const finalProvenance = {
  attemptCount: 3,
  checkedHead: "ac393f85d2eff599b344ec29c95b47ab7186c650",
  contentBaseCommit: "e5420b90672011aa84d3e5de3c3e38f704a5033d",
  workflowRunId: 34235010164,
  workflowJobId: 102090344721,
  workflowUrl:
    "https://github.com/OWASP/CheatSheetSeries/actions/runs/34235010164/job/102090344721",
};
const reviewedProvenance = {
  attemptCount: 3,
  checkedHead: "100ec630ce8ca4c2909463995f05986ca34a3ed5",
  contentBaseCommit: "327812ee76aac6a87e32fbdce5b5d1cce39b5741",
  workflowRunId: 36353962728,
  workflowJobId: 108717860244,
  workflowUrl:
    "https://github.com/OWASP/CheatSheetSeries/actions/runs/36353962728/job/108717860244",
};
const currentPushProvenance = {
  attemptCount: 3,
  checkedHead: "fb62bdea203001e10598c33eb157a26d987a372f",
  contentBaseCommit: "57581d18010feba51d8eda5e2dfb6dabb7b7316c",
  workflowRunId: 36494363113,
  workflowJobId: 109170327939,
  workflowUrl:
    "https://github.com/OWASP/CheatSheetSeries/actions/runs/36494363113/job/109170327939",
};
const currentPrProvenance = {
  ...currentPushProvenance,
  workflowRunId: 36494366260,
  workflowJobId: 109170338388,
  workflowUrl:
    "https://github.com/OWASP/CheatSheetSeries/actions/runs/36494366260/job/109170338388",
};
const followupPushProvenance = {
  attemptCount: 3,
  checkedHead: "c8ac16354c4231e64a0416f33538e47cf8648a49",
  contentBaseCommit: "57581d18010feba51d8eda5e2dfb6dabb7b7316c",
  workflowRunId: 36496455840,
  workflowJobId: 109177047372,
  workflowUrl:
    "https://github.com/OWASP/CheatSheetSeries/actions/runs/36496455840/job/109177047372",
};
const followupPrProvenance = {
  ...followupPushProvenance,
  workflowRunId: 36496459649,
  workflowJobId: 109177059538,
  workflowUrl:
    "https://github.com/OWASP/CheatSheetSeries/actions/runs/36496459649/job/109177059538",
};
const rerunPrProvenance = {
  attemptCount: 3,
  checkedHead: "42570a09befae5e2c5ed5b6be8d2901b488028fe",
  contentBaseCommit: "57581d18010feba51d8eda5e2dfb6dabb7b7316c",
  workflowRunId: 36498326700,
  workflowJobId: 109247737627,
  workflowUrl:
    "https://github.com/OWASP/CheatSheetSeries/actions/runs/36498326700/job/109247737627",
};

// Reviewed CI evidence for the shared failures affecting otherwise unchanged sheets.
const sharedFailureBatches = [
  {
    generatedFrom: {
      attemptCount: 3,
      checkedHead: "d6146c3844212b9514e3003375dd34b76373c8c7",
      contentBaseCommit: "d6146c3844212b9514e3003375dd34b76373c8c7",
      workflowRunId: 36740088549,
      workflowJobId: 109971909099,
      workflowUrl: "https://github.com/OWASP/CheatSheetSeries/actions/runs/36740088549/job/109971909099"
    },
    failures: [
      {
        file: "cheatsheets/XPath_Injection_Prevention_Cheat_Sheet.md",
        url: "https://www.w3.org/TR/xpath-31/#id-variables",
        observedStatuses: [403, 403, 403]
      }
    ]
  },
  {
    generatedFrom: {
      attemptCount: 3,
      checkedHead: "3b5b33b6b2df06afb81dfc645b8f156a71569739",
      contentBaseCommit: "b2d78808122127ab402f62c076e19756a09cfca4",
      workflowRunId: 36708732055,
      workflowJobId: 109977286541,
      workflowUrl: "https://github.com/OWASP/CheatSheetSeries/actions/runs/36708732055/job/109977286541"
    },
    failures: [
      {
        file: "cheatsheets/Virtual_Patching_Cheat_Sheet.md",
        url: "https://web.archive.org/web/20181011065823/http://www.jwall.org/web/audit/viewer.jsp",
        observedStatuses: [429, 429, 429]
      }
    ]
  },
  {
    generatedFrom: {
      attemptCount: 3,
      checkedHead: "6cce391c9e6578c6ef64d4ecff059c71d50d0ee4",
      contentBaseCommit: "b2d78808122127ab402f62c076e19756a09cfca4",
      workflowRunId: 36714167518,
      workflowJobId: 109977303743,
      workflowUrl: "https://github.com/OWASP/CheatSheetSeries/actions/runs/36714167518/job/109977303743"
    },
    failures: [
      {
        file: "cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.md",
        url: "https://embeddedartistry.com/blog/2017/04/10/recursive-make-considered-harmful/",
        observedStatuses: [0, 0, 0]
      }
    ]
  },
  {
    generatedFrom: {
      attemptCount: 3,
      checkedHead: "19974462ddfd97991dc0074adc263864b0032b94",
      contentBaseCommit: "b2d78808122127ab402f62c076e19756a09cfca4",
      workflowRunId: 36731824972,
      workflowJobId: 109943166585,
      workflowUrl: "https://github.com/OWASP/CheatSheetSeries/actions/runs/36731824972/job/109943166585"
    },
    failures: [
      {
        file: "cheatsheets/Input_Validation_Cheat_Sheet.md",
        url: "https://web.archive.org/web/20170717174432/https://ipsec.pl/python/2017/input-validation-free-form-unicode-text-python.html/",
        observedStatuses: [429, 429, 429]
      },
      {
        file: "cheatsheets/Web_Cache_Security_Cheat_Sheet.md",
        url: "https://owasp.org/www-community/attacks/Cache_Poisoning",
        observedStatuses: [403, 403, 403]
      },
      {
        file: "cheatsheets/XPath_Injection_Prevention_Cheat_Sheet.md",
        url: "https://owasp.org/www-community/Access_Control#principle-of-least-privilege",
        observedStatuses: [403, 403, 403]
      }
    ]
  },
  {
    generatedFrom: {
      attemptCount: 3,
      checkedHead: "a9b9d284010284843b9415ec253776d4faf1a34d",
      contentBaseCommit: "a9b9d284010284843b9415ec253776d4faf1a34d",
      workflowRunId: 36758158538,
      workflowJobId: 110033594899,
      workflowUrl: "https://github.com/OWASP/CheatSheetSeries/actions/runs/36758158538/job/110033594899"
    },
    failures: [
      {
        file: "cheatsheets/NPM_Security_Cheat_Sheet.md",
        url: "https://owasp.org/www-community/Component_Analysis",
        observedStatuses: [403, 403, 403]
      },
      {
        file: "cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.md",
        url: "https://owasp.org/www-community/attacks/Command_Injection",
        observedStatuses: [403, 403, 403]
      },
      {
        file: "cheatsheets/Pinning_Cheat_Sheet.md",
        url: "https://owasp.org/www-community/Injection_Theory",
        observedStatuses: [403, 403, 403]
      },
      {
        file: "cheatsheets/Pinning_Cheat_Sheet.md",
        url: "https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning",
        observedStatuses: [403, 403, 403]
      }
    ]
  },
  {
    generatedFrom: {
      attemptCount: 3,
      checkedHead: "2ac768df90f5e770a331a83cc670a06bdea91bdb",
      contentBaseCommit: "2ac768df90f5e770a331a83cc670a06bdea91bdb",
      workflowRunId: 36762726124,
      workflowJobId: 110049099112,
      workflowUrl: "https://github.com/OWASP/CheatSheetSeries/actions/runs/36762726124/job/110049099112"
    },
    failures: [
      {
        file: "cheatsheets/C-Based_Toolchain_Hardening_Cheat_Sheet.md",
        url: "https://www.gnu.org/software/automake/manual/html_node/VPATH-Builds.html",
        observedStatuses: [403, 0, 0]
      }
    ]
  }
];

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

  const result = spawnSync(process.execPath, linkCheckArgs, {
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
  assert.equal(value.batches.length, 15);
  assert.deepEqual(value.batches.slice(9), sharedFailureBatches);
  assert.deepEqual(value.batches[0].generatedFrom, provenance);
  assert.deepEqual(value.batches[1].generatedFrom, supplementalProvenance);
  assert.deepEqual(value.batches[2].generatedFrom, finalProvenance);
  assert.deepEqual(value.batches[3].generatedFrom, reviewedProvenance);
  assert.deepEqual(value.batches[4].generatedFrom, currentPushProvenance);
  assert.deepEqual(value.batches[5].generatedFrom, currentPrProvenance);
  assert.deepEqual(value.batches[6].generatedFrom, followupPushProvenance);
  assert.deepEqual(value.batches[7].generatedFrom, followupPrProvenance);
  assert.deepEqual(value.batches[8].generatedFrom, rerunPrProvenance);
  assert.equal(value.batches[0].failures.length, 156);
  assert.equal(value.batches[1].failures.length, 7);
  assert.equal(value.batches[3].failures.length, 107);
  assert.equal(value.batches[4].failures.length, 33);
  assert.equal(value.batches[5].failures.length, 14);
  assert.equal(value.batches[6].failures.length, 9);
  assert.equal(value.batches[7].failures.length, 1);
  assert.equal(value.batches[8].failures.length, 10);
  assert.deepEqual(value.batches[2].failures, [
    {
      file: "cheatsheets/Drone_Security_Cheat_Sheet.md",
      url: "https://ieeexplore.ieee.org/abstract/document/9994719",
      observedStatuses: [418, 418, 418],
    },
    {
      file: "cheatsheets/Pinning_Cheat_Sheet.md",
      url: "https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05g-Testing-Network-Communication.md#network-libraries-and-webviews",
      observedStatuses: [429, 429, 429],
    },
  ]);
  const failures = value.batches.flatMap((batch) => batch.failures);
  assert.equal(failures.length, 350);
  assert.equal(new Set(failures.map(({ file }) => file)).size, 88);
  assert.equal(
    new Set(failures.map(({ file, url }) => `${file}\0${url}`)).size,
    350,
  );
  assert.ok(
    value.batches.slice(1).every(({ failures: batchFailures }) =>
      batchFailures.every(
        ({ observedStatuses }) =>
          observedStatuses.length === 3 &&
          observedStatuses.every(Number.isInteger),
      ),
    ),
  );
  for (const inconsistentUrl of [
    "https://github.com/jdereg/json-io/blob/master/user-guide.md#non-typed-usage",
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
  assert.ok(result.stderr.includes(result.unexpected));
});

test("an unsupported link cannot pass as a checker warning", (t) => {
  const result = runLinkCheck(t, {
    files: { "unsupported.md": "# Unsupported\n\n[Unsupported](ftp://example.invalid/file)\n" },
  });

  assert.equal(result.status, 1);
  assert.match(result.raw, /\[⚠\]/);
  assert.match(result.stderr, /unsupported\.md: checker could not assess link/);
  assert.doesNotMatch(result.stdout, /No unexpected link failures/);
  assert.equal(result.unexpected, "");
});

test("a checker warning stays fatal alongside an exact known failure", (t) => {
  const checker = createChecker(t, [
    "const file = process.argv.at(-1);",
    "console.log(`FILE: ${file}`);",
    'console.log("  [\\u001B[33m⚠\\u001B[39m] ftp://example.invalid/file");',
    'console.log("  2 links checked.");',
    'console.error("  ERROR: 1 dead link found!");',
    'console.log("  [✖] missing.md → Status: 400");',
    "process.exitCode = 1;",
  ].join("\n"));
  const result = runLinkCheck(t, {
    checker,
    baselineContents: JSON.stringify(baseline([{
      file: "cheatsheets/valid.md", url: "missing.md", observedStatus: 400,
    }])),
  });

  assert.equal(result.status, 1);
  assert.match(result.stderr, /checker could not assess link/);
  assert.doesNotMatch(result.known, /\[known\]|\[recovered\]/);
  assert.equal(result.unexpected, "");
});

test("an empty target cannot pass without checking any files", (t) => {
  const result = runLinkCheck(t, { files: {} });

  assert.equal(result.status, 1);
  assert.match(result.stderr, /no Markdown files found; no links were checked/);
  assert.doesNotMatch(result.raw, /^===== FILE:/m);
  assert.doesNotMatch(result.stdout, /No unexpected link failures/);
});

test("ANSI-colored checker output retains exact file and URL provenance", (t) => {
  const checker = createChecker(
    t,
    [
      "const file = process.argv.at(-1);",
      "console.log(`\\u001B[36mFILE: ${file}\\u001B[39m`);",
      'console.log("  1 link checked.");',
      'console.error("  \\u001B[31mERROR: 1 dead link found!\\u001B[39m");',
      'console.log("  [\\u001B[31m✖\\u001B[39m] https://color.invalid/failure → Status: 404");',
      "process.exitCode = 1;",
      "",
    ].join("\n"),
  );
  const result = runLinkCheck(t, {
    checker,
    files: { "colored.md": "# Colored\n" },
  });

  assert.notEqual(result.status, 0);
  assert.match(result.raw, /\u001B\[36mFILE:/);
  assert.match(result.raw, /\[\u001B\[31m✖\u001B\[39m\]/);
  assert.match(result.unexpected, /FILE: cheatsheets\/colored\.md/);
  assert.match(result.unexpected, /https:\/\/color\.invalid\/failure/);
  assert.doesNotMatch(result.raw, /lacks the expected FILE header/);
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
  assert.ok(result.stderr.includes(result.unexpected));
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
  assert.match(result.stderr, /valid\.md: checker exited with unexpected status 42/);
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

test("a nonzero checker result with no dead links remains fatal", (t) => {
  const checker = createChecker(t, [
    "console.log(`FILE: ${process.argv.at(-1)}`);",
    'console.log("  0 links checked.");',
    'console.error("  ERROR: 0 dead links found!");',
    "process.exitCode = 1;",
  ].join("\n"));
  const result = runLinkCheck(t, { checker });

  assert.equal(result.status, 1);
  assert.match(result.stderr, /nonzero checker result has an invalid dead-link count/);
  assert.doesNotMatch(result.stdout, /No unexpected link failures/);
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
  assert.ok(result.stderr.includes(result.unexpected));
  assert.doesNotMatch(result.stderr, /mixed\.invalid\/known/);
});
