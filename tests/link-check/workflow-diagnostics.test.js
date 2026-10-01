const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const { python, repoRoot } = require("./helpers");

const prepareScript = path.join(repoRoot, "scripts", "Prepare_Link_Check_Diagnostics.js");

function loadWorkflow(name) {
  const result = spawnSync(
    python,
    ["-c", "import json, sys, yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1]))))", path.join(repoRoot, ".github", "workflows", name)],
    { encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
  const workflow = JSON.parse(result.stdout);
  // YAML 1.1 reads the "on" key as true.
  workflow.on = workflow.on || workflow.true;
  return workflow;
}

function runPrepare(t, { results, outcome }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "link-check-summary-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  if (results) {
    fs.writeFileSync(path.join(dir, "results.json"), JSON.stringify(results));
  }
  const summaryPath = path.join(dir, "summary.md");
  const run = spawnSync(process.execPath, [prepareScript], {
    encoding: "utf8",
    env: { ...process.env, GITHUB_STEP_SUMMARY: summaryPath, LINK_CHECK_OUTCOME: outcome, LINK_CHECK_OUTPUT_DIR: dir },
  });
  assert.equal(run.status, 0, run.stderr);
  return fs.readFileSync(summaryPath, "utf8");
}

const baseResults = (overrides = {}) => ({
  schemaVersion: 1,
  status: "passed",
  mode: "full",
  base: { mergeBase: "a".repeat(40) },
  counts: { files: 2, occurrences: { total: 5 }, external: { selectedOccurrences: 2, distinctPages: 1, assessedPages: 1, cacheHits: 0, requests: 2 } },
  errors: [],
  findings: [],
  exceptions: [],
  durationMs: 1000,
  ...overrides,
});

const item = (overrides) => ({ file: "cheatsheets/A.md", line: 3, ordinal: 1, url: "https://x.example/", outcome: "unverified", category: "access-restricted", ...overrides });

test("a passing PR summary still lists new links needing manual verification", (t) => {
  const summary = runPrepare(t, {
    outcome: "success",
    results: baseResults({ findings: [item({ new: true }), item({ url: "https://old.example/", new: false })] }),
  });
  assert.match(summary, /# Markdown link check PASSED/);
  assert.match(summary, /## Manual verification requested for new links \(1\)/);
  assert.match(summary, /x\.example/);
  assert.doesNotMatch(summary, /old\.example/);
  assert.match(summary, /link-check-diagnostics/);
});

test("a failing summary shows blocking problems and existing debt separately", (t) => {
  const summary = runPrepare(t, {
    outcome: "failure",
    results: baseResults({
      status: "failed",
      base: null,
      findings: [
        item({ outcome: "broken", category: "not-found", blocking: true }),
        item({ outcome: "broken", category: "missing-anchor", blocking: false, exception: { expiresOn: "2026-12-31" } }),
      ],
    }),
  });
  assert.match(summary, /# Markdown link check FAILED/);
  assert.match(summary, /## Blocking problems \(1\)/);
  assert.match(summary, /## Existing broken links \(maintenance debt, not blocking\) \(1\)/);
  assert.match(summary, /excepted until 2026-12-31/);
});

test("a missing results file produces an incomplete summary", (t) => {
  const summary = runPrepare(t, { outcome: "failure" });
  assert.match(summary, /# Markdown link check INCOMPLETE/);
  assert.match(summary, /no results file was written/);
  assert.match(summary, /No links should be treated as checked/);
});

test("a cancelled step is flagged even when a results file exists", (t) => {
  const summary = runPrepare(t, {
    outcome: "cancelled",
    results: baseResults({ status: "incomplete", errors: ["the checker started but did not finish"] }),
  });
  assert.match(summary, /step outcome was `cancelled`/);
  assert.match(summary, /## Internal errors \(the check is incomplete\) \(1\)/);
});

test("summaries are bounded while results.json keeps every row", (t) => {
  const findings = Array.from({ length: 250 }, (_, index) =>
    item({ url: `https://x.example/${index}`, ordinal: index, outcome: "broken", category: "not-found", blocking: true }),
  );
  const summary = runPrepare(t, { outcome: "failure", results: baseResults({ status: "failed", base: null, findings }) });
  assert.match(summary, /## Blocking problems \(250\)/);
  assert.match(summary, /…and 150 more in `results\.json`/);
});

test("the workflow covers every PR, runs unprivileged, and cancels superseded PR runs", () => {
  const workflow = loadWorkflow("md-link-check.yml");
  assert.deepEqual(Object.keys(workflow.on).sort(), ["pull_request", "push", "schedule", "workflow_dispatch"]);
  assert.deepEqual(workflow.on.pull_request, {
    types: ["opened", "synchronize", "reopened", "edited", "ready_for_review"],
  }, "every target branch and changed path is eligible, including retargeted PRs");
  assert.deepEqual(workflow.on.push, { branches: ["master"] }, "branch pushes do not duplicate their PR run");
  assert.equal(workflow.on.workflow_dispatch.inputs.fresh.type, "boolean");
  assert.match(workflow.concurrency.group, /github\.event\.pull_request\.number/);
  assert.match(workflow.concurrency.group, /github\.run_id/, "audits do not share a group");
  assert.equal(workflow.concurrency["cancel-in-progress"], "${{ github.event_name == 'pull_request' }}");

  const text = fs.readFileSync(path.join(repoRoot, ".github", "workflows", "md-link-check.yml"), "utf8");
  assert.doesNotMatch(text, /pull_request_target|secrets\.|GITHUB_TOKEN|github\.token|pull-requests:/);
  assert.deepEqual(workflow.permissions, {});
  const job = workflow.jobs["link-check"];
  assert.equal(job.if, undefined, "drafts, forks, and bot authors must not skip the job");
  const checkIndex = job.steps.findIndex((s) => s.id === "link_check");
  assert.ok(checkIndex >= 0, "the link checker step is present");
  for (const step of job.steps.slice(0, checkIndex + 1)) {
    if (step.name === "Restore cached successes") continue;
    assert.equal(step.if, undefined, `${step.name} must run for every PR`);
  }
  assert.deepEqual(job.permissions, { contents: "read" });
  assert.ok(job["timeout-minutes"] > job.steps.find((s) => s.id === "link_check")["timeout-minutes"], "diagnostics outlive the check step");
  const checkout = job.steps.find((s) => String(s.uses).startsWith("actions/checkout@"));
  assert.equal(checkout.with["persist-credentials"], false);
  for (const step of job.steps.filter((s) => s.uses)) {
    assert.match(step.uses, /@[0-9a-f]{40}$/, `${step.uses} is pinned`);
  }
  // Untrusted values reach the shell through environment variables only.
  const check = job.steps.find((s) => s.id === "link_check");
  assert.doesNotMatch(check.run, /\$\{\{/);
});

test("the workflow keeps diagnostics on failure and scopes caches by trust", () => {
  const job = loadWorkflow("md-link-check.yml").jobs["link-check"];
  const step = (name) => job.steps.find((s) => s.name === name);
  assert.equal(step("Prepare link check diagnostics").if, "always()");
  const upload = step("Preserve link check diagnostics");
  assert.equal(upload.if, "always()");
  assert.equal(upload.with.path, ".link-check/");
  assert.equal(upload.with.name, "link-check-diagnostics");

  const save = step("Save cached successes");
  assert.match(save.if, /^always\(\)/);
  assert.match(save.if, /env\.TRUSTED_AUDIT == 'true'/);
  assert.doesNotMatch(save.if, /pull_request/);
  assert.match(job.env.TRUSTED_AUDIT, /github\.ref == format\('refs\/heads\/\{0\}', github\.event\.repository\.default_branch\)/);
  assert.equal(job.env.CACHE_PREFIX, "link-check-http-v2-trusted-");
  const restore = step("Restore cached successes");
  assert.match(restore.if, /github\.event\.pull_request\.head\.repo\.full_name == github\.repository/);
  assert.equal(restore.with["restore-keys"].trim(), "${{ env.CACHE_PREFIX }}");
  assert.equal(save.with.path, ".link-check-cache/");
  assert.equal(save.with.key, step("Restore cached successes").with.key);
  assert.doesNotMatch(step("Restore cached successes").if, /push/);
});

test("the run step chooses the mode for each event", (t) => {
  const job = loadWorkflow("md-link-check.yml").jobs["link-check"];
  const script = job.steps.find((s) => s.id === "link_check").run;
  const bin = fs.mkdtempSync(path.join(os.tmpdir(), "fake-npm-"));
  t.after(() => fs.rmSync(bin, { recursive: true, force: true }));
  fs.writeFileSync(path.join(bin, "npm"), '#!/bin/sh\nprintf "%s|" "$@"\n', { mode: 0o755 });
  const sha = "0123456789abcdef0123456789abcdef01234567";
  const run = (env) => {
    const result = spawnSync("bash", ["-e", "-c", script], {
      encoding: "utf8",
      env: { PATH: `${bin}:${process.env.PATH}`, EVENT_NAME: "", PR_BASE_SHA: "", PUSH_BEFORE_SHA: "", FRESH: "false", ...env },
    });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout;
  };
  const prefix = "run|link-check|--silent|--|";
  assert.equal(run({ EVENT_NAME: "pull_request", PR_BASE_SHA: sha }), `${prefix}--base|${sha}|`);
  assert.equal(run({ EVENT_NAME: "push", PUSH_BEFORE_SHA: sha }), `${prefix}--local-only|--base|${sha}|`);
  assert.equal(run({ EVENT_NAME: "push", PUSH_BEFORE_SHA: "0".repeat(40) }), `${prefix}--local-only|`);
  assert.equal(run({ EVENT_NAME: "push", PUSH_BEFORE_SHA: "$(touch /tmp/x)" }), `${prefix}--local-only|`);
  assert.equal(run({ EVENT_NAME: "schedule", FRESH: "true" }), `${prefix}--fresh|`);
  assert.equal(run({ EVENT_NAME: "workflow_dispatch", FRESH: "false" }), prefix);
});

test("the lint workflow installs the renderer that npm test needs", () => {
  const job = loadWorkflow("md_lint_check.yml").jobs.lint;
  const install = job.steps.find((s) => s.name === "Install dependencies");
  assert.match(install.run, /pip install .*-r scripts\/link_check\/requirements\.txt/);
  assert.ok(job.steps.some((s) => String(s.uses).startsWith("actions/setup-python@")));
});


test("review guidance requires source reading even for healthy or cached citations", () => {
  for (const file of [".github/skills/code-review/SKILL.md", ".github/instructions/cheatsheets.instructions.md"]) {
    const text = fs.readFileSync(path.join(repoRoot, file), "utf8");
    assert.match(text, /Fetch and read every new or changed source/);
    assert.match(text, /healthy or cached/);
    assert.doesNotMatch(text, /open only|Fetch links yourself only|ignored domain/);
  }
});


test("each CI revision discards PR-controlled cache evidence before trusted restore", (t) => {
  const job = loadWorkflow("md-link-check.yml").jobs["link-check"];
  const clear = job.steps.find((step) => step.name === "Clear checkout cache evidence");
  const restore = job.steps.find((step) => step.name === "Restore cached successes");
  assert.ok(job.steps.indexOf(clear) < job.steps.indexOf(restore));
  assert.equal(clear.if, undefined, "fork and same-repository PRs both clear checkout evidence");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ci-revisions-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  // Revision A manufactures success evidence. Revision B must start without it.
  for (const revision of ["malicious-A", "clean-B"]) {
    fs.mkdirSync(path.join(root, ".link-check-cache"), { recursive: true });
    fs.writeFileSync(path.join(root, ".link-check-cache/http-success.json"), revision);
    const result = spawnSync("bash", ["-c", clear.run], { cwd: root, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(fs.existsSync(path.join(root, ".link-check-cache/http-success.json")), false);
  }
  assert.equal(job.env.CACHE_PREFIX, "link-check-http-v2-trusted-");
  assert.doesNotMatch(restore.with["restore-keys"], /pr-/);
  assert.doesNotMatch(job.steps.find((step) => step.name === "Save cached successes").if, /pull_request/);
});


test("checkout fetches complete history for PR and push merge-base comparisons", () => {
  const job = loadWorkflow("md-link-check.yml").jobs["link-check"];
  const checkout = job.steps.find((step) => step.uses?.startsWith("actions/checkout@"));
  assert.equal(checkout.with["fetch-depth"], 0, "the parsed depth must be zero, not a truthiness expression that evaluates to one");
});
