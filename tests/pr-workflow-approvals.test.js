"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { audit, matchingApprovalRuns } = require("../scripts/Check_PR_Workflow_Approvals.js");

const pr = {
  number: 2402,
  created_at: "2026-09-03T07:00:00Z",
  closed_at: null,
  head: { ref: "topic", sha: "current", repo: { full_name: "contributor/CheatSheetSeries" } },
};
const held = {
  id: 1, name: "Index Drift Check", event: "pull_request", head_branch: "topic",
  head_sha: "older", head_repository: { full_name: "contributor/CheatSheetSeries" },
  created_at: "2026-10-01T17:29:38Z", status: "completed", conclusion: "action_required",
  pull_requests: [],
};

test("finds completed approval holds on old commits and duplicate runs on the current commit", () => {
  const runs = [held, { ...held, id: 2, head_sha: "current" }, { ...held, id: 3, head_sha: "current" }];
  assert.deepEqual(matchingApprovalRuns(pr, runs).map((run) => run.id), [1, 2, 3]);
});

test("excludes another fork, branch, event, PR, and runs predating the PR", () => {
  const unrelated = [
    { ...held, head_repository: { full_name: "other/CheatSheetSeries" } },
    { ...held, head_branch: "other" },
    { ...held, event: "push" },
    { ...held, pull_requests: [{ number: 2403 }] },
    { ...held, created_at: "2026-09-01T00:00:00Z" },
  ];
  assert.deepEqual(matchingApprovalRuns(pr, unrelated), []);
});

test("does not reinterpret historical failures or cancellations as approval holds", () => {
  const finished = ["success", "failure", "cancelled", "skipped"].map((conclusion) => ({ ...held, conclusion }));
  assert.deepEqual(matchingApprovalRuns(pr, finished), []);
});

test("excludes runs from branch reuse after a PR closed", () => {
  assert.deepEqual(matchingApprovalRuns({ ...pr, closed_at: "2026-10-01T00:00:00Z" }, [held]), []);
});

test("reads all API pages and includes old holds despite current-commit checks passing", () => {
  const calls = [];
  const request = (args) => {
    calls.push(args);
    return calls.length === 1 ? pr : [
      { total_count: 2, workflow_runs: [{ ...held, id: 2, head_sha: "current" }] },
      { total_count: 2, workflow_runs: [held] },
    ];
  };
  assert.deepEqual(audit("OWASP/CheatSheetSeries", 2402, "current", request).held.map((run) => run.id), [1, 2]);
  assert.deepEqual(calls[1].slice(0, 3), ["api", "--paginate", "--slurp"]);
  assert.equal(new URL(`https://api.github.com/${calls[1][3]}`).searchParams.get("status"), "action_required");
});

test("fails closed if the reviewed head changed", () => {
  assert.throws(() => audit("OWASP/CheatSheetSeries", 2402, "reviewed", () => pr), /head changed/);
});

test("fails closed on missing fork metadata, malformed pages, or a truncated search", () => {
  assert.throws(() => matchingApprovalRuns({ ...pr, head: { repo: null } }, []), /Cannot identify/);
  for (const pages of [[], [{}], [{ total_count: 1000, workflow_runs: [] }]]) {
    let calls = 0;
    assert.throws(() => audit("OWASP/CheatSheetSeries", 2402, null, () => ++calls === 1 ? pr : pages));
  }
});

test("rejects malformed repository and PR inputs before invoking GitHub", () => {
  const unexpected = () => assert.fail("GitHub must not be called");
  assert.throws(() => audit("--help", 2402, null, unexpected));
  assert.throws(() => audit("OWASP/CheatSheetSeries", "-1", null, unexpected));
});
