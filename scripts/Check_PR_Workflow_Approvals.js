#!/usr/bin/env node
"use strict";

const { execFileSync } = require("node:child_process");

function github(args) {
  return JSON.parse(execFileSync("gh", args, { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 }));
}

function matchingApprovalRuns(pr, runs) {
  if (!pr.head?.repo?.full_name || !pr.head.ref || !pr.created_at) {
    throw new Error("Cannot identify the PR's source repository, branch, and creation time.");
  }
  return runs.filter((run) => {
    const references = run.pull_requests || [];
    return run.event === "pull_request"
      && run.head_repository?.full_name?.toLowerCase() === pr.head.repo.full_name.toLowerCase()
      && run.head_branch === pr.head.ref
      && run.created_at >= pr.created_at
      && (!pr.closed_at || run.created_at <= pr.closed_at)
      && (!references.length || references.some((item) => item.number === pr.number))
      // GitHub reports approval holds as completed/action_required, with no jobs.
      && (run.conclusion === "action_required" || run.status === "action_required");
  }).sort((a, b) => a.id - b.id);
}

function audit(repo, number, expectedHead, request = github) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo) || !/^[1-9][0-9]*$/.test(String(number))) {
    throw new Error("Use --repo OWNER/REPO and a positive pull request number.");
  }
  const pr = request(["api", `repos/${repo}/pulls/${number}`]);
  if (expectedHead && pr.head?.sha !== expectedHead) {
    throw new Error(`PR head changed: expected ${expectedHead}, found ${pr.head?.sha}.`);
  }
  if (!pr.head?.repo?.full_name || !pr.head.ref || !pr.created_at) {
    throw new Error("Cannot audit a PR whose source repository or branch is unavailable.");
  }
  const query = new URLSearchParams({
    branch: pr.head.ref,
    event: "pull_request",
    status: "action_required",
    created: `>=${pr.created_at}`,
    per_page: "100",
  });
  const pages = request(["api", "--paginate", "--slurp", `repos/${repo}/actions/runs?${query}`]);
  if (!Array.isArray(pages) || !pages.length || pages.some((page) => !Array.isArray(page.workflow_runs))) {
    throw new Error("Incomplete workflow-run response; approval audit could not finish.");
  }
  // GitHub caps filtered run searches at 1,000 results. Never report a partial audit as clear.
  if (pages.some((page) => page.total_count >= 1000)) {
    throw new Error("Workflow search reached GitHub's 1,000-run limit; audit smaller date ranges manually.");
  }
  return { pr, held: matchingApprovalRuns(pr, pages.flatMap((page) => page.workflow_runs)) };
}

function main(args) {
  const number = args.shift();
  let repo;
  let expectedHead;
  while (args.length) {
    const option = args.shift();
    if (option === "--repo" && args.length) repo = args.shift();
    else if (option === "--head" && args.length) expectedHead = args.shift();
    else throw new Error("Usage: node scripts/Check_PR_Workflow_Approvals.js PR --repo OWNER/REPO [--head SHA]");
  }
  if (!repo) throw new Error("Specify --repo OWNER/REPO.");
  const { pr, held } = audit(repo, number, expectedHead);
  console.log(`Read-only approval audit: ${repo}#${number}, head ${pr.head.sha}`);
  if (!held.length) {
    console.log("No workflow runs are awaiting approval across this PR's history.");
    console.log("Also verify the final commit's required checks before merging.");
    return 0;
  }
  for (const run of held) {
    const revision = run.head_sha === pr.head.sha ? "current commit" : "older commit";
    console.log(`${run.id}: ${run.name} (${revision}, ${run.head_sha})`);
    console.log(`  ${run.html_url}`);
  }
  console.error(`${held.length} approval-held run(s) remain. Resolve them before merging or closing the PR.`);
  console.error("Review each revision before approving it. After approval, cancel obsolete queued/running runs and verify their terminal state.");
  return 1;
}

if (require.main === module) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (error) {
    console.error(`Approval audit failed: ${error.message}`);
    process.exitCode = 2;
  }
}

module.exports = { audit, matchingApprovalRuns };
