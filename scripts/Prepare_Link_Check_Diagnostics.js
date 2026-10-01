// Writes the GitHub Actions job summary from .link-check/results.json.
const fs = require("node:fs");
const path = require("node:path");
const { RESULTS_SCHEMA, clean, renderMarkdown } = require("./link_check/report");

const repoRoot = path.resolve(__dirname, "..");
// Step summaries are limited to 1 MiB; the artifact keeps the full report.
const MAX_SUMMARY_ROWS = 100;

function readResults(file) {
  try {
    const results = JSON.parse(fs.readFileSync(file, "utf8"));
    if (results?.schemaVersion !== RESULTS_SCHEMA) {
      return { problem: `unsupported results schema ${clean(results?.schemaVersion)}` };
    }
    return { results };
  } catch (error) {
    return { problem: error.code === "ENOENT" ? "no results file was written" : `unreadable results (${clean(error.message)})` };
  }
}

function main() {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) {
    throw new Error("GITHUB_STEP_SUMMARY is required");
  }
  const outputDir = path.resolve(
    repoRoot,
    process.env.LINK_CHECK_OUTPUT_DIR || ".link-check",
  );
  const outcome = process.env.LINK_CHECK_OUTCOME || "unknown";
  const { results, problem } = readResults(path.join(outputDir, "results.json"));

  let summary;
  if (!results) {
    summary = [
      "# Markdown link check INCOMPLETE",
      "",
      `The link check step finished with outcome \`${clean(outcome)}\`, but ${problem}. No links should be treated as checked.`,
      "Inspect the failed step log (for example, a setup or dependency installation failure).",
      "",
    ].join("\n");
  } else {
    summary = renderMarkdown(results, { maxRows: MAX_SUMMARY_ROWS });
    const expected = results.status === "passed" ? "success" : "failure";
    if (outcome !== expected) {
      summary = [
        `> **Note:** the link check step outcome was \`${clean(outcome)}\` while the results file says \`${clean(results.status)}\`. The step may have been cancelled or timed out; treat the check as incomplete.`,
        "",
        summary,
      ].join("\n");
    }
  }
  summary +=
    "\nThe **link-check-diagnostics** artifact contains `results.json` (every occurrence, page, request, and observation) and `report.md`.\n";
  fs.appendFileSync(summaryPath, summary);
}

main();
