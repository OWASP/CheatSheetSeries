const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..");

function resolvedPath(environmentName, defaultPath) {
  return path.resolve(process.env[environmentName] || defaultPath);
}

function readIfPresent(file) {
  try {
    return fs.readFileSync(file, "utf8");
  } catch (error) {
    if (error.code === "ENOENT") {
      return "";
    }
    throw error;
  }
}

function countRows(contents, marker) {
  const pattern = new RegExp(`^\\s+\\[${marker}\\]`);
  return contents
    .split(/\r?\n/)
    .filter((line) => pattern.test(line)).length;
}

function main() {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  const outputPath = process.env.GITHUB_OUTPUT;
  if (!summaryPath || !outputPath) {
    throw new Error("GITHUB_STEP_SUMMARY and GITHUB_OUTPUT are required");
  }

  const knownPath = resolvedPath(
    "MARKDOWN_LINK_CHECK_KNOWN",
    path.join(repoRoot, "link-check-known-debt.md"),
  );
  const unexpectedPath = resolvedPath(
    "MARKDOWN_LINK_CHECK_UNEXPECTED",
    path.join(repoRoot, "link-check-unexpected.md"),
  );
  const known = readIfPresent(knownPath);
  const unexpected = readIfPresent(unexpectedPath);
  const outcome = process.env.LINK_CHECK_OUTCOME;
  const failed = outcome !== "success";

  let summary;
  if (failed) {
    summary = unexpected.trim()
      ? `# Markdown link check failed\n\n${unexpected}`
      : [
          "# Markdown link check failed",
          "",
          "The checker failed before actionable diagnostics could be recovered.",
          "Inspect the raw **Run link check** step output.",
          "",
        ].join("\n");
  } else {
    if (unexpected.trim()) {
      throw new Error("unexpected diagnostics exist despite a successful link check");
    }
    const knownCount = countRows(known, "known");
    const recoveredCount = countRows(known, "recovered");
    const transientCount = countRows(known, "transient");
    summary = [
      "# Markdown link check passed",
      "",
      `No unexpected failures were found. ${knownCount} exact known-failure tuple(s) remain; ${recoveredCount} baseline row(s) are recovered or stale; ${transientCount} unbaselined network failure(s) were not persistent across every observation.`,
      "",
    ].join("\n");
  }

  fs.appendFileSync(summaryPath, summary);
  const shouldComment =
    failed &&
    unexpected.trim().length > 0 &&
    process.env.LINK_CHECK_EVENT_NAME === "pull_request" &&
    process.env.LINK_CHECK_HEAD_REPOSITORY ===
      process.env.LINK_CHECK_REPOSITORY;
  fs.appendFileSync(outputPath, `should_comment=${shouldComment}\n`);
}

main();
