// Renders structured link-check results for logs, reports, and job summaries.
// File names and URLs come from contributions, so they are sanitized before
// they reach Markdown or the Actions log.

const RESULTS_SCHEMA = 1;
function modeTitle(results) {
  if (results.mode === "local-only") {
    return results.base ? "local links, blocking only on changes since the merge base" : "local links only";
  }
  return results.base ? "links changed since the merge base" : "full audit";
}

function clean(value, limit = 300) {
  const text = String(value ?? "")
    // Control, line-separator, and bidirectional formatting characters.
    .replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g, " ")
    .trim();
  return text.length > limit ? `${text.slice(0, limit - 1)}…` : text;
}

function code(value) {
  return `\`${clean(value).replace(/`/g, "%60")}\``;
}

function plain(value) {
  // Escapes Markdown and HTML metacharacters in free text such as error details.
  return clean(value).replace(/[\\`*_[\]<>|#]/g, (character) => `\\${character}`);
}

function location(finding) {
  const where = finding.line ? `line ${finding.line}` : `link #${finding.ordinal}`;
  return `${code(finding.file)} ${where}`;
}

function findingLine(finding) {
  const parts = [`${location(finding)}: ${code(finding.url)} — ${finding.category}`];
  if (finding.finalUrl) parts.push(`redirect destination: ${code(finding.finalUrl)}`);
  if (finding.detail) parts.push(plain(finding.detail));
  if (finding.exception) parts.push(`excepted until ${finding.exception.expiresOn}`);
  if (finding.legacyEvidence) {
    parts.push(`legacy baseline observed ${finding.legacyEvidence.observedStatuses.join("/")}`);
  }
  return `- ${parts.join("; ")}`;
}

function section(title, rows, maxRows, empty) {
  if (rows.length === 0) {
    return empty ? [`## ${title}`, "", empty, ""] : [];
  }
  const shown = rows.slice(0, maxRows);
  const lines = [`## ${title} (${rows.length})`, "", ...shown];
  if (rows.length > shown.length) {
    lines.push(`- …and ${rows.length - shown.length} more in \`results.json\``);
  }
  lines.push("");
  return lines;
}

function groupCounts(findings) {
  const counts = new Map();
  for (const finding of findings) {
    counts.set(finding.category, (counts.get(finding.category) || 0) + 1);
  }
  return [...counts]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([category, count]) => `${category}: ${count}`)
    .join(", ");
}

function renderMarkdown(results, { maxRows = Infinity } = {}) {
  const findings = results.findings || [];
  const blocking = findings.filter((finding) => finding.blocking);
  const unassessed = findings.filter((finding) => finding.outcome === "unassessed");
  const manual = findings.filter(
    (finding) => finding.outcome === "unverified" && (!results.base || finding.new),
  );
  const debt = findings.filter(
    (finding) => finding.outcome === "broken" && !finding.blocking,
  );
  const counts = results.counts || {};
  const external = counts.external || {};
  const lines = [
    `# Markdown link check ${String(results.status).toUpperCase()}`,
    "",
    `Mode: ${modeTitle(results)}${results.base ? ` (base ${code(results.base.mergeBase)})` : ""}.`,
    "",
    `- Published Markdown files scanned: ${counts.files ?? 0}; link occurrences: ${counts.occurrences?.total ?? 0}`,
    `- External occurrences selected: ${external.selectedOccurrences ?? 0}; distinct pages: ${external.distinctPages ?? 0}; assessed: ${external.assessedPages ?? 0}; cache hits: ${external.cacheHits ?? 0}; HTTP requests: ${external.requests ?? 0}`,
    `- Findings: ${groupCounts(findings) || "none"}`,
    `- Duration: ${Math.round((results.durationMs || 0) / 1000)}s`,
    "",
  ];
  lines.push(
    ...section(
      "Internal errors (the check is incomplete)",
      (results.errors || []).map((error) => `- ${plain(error)}`),
      maxRows,
    ),
    ...section(
      "Not assessed before the deadline (the check is incomplete)",
      unassessed.map(findingLine),
      maxRows,
    ),
    ...section("Blocking problems", blocking.map(findingLine), maxRows),
    ...section(
      results.base
        ? "Manual verification requested for new links"
        : "Unverified links",
      manual.map(findingLine),
      maxRows,
    ),
    ...section("Existing broken links (maintenance debt, not blocking)", debt.map(findingLine), maxRows),
    ...section(
      "Link check exceptions",
      (results.exceptions || []).map(
        (exception) =>
          `- ${code(exception.file)}: ${code(exception.url)} — ${exception.state}${exception.expired ? " (expired)" : ""}; expected ${exception.category}${exception.observedCategories ? `, observed ${exception.observedCategories.join("/")}` : ""}`,
      ),
      maxRows,
    ),
  );
  if (manual.length > 0) {
    lines.push(
      "Unverified links were not proven broken or healthy (for example 401/403, 429, server errors, timeouts, or unchecked anchors). Open each one in a browser and confirm that it supports the claim.",
      "",
    );
  }
  lines.push(
    "A successful HTTP response only shows that a page answered. It does not show that the source supports the claim it is cited for.",
    "",
  );
  return `${lines.join("\n")}\n`;
}

// Log lines never begin with untrusted text, so content cannot form an
// Actions workflow command such as "::set-output".
function consoleLines(results) {
  const findings = results.findings || [];
  const lines = [];
  for (const error of results.errors || []) {
    lines.push(`[internal] ${clean(error, 1000)}`);
  }
  for (const finding of findings) {
    const label = finding.blocking
      ? "blocking"
      : finding.outcome === "unassessed"
        ? "unassessed"
        : finding.outcome === "unverified" && (!results.base || finding.new)
          ? "verify manually"
          : finding.exception
            ? "excepted"
            : finding.outcome === "broken"
              ? "existing"
              : null;
    if (label) {
      const where = finding.line ? `:${finding.line}` : ` link #${finding.ordinal}`;
      lines.push(
        `[${label}] ${clean(finding.file)}${where} ${clean(finding.url)} (${finding.category}${finding.detail ? `: ${clean(finding.detail)}` : ""})`,
      );
    }
  }
  const external = results.counts?.external || {};
  lines.push(
    `[${results.status}] ${modeTitle(results)}: ${results.counts?.occurrences?.total ?? 0} link occurrence(s), ${external.distinctPages ?? 0} external page(s), ${external.requests ?? 0} HTTP request(s), ${findings.filter((f) => f.blocking).length} blocking, ${findings.filter((f) => f.outcome === "unverified").length} unverified, ${(results.errors || []).length} internal error(s); details in .link-check/report.md`,
  );
  return lines.map((line) => `  ${line}`);
}

module.exports = { RESULTS_SCHEMA, clean, consoleLines, renderMarkdown };
