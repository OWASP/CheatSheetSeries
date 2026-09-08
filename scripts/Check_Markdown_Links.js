const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..");
// One initial observation plus at most two immediate confirmations.
const NETWORK_ATTEMPT_LIMIT = 3;

function resolvedPath(environmentName, defaultPath) {
  return path.resolve(process.env[environmentName] || defaultPath);
}

const paths = {
  baseline: resolvedPath(
    "MARKDOWN_LINK_CHECK_BASELINE",
    path.join(repoRoot, "link-check-known-failures.json"),
  ),
  checker: resolvedPath(
    "MARKDOWN_LINK_CHECK_BIN",
    path.join(
      repoRoot,
      "node_modules",
      "markdown-link-check",
      "markdown-link-check",
    ),
  ),
  config: resolvedPath(
    "MARKDOWN_LINK_CHECK_CONFIG",
    path.join(repoRoot, "markdown-link-check-config.json"),
  ),
  known: resolvedPath(
    "MARKDOWN_LINK_CHECK_KNOWN",
    path.join(repoRoot, "link-check-known-debt.md"),
  ),
  raw: resolvedPath("MARKDOWN_LINK_CHECK_LOG", path.join(repoRoot, "log")),
  target: resolvedPath(
    "MARKDOWN_LINK_CHECK_TARGET",
    path.join(repoRoot, "cheatsheets"),
  ),
  unexpected: resolvedPath(
    "MARKDOWN_LINK_CHECK_UNEXPECTED",
    path.join(repoRoot, "link-check-unexpected.md"),
  ),
};

function tupleKey(file, url) {
  return `${file}\0${url}`;
}

function isNetworkUrl(url) {
  return /^https?:\/\//i.test(url);
}

function exactKeys(value, expected) {
  const actual = Object.keys(value).sort();
  return (
    actual.length === expected.length &&
    expected.every((key, index) => key === actual[index])
  );
}

function validateBaseline(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    !exactKeys(value, ["failures", "generatedFrom", "schemaVersion"])
  ) {
    throw new Error("baseline must contain only schemaVersion, generatedFrom, and failures");
  }
  if (value.schemaVersion !== 1) {
    throw new Error("baseline schemaVersion must be 1");
  }

  const provenance = value.generatedFrom;
  if (
    !provenance ||
    typeof provenance !== "object" ||
    Array.isArray(provenance) ||
    !exactKeys(provenance, [
      "baseCommit",
      "workflowJobId",
      "workflowRunId",
      "workflowUrl",
    ]) ||
    !/^[0-9a-f]{40}$/.test(provenance.baseCommit) ||
    !Number.isSafeInteger(provenance.workflowRunId) ||
    provenance.workflowRunId <= 0 ||
    !Number.isSafeInteger(provenance.workflowJobId) ||
    provenance.workflowJobId <= 0 ||
    provenance.workflowUrl !==
      `https://github.com/OWASP/CheatSheetSeries/actions/runs/${provenance.workflowRunId}/job/${provenance.workflowJobId}`
  ) {
    throw new Error("baseline generatedFrom provenance is malformed");
  }
  if (!Array.isArray(value.failures)) {
    throw new Error("baseline failures must be an array");
  }

  const byKey = new Map();
  let previousKey = null;
  for (const [index, failure] of value.failures.entries()) {
    if (
      !failure ||
      typeof failure !== "object" ||
      Array.isArray(failure) ||
      !exactKeys(failure, ["file", "observedStatus", "url"])
    ) {
      throw new Error(`baseline failure ${index} has an invalid shape`);
    }
    if (
      typeof failure.file !== "string" ||
      !failure.file.startsWith("cheatsheets/") ||
      !failure.file.endsWith(".md") ||
      path.posix.normalize(failure.file) !== failure.file ||
      failure.file.includes("\\") ||
      typeof failure.url !== "string" ||
      failure.url.length === 0 ||
      /[\r\n]/.test(failure.url) ||
      !Number.isInteger(failure.observedStatus) ||
      failure.observedStatus < 0 ||
      failure.observedStatus > 599
    ) {
      throw new Error(`baseline failure ${index} is malformed`);
    }

    const key = tupleKey(failure.file, failure.url);
    if (byKey.has(key)) {
      throw new Error(`baseline contains a duplicate tuple: ${failure.file} ${failure.url}`);
    }
    if (previousKey !== null && key < previousKey) {
      throw new Error("baseline failures must be sorted by file and URL");
    }
    previousKey = key;
    byKey.set(key, failure);
  }

  return { byKey, provenance };
}

function readJson(file, description) {
  let contents;
  try {
    contents = fs.readFileSync(file, "utf8");
  } catch (error) {
    throw new Error(`${description} is unavailable: ${file} (${error.message})`);
  }
  try {
    const parsed = JSON.parse(contents);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("root value must be an object");
    }
    return parsed;
  } catch (error) {
    throw new Error(`${description} is malformed: ${file} (${error.message})`);
  }
}

function enumerateMarkdownFiles(directory) {
  const files = [];
  const visit = (current) => {
    const entries = fs
      .readdirSync(current, { withFileTypes: true })
      .sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      const entryPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        visit(entryPath);
      } else if (entry.isFile() && entry.name.endsWith(".md")) {
        files.push(entryPath);
      }
    }
  };
  visit(directory);
  return files;
}

function logicalFileName(markdownFile) {
  const relative = path.relative(paths.target, markdownFile);
  if (
    relative.length === 0 ||
    relative.startsWith("..") ||
    path.isAbsolute(relative)
  ) {
    throw new Error(`enumerated file escaped the target directory: ${markdownFile}`);
  }
  return path.posix.join("cheatsheets", relative.split(path.sep).join("/"));
}

function parseCanonicalFailures(output, markdownFile) {
  const lines = output.split(/\r?\n/);
  const fileHeaders = lines
    .filter((line) => line.startsWith("FILE: "))
    .map((line) => path.resolve(line.slice("FILE: ".length).trim()));
  if (
    fileHeaders.length !== 1 ||
    fileHeaders[0] !== path.resolve(markdownFile)
  ) {
    throw new Error("nonzero checker result lacks the expected FILE header");
  }

  const errorLines = lines.filter((line) =>
    /^\s*ERROR:\s+\d+\s+dead links? found!\s*$/.test(line),
  );
  if (errorLines.length !== 1) {
    throw new Error("nonzero checker result lacks a canonical ERROR count");
  }
  const expectedCount = Number(errorLines[0].match(/ERROR:\s+(\d+)\s+/)[1]);
  const failures = [];
  for (const line of lines) {
    const match = line.match(
      /^\s*\[✖\]\s+(.+?)\s+→\s+Status:\s+(\d+)\s*$/,
    );
    if (match) {
      failures.push({ url: match[1], status: Number(match[2]) });
    }
  }
  if (failures.length !== expectedCount) {
    throw new Error(
      `canonical ERROR count is ${expectedCount}, but ${failures.length} detailed failures were present`,
    );
  }
  return failures;
}

function validateCanonicalSuccess(output, markdownFile) {
  const lines = output.split(/\r?\n/);
  const fileHeaders = lines
    .filter((line) => line.startsWith("FILE: "))
    .map((line) => path.resolve(line.slice("FILE: ".length).trim()));
  if (
    fileHeaders.length !== 1 ||
    fileHeaders[0] !== path.resolve(markdownFile)
  ) {
    throw new Error("successful checker result lacks the expected FILE header");
  }
  const checkedLines = lines.filter((line) =>
    /^\s*\d+\s+links? checked\.\s*$/.test(line),
  );
  if (checkedLines.length !== 1) {
    throw new Error("successful checker result lacks a canonical checked-link count");
  }
  if (/^\s*ERROR:/m.test(output) || /\[✖\].*Status:/m.test(output)) {
    throw new Error("checker reported canonical failures with exit status 0");
  }
}

function markdownRows(title, rows, marker) {
  if (rows.length === 0) {
    return "";
  }
  const grouped = new Map();
  for (const row of rows) {
    if (!grouped.has(row.file)) {
      grouped.set(row.file, []);
    }
    grouped.get(row.file).push(row);
  }

  const lines = [`## ${title}`, ""];
  for (const [file, fileRows] of grouped) {
    lines.push(`    FILE: ${file}`);
    for (const row of fileRows) {
      const provenance =
        row.observedStatus === undefined
          ? ""
          : `; baseline observed ${row.observedStatus}`;
      const attempts = row.attempts ? `; attempts: ${row.attempts}` : "";
      lines.push(
        `      [${marker}] ${row.url} → Status: ${row.status}${provenance}${attempts}`,
      );
    }
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}

function writeOutputs({ known, recovered, transient, unexpected }) {
  const knownText = [
    markdownRows("Known Markdown link failures", known, "known"),
    markdownRows("Recovered or stale baseline entries", recovered, "recovered"),
    markdownRows(
      "Transient unbaselined network failures recovered on confirmation",
      transient,
      "transient",
    ),
  ].join("");
  const unexpectedText = markdownRows(
    "Unexpected Markdown link failures",
    unexpected,
    "✖",
  );

  fs.writeFileSync(paths.known, knownText);
  fs.writeFileSync(paths.unexpected, unexpectedText);
}

function runCheckerAttempt(markdownFile, file, attempt) {
  fs.appendFileSync(
    paths.raw,
    `\n===== FILE: ${file}; attempt ${attempt}/${NETWORK_ATTEMPT_LIMIT} =====\n`,
  );
  const result = spawnSync(
    process.execPath,
    [paths.checker, "-c", paths.config, markdownFile],
    { encoding: "utf8" },
  );
  const output = `${result.stdout || ""}${result.stderr || ""}`;
  fs.appendFileSync(paths.raw, output.endsWith("\n") ? output : `${output}\n`);

  let message;
  if (result.error || result.signal || !Number.isInteger(result.status)) {
    message = `${file}: checker could not complete (${result.error?.message || result.signal || "unknown process result"})`;
  } else if (result.status === 0) {
    try {
      validateCanonicalSuccess(output, markdownFile);
      return { failures: [] };
    } catch (error) {
      message = `${file}: ${error.message}`;
    }
  } else if (result.status !== 1) {
    message = `${file}: checker exited with unexpected status ${result.status}`;
  } else {
    try {
      return { failures: parseCanonicalFailures(output, markdownFile) };
    } catch (error) {
      message = `${file}: ${error.message} (exit ${result.status})`;
    }
  }

  fs.appendFileSync(paths.raw, `[!] ${message}\n`);
  return { internal: message };
}

function attemptHistory(canonicalAttempts, file, baseline) {
  const histories = new Map();
  for (const [attemptIndex, failures] of canonicalAttempts.entries()) {
    const current = new Map();
    for (const failure of failures) {
      const key = tupleKey(file, failure.url);
      if (!baseline.byKey.has(key)) {
        current.set(key, failure);
      }
    }
    for (const history of histories.values()) {
      const failure = current.get(history.key);
      history.values.push(failure ? failure.status : "recovered");
    }
    for (const [key, failure] of current) {
      if (!histories.has(key)) {
        histories.set(key, {
          file,
          key,
          url: failure.url,
          values: [
            ...Array(attemptIndex).fill("not failing"),
            failure.status,
          ],
        });
      }
    }
  }
  return histories;
}

function formatAttemptHistory(values) {
  return values.map((value, index) => `${index + 1}=${value}`).join(", ");
}

function main() {
  const distinctOutputs = new Set([paths.raw, paths.known, paths.unexpected]);
  if (distinctOutputs.size !== 3) {
    console.error("[!] Raw, known-debt, and unexpected output paths must be distinct.");
    return 1;
  }
  const protectedInputs = new Set([paths.baseline, paths.checker, paths.config]);
  if ([...distinctOutputs].some((output) => protectedInputs.has(output))) {
    console.error("[!] Diagnostic output paths must not overwrite checker inputs.");
    return 1;
  }
  try {
    for (const output of distinctOutputs) {
      fs.writeFileSync(output, "");
    }
  } catch (error) {
    console.error(`[!] Cannot initialize link-check diagnostics: ${error.message}`);
    return 1;
  }

  const internal = [];
  const known = [];
  const unexpected = [];
  let baseline;

  try {
    fs.accessSync(paths.checker, fs.constants.R_OK);
  } catch (error) {
    internal.push(`Link checker executable is unavailable: ${paths.checker}`);
  }
  try {
    readJson(paths.config, "Link checker configuration");
  } catch (error) {
    internal.push(error.message);
  }
  try {
    baseline = validateBaseline(readJson(paths.baseline, "Known-failure baseline"));
  } catch (error) {
    internal.push(error.message);
  }
  try {
    if (!fs.statSync(paths.target).isDirectory()) {
      throw new Error("not a directory");
    }
  } catch (error) {
    internal.push(`Link-check target directory is unavailable: ${paths.target}`);
  }

  if (internal.length > 0) {
    fs.appendFileSync(
      paths.raw,
      `${internal.map((message) => `[!] ${message}`).join("\n")}\n`,
    );
    writeOutputs({ known, recovered: [], transient: [], unexpected });
    console.error(`[!] Link validator could not start: ${internal.join("; ")}`);
    return 1;
  }

  let markdownFiles;
  try {
    markdownFiles = enumerateMarkdownFiles(paths.target);
  } catch (error) {
    internal.push(`Cannot enumerate Markdown files under ${paths.target}: ${error.message}`);
    fs.appendFileSync(paths.raw, `[!] ${internal[0]}\n`);
    writeOutputs({ known, recovered: [], transient: [], unexpected });
    console.error(`[!] ${internal[0]}`);
    return 1;
  }

  const assessedFailuresByFile = new Map();
  const transient = [];
  for (const markdownFile of markdownFiles) {
    const file = logicalFileName(markdownFile);
    const canonicalAttempts = [];
    let assessment = null;
    for (let attempt = 1; attempt <= NETWORK_ATTEMPT_LIMIT; attempt += 1) {
      const result = runCheckerAttempt(markdownFile, file, attempt);
      if (result.internal) {
        internal.push(result.internal);
        assessment = null;
        break;
      }
      canonicalAttempts.push(result.failures);
      assessment = result.failures;
      const unbaselinedNetworkFailures = result.failures.filter(
        (failure) =>
          isNetworkUrl(failure.url) &&
          !baseline.byKey.has(tupleKey(file, failure.url)),
      );
      if (
        unbaselinedNetworkFailures.length === 0 ||
        attempt === NETWORK_ATTEMPT_LIMIT
      ) {
        break;
      }
    }
    if (assessment === null) {
      continue;
    }

    const finalFailures = new Map();
    for (const failure of assessment) {
      const key = tupleKey(file, failure.url);
      finalFailures.set(key, failure);
      const baselineFailure = baseline.byKey.get(key);
      if (baselineFailure) {
        known.push({
          file,
          url: failure.url,
          status: failure.status,
          observedStatus: baselineFailure.observedStatus,
        });
      }
    }
    assessedFailuresByFile.set(file, finalFailures);

    const histories = attemptHistory(canonicalAttempts, file, baseline);
    for (const history of histories.values()) {
      const finalFailure = finalFailures.get(history.key);
      const row = {
        file,
        url: history.url,
        status: finalFailure
          ? finalFailure.status
          : history.values.findLast((value) => Number.isInteger(value)),
        attempts: formatAttemptHistory(history.values),
      };
      if (isNetworkUrl(history.url) && !finalFailure) {
        transient.push({ ...row, status: "recovered" });
      } else {
        unexpected.push(row);
      }
    }
  }

  const recovered = [];
  for (const [key, failure] of baseline.byKey) {
    const assessedFailures = assessedFailuresByFile.get(failure.file);
    if (assessedFailures && !assessedFailures.has(key)) {
      recovered.push({
        file: failure.file,
        url: failure.url,
        status: "not failing",
        observedStatus: failure.observedStatus,
      });
    }
  }

  writeOutputs({ known, recovered, transient, unexpected });
  if (unexpected.length > 0 || internal.length > 0) {
    console.error(
      `[!] Link validator found ${unexpected.length} unexpected link failure(s) and ${internal.length} internal failure(s).`,
    );
    return 1;
  }

  console.log(
    `[+] No unexpected link failures; ${known.length} known failure(s) remain, ${recovered.length} baseline row(s) are recovered or stale, and ${transient.length} transient network failure(s) recovered on confirmation.`,
  );
  return 0;
}

process.exitCode = main();
