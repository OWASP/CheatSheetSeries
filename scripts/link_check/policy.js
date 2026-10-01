// Loads and validates checker settings, reviewed exceptions, and the legacy
// failure evidence, and applies exceptions to findings.
const fs = require("node:fs");
const path = require("node:path");

const SUPPRESSIBLE_CATEGORIES = new Set([
  "not-found",
  "gone",
  "missing-file",
  "missing-anchor",
  "malformed-url",
  "access-restricted",
  "rate-limited",
  "server-error",
  "network-error",
  "timeout",
  "unexpected-status",
  "redirect-error",
  "unconfirmed-not-found",
  "app-shell-404",
  "missing-external-anchor",
  "unsupported-fragment",
  "unsupported-scheme",
]);
const MAX_EXCEPTION_DAYS = 366;
const DAY_MS = 24 * 60 * 60 * 1000;

const SETTING_BOUNDS = {
  budgetSeconds: [1, 3600],
  cacheTtlHours: [0, 24],
  http: {
    concurrency: [1, 32],
    perHostConcurrency: [1, 8],
    requestTimeoutSeconds: [0.01, 120],
    maxObservations: [2, 5],
    retryBaseDelaySeconds: [0, 60],
    maxRetryDelaySeconds: [0, 300],
    maxRedirects: [0, 10],
    maxBodyBytes: [1024, 20 * 1024 * 1024],
  },
};

function readJson(file, description) {
  let text;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch (error) {
    throw new Error(`${description} is unavailable: ${file} (${error.message})`);
  }
  try {
    const value = JSON.parse(text);
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("root value must be an object");
    }
    return value;
  } catch (error) {
    throw new Error(`${description} is malformed: ${file} (${error.message})`);
  }
}

function exactKeys(value, expected) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort())
  );
}

function checkBounds(values, bounds, prefix) {
  if (!exactKeys(values, Object.keys(bounds))) {
    throw new Error(`${prefix || "config"} must contain exactly: ${Object.keys(bounds).join(", ")}`);
  }
  for (const [key, bound] of Object.entries(bounds)) {
    const name = prefix ? `${prefix}.${key}` : key;
    if (!Array.isArray(bound)) {
      checkBounds(values[key], bound, name);
    } else if (
      typeof values[key] !== "number" ||
      !Number.isFinite(values[key]) ||
      values[key] < bound[0] ||
      values[key] > bound[1]
    ) {
      throw new Error(`config ${name} must be a number from ${bound[0]} to ${bound[1]}`);
    }
  }
}

function loadConfig(file) {
  const config = readJson(file, "Link checker configuration");
  if (config.schemaVersion !== 1) {
    throw new Error("link checker configuration schemaVersion must be 1");
  }
  const { schemaVersion, http, ...rest } = config;
  if (!http || typeof http.userAgent !== "string" || http.userAgent.trim() === "") {
    throw new Error("config http.userAgent must be a nonempty string");
  }
  const { userAgent, ...httpNumbers } = http;
  checkBounds({ ...rest, http: httpNumbers }, SETTING_BOUNDS);
  for (const key of ["concurrency", "perHostConcurrency", "maxObservations", "maxRedirects", "maxBodyBytes"]) {
    if (!Number.isInteger(http[key])) {
      throw new Error(`config http.${key} must be an integer`);
    }
  }
  return config;
}

function isoDate(value) {
  return (
    typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}$/.test(value) &&
    Number.isFinite(Date.parse(`${value}T00:00:00Z`)) &&
    new Date(`${value}T00:00:00Z`).toISOString().startsWith(value)
  );
}

function validateToday(today) {
  if (!isoDate(today)) throw new Error("link checker today must be YYYY-MM-DD");
}

function loadExceptions(file, today = new Date().toISOString().slice(0, 10)) {
  validateToday(today);
  const value = readJson(file, "Link check exceptions");
  if (!exactKeys(value, ["schemaVersion", "exceptions"]) || value.schemaVersion !== 1) {
    throw new Error("link check exceptions must contain only schemaVersion 1 and exceptions");
  }
  if (!Array.isArray(value.exceptions)) {
    throw new Error("link check exceptions must be an array");
  }
  const seen = new Set();
  return value.exceptions.map((exception, index) => {
    const where = `link check exception ${index}`;
    const keys = ["file", "url", "category", "reason", "reviewedOn", "expiresOn", "reference"];
    if (!exactKeys(exception, keys)) {
      throw new Error(`${where} must contain exactly: ${keys.join(", ")}`);
    }
    const { file, url, category, reason, reviewedOn, expiresOn, reference } = exception;
    if (
      typeof file !== "string" ||
      path.posix.normalize(file) !== file ||
      file.startsWith("../") ||
      !file.endsWith(".md")
    ) {
      throw new Error(`${where} has an invalid file`);
    }
    if (typeof url !== "string" || url.length === 0 || /[\r\n]/.test(url)) {
      throw new Error(`${where} has an invalid url`);
    }
    if (!SUPPRESSIBLE_CATEGORIES.has(category)) {
      throw new Error(`${where} has an unsupported category: ${category}`);
    }
    if (typeof reason !== "string" || reason.trim().length < 10) {
      throw new Error(`${where} needs a reviewed reason`);
    }
    if (!isoDate(reviewedOn) || !isoDate(expiresOn)) {
      throw new Error(`${where} dates must be YYYY-MM-DD`);
    }
    if (reviewedOn > today) throw new Error(`${where} review date cannot be in the future`);
    const days = (Date.parse(expiresOn) - Date.parse(reviewedOn)) / DAY_MS;
    if (days < 0 || days > MAX_EXCEPTION_DAYS) {
      throw new Error(`${where} must expire 0 to ${MAX_EXCEPTION_DAYS} days after review`);
    }
    if (typeof reference !== "string" || !/^https:\/\/\S+$/.test(reference)) {
      throw new Error(`${where} reference must be an https URL to the review`);
    }
    const key = `${file}\0${url}`;
    if (seen.has(key)) {
      throw new Error(`${where} duplicates ${file} ${url}`);
    }
    seen.add(key);
    return exception;
  });
}

// The pre-2488 baseline is kept as historical evidence only. It never
// suppresses a result; matching findings are annotated with its provenance.
function loadLegacyEvidence(file) {
  const value = readJson(file, "Legacy link-check evidence");
  if (value.schemaVersion !== 2 || !Array.isArray(value.batches)) {
    throw new Error("legacy link-check evidence must be schemaVersion 2 with batches");
  }
  const byKey = new Map();
  for (const batch of value.batches) {
    for (const failure of batch.failures || []) {
      byKey.set(`${failure.file}\0${failure.url}`, {
        observedStatuses: failure.observedStatuses || [failure.observedStatus],
        workflowUrl: batch.generatedFrom?.workflowUrl,
      });
    }
  }
  return byKey;
}

// Applies exceptions to findings and reports each exception's state.
// assessedPairs holds "file\0url" keys whose result was assessed in this run;
// presentPairs holds keys that exist in the checked content.
function applyExceptions({ exceptions, findings, assessedPairs, presentPairs, today }) {
  validateToday(today);
  if (exceptions.some((exception) => exception.reviewedOn > today)) {
    throw new Error("link check exception review date cannot be in the future");
  }
  const findingsByPair = new Map();
  for (const finding of findings) {
    const key = `${finding.file}\0${finding.url}`;
    if (!findingsByPair.has(key)) findingsByPair.set(key, []);
    findingsByPair.get(key).push(finding);
  }
  return exceptions.map((exception) => {
    const key = `${exception.file}\0${exception.url}`;
    const expired = today > exception.expiresOn;
    const report = { ...exception, expired };
    if (!presentPairs.has(key)) {
      return { ...report, state: "stale-removed" };
    }
    if (!assessedPairs.has(key)) {
      return { ...report, state: "unassessed" };
    }
    const matching = (findingsByPair.get(key) || []).filter(
      (finding) => finding.outcome !== "unassessed",
    );
    if (matching.length === 0) {
      return { ...report, state: "recovered" };
    }
    const categories = [...new Set(matching.map((finding) => finding.category))];
    if (categories.some((category) => category !== exception.category)) {
      return { ...report, state: "category-changed", observedCategories: categories };
    }
    if (expired) {
      return { ...report, state: "expired" };
    }
    let applied = 0;
    for (const finding of matching) {
      // A newly introduced occurrence always needs fresh review.
      if (!finding.new) {
        finding.exception = { reason: exception.reason, expiresOn: exception.expiresOn, reference: exception.reference };
        applied += 1;
      }
    }
    return { ...report, state: applied > 0 ? "applied" : "not-applied-to-new-occurrence" };
  });
}

module.exports = {
  SUPPRESSIBLE_CATEGORIES,
  applyExceptions,
  loadConfig,
  loadExceptions,
  loadLegacyEvidence,
  readJson,
};
