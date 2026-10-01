// Checks links in the published Markdown sources.
//
//   node scripts/Check_Markdown_Links.js                 full audit
//   node scripts/Check_Markdown_Links.js --base <ref>    PR mode: only external
//        links added since the merge base, and only newly broken local links block
//   --local-only                                         skip external links
//   --fresh                                              ignore cached successes
//
// Exit status: 0 passed, 1 blocking broken links, 2 incomplete or internal error.
const fs = require("node:fs");
const path = require("node:path");
const { performance } = require("node:perf_hooks");

const corpus = require("./link_check/corpus");
const external = require("./link_check/external");
const policy = require("./link_check/policy");
const report = require("./link_check/report");

const USAGE =
  "usage: Check_Markdown_Links.js [--base <git-ref>] [--local-only] [--fresh]";

function settings() {
  const root = path.resolve(process.env.LINK_CHECK_ROOT || path.join(__dirname, ".."));
  const fromRoot = (name, fallback) => path.resolve(root, process.env[name] || fallback);
  return {
    root,
    config: fromRoot("LINK_CHECK_CONFIG", "link-check-config.json"),
    exceptions: fromRoot("LINK_CHECK_EXCEPTIONS", "link-check-exceptions.json"),
    legacy: fromRoot("LINK_CHECK_LEGACY_EVIDENCE", "link-check-known-failures.json"),
    outputDir: fromRoot("LINK_CHECK_OUTPUT_DIR", ".link-check"),
    cacheFile: fromRoot("LINK_CHECK_CACHE_FILE", ".link-check-cache/http-success.json"),
    python: process.env.LINK_CHECK_PYTHON || (process.platform === "win32" ? "python" : "python3"),
    // UTC date used for exception expiry; overridable for deterministic tests.
    today: process.env.LINK_CHECK_TODAY ?? new Date().toISOString().slice(0, 10),
  };
}

function parseArgs(argv) {
  const options = { base: null, localOnly: false, fresh: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--base") {
      options.base = argv[++index];
      if (options.base === undefined) throw new Error("--base needs a git ref");
    } else if (argument.startsWith("--base=")) {
      options.base = argument.slice("--base=".length);
    } else if (argument === "--local-only") {
      options.localOnly = true;
    } else if (argument === "--fresh") {
      options.fresh = true;
    } else if (argument === "--help" || argument === "-h") {
      options.help = true;
    } else {
      throw new Error(`unknown argument ${argument}`);
    }
  }
  return options;
}

const pairKey = (file, url) => `${file}\0${url}`;

// Marks occurrences beyond the base count of the same file+URL as new.
function markNew(occurrences, baseCounts, filter = () => true) {
  const seen = new Map();
  for (const occurrence of occurrences) {
    if (!filter(occurrence)) continue;
    const key = pairKey(occurrence.file, occurrence.url);
    const index = seen.get(key) || 0;
    seen.set(key, index + 1);
    occurrence.new = index >= (baseCounts.get(key) || 0);
  }
}

function countPairs(occurrences, filter) {
  const counts = new Map();
  for (const occurrence of occurrences) {
    if (filter(occurrence)) {
      const key = pairKey(occurrence.file, occurrence.url);
      counts.set(key, (counts.get(key) || 0) + 1);
    }
  }
  return counts;
}

function pageDetail(page) {
  const statuses = page.observations
    .map((o) => o.status ?? o.category)
    .join(", ");
  const error = page.observations.map((o) => o.error).filter(Boolean).at(-1);
  return [
    statuses && `observations: ${statuses}`,
    error,
    ...page.notes,
  ]
    .filter(Boolean)
    .join("; ");
}

async function run(results, options, paths) {
  const config = policy.loadConfig(paths.config);
  const exceptions = policy.loadExceptions(paths.exceptions, paths.today);
  const legacy = policy.loadLegacyEvidence(paths.legacy);
  const deadlineAt = Date.parse(results.startedAt) + config.budgetSeconds * 1000;

  const head = corpus.workingTreeSnapshot(paths.root);
  if (![...head.pages.keys()].some((page) => page.startsWith("cheatsheets/"))) {
    throw new Error(`no Markdown files found under ${path.join(paths.root, "cheatsheets")}`);
  }
  const snapshots = [head];
  if (options.base) {
    results.base = corpus.resolveBase(paths.root, options.base);
    snapshots.push(corpus.gitSnapshot(paths.root, results.base.mergeBase));
  }
  const extractStarted = performance.now();
  results.renderer = corpus.extractSnapshots(snapshots, paths.python);
  results.metrics.extractMs = Math.round(performance.now() - extractStarted);

  const occurrences = corpus.occurrencesOf(head);
  const isExternal = (o) => o.scope === "external";
  const isLocal = (o) => o.scope !== "external";
  const notHealthy = (o) => isLocal(o) && o.outcome !== "healthy";
  if (options.base) {
    const baseOccurrences = corpus.occurrencesOf(snapshots[1]);
    markNew(occurrences, countPairs(baseOccurrences, isExternal), isExternal);
    // A local link is new when the head has more failing occurrences of the
    // same file+URL than the base, which also catches deleted targets.
    markNew(occurrences, countPairs(baseOccurrences, notHealthy), notHealthy);
  }
  results.counts.files = head.pages.size;
  results.counts.occurrences = {
    total: occurrences.length,
    local: occurrences.filter((o) => o.scope === "local").length,
    external: occurrences.filter(isExternal).length,
    other: occurrences.filter((o) => o.scope === "other").length,
  };

  const findings = occurrences.filter(notHealthy).map((o) => ({ ...o }));
  const assessedPairs = new Set(occurrences.filter(isLocal).map((o) => pairKey(o.file, o.url)));
  const selected = options.localOnly
    ? []
    : occurrences.filter(
        (o) =>
          isExternal(o) &&
          o.file.startsWith("cheatsheets/") &&
          (!options.base || o.new),
      );

  const pages = new Map();
  for (const occurrence of selected) {
    const key = external.pageKey(occurrence.absoluteUrl);
    if (!pages.has(key)) pages.set(key, { key, fragments: new Set(), occurrences: [] });
    const page = pages.get(key);
    const hash = new URL(occurrence.absoluteUrl).hash;
    occurrence.fragment = hash ? hash.slice(1) : "";
    page.fragments.add(occurrence.fragment);
    page.occurrences.push(occurrence);
  }
  results.counts.external = {
    selectedOccurrences: selected.length,
    distinctPages: pages.size,
    assessedPages: 0,
    cacheHits: 0,
    requests: 0,
    observations: 0,
  };

  if (pages.size > 0) {
    const fingerprint = external.cacheFingerprint(config.http);
    const ttlMs = config.cacheTtlHours * 60 * 60 * 1000;
    const cache = external.loadCache(paths.cacheFile, fingerprint, ttlMs);
    results.cache = { file: path.relative(paths.root, paths.cacheFile), fresh: options.fresh, note: cache.note };
    const externalStarted = performance.now();
    let lastProgress = 0;
    const checked = await external.checkPages([...pages.values()], {
      http: config.http,
      deadlineAt,
      cacheEntries: cache.entries,
      fresh: options.fresh,
      onProgress(done, total) {
        if (Date.now() - lastProgress > 30000 || done === total) {
          lastProgress = Date.now();
          console.log(`  [progress] ${done}/${total} external page(s) assessed`);
        }
      },
    });
    results.metrics.externalMs = Math.round(performance.now() - externalStarted);
    Object.assign(results.metrics, {
      peakActiveRequests: checked.stats.peakActive,
      peakRequestsPerHost: checked.stats.peakPerHost,
      perHost: checked.stats.perHost,
    });

    for (const [key, page] of pages) {
      const outcome = checked.results.get(key);
      const counts = results.counts.external;
      if (outcome.outcome !== "unassessed") counts.assessedPages += 1;
      if (outcome.cache === "hit") counts.cacheHits += 1;
      counts.observations += outcome.cache === "hit" ? 0 : outcome.observations.length;
      results.pages.push({
        ...outcome,
        occurrences: page.occurrences.map(({ file, line, ordinal, url, new: isNew }) => ({
          file, line, ordinal, url, ...(options.base ? { new: isNew } : {}),
        })),
      });
      for (const occurrence of page.occurrences) {
        const assessed =
          outcome.outcome === "healthy"
            ? outcome.fragments[occurrence.fragment]
            : { outcome: outcome.outcome, category: outcome.category, detail: pageDetail(outcome) };
        if (assessed.outcome !== "unassessed") {
          assessedPairs.add(pairKey(occurrence.file, occurrence.url));
        }
        if (assessed.outcome !== "healthy") {
          const { fragment, absoluteUrl, ...rest } = occurrence;
          findings.push({ ...rest, ...assessed, page: key, finalUrl: outcome.finalUrl });
        }
      }
    }

    // Includes requests made for the pages' shared home-page comparisons.
    results.counts.external.requests = checked.stats.requests;

    // Keep unexpired successes, drop pages that failed now, add fresh successes.
    const entries = new Map(cache.entries);
    for (const [key, outcome] of checked.results) {
      if (outcome.outcome !== "healthy") entries.delete(key);
    }
    for (const [key, entry] of checked.freshSuccesses) entries.set(key, entry);
    try {
      external.saveCache(paths.cacheFile, fingerprint, entries);
    } catch (error) {
      results.cache.note += `; cache not saved (${error.message})`;
    }
  }

  for (const finding of findings) {
    const evidence = legacy.get(pairKey(finding.file, finding.url));
    if (evidence) finding.legacyEvidence = evidence;
  }
  results.exceptions = policy.applyExceptions({
    exceptions,
    findings,
    assessedPairs,
    presentPairs: new Set(occurrences.map((o) => pairKey(o.file, o.url))),
    today: paths.today,
  });
  for (const finding of findings) {
    finding.blocking =
      finding.outcome === "broken" && !finding.exception && (!options.base || finding.new === true);
    delete finding.target;
  }
  results.findings = findings.sort(
    (a, b) =>
      Number(b.blocking) - Number(a.blocking) ||
      a.file.localeCompare(b.file) ||
      a.ordinal - b.ordinal,
  );
}

function writeResults(paths, results) {
  fs.mkdirSync(paths.outputDir, { recursive: true });
  const file = path.join(paths.outputDir, "results.json");
  fs.writeFileSync(`${file}.tmp`, `${JSON.stringify(results, null, 2)}\n`);
  fs.renameSync(`${file}.tmp`, file);
  fs.writeFileSync(path.join(paths.outputDir, "report.md"), report.renderMarkdown(results));
}

async function main(argv) {
  let options;
  try {
    options = parseArgs(argv);
  } catch (error) {
    console.error(`${error.message}\n${USAGE}`);
    return 2;
  }
  if (options.help) {
    console.log(USAGE);
    return 0;
  }
  const paths = settings();
  const started = performance.now();
  const results = {
    schemaVersion: report.RESULTS_SCHEMA,
    status: "incomplete",
    mode: options.localOnly ? "local-only" : "full",
    startedAt: new Date().toISOString(),
    options: { base: options.base, localOnly: options.localOnly, fresh: options.fresh },
    base: null,
    counts: {},
    metrics: {},
    errors: [],
    findings: [],
    pages: [],
    exceptions: [],
  };
  try {
    fs.rmSync(path.join(paths.outputDir, "report.md"), { force: true });
    // A crash or timeout leaves this marker instead of an older passing report.
    writeResults(paths, { ...results, errors: ["the checker started but did not finish"] });
  } catch (error) {
    console.error(`  [internal] cannot write ${paths.outputDir}: ${error.message}`);
    return 2;
  }

  try {
    await run(results, options, paths);
  } catch (error) {
    results.errors.push(error.message);
  }
  const unassessed = results.findings.filter((f) => f.outcome === "unassessed").length;
  results.status =
    results.errors.length > 0 || unassessed > 0
      ? "incomplete"
      : results.findings.some((f) => f.blocking)
        ? "failed"
        : "passed";
  results.finishedAt = new Date().toISOString();
  results.durationMs = Math.round(performance.now() - started);
  writeResults(paths, results);
  const lines = report.consoleLines(results);
  (results.status === "passed" ? console.log : console.error)(lines.join("\n"));
  return { passed: 0, failed: 1, incomplete: 2 }[results.status];
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error) => {
    console.error(`  [internal] ${error.stack || error}`);
    process.exitCode = 2;
  },
);
