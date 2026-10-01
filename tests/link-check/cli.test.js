const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const { TEST_CONFIG, commit, finding, makeRepo, runChecker, startServer, writeFiles } = require("./helpers");

const html = (body = "ok") => ({ status: 200, body: `<html><body>${body}</body></html>` });

async function fixtureServer(t) {
  return startServer(t, {
    "/ok": () => html('<h2 id="part">x</h2>'),
    "/other": () => html(),
    "/missing": () => ({ status: 404 }),
    "/forbidden": () => ({ status: 403 }),
    "/new": () => html(),
  });
}

test("a full audit reports outcomes, blocks only on confirmed broken links, and writes results", async (t) => {
  const server = await fixtureServer(t);
  const root = makeRepo(t, {
    "cheatsheets/A.md": `# A\n\n[ok](${server.url("/ok")}) [gone](${server.url("/missing")}) [denied](${server.url("/forbidden")})\n`,
    "cheatsheets/B.md": `# B\n\n[ok again](${server.url("/ok")}#part) [anchor](${server.url("/ok")}#absent)\n`,
    "cheatsheets/C.md": `# C\n\n[protocol-relative](${server.url("/ok").replace("http:", "")})\n`,
  });
  const run = await runChecker(root);
  assert.equal(run.status, 1, run.stderr);
  const { results } = run;
  assert.equal(results.schemaVersion, 1);
  assert.equal(results.status, "failed");
  assert.equal(results.mode, "full");
  assert.equal(results.counts.external.selectedOccurrences, 6);
  assert.equal(results.counts.external.distinctPages, 4);

  const gone = finding(results, (f) => f.url.endsWith("/missing"));
  assert.equal(gone.outcome, "broken");
  assert.equal(gone.blocking, true);
  assert.equal(gone.line, 3);
  const denied = finding(results, (f) => f.url.endsWith("/forbidden"));
  assert.equal(denied.outcome, "unverified");
  assert.equal(denied.category, "access-restricted");
  assert.equal(denied.blocking, false);
  const anchor = finding(results, (f) => f.url.endsWith("#absent"));
  assert.equal(anchor.category, "missing-external-anchor");
  assert.equal(anchor.blocking, false);

  // One page fetch serves every occurrence and fragment, and keeps attribution.
  const okPage = results.pages.find((p) => p.key === server.url("/ok"));
  assert.deepEqual(
    okPage.occurrences.map((o) => [o.file, o.url]),
    [
      ["cheatsheets/A.md", server.url("/ok")],
      ["cheatsheets/B.md", `${server.url("/ok")}#part`],
      ["cheatsheets/B.md", `${server.url("/ok")}#absent`],
    ],
  );
  assert.equal(server.count("/ok"), 1);
  assert.equal(server.count("/ok", "GET"), 1);

  // The published site is HTTPS, so a protocol-relative link resolves to https.
  const relative = finding(results, (f) => f.file === "cheatsheets/C.md");
  assert.equal(relative.page, server.url("/ok").replace("http:", "https:"));
  assert.equal(relative.outcome, "unverified");

  const report = fs.readFileSync(path.join(root, ".link-check", "report.md"), "utf8");
  assert.match(report, /## Blocking problems \(1\)/);
  assert.match(report, /## Unverified links \(3\)/);
  assert.match(report, /does not show that the source supports the claim/);
  assert.match(run.stderr, /\[blocking\] cheatsheets\/A\.md:3 /);
});

test("unverified links alone do not fail a full audit", async (t) => {
  const server = await fixtureServer(t);
  const root = makeRepo(t, {
    "cheatsheets/A.md": `# A\n\n[denied](${server.url("/forbidden")})\n`,
  });
  const run = await runChecker(root);
  assert.equal(run.status, 0, run.stderr);
  assert.equal(run.results.status, "passed");
  assert.match(run.stdout, /\[verify manually\] cheatsheets\/A\.md:3/);
});

test("PR mode checks only new occurrences, including new citations of existing URLs", async (t) => {
  const server = await fixtureServer(t);
  const root = makeRepo(t, {
    "cheatsheets/A.md": `# A\n\n[ok](${server.url("/ok")})\n\n[old ref][r]\n\n[r]: ${server.url("/other")}\n`,
    "cheatsheets/B.md": `# B\n\n[unchanged](${server.url("/missing")})\n`,
  });
  const base = commit(root, "base");

  const unchanged = await runChecker(root, ["--base", base]);
  assert.equal(unchanged.status, 0, unchanged.stderr);
  assert.equal(unchanged.results.counts.external.selectedOccurrences, 0);
  assert.equal(server.requests.length, 0, "no external requests without changes");

  writeFiles(root, {
    // A second occurrence in A, a new citation in C, and a changed reference definition.
    "cheatsheets/A.md": `# A\n\nMoved down.\n\n[ok](${server.url("/ok")})\n\n[old ref][r] [ok twice](${server.url("/ok")})\n\n[r]: ${server.url("/new")}\n`,
    "cheatsheets/C.md": `# C\n\n[cite](${server.url("/ok")}) [dead](${server.url("/missing")})\n`,
  });
  commit(root, "head");
  const run = await runChecker(root, ["--base", "master~1"]);
  assert.equal(run.status, 1, run.stderr);
  const { results } = run;
  assert.equal(results.base.mergeBase, base);
  const selected = results.pages.flatMap((p) => p.occurrences.map((o) => `${o.file} ${o.url}`)).sort();
  assert.deepEqual(selected, [
    `cheatsheets/A.md ${server.url("/new")}`,
    `cheatsheets/A.md ${server.url("/ok")}`,
    `cheatsheets/C.md ${server.url("/missing")}`,
    `cheatsheets/C.md ${server.url("/ok")}`,
  ]);
  assert.equal(server.count("/ok"), 1, "deduplicated across files");
  assert.equal(server.count("/other"), 0, "an unchanged citation is not rechecked");
  const blocking = results.findings.filter((f) => f.blocking);
  assert.deepEqual(blocking.map((f) => f.file), ["cheatsheets/C.md"], "B's existing dead link does not block");
});

test("PR mode blocks newly broken local links even in untouched files", async (t) => {
  const root = makeRepo(t, {
    "cheatsheets/A.md": "# A\n\n[part](B.md#part) [old debt](B.md#never)\n",
    "cheatsheets/B.md": "# B\n\n## Part\n",
    "cheatsheets/C.md": "# C\n\n[c](D.md)\n",
    "cheatsheets/D.md": "# D\n",
  });
  const base = commit(root, "base");
  writeFiles(root, {
    "cheatsheets/B.md": "# B\n\n## Renamed Part\n",
    "cheatsheets/D.md": null,
  });
  const run = await runChecker(root, ["--base", base, "--local-only"]);
  assert.equal(run.status, 1, run.stderr);
  const blocking = run.results.findings.filter((f) => f.blocking).map((f) => `${f.file} ${f.url} ${f.category}`);
  assert.deepEqual(blocking, [
    "cheatsheets/A.md B.md#part missing-anchor",
    "cheatsheets/C.md D.md missing-file",
  ]);
  const debt = finding(run.results, (f) => f.url === "B.md#never");
  assert.equal(debt.blocking, false);
  assert.equal(debt.new, false);
  assert.match(fs.readFileSync(path.join(root, ".link-check", "report.md"), "utf8"), /maintenance debt/);
});

test("exceptions suppress only matching, unexpired categories and report their state", async (t) => {
  const server = await fixtureServer(t);
  const exception = (url, category, extra = {}) => ({
    file: "cheatsheets/A.md",
    url,
    category,
    reason: "Reviewed: the archived page is cited for historical context.",
    reviewedOn: "2026-01-01",
    expiresOn: "2026-12-31",
    reference: "https://github.com/OWASP/CheatSheetSeries/issues/1",
    ...extra,
  });
  const exceptions = [
    exception(server.url("/missing"), "not-found"),
    exception("B.md#gone", "missing-anchor", { reviewedOn: "2020-01-01", expiresOn: "2020-06-01" }),
    exception(server.url("/forbidden"), "not-found"),
    exception(server.url("/ok"), "access-restricted"),
    exception("https://removed.example/", "not-found"),
  ];
  const root = makeRepo(
    t,
    {
      "cheatsheets/A.md": `# A\n\n[a](${server.url("/missing")}) [b](B.md#gone) [c](${server.url("/forbidden")}) [d](${server.url("/ok")})\n`,
      "cheatsheets/B.md": "# B\n",
    },
    { exceptions },
  );
  const today = { LINK_CHECK_TODAY: "2026-03-01" };
  const run = await runChecker(root, [], today);
  assert.deepEqual(run.results.errors, []);
  const states = Object.fromEntries(run.results.exceptions.map((e) => [e.url, e.state]));
  assert.deepEqual(states, {
    [server.url("/missing")]: "applied",
    "B.md#gone": "expired",
    [server.url("/forbidden")]: "category-changed",
    [server.url("/ok")]: "recovered",
    "https://removed.example/": "stale-removed",
  });
  assert.equal(finding(run.results, (f) => f.url === server.url("/missing")).blocking, false);
  assert.equal(finding(run.results, (f) => f.url === "B.md#gone").blocking, true, "an expired exception no longer suppresses");
  assert.equal(run.status, 1);

  const local = await runChecker(root, ["--local-only"], today);
  const localStates = Object.fromEntries(local.results.exceptions.map((e) => [e.url, e.state]));
  assert.equal(localStates[server.url("/missing")], "unassessed", "unchecked links are not called recovered");
});

test("an exception never suppresses a newly added occurrence", async (t) => {
  const server = await fixtureServer(t);
  const exceptions = [
    {
      file: "cheatsheets/A.md",
      url: server.url("/missing"),
      category: "not-found",
      reason: "Reviewed: kept for historical context.",
      reviewedOn: "2026-01-01",
      expiresOn: "2026-12-31",
      reference: "https://github.com/OWASP/CheatSheetSeries/issues/1",
    },
  ];
  const root = makeRepo(t, { "cheatsheets/A.md": `# A\n\n[a](${server.url("/missing")})\n` }, { exceptions });
  const base = commit(root, "base");
  writeFiles(root, { "cheatsheets/A.md": `# A\n\n[a](${server.url("/missing")})\n\n[again](${server.url("/missing")})\n` });
  const run = await runChecker(root, ["--base", base], { LINK_CHECK_TODAY: "2026-03-01" });
  assert.equal(run.status, 1, run.stderr);
  assert.equal(run.results.exceptions[0].state, "not-applied-to-new-occurrence");
  const added = run.results.findings.filter((f) => f.url === server.url("/missing"));
  assert.equal(added.length, 1);
  assert.equal(added[0].new, true);
  assert.equal(added[0].blocking, true);
});

test("invalid inputs are internal errors that leave an incomplete result", async (t) => {
  const root = makeRepo(t, { "cheatsheets/A.md": "# A\n" });
  commit(root);
  const cases = [
    [{}, [], { LINK_CHECK_TODAY: "" }, /today must be YYYY-MM-DD/],
    [{}, [], { LINK_CHECK_TODAY: "2026-99-99" }, /today must be YYYY-MM-DD/],
    [{ "link-check-config.json": { ...TEST_CONFIG, budgetSeconds: 0 } }, [], {}, /budgetSeconds must be a number/],
    [{ "link-check-config.json": "{" }, [], {}, /configuration is malformed/],
    [{ "link-check-exceptions.json": { schemaVersion: 1, exceptions: [{ file: "cheatsheets/A.md" }] } }, [], {}, /must contain exactly/],
    [{}, ["--base", "no-such-ref"], {}, /git rev-parse failed/],
    [{}, ["--base", "--upload-pack=x"], {}, /invalid base ref/],
    [{}, [], { LINK_CHECK_PYTHON: path.join(root, "missing-python") }, /cannot run the Markdown extractor/],
    [{ "cheatsheets/A.md": null }, [], {}, /no Markdown files found/],
  ];
  for (const [files, args, env, message] of cases) {
    const saved = Object.fromEntries(Object.keys(files).map((file) => [file, fs.readFileSync(path.join(root, file), "utf8")]));
    writeFiles(root, files);
    const run = await runChecker(root, args, env);
    writeFiles(root, saved);
    assert.equal(run.status, 2, `${message}: ${run.stderr}`);
    assert.equal(run.results.status, "incomplete");
    assert.match(run.results.errors.join("\n"), message);
    assert.match(run.stderr, /\[internal\]/);
  }
});

test("the success cache avoids repeat requests and --fresh bypasses it", async (t) => {
  const server = await fixtureServer(t);
  const root = makeRepo(t, { "cheatsheets/A.md": `# A\n\n[ok](${server.url("/ok")}) [x](${server.url("/missing")})\n` });
  await runChecker(root);
  const afterFirst = server.requests.length;
  const cacheFile = path.join(root, ".link-check-cache", "http-success.json");
  assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(cacheFile, "utf8")).entries), [server.url("/ok")]);

  const cached = await runChecker(root);
  assert.equal(cached.results.counts.external.cacheHits, 1);
  assert.equal(server.count("/ok"), 1);
  assert.ok(server.requests.length > afterFirst, "the failure was observed again, not cached");

  const fresh = await runChecker(root, ["--fresh"]);
  assert.equal(fresh.results.counts.external.cacheHits, 0);
  assert.equal(server.count("/ok"), 2);
  assert.equal(fs.existsSync(path.join(root, ".link-check", "http-success.json")), false, "the cache is not part of diagnostics");
});

test("untrusted file names and URLs cannot inject Markdown or workflow commands", async (t) => {
  const root = makeRepo(t, {
    "cheatsheets/A.md": "# A\n\n[x](Missing.md#a%0A::error::x`|) [y](<missing file.md>)\n",
  });
  const run = await runChecker(root, ["--local-only"]);
  assert.equal(run.status, 1);
  for (const line of run.stderr.split("\n")) {
    assert.doesNotMatch(line, /^::/);
  }
  const report = fs.readFileSync(path.join(root, ".link-check", "report.md"), "utf8");
  assert.doesNotMatch(report, /\n::error/);
  assert.match(report, /`Missing\.md#a%0A::error::x%60\|`/);
});


test("redirected failure destinations reach structured findings and the readable report", async (t) => {
  const destination = await startServer(t, { "/blocked": () => ({ status: 403 }) });
  const source = await startServer(t, { "/start": () => ({ status: 302, headers: { location: destination.url("/blocked") } }) });
  const root = makeRepo(t, { "cheatsheets/A.md": `# A\n\n[ref](${source.url("/start")})\n` });
  const run = await runChecker(root);
  assert.equal(run.status, 0, run.stderr);
  assert.equal(run.results.findings[0].finalUrl, destination.url("/blocked"));
  const report = fs.readFileSync(path.join(root, ".link-check/report.md"), "utf8");
  assert.ok(report.includes(`redirect destination: \`${destination.url("/blocked")}\``));
});
