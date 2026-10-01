const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const external = require("../../scripts/link_check/external");
const { TEST_CONFIG, startServer } = require("./helpers");

const page = (url, fragments = [""]) => ({ key: external.pageKey(url), fragments: new Set(fragments) });

function check(pages, overrides = {}, options = {}) {
  return external.checkPages(pages, {
    http: { ...TEST_CONFIG.http, ...overrides },
    deadlineAt: Date.now() + (options.budgetMs ?? 30000),
    ...options,
  });
}

const html = (body) => ({ status: 200, body: `<!doctype html><html><body>${body}</body></html>` });

test("a healthy fragmentless page needs one HEAD request", async (t) => {
  const server = await startServer(t, { "/ok": () => html("ok") });
  const { results, stats } = await check([page(server.url("/ok"))]);
  const result = results.get(server.url("/ok"));
  assert.equal(result.outcome, "healthy");
  assert.equal(result.category, "ok");
  assert.equal(server.count("/ok", "HEAD"), 1);
  assert.equal(server.count("/ok", "GET"), 0);
  assert.equal(stats.requests, 1);
});

test("a HEAD rejection falls back to GET instead of failing", async (t) => {
  for (const headStatus of [403, 404, 405, 501]) {
    const route = `/head-${headStatus}`;
    const server = await startServer(t, {
      [route]: ({ method }) => (method === "HEAD" ? { status: headStatus } : html("ok")),
    });
    const { results } = await check([page(server.url(route))]);
    const result = results.get(server.url(route));
    assert.equal(result.outcome, "healthy", `HEAD ${headStatus}`);
    assert.equal(result.observations.length, 1);
    assert.equal(result.observations[0].headStatus, headStatus);
    assert.equal(server.count(route, "GET"), 1);
  }
});

test("redirects are followed manually and the final destination is recorded", async (t) => {
  const server = await startServer(t, {
    "/start": () => ({ status: 301, headers: { location: "/middle" } }),
    "/middle": () => ({ status: 302, headers: { location: server.url("/final", "localhost") } }),
    "/final": () => html("done"),
    "/loop": () => ({ status: 302, headers: { location: "/loop" } }),
  });
  const { results } = await check([page(server.url("/start")), page(server.url("/loop"))]);
  const start = results.get(server.url("/start"));
  assert.equal(start.outcome, "healthy");
  assert.equal(start.finalUrl, server.url("/final", "localhost"));
  assert.deepEqual(
    start.requests.map((r) => r.status),
    [301, 302, 200],
  );
  const loop = results.get(server.url("/loop"));
  assert.equal(loop.outcome, "unverified");
  assert.equal(loop.category, "redirect-error");
  assert.match(loop.observations[0].error, /more than 5 redirects/);
});

test("404 and 410 are broken only after two fresh GET observations", async (t) => {
  const server = await startServer(t, {
    "/missing": () => ({ status: 404 }),
    "/gone": () => ({ status: 410 }),
  });
  const { results } = await check([page(server.url("/missing")), page(server.url("/gone"))]);
  const missing = results.get(server.url("/missing"));
  assert.equal(missing.outcome, "broken");
  assert.equal(missing.category, "not-found");
  assert.equal(missing.observations.length, 2);
  assert.equal(server.count("/missing", "GET"), 2);
  assert.equal(server.count("/missing", "HEAD"), 1);
  assert.equal(results.get(server.url("/gone")).category, "gone");
});

test("a 404 that serves the site's home page document is unverified", async (t) => {
  const shell = '<html><body><div id="app"></div><script src="/app.js"></script></body></html>';
  const server = await startServer(t, {
    "/": () => ({ status: 200, body: shell }),
    "/techniques/T1": () => ({ status: 404, body: shell }),
    "/techniques/T2": () => ({ status: 404, body: shell }),
    "/really-missing": () => ({ status: 404, body: "<html><body>Not found</body></html>" }),
  });
  const { results } = await check(
    ["/techniques/T1", "/techniques/T2", "/really-missing"].map((route) => page(server.url(route))),
  );
  for (const route of ["/techniques/T1", "/techniques/T2"]) {
    const result = results.get(server.url(route));
    assert.equal(result.outcome, "unverified", route);
    assert.equal(result.category, "app-shell-404");
    assert.equal(result.observations.length, 1, "no repeated confirmation");
  }
  assert.equal(results.get(server.url("/really-missing")).outcome, "broken");
  assert.equal(server.count("/", "GET"), 1, "the home page is fetched once per origin");
});

test("a missing page that later denies access is unverified, not broken", async (t) => {
  const server = await startServer(t, {
    "/conflict": ({ method, count }) => ({ status: method === "GET" && count > 1 ? 403 : 404 }),
  });
  const { results } = await check([page(server.url("/conflict"))]);
  const result = results.get(server.url("/conflict"));
  assert.equal(result.outcome, "unverified");
  assert.equal(result.category, "unconfirmed-not-found");
});

test("access restrictions are unverified and not retried", async (t) => {
  const server = await startServer(t, {
    "/forbidden": () => ({ status: 403 }),
    "/login": () => ({ status: 401 }),
  });
  const { results } = await check([page(server.url("/forbidden")), page(server.url("/login"))]);
  for (const route of ["/forbidden", "/login"]) {
    const result = results.get(server.url(route));
    assert.equal(result.outcome, "unverified");
    assert.equal(result.category, "access-restricted");
    assert.equal(result.observations.length, 1);
    assert.equal(server.count(route, "GET"), 1);
  }
});

test("429 honors numeric Retry-After and cools down the host", async (t) => {
  const server = await startServer(t, {
    "/limited": ({ method, count }) =>
      method === "GET" && count === 1
        ? { status: 429, headers: { "retry-after": "1" } }
        : method === "HEAD"
          ? { status: 429, headers: { "retry-after": "1" } }
          : html("ok"),
  });
  const started = Date.now();
  const { results } = await check([page(server.url("/limited"))]);
  const result = results.get(server.url("/limited"));
  assert.equal(result.outcome, "healthy");
  assert.equal(result.category, "recovered");
  const gets = server.requests.filter((r) => r.path === "/limited" && r.method === "GET");
  assert.equal(gets.length, 2);
  assert.ok(gets[1].at - gets[0].at >= 950, "the retry waited for Retry-After");
  assert.ok(Date.now() - started >= 950);
});

test("an HTTP-date Retry-After delays other requests to the same host", async (t) => {
  const retryAt = () => new Date(Date.now() + 1500).toUTCString();
  const server = await startServer(t, {
    "/busy": ({ count }) =>
      count === 1 ? { status: 503, headers: { "retry-after": retryAt() } } : html("ok"),
    "/other": () => ({ ...html("other"), delayMs: 50 }),
  });
  // The first page's 503 sets a host cooldown that the second page must respect.
  const { results } = await check(
    [page(server.url("/busy"), ["x"]), page(server.url("/other"), ["y"])],
    { perHostConcurrency: 1 },
  );
  assert.equal(results.get(server.url("/busy")).outcome, "healthy");
  const busy = server.requests.filter((r) => r.path === "/busy");
  const other = server.requests.find((r) => r.path === "/other");
  assert.equal(busy.length, 2);
  assert.ok(busy[1].at - busy[0].at >= 400, "the retry waited for the HTTP date");
  assert.ok(other.at - busy[0].at >= 400, "another page on the host waited for the cooldown");
});

test("a Retry-After beyond the limit stops requests to that host", async (t) => {
  const server = await startServer(t, {
    "/later": () => ({ status: 429, headers: { "retry-after": "3600" } }),
    "/sibling": () => html("never requested"),
  });
  const started = Date.now();
  const { results } = await check(
    [page(server.url("/later"), ["a"]), page(server.url("/sibling"), ["b"])],
    { perHostConcurrency: 1 },
  );
  assert.ok(Date.now() - started < 2000, "no long sleep");
  const result = results.get(server.url("/later"));
  assert.equal(result.outcome, "unverified");
  assert.equal(result.category, "rate-limited");
  assert.match(result.notes.join(" "), /3600s exceeds the 5s limit/);
  assert.equal(server.count("/later"), 1);
  const sibling = results.get(server.url("/sibling"));
  assert.equal(sibling.outcome, "unverified", "assessed as rate-limited, not left incomplete");
  assert.equal(sibling.category, "rate-limited");
  assert.match(sibling.notes.join(" "), /asked clients to wait 3600s/);
  assert.equal(server.count("/sibling"), 0);
});

test("temporary outages recover and persistent ones stay unverified", async (t) => {
  const server = await startServer(t, {
    "/flaky": ({ method, count }) => (method === "GET" && count >= 2 ? html("ok") : { status: 503 }),
    "/down": () => ({ status: 500 }),
  });
  const { results } = await check([page(server.url("/flaky")), page(server.url("/down"))]);
  const flaky = results.get(server.url("/flaky"));
  assert.equal(flaky.outcome, "healthy");
  assert.equal(flaky.category, "recovered");
  const down = results.get(server.url("/down"));
  assert.equal(down.outcome, "unverified");
  assert.equal(down.category, "server-error");
  assert.equal(down.observations.length, 3);
  assert.equal(server.count("/down", "GET"), 3);
});

test("only failing pages are retried", async (t) => {
  const server = await startServer(t, {
    "/a": () => html("a"),
    "/b": () => html("b"),
    "/c": ({ method, count }) => (method === "GET" && count >= 2 ? html("c") : { status: 502 }),
  });
  const { stats } = await check(["/a", "/b", "/c"].map((route) => page(server.url(route))));
  assert.equal(server.count("/a"), 1);
  assert.equal(server.count("/b"), 1);
  assert.equal(server.count("/c", "GET"), 2);
  assert.equal(stats.requests, 5);
});

test("request timeouts are unverified with the underlying error", async (t) => {
  const server = await startServer(t, {
    "/slow": () => ({ ...html("late"), delayMs: 2000 }),
  });
  const { results } = await check([page(server.url("/slow"))], {
    requestTimeoutSeconds: 0.2,
    maxObservations: 2,
  });
  const result = results.get(server.url("/slow"));
  assert.equal(result.outcome, "unverified");
  assert.equal(result.category, "timeout");
  assert.equal(result.observations.length, 2);
  assert.match(result.observations[0].error, /request deadline/);
});

test("network errors keep their cause", async () => {
  // Reserve a port, then close it so connections are refused.
  const listener = require("node:net").createServer();
  await new Promise((resolve) => listener.listen(0, "127.0.0.1", resolve));
  const { port } = listener.address();
  await new Promise((resolve) => listener.close(resolve));
  const url = `http://127.0.0.1:${port}/refused`;
  const { results } = await check([page(url)], { maxObservations: 2 });
  const result = results.get(url);
  assert.equal(result.outcome, "unverified");
  assert.equal(result.category, "network-error");
  assert.match(result.observations[0].error, /ECONNREFUSED/);
});

test("the run deadline leaves unstarted pages unassessed", async (t) => {
  const routes = {};
  for (let index = 0; index < 4; index += 1) {
    routes[`/slow${index}`] = () => ({ ...html("late"), delayMs: 1500 });
  }
  const server = await startServer(t, routes);
  const pages = Object.keys(routes).map((route) => page(server.url(route)));
  const { results } = await check(pages, { concurrency: 1, requestTimeoutSeconds: 5 }, { budgetMs: 300 });
  const outcomes = [...results.values()].map((r) => r.outcome);
  assert.deepEqual(outcomes, ["unassessed", "unassessed", "unassessed", "unassessed"]);
  assert.equal(server.requests.length, 1, "queued pages never started after the deadline");
});

test("global and per-host limits apply to every hop, including redirects", async (t) => {
  const routes = {};
  for (let index = 0; index < 12; index += 1) {
    routes[`/hop${index}`] = () => ({ status: 302, headers: { location: server.url(`/target${index}`, "localhost") } });
    routes[`/target${index}`] = () => ({ ...html("t"), delayMs: 60 });
  }
  const server = await startServer(t, routes);
  const pages = Object.keys(routes)
    .filter((route) => route.startsWith("/hop"))
    .map((route) => page(server.url(route)));
  const { stats } = await check(pages, { concurrency: 3, perHostConcurrency: 2 });
  assert.ok(stats.peakActive <= 3);
  assert.equal(stats.peakPerHost, 2);
  for (const peak of server.peakByHost.values()) {
    assert.ok(peak <= 2, `peak per host ${peak}`);
  }
});

test("external fragments use a real HTML parser and are unverified when missing", async (t) => {
  const server = await startServer(t, {
    "/doc": () =>
      html(`<h2 id="present">x</h2><a name="named"></a><template><p id="templated"></p></template><!-- <p id="commented"> -->`),
    "/file.pdf": () => ({ status: 200, headers: { "content-type": "application/pdf" }, body: "%PDF" }),
    "/huge": () => html(`${"x".repeat(5000)}<p id="late"></p>`),
  });
  const { results } = await check([
    page(server.url("/doc"), ["present", "named", "templated", "commented", "absent", ":~:text=hello", ""]),
    page(server.url("/file.pdf"), ["page=2"]),
    page(server.url("/huge"), ["late"]),
  ]);
  const doc = results.get(server.url("/doc")).fragments;
  assert.equal(doc.present.outcome, "healthy");
  assert.equal(doc.named.outcome, "healthy");
  assert.equal(doc.templated.outcome, "healthy");
  assert.equal(doc.commented.category, "missing-external-anchor");
  assert.equal(doc.absent.outcome, "unverified");
  assert.equal(doc[":~:text=hello"].category, "unsupported-fragment");
  assert.equal(doc[""].outcome, "healthy");
  assert.equal(server.count("/doc", "GET"), 1, "one GET serves every fragment");
  assert.equal(server.count("/doc", "HEAD"), 0);
  assert.match(results.get(server.url("/file.pdf")).fragments["page=2"].detail, /not HTML/);
  assert.match(results.get(server.url("/huge")).fragments.late.detail, /size limit/);
});

test("the success cache expires, never stores failures, and cannot prove anchors from HEAD", async (t) => {
  const server = await startServer(t, {
    "/ok": () => html('<p id="frag"></p>'),
    "/missing": () => ({ status: 404 }),
  });
  const cacheFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "link-cache-")), "cache.json");
  t.after(() => fs.rmSync(path.dirname(cacheFile), { recursive: true, force: true }));
  const fingerprint = external.cacheFingerprint(TEST_CONFIG.http);
  const first = await check([page(server.url("/ok")), page(server.url("/missing"))]);
  assert.equal(first.freshSuccesses.size, 1);
  external.saveCache(cacheFile, fingerprint, first.freshSuccesses);
  const ttl = 24 * 3600 * 1000;

  let cache = external.loadCache(cacheFile, fingerprint, ttl);
  assert.deepEqual([...cache.entries.keys()], [server.url("/ok")]);
  const requestsBefore = server.requests.length;
  const hit = await check([page(server.url("/ok"))], {}, { cacheEntries: cache.entries });
  assert.equal(hit.results.get(server.url("/ok")).cache, "hit");
  assert.equal(server.requests.length, requestsBefore);

  // A cached HEAD success cannot prove that a fragment exists.
  const withFragment = await check([page(server.url("/ok"), ["frag"])], {}, { cacheEntries: cache.entries });
  assert.equal(withFragment.results.get(server.url("/ok")).cache, "miss");
  assert.equal(withFragment.results.get(server.url("/ok")).fragments.frag.outcome, "healthy");

  const fresh = await check([page(server.url("/ok"))], {}, { cacheEntries: cache.entries, fresh: true });
  assert.equal(fresh.results.get(server.url("/ok")).cache, "miss");

  const later = Date.now() + ttl + 1000;
  assert.equal(external.loadCache(cacheFile, fingerprint, ttl, later).entries.size, 0);
  const earlier = Date.now() - 60000;
  assert.equal(external.loadCache(cacheFile, fingerprint, ttl, earlier).entries.size, 0, "future timestamps are rejected");
  assert.equal(external.loadCache(cacheFile, "other", ttl).entries.size, 0);
  fs.writeFileSync(cacheFile, "{not json");
  cache = external.loadCache(cacheFile, fingerprint, ttl);
  assert.equal(cache.entries.size, 0);
  assert.match(cache.note, /unreadable/);
});

test("Retry-After parsing accepts seconds and HTTP dates", () => {
  const now = Date.parse("2026-01-01T00:00:00Z");
  assert.equal(external.retryAfterMs("120", now), 120000);
  assert.equal(external.retryAfterMs("Thu, 01 Jan 2026 00:00:30 GMT", now), 30000);
  assert.equal(external.retryAfterMs("Wed, 31 Dec 2025 00:00:00 GMT", now), 0);
  assert.equal(external.retryAfterMs("soon", now), null);
});

test("page keys drop only the fragment", () => {
  assert.equal(
    external.pageKey("HTTPS://Example.COM:443/A/B?Z=1&a=2#Frag"),
    "https://example.com/A/B?Z=1&a=2",
  );
});

test("shell detection requires complete nonempty 404 bodies and preserves 410", async (t) => {
  for (const [name, home, missing, status, limit] of [
    ["truncated", "0123456789abcdefHOME", "0123456789abcdefMISSING", 404, 16],
    ["empty", "", "", 404, 4096],
    ["gone", "same", "same", 410, 4096],
    ["truncated-home", "0123456789abcdefHOME", "0123456789abcdef", 404, 16],
  ]) {
    const server = await startServer(t, {
      "/": () => ({ status: 200, body: home }),
      "/missing": () => ({ status, body: missing }),
    });
    const { results } = await check([page(server.url("/missing"))], { maxBodyBytes: limit });
    const result = results.get(server.url("/missing"));
    assert.equal(result.outcome, "broken", name);
    assert.equal(result.category, status === 410 ? "gone" : "not-found", name);
    assert.equal(server.count("/missing", "GET"), 2, name);
    if (status === 410) assert.equal(server.count("/", "GET"), 0);
  }
});

test("redirected failures retain destinations and attribute failure to response host", async (t) => {
  const destination = await startServer(t, {
    "/": () => html("home"),
    "/blocked": () => ({ status: 403 }),
    "/missing": () => ({ status: 404 }),
    "/limited": () => ({ status: 429, headers: { "retry-after": "0" } }),
  });
  const source = await startServer(t, Object.fromEntries(["blocked", "missing", "limited"].map((name) => [
    `/${name}`, () => ({ status: 302, headers: { location: destination.url(`/${name}`) } }),
  ])));
  const { results, stats } = await check(["blocked", "missing", "limited"].map((name) => page(source.url(`/${name}`))));
  for (const [name, category] of [["blocked", "access-restricted"], ["missing", "not-found"], ["limited", "rate-limited"]]) {
    const result = results.get(source.url(`/${name}`));
    assert.equal(result.finalUrl, destination.url(`/${name}`));
    assert.equal(result.category, category);
    assert.equal(stats.perHost[new URL(destination.url("/")).host].failures[category], 1);
  }
  assert.deepEqual(stats.perHost[new URL(source.url("/")).host].failures, {});
  assert.equal(destination.count("/missing", "GET"), 2);
});

test("a poisoned HEAD cache cannot prove a later citation anchor", async (t) => {
  const server = await startServer(t, { "/ok": () => html("no anchor") });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "poison-cache-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, "cache.json");
  const fingerprint = external.cacheFingerprint(TEST_CONFIG.http);
  const forged = { checkedAt: new Date().toISOString(), method: "HEAD", status: 200, fragmentEvidence: "ids", ids: ["fake"] };
  external.saveCache(file, fingerprint, new Map([[server.url("/ok"), forged]]));
  const cache = external.loadCache(file, fingerprint, 86400000);
  assert.equal(cache.entries.size, 0);
  const run = await check([page(server.url("/ok"), ["fake"])], {}, { cacheEntries: cache.entries });
  assert.equal(run.results.get(server.url("/ok")).fragments.fake.category, "missing-external-anchor");
  assert.equal(server.count("/ok", "GET"), 1);
  external.saveCache(file, fingerprint, new Map([[server.url("/ok"), { ...forged, method: "GET", ids: [123] }]]));
  assert.equal(external.loadCache(file, fingerprint, 86400000).entries.size, 0);
});
