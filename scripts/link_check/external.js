// Checks external pages through one shared, per-host limited request queue.
// Each distinct page (URL without fragment) is fetched once per observation;
// only pages whose observation failed are retried.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { performance } = require("node:perf_hooks");
const parse5 = require("parse5");

const CACHE_SCHEMA = 1;
const RETRYABLE = new Set(["rate-limited", "server-error", "timeout", "network-error"]);

class DeadlineError extends Error {
  constructor() {
    super("run deadline reached");
    this.name = "DeadlineError";
  }
}

// Limits active requests overall and per host, and honors host cooldowns.
// Waiting tasks hold no slot, so a cooled-down host never blocks others.
class Scheduler {
  constructor({ concurrency, perHost }) {
    this.concurrency = concurrency;
    this.perHost = perHost;
    this.active = 0;
    this.hostActive = new Map();
    this.cooldowns = new Map();
    this.queue = [];
    this.timer = null;
    this.peakActive = 0;
    this.peakPerHost = 0;
  }

  run(host, task) {
    return new Promise((resolve, reject) => {
      this.queue.push({ host, task, resolve, reject });
      this.pump();
    });
  }

  coolDown(host, until) {
    this.cooldowns.set(host, Math.max(this.cooldowns.get(host) || 0, until));
  }

  cancelPending(error) {
    for (const entry of this.queue.splice(0)) {
      entry.reject(error);
    }
    clearTimeout(this.timer);
  }

  pump() {
    const now = Date.now();
    let nextCooldown = Infinity;
    for (let index = 0; index < this.queue.length; ) {
      if (this.active >= this.concurrency) {
        break;
      }
      const entry = this.queue[index];
      const cooldown = this.cooldowns.get(entry.host) || 0;
      if (cooldown > now) {
        nextCooldown = Math.min(nextCooldown, cooldown);
        index += 1;
      } else if ((this.hostActive.get(entry.host) || 0) >= this.perHost) {
        index += 1;
      } else {
        this.queue.splice(index, 1);
        this.start(entry);
      }
    }
    clearTimeout(this.timer);
    if (nextCooldown !== Infinity) {
      this.timer = setTimeout(() => this.pump(), nextCooldown - now);
    }
  }

  start(entry) {
    this.active += 1;
    const hostActive = (this.hostActive.get(entry.host) || 0) + 1;
    this.hostActive.set(entry.host, hostActive);
    this.peakActive = Math.max(this.peakActive, this.active);
    this.peakPerHost = Math.max(this.peakPerHost, hostActive);
    Promise.resolve()
      .then(entry.task)
      .then(entry.resolve, entry.reject)
      .finally(() => {
        this.active -= 1;
        this.hostActive.set(entry.host, this.hostActive.get(entry.host) - 1);
        this.pump();
      });
  }
}

// Normalizes a URL for fetching: WHATWG parsing, fragment removed, and path
// and query case and order kept.
function pageKey(url) {
  const parsed = new URL(url);
  parsed.hash = "";
  return parsed.href;
}

function retryAfterMs(value, now = Date.now()) {
  if (!value) {
    return null;
  }
  if (/^\s*\d+\s*$/.test(value)) {
    return Number(value) * 1000;
  }
  const date = Date.parse(value);
  return Number.isNaN(date) ? null : Math.max(0, date - now);
}

function categoryForStatus(status) {
  if (status >= 200 && status < 300) return "ok";
  if (status === 404) return "not-found";
  if (status === 410) return "gone";
  if (status === 401 || status === 403) return "access-restricted";
  if (status === 429) return "rate-limited";
  if (status >= 500) return "server-error";
  if (status >= 300 && status < 400) return "redirect-error";
  return "unexpected-status";
}

function describeError(error, runSignal, timeoutSignal) {
  if (runSignal.aborted) {
    return { category: "deadline", error: "run deadline reached" };
  }
  if (timeoutSignal.aborted) {
    return { category: "timeout", error: "request deadline reached" };
  }
  const cause = error.cause;
  const code = cause?.code || error.code;
  const detail = [error.message, code, cause?.message]
    .filter(Boolean)
    .filter((value, index, all) => all.indexOf(value) === index)
    .join(": ");
  const timeout = /TIMEOUT/i.test(code || "");
  return { category: timeout ? "timeout" : "network-error", error: detail, errorCode: code };
}

function htmlIds(html) {
  const ids = new Set();
  const visit = (node) => {
    for (const attribute of node.attrs || []) {
      if (attribute.name === "id" || (attribute.name === "name" && node.tagName === "a")) {
        ids.add(attribute.value);
      }
    }
    for (const child of node.childNodes || []) {
      visit(child);
    }
    if (node.content) {
      visit(node.content);
    }
  };
  visit(parse5.parse(html));
  return ids;
}

async function readCapped(body, limit) {
  const reader = body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      return { buffer: Buffer.concat(chunks), truncated: false };
    }
    if (size + value.length > limit) {
      chunks.push(Buffer.from(value.subarray(0, limit - size)));
      await reader.cancel().catch(() => {});
      return { buffer: Buffer.concat(chunks), truncated: true };
    }
    chunks.push(Buffer.from(value));
    size += value.length;
  }
}

function loadCache(file, fingerprint, ttlMs, now = Date.now()) {
  const entries = new Map();
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    return { entries, note: error.code === "ENOENT" ? "no cache file" : `unreadable cache ignored (${error.message})` };
  }
  if (parsed?.schemaVersion !== CACHE_SCHEMA || parsed.fingerprint !== fingerprint) {
    return { entries, note: "cache from a different checker configuration ignored" };
  }
  let rejected = 0;
  for (const [key, entry] of Object.entries(parsed.entries || {})) {
    const checkedAt = Date.parse(entry?.checkedAt);
    const age = now - checkedAt;
    const valid =
      Number.isFinite(checkedAt) &&
      age >= 0 &&
      age <= ttlMs &&
      ["GET", "HEAD"].includes(entry.method) &&
      Number.isInteger(entry.status) &&
      entry.status >= 200 &&
      entry.status < 300 &&
      ["ids", "not-html", "truncated", "none"].includes(entry.fragmentEvidence) &&
      (entry.method !== "HEAD" || entry.fragmentEvidence === "none") &&
      (entry.fragmentEvidence !== "ids" ||
        (entry.method === "GET" && Array.isArray(entry.ids) && entry.ids.every((id) => typeof id === "string")));
    if (valid) {
      entries.set(key, entry);
    } else {
      rejected += 1;
    }
  }
  return { entries, note: `${entries.size} cached success(es) loaded; ${rejected} expired or invalid entr(ies) ignored` };
}

function saveCache(file, fingerprint, entries) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(
    temporary,
    JSON.stringify({
      schemaVersion: CACHE_SCHEMA,
      fingerprint,
      entries: Object.fromEntries(entries),
    }),
  );
  fs.renameSync(temporary, file);
}

function cacheFingerprint(http) {
  return crypto
    .createHash("sha256")
    .update(JSON.stringify({ CACHE_SCHEMA, userAgent: http.userAgent, maxBodyBytes: http.maxBodyBytes }))
    .digest("hex");
}

function fragmentResult(fragment, evidence, ids) {
  if (fragment === "") {
    return { outcome: "healthy", category: "ok", detail: "page reachable" };
  }
  if (fragment.startsWith(":~:")) {
    return { outcome: "unverified", category: "unsupported-fragment", detail: "text fragments are not checked" };
  }
  if (evidence === "ids") {
    const decoded = (() => {
      try {
        return decodeURIComponent(fragment);
      } catch {
        return fragment;
      }
    })();
    if (ids.has(fragment) || ids.has(decoded)) {
      return { outcome: "healthy", category: "ok", detail: "page reachable and anchor present" };
    }
    return {
      outcome: "unverified",
      category: "missing-external-anchor",
      detail: `#${fragment} was not found in the static HTML; it may be added by scripts`,
    };
  }
  const reason = {
    "not-html": "the response is not HTML",
    truncated: "the HTML exceeded the inspected size limit",
    none: "the page body was not retrieved",
  }[evidence];
  return { outcome: "unverified", category: "unsupported-fragment", detail: `anchor not checked: ${reason}` };
}

// Checks pages: [{ key, fragments: Set<string> }]. Returns Map key -> result.
async function checkPages(pages, options) {
  const {
    http,
    deadlineAt,
    cacheEntries = new Map(),
    fresh = false,
    fetchImpl = fetch,
    onProgress = () => {},
  } = options;
  const scheduler = new Scheduler({ concurrency: http.concurrency, perHost: http.perHostConcurrency });
  const runController = new AbortController();
  const deadlineTimer = setTimeout(() => {
    runController.abort();
    scheduler.cancelPending(new DeadlineError());
  }, Math.max(0, deadlineAt - Date.now()));
  const runSignal = runController.signal;
  const headers = {
    "User-Agent": http.userAgent,
    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
  };
  const freshSuccesses = new Map();
  const exhaustedHosts = new Map();
  const perHost = new Map();
  const hostStats = (host) => {
    if (!perHost.has(host)) perHost.set(host, { requests: 0, failures: {} });
    return perHost.get(host);
  };
  let requestCount = 0;

  async function request(url, method, wantBody) {
    const host = new URL(url).host;
    return scheduler.run(host, async () => {
      if (exhaustedHosts.has(host)) {
        return { skipped: exhaustedHosts.get(host) };
      }
      const started = performance.now();
      const timeoutSignal = AbortSignal.timeout(http.requestTimeoutSeconds * 1000);
      const signal = AbortSignal.any([runSignal, timeoutSignal]);
      requestCount += 1;
      hostStats(host).requests += 1;
      const record = { method, url, at: new Date().toISOString() };
      try {
        const response = await fetchImpl(url, { method, headers, redirect: "manual", signal });
        record.status = response.status;
        const location = response.headers.get("location");
        if (location) record.location = location;
        const retryAfter = response.headers.get("retry-after");
        if (retryAfter) record.retryAfter = retryAfter;
        if (response.status === 429 || response.status === 503) {
          // Cool the host down before releasing this slot so queued requests
          // to the same host wait as well.
          const delay = retryAfterMs(retryAfter) ?? http.retryBaseDelaySeconds * 1000;
          if (delay > http.maxRetryDelaySeconds * 1000 || Date.now() + delay >= deadlineAt) {
            exhaustedHosts.set(host, `${host} asked clients to wait ${Math.round(delay / 1000)}s (Retry-After), beyond this run's limits`);
          } else {
            scheduler.coolDown(host, Date.now() + delay);
          }
        }
        const contentType = response.headers.get("content-type") || "";
        let body = null;
        const html = /\b(text\/html|application\/xhtml\+xml)\b/i.test(contentType);
        if (method === "GET" && response.status === 404 && html && response.body) {
          // Kept to recognize applications that answer every route with one document.
          const { buffer, truncated } = await readCapped(response.body, http.maxBodyBytes);
          record.bodyTruncated = truncated;
          record.bodyLength = buffer.length;
          record.bodyHash = crypto.createHash("sha256").update(buffer).digest("hex");
        } else if (wantBody && method === "GET" && response.ok && response.body) {
          if (html) {
            body = await readCapped(response.body, http.maxBodyBytes);
            record.bodyTruncated = body.truncated;
            record.bodyLength = body.buffer.length;
            record.bodyHash = crypto.createHash("sha256").update(body.buffer).digest("hex");
          } else {
            record.notHtml = true;
            await response.body.cancel().catch(() => {});
          }
        } else if (response.body) {
          await response.body.cancel().catch(() => {});
        }
        record.durationMs = Math.round(performance.now() - started);
        return { record, body };
      } catch (error) {
        Object.assign(record, describeError(error, runSignal, timeoutSignal));
        record.durationMs = Math.round(performance.now() - started);
        return { record, body: null };
      }
    });
  }

  // One observation: a request (following redirects manually so each hop is
  // limited by its own host), classified by its final response.
  async function observe(url, method, wantBody) {
    const requests = [];
    let current = url;
    for (let hop = 0; ; hop += 1) {
      const { record, body, skipped } = await request(current, method, wantBody);
      if (skipped) {
        return { method, category: "rate-limited", error: `not requested: ${skipped}`, requests, finalUrl: current !== url ? current : null };
      }
      requests.push(record);
      if (record.category) {
        return { method, category: record.category, error: record.error, errorCode: record.errorCode, requests, finalUrl: current !== url ? current : null };
      }
      const observation = { method, status: record.status, category: categoryForStatus(record.status), requests, finalUrl: current !== url ? current : null };
      if (record.status >= 300 && record.status < 400 && record.location) {
        let next;
        try {
          next = new URL(record.location, current);
        } catch {
          return { ...observation, error: `invalid redirect location ${record.location}` };
        }
        if (next.protocol !== "http:" && next.protocol !== "https:") {
          return { ...observation, error: `redirect to unsupported ${next.protocol} URL` };
        }
        if (hop >= http.maxRedirects) {
          return { ...observation, error: `more than ${http.maxRedirects} redirects` };
        }
        current = next.href;
        continue;
      }
      if (record.bodyHash) {
        observation.bodyHash = record.bodyHash;
        observation.bodyTruncated = record.bodyTruncated;
        observation.bodyLength = record.bodyLength;
      }
      if (current !== url) observation.finalUrl = current;
      if (record.retryAfter) observation.retryAfter = record.retryAfter;
      if (observation.category === "ok") {
        if (body) {
          observation.fragmentEvidence = body.truncated ? "truncated" : "ids";
          observation.ids = htmlIds(body.buffer.toString("utf8"));
        } else {
          observation.fragmentEvidence = record.notHtml ? "not-html" : "none";
        }
      }
      return observation;
    }
  }

  // Some single-page applications return their home page document with a 404
  // status for every route, so the status says nothing about the route.
  const homePages = new Map();
  function homePageHash(url) {
    const home = `${new URL(url).origin}/`;
    if (!homePages.has(home)) {
      homePages.set(
        home,
        observe(home, "GET", true).then(
          (observation) => (observation.category === "ok" && !observation.bodyTruncated && observation.bodyLength > 0 ? observation.bodyHash : null),
          () => null,
        ),
      );
    }
    return homePages.get(home);
  }

  function retryDelay(observation, attempt) {
    const fromHeader =
      observation.status === 429 || observation.status === 503
        ? retryAfterMs(observation.retryAfter)
        : null;
    if (fromHeader !== null) {
      return fromHeader;
    }
    return http.retryBaseDelaySeconds * 1000 * 2 ** (attempt - 1);
  }

  function summarize(page, observations, notes) {
    const success = observations.at(-1)?.category === "ok" ? observations.at(-1) : null;
    const missing = observations.filter((o) => o.category === "not-found" || o.category === "gone");
    let outcome;
    let category;
    if (success) {
      outcome = "healthy";
      category = observations.length > 1 ? "recovered" : "ok";
    } else if (observations.length === 0) {
      outcome = "unassessed";
      category = "deadline";
    } else if (missing.length >= 2 && missing.length === observations.length) {
      outcome = "broken";
      category = observations.at(-1).category;
    } else if (missing.length > 0) {
      outcome = "unverified";
      category = "unconfirmed-not-found";
    } else {
      outcome = "unverified";
      category = observations.at(-1).category;
    }
    return {
      key: page.key,
      outcome,
      category,
      status: observations.at(-1)?.status ?? null,
      finalUrl: observations.at(-1)?.finalUrl || null,
      cache: "miss",
      observations: observations.map(({ ids, requests, ...rest }) => ({
        ...rest,
        requests: requests.length,
      })),
      requests: observations.flatMap((o) => o.requests),
      notes,
      success,
    };
  }

  async function assess(page) {
    const wantBody = page.fragments.size > 0 && [...page.fragments].some((f) => f !== "");
    const cached = fresh ? null : cacheEntries.get(page.key);
    if (cached && (!wantBody || cached.fragmentEvidence !== "none")) {
      return {
        key: page.key,
        outcome: "healthy",
        category: "ok",
        status: cached.status,
        finalUrl: cached.finalUrl || null,
        cache: "hit",
        checkedAt: cached.checkedAt,
        observations: [{ method: cached.method, status: cached.status, category: "ok", cachedAt: cached.checkedAt }],
        requests: [],
        notes: [`success cached at ${cached.checkedAt}`],
        success: {
          fragmentEvidence: cached.fragmentEvidence,
          ids: new Set(cached.ids || []),
        },
      };
    }
    const started = performance.now();
    const observations = [];
    const notes = [];
    let method = wantBody ? "GET" : "HEAD";
    while (observations.length < http.maxObservations) {
      const host = new URL(page.key).host;
      if (exhaustedHosts.has(host)) {
        // Respect the host's request to back off instead of sending more requests.
        notes.push(exhaustedHosts.get(host));
        if (observations.length === 0) {
          observations.push({ method: "GET", category: "rate-limited", error: "not requested", requests: [] });
        }
        break;
      }
      let observation;
      try {
        observation = await observe(page.key, method, wantBody);
        if (method === "HEAD" && observation.category !== "ok") {
          // HEAD rejections are common; only a GET response is evidence.
          const head = observation;
          observation = await observe(page.key, "GET", wantBody);
          observation.requests = [...head.requests, ...observation.requests];
          observation.headStatus = head.status ?? head.category;
        }
      } catch (error) {
        if (!(error instanceof DeadlineError)) throw error;
        notes.push("run deadline reached before this observation could start");
        break;
      }
      method = "GET";
      if (observation.category === "deadline") {
        notes.push("run deadline interrupted an observation");
        break;
      }
      if (
        observation.category === "not-found" &&
        !observation.bodyTruncated && observation.bodyLength > 0 &&
        observation.bodyHash &&
        new URL(observation.finalUrl || page.key).pathname !== "/" &&
        observation.bodyHash === (await homePageHash(observation.finalUrl || page.key))
      ) {
        observation.category = "app-shell-404";
        observation.error = "the response body is identical to the site's home page, so the status does not show whether this route exists";
      }
      observations.push(observation);
      const { category } = observation;
      if (category === "ok") break;
      const missing = category === "not-found" || category === "gone";
      const allMissing = observations.every((o) => o.category === "not-found" || o.category === "gone");
      if (missing && !allMissing) break;
      if (missing && observations.length >= 2) break;
      if (!missing && !RETRYABLE.has(category)) break;
      if (observations.length >= http.maxObservations) break;
      const delay = missing
        ? http.retryBaseDelaySeconds * 1000
        : retryDelay(observation, observations.length);
      if (delay > http.maxRetryDelaySeconds * 1000) {
        notes.push(`retry skipped: requested delay ${Math.round(delay / 1000)}s exceeds the ${http.maxRetryDelaySeconds}s limit`);
        break;
      }
      if (Date.now() + delay >= deadlineAt) {
        notes.push(`retry skipped: a ${Math.round(delay / 1000)}s delay would pass the run deadline`);
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
    const summary = summarize(page, observations, notes);
    summary.durationMs = Math.round(performance.now() - started);
    if (summary.outcome !== "healthy") {
      const stats = hostStats(new URL(summary.finalUrl || page.key).host);
      stats.failures[summary.category] = (stats.failures[summary.category] || 0) + 1;
    } else {
      const { success } = summary;
      freshSuccesses.set(page.key, {
        checkedAt: new Date().toISOString(),
        method: success.method,
        status: success.status,
        finalUrl: success.finalUrl,
        fragmentEvidence: success.fragmentEvidence,
        ...(success.fragmentEvidence === "ids" ? { ids: [...success.ids] } : {}),
      });
    }
    return summary;
  }

  const results = new Map();
  let completed = 0;
  try {
    await Promise.all(
      pages.map(async (page) => {
        const outcome = await assess(page);
        const fragments = {};
        for (const fragment of page.fragments) {
          fragments[fragment] =
            outcome.outcome === "healthy"
              ? fragmentResult(fragment, outcome.success.fragmentEvidence, outcome.success.ids)
              : null;
        }
        delete outcome.success;
        outcome.fragments = fragments;
        results.set(page.key, outcome);
        completed += 1;
        onProgress(completed, pages.length);
      }),
    );
  } finally {
    clearTimeout(deadlineTimer);
    scheduler.cancelPending(new DeadlineError());
  }
  return {
    results,
    freshSuccesses,
    stats: {
      requests: requestCount,
      peakActive: scheduler.peakActive,
      peakPerHost: scheduler.peakPerHost,
      perHost: Object.fromEntries([...perHost].sort(([a], [b]) => a.localeCompare(b))),
    },
  };
}

module.exports = {
  Scheduler,
  cacheFingerprint,
  categoryForStatus,
  checkPages,
  htmlIds,
  loadCache,
  pageKey,
  retryAfterMs,
  saveCache,
};
