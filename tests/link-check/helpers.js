const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");

const repoRoot = path.resolve(__dirname, "../..");
const checker = path.join(repoRoot, "scripts", "Check_Markdown_Links.js");
const python =
  process.env.LINK_CHECK_PYTHON || (process.platform === "win32" ? "python" : "python3");

const TEST_CONFIG = {
  schemaVersion: 1,
  budgetSeconds: 60,
  cacheTtlHours: 24,
  http: {
    concurrency: 8,
    perHostConcurrency: 2,
    requestTimeoutSeconds: 1,
    maxObservations: 3,
    retryBaseDelaySeconds: 0.01,
    maxRetryDelaySeconds: 5,
    maxRedirects: 5,
    maxBodyBytes: 4096,
    userAgent: "link-check-test",
  },
};

// A local HTTP server whose routes return scripted responses. Every request
// is recorded with its method, path, Host header, and start time.
async function startServer(t, routes) {
  const requests = [];
  const active = new Map();
  const peakByHost = new Map();
  const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, "http://fixture");
    const host = request.headers.host;
    const record = { method: request.method, path: url.pathname, host, at: Date.now() };
    requests.push(record);
    active.set(host, (active.get(host) || 0) + 1);
    peakByHost.set(host, Math.max(peakByHost.get(host) || 0, active.get(host)));
    response.on("close", () => active.set(host, active.get(host) - 1));
    const route = routes[url.pathname];
    if (!route) {
      response.writeHead(404, { "content-type": "text/html" }).end("<p>missing</p>");
      return;
    }
    const count = requests.filter((r) => r.path === url.pathname && r.method === request.method).length;
    const reply = await route({ method: request.method, count, url, host });
    if (reply.delayMs) {
      await new Promise((resolve) => setTimeout(resolve, reply.delayMs));
    }
    if (response.destroyed) return;
    const headers = { "content-type": "text/html; charset=utf-8", ...(reply.headers || {}) };
    response.writeHead(reply.status, headers);
    response.end(request.method === "HEAD" ? undefined : reply.body ?? "<html><body>ok</body></html>");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => {
    server.closeAllConnections();
    return new Promise((resolve) => server.close(resolve));
  });
  const { port } = server.address();
  return {
    port,
    url: (pathname, host = "127.0.0.1") => `http://${host}:${port}${pathname}`,
    requests,
    peakByHost,
    count: (pathname, method) =>
      requests.filter((r) => r.path === pathname && (!method || r.method === method)).length,
  };
}

function git(cwd, ...args) {
  const result = spawnSync("git", args, { cwd, encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} failed: ${result.stderr}`);
  }
  return result.stdout.trim();
}

function writeFiles(root, files) {
  for (const [file, contents] of Object.entries(files)) {
    const target = path.join(root, file);
    if (contents === null) {
      fs.rmSync(target, { force: true });
      continue;
    }
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, typeof contents === "string" ? contents : JSON.stringify(contents, null, 2));
  }
}

// Creates a temporary repository with checker inputs and the given content.
function makeRepo(t, files, { config = TEST_CONFIG, exceptions = [] } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "link-check-repo-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  git(root, "init", "-q", "-b", "master");
  git(root, "config", "user.email", "test@example.invalid");
  git(root, "config", "user.name", "Link Check Test");
  git(root, "config", "commit.gpgsign", "false");
  writeFiles(root, {
    "link-check-config.json": config,
    "link-check-exceptions.json": { schemaVersion: 1, exceptions },
    "link-check-known-failures.json": { schemaVersion: 2, batches: [] },
    ".gitignore": ".link-check/\n.link-check-cache/\n",
    ...files,
  });
  return root;
}

function commit(root, message = "commit") {
  git(root, "add", "-A");
  git(root, "commit", "-q", "-m", message);
  return git(root, "rev-parse", "HEAD");
}

// Runs the checker asynchronously so in-process fixture servers keep serving.
async function runChecker(root, args = [], env = {}) {
  const child = spawn(process.execPath, [checker, ...args], {
    cwd: root,
    env: { ...process.env, LINK_CHECK_ROOT: root, LINK_CHECK_PYTHON: python, ...env },
  });
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => (stdout += chunk));
  child.stderr.on("data", (chunk) => (stderr += chunk));
  const status = await new Promise((resolve) => child.on("close", resolve));
  const result = { status, stdout, stderr };
  let results = null;
  try {
    results = JSON.parse(fs.readFileSync(path.join(root, ".link-check", "results.json"), "utf8"));
  } catch {
    // Left null so tests can assert on the missing file.
  }
  return { ...result, results };
}

function finding(results, predicate) {
  return results.findings.find(predicate);
}

module.exports = {
  TEST_CONFIG,
  commit,
  finding,
  git,
  makeRepo,
  python,
  repoRoot,
  runChecker,
  startServer,
  writeFiles,
};
