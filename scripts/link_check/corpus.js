// Reads repository snapshots, extracts links with the site's Markdown renderer,
// and resolves links to pages and files of the published site.
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const SITE_ORIGIN = "https://cheatsheetseries.owasp.org";
// Redirect aliases emitted on both supported platforms by the site build.
const SITE_ALIASES = new Map([
  ["Authorization_Testing_Automation", "Authorization_Testing_Automation_Cheat_Sheet"],
  ["Drone_security_sheet", "Drone_Security_Cheat_Sheet"],
  ["Injection_Prevention_Cheat_Sheet_in_Java", "Injection_Prevention_in_Java_Cheat_Sheet"],
  ["Ruby_on_Rails_Cheatsheet", "Ruby_on_Rails_Cheat_Sheet"],
  ["Nodejs_security_cheat_sheet", "Nodejs_Security_Cheat_Sheet"],
  ["Application_Logging_Vocabulary_Cheat_Sheet", "Logging_Vocabulary_Cheat_Sheet"],
  ["AJAX_Security_Cheat_Sheet", "Web_Frontend_Security_Cheat_Sheet"],
].map(([alias, target]) => [`cheatsheets/${alias}.html`, `cheatsheets/${target}.md`]));
// The JSON token redirects differ between platforms and the Linux target is
// not a published source. Check these URLs externally rather than inventing a target.
const EXTERNAL_SITE_ALIASES = new Set([
  "cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
  "cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html",
]);
// Mirrors scripts/Generate_Site_mkDocs.sh: site (docs_dir) path -> source path.
const INDEX_PAGES = new Map([
  ["index.md", "Preface.md"],
  ["Glossary.md", "Index.md"],
  ["IndexASVS.md", "IndexASVS.md"],
  ["IndexMASVS.md", "IndexMASVS.md"],
  ["IndexProactiveControls.md", "IndexProactiveControls.md"],
  ["IndexTopTen.md", "IndexTopTen.md"],
]);
// Files the site build generates at the site root rather than copying.
const GENERATED_SITE_FILES = new Set(["News.xml", "bundle.zip"]);
const EXTRACTOR = path.join(__dirname, "extract_links.py");

function git(root, args, input) {
  const result = spawnSync("git", args, {
    cwd: root,
    input,
    maxBuffer: 512 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    const detail = result.error?.message || result.stderr.toString().trim();
    throw new Error(`git ${args[0]} failed: ${detail}`);
  }
  return result.stdout;
}

function resolveBase(root, ref) {
  if (typeof ref !== "string" || ref.length === 0 || ref.startsWith("-")) {
    throw new Error(`invalid base ref: ${JSON.stringify(ref)}`);
  }
  const sha = git(root, [
    "rev-parse",
    "--verify",
    "--quiet",
    "--end-of-options",
    `${ref}^{commit}`,
  ])
    .toString()
    .trim();
  const mergeBase = git(root, ["merge-base", sha, "HEAD"]).toString().trim();
  if (!/^[0-9a-f]{40,64}$/.test(mergeBase)) {
    throw new Error(`cannot determine the merge base of ${ref} and HEAD`);
  }
  return { ref, sha, mergeBase };
}

function readGitBlobs(root, commit, files) {
  if (files.length === 0) {
    return new Map();
  }
  const output = git(
    root,
    ["cat-file", "--batch"],
    files.map((file) => `${commit}:${file}\n`).join(""),
  );
  const contents = new Map();
  let offset = 0;
  for (const file of files) {
    const headerEnd = output.indexOf(0x0a, offset);
    const header = output.subarray(offset, headerEnd).toString();
    const size = Number(header.split(" ")[2]);
    if (!/ blob \d+$/.test(header) || !Number.isSafeInteger(size)) {
      throw new Error(`cannot read ${file} at ${commit}: ${header}`);
    }
    const start = headerEnd + 1;
    contents.set(file, output.subarray(start, start + size).toString("utf8"));
    offset = start + size + 1;
  }
  return contents;
}

// A snapshot exposes the published Markdown sources and the set of site files.
function sitePagesFor(sourceFiles) {
  const pages = new Map();
  for (const file of sourceFiles) {
    if (file.startsWith("cheatsheets/") && file.endsWith(".md")) {
      pages.set(file, file);
    }
  }
  for (const [docsPath, source] of INDEX_PAGES) {
    if (sourceFiles.has(source)) {
      pages.set(docsPath, source);
    }
  }
  return pages;
}

function prepareText(source, text) {
  // The site build renames Index.md and rewrites its links with
  // sed 's/Index.md/Glossary.md/g'; apply the same textual rewrite.
  return source === "Index.md"
    ? text.replace(/Index.md/g, "Glossary.md")
    : text;
}

function workingTreeSnapshot(root) {
  const sourceFiles = new Set();
  const visit = (relative) => {
    const absolute = path.join(root, relative);
    if (!fs.existsSync(absolute)) {
      return;
    }
    for (const entry of fs.readdirSync(absolute, { withFileTypes: true })) {
      const child = relative ? `${relative}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        visit(child);
      } else if (entry.isFile()) {
        sourceFiles.add(child);
      }
    }
  };
  visit("cheatsheets");
  visit("assets");
  for (const source of INDEX_PAGES.values()) {
    if (fs.existsSync(path.join(root, source))) {
      sourceFiles.add(source);
    }
  }
  const pages = sitePagesFor(sourceFiles);
  const texts = new Map();
  for (const source of pages.values()) {
    texts.set(
      source,
      prepareText(source, fs.readFileSync(path.join(root, source), "utf8")),
    );
  }
  return { label: "working tree", sourceFiles, pages, texts };
}

function gitSnapshot(root, commit) {
  const listed = git(root, ["ls-tree", "-r", "-z", "--name-only", commit, "--"])
    .toString()
    .split("\0")
    .filter(Boolean);
  const sourceFiles = new Set(
    listed.filter(
      (file) =>
        file.startsWith("cheatsheets/") ||
        file.startsWith("assets/") ||
        [...INDEX_PAGES.values()].includes(file),
    ),
  );
  const pages = sitePagesFor(sourceFiles);
  const blobs = readGitBlobs(root, commit, [...pages.values()]);
  const texts = new Map();
  for (const [source, text] of blobs) {
    texts.set(source, prepareText(source, text));
  }
  return { label: commit, sourceFiles, pages, texts };
}

// Renders every distinct text once and attaches links/IDs to each snapshot.
function extractSnapshots(snapshots, python) {
  const byHash = new Map();
  for (const snapshot of snapshots) {
    for (const text of snapshot.texts.values()) {
      const hash = crypto.createHash("sha256").update(text).digest("hex");
      byHash.set(hash, text);
    }
  }
  const request = JSON.stringify({
    documents: [...byHash].map(([key, text]) => ({ key, text })),
  });
  const result = spawnSync(python, [EXTRACTOR], {
    input: request,
    encoding: "utf8",
    maxBuffer: 512 * 1024 * 1024,
  });
  if (result.error) {
    throw new Error(
      `cannot run the Markdown extractor with ${python} (${result.error.message}); install Python 3 or set LINK_CHECK_PYTHON`,
    );
  }
  if (result.status !== 0) {
    throw new Error(
      `Markdown extractor exited with status ${result.status}: ${result.stderr.trim()}`,
    );
  }
  let parsed;
  try {
    parsed = JSON.parse(result.stdout);
  } catch (error) {
    throw new Error(`Markdown extractor returned invalid JSON: ${error.message}`);
  }
  const extracted = new Map();
  for (const document of parsed.documents || []) {
    extracted.set(document.key, document);
  }
  if (extracted.size !== byHash.size) {
    throw new Error(
      `Markdown extractor returned ${extracted.size} of ${byHash.size} documents`,
    );
  }
  for (const snapshot of snapshots) {
    snapshot.documents = new Map();
    snapshot.idsByDocsPath = new Map();
    for (const [docsPath, source] of snapshot.pages) {
      const hash = crypto
        .createHash("sha256")
        .update(snapshot.texts.get(source))
        .digest("hex");
      const document = extracted.get(hash);
      snapshot.documents.set(source, { docsPath, links: document.links });
      snapshot.idsByDocsPath.set(docsPath, new Set(document.ids));
    }
  }
  return parsed.renderer;
}

function pageUrl(docsPath) {
  return `${SITE_ORIGIN}/${docsPath.replace(/\.md$/, ".html")}`;
}

function decode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

function result(outcome, category, detail, extra = {}) {
  return { outcome, category, detail, ...extra };
}

// Classifies one href from a published page. External links are returned for
// the HTTP checker; everything else is resolved against the snapshot.
function resolveLink(snapshot, docsPath, href) {
  const relative = !/^[a-z][a-z0-9+.-]*:/i.test(href) && !href.startsWith("//");
  let url;
  try {
    url = new URL(href, pageUrl(docsPath));
  } catch (error) {
    return {
      scope: "local",
      ...result("broken", "malformed-url", error.message),
    };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return {
      scope: "other",
      ...result(
        "unverified",
        "unsupported-scheme",
        `${url.protocol} links are not checked automatically`,
      ),
    };
  }
  if (url.origin !== SITE_ORIGIN || url.username || url.password) {
    return { scope: "external", absoluteUrl: url.href };
  }

  const segments = url.pathname.split("/").slice(1).map(decode);
  const fragment = url.hash ? decode(url.hash.slice(1)) : "";
  if (segments.includes(null) || fragment === null) {
    return {
      scope: "local",
      ...result("broken", "malformed-url", "malformed percent-encoding"),
    };
  }
  let target = segments.join("/");
  if (EXTERNAL_SITE_ALIASES.has(target)) return { scope: "external", absoluteUrl: url.href };
  target = SITE_ALIASES.get(target) || target;
  if (target === "" || target === "index.html") {
    target = "index.md";
  } else if (target.endsWith(".html")) {
    const page = target.replace(/\.html$/, ".md");
    if (snapshot.pages.has(page)) {
      target = page;
    }
  } else if (target.endsWith(".md") && !relative) {
    // MkDocs rewrites only relative .md links; the site does not publish .md files.
    return {
      scope: "local",
      ...result("broken", "missing-file", `the site does not publish ${target}`),
    };
  }

  const local = { scope: "local", target };
  if (snapshot.pages.has(target)) {
    if (!fragment) {
      return { ...local, ...result("healthy", "ok", "page exists") };
    }
    if (snapshot.idsByDocsPath.get(target).has(fragment)) {
      return { ...local, ...result("healthy", "ok", "anchor exists") };
    }
    return {
      ...local,
      ...result("broken", "missing-anchor", `#${fragment} is not an ID in ${snapshot.pages.get(target)}`),
    };
  }
  const exists =
    GENERATED_SITE_FILES.has(target) ||
    (target.startsWith("assets/") && snapshot.sourceFiles.has(target));
  if (!exists) {
    return {
      ...local,
      ...result("broken", "missing-file", `${target} is not part of the published site`),
    };
  }
  if (fragment) {
    return {
      ...local,
      ...result(
        "unverified",
        "unsupported-fragment",
        `fragments in ${target} are not checked automatically`,
      ),
    };
  }
  return { ...local, ...result("healthy", "ok", "file exists") };
}

// Returns every link occurrence of the snapshot's published pages.
function occurrencesOf(snapshot) {
  const occurrences = [];
  for (const [source, document] of [...snapshot.documents].sort(([a], [b]) =>
    a.localeCompare(b),
  )) {
    for (const link of document.links) {
      occurrences.push({
        file: source,
        url: link.url,
        line: link.line,
        ordinal: link.ordinal,
        kind: link.kind,
        ...resolveLink(snapshot, document.docsPath, link.url),
      });
    }
  }
  return occurrences;
}

module.exports = {
  EXTERNAL_SITE_ALIASES,
  SITE_ALIASES,
  GENERATED_SITE_FILES,
  INDEX_PAGES,
  extractSnapshots,
  gitSnapshot,
  occurrencesOf,
  resolveBase,
  resolveLink,
  workingTreeSnapshot,
};
