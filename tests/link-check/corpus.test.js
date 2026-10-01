const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const corpus = require("../../scripts/link_check/corpus");
const { makeRepo, python, repoRoot } = require("./helpers");

function snapshotOf(t, files) {
  const root = makeRepo(t, files);
  const snapshot = corpus.workingTreeSnapshot(root);
  corpus.extractSnapshots([snapshot], python);
  return snapshot;
}

function linksOf(snapshot, file) {
  return corpus.occurrencesOf(snapshot).filter((o) => o.file === file);
}

test("links come from the rendered Markdown, not from code or raw text", (t) => {
  const snapshot = snapshotOf(t, {
    "cheatsheets/A.md": [
      "# A",
      "",
      "Inline [one](https://one.example/a?x=1&amp;y=2#Frag) and <https://auto.example/>.",
      "![image](../assets/pic.png)",
      "",
      "Twice [r][ref] and [again][ref].",
      "",
      "[ref]: https://ref.example/page \"Title\"",
      "",
      "```html",
      '<a href="https://fenced.example/">no</a>',
      "```",
      "",
      "    https://indented.example/",
      "",
      "Code `[x](https://span.example/)` and :warning: emoji.",
      "",
    ].join("\n"),
    "assets/pic.png": "png",
  });
  const links = linksOf(snapshot, "cheatsheets/A.md");
  assert.deepEqual(
    links.map((link) => [link.url, link.kind, link.line]),
    [
      ["https://one.example/a?x=1&y=2#Frag", "link", 3],
      ["https://auto.example/", "link", 3],
      ["../assets/pic.png", "image", 4],
      ["https://ref.example/page", "link", 8],
      ["https://ref.example/page", "link", 8],
    ],
  );
  assert.deepEqual(links.map((link) => link.ordinal), [1, 2, 3, 4, 5]);
  assert.equal(links[2].outcome, "healthy");
});

test("local anchors follow the site's Python-Markdown heading IDs", (t) => {
  const snapshot = snapshotOf(t, {
    "cheatsheets/Target.md": [
      "# Target",
      "",
      "## Rule #1 - Use `code` **now**",
      "",
      "## Duplicate",
      "",
      "## Duplicate",
      "",
      "Setext Heading",
      "--------------",
      "",
      "## Ünïcode Café",
      "",
      "## Q&amp;A",
      "",
      '<a name="named-anchor"></a>',
      "",
    ].join("\n"),
    "cheatsheets/Source.md": [
      "# Source",
      "",
      "- [ok](Target.md#rule-1-use-code-now)",
      "- [github style](Target.md#rule-1---use-code-now)",
      "- [dup](Target.md#duplicate_1)",
      "- [setext](Target.md#setext-heading)",
      "- [unicode](Target.md#unicode-cafe)",
      "- [entity](Target.md#qa)",
      "- [named](Target.md#named-anchor)",
      "- [case](Target.md#Duplicate)",
      "- [self](#source)",
      "- [missing self](#nope)",
      "- [published](Target.html#duplicate)",
      "- [absolute](https://cheatsheetseries.owasp.org/cheatsheets/Target.html#setext-heading)",
      "- [absolute md](https://cheatsheetseries.owasp.org/cheatsheets/Target.md)",
      "- [root](/cheatsheets/Target.html?x=1#duplicate)",
      "- [query](Target.md?x=1#duplicate)",
      "- [encoded](Target.md#rule%2D1-use-code-now)",
      "- [malformed](Target.md#bad%zz)",
      "- [missing file](Missing.md)",
      "- [outside](../../../etc/passwd)",
      "- [repo file](../CONTRIBUTING.md)",
      "- [news](../News.xml)",
      "- [bundle](../bundle.zip)",
      "- [asset fragment](../assets/doc.pdf#page=2)",
      "- [mail](mailto:someone@example.org)",
      "",
    ].join("\n"),
    "assets/doc.pdf": "%PDF",
    "CONTRIBUTING.md": "# Not published\n",
  });
  const byText = new Map(linksOf(snapshot, "cheatsheets/Source.md").map((o) => [o.url, o]));
  const expect = (url, outcome, category) => {
    const occurrence = byText.get(url);
    assert.ok(occurrence, url);
    assert.equal(occurrence.outcome, outcome, url);
    if (category) assert.equal(occurrence.category, category, url);
  };
  expect("Target.md#rule-1-use-code-now", "healthy");
  expect("Target.md#rule-1---use-code-now", "broken", "missing-anchor");
  expect("Target.md#duplicate_1", "healthy");
  expect("Target.md#setext-heading", "healthy");
  expect("Target.md#unicode-cafe", "healthy");
  expect("Target.md#qa", "healthy");
  expect("Target.md#named-anchor", "healthy");
  expect("Target.md#Duplicate", "broken", "missing-anchor");
  expect("#source", "healthy");
  expect("#nope", "broken", "missing-anchor");
  expect("Target.html#duplicate", "healthy");
  expect("https://cheatsheetseries.owasp.org/cheatsheets/Target.html#setext-heading", "healthy");
  expect("https://cheatsheetseries.owasp.org/cheatsheets/Target.md", "broken", "missing-file");
  expect("/cheatsheets/Target.html?x=1#duplicate", "healthy");
  expect("Target.md?x=1#duplicate", "healthy");
  expect("Target.md#rule%2D1-use-code-now", "healthy");
  expect("Target.md#bad%zz", "broken", "malformed-url");
  expect("Missing.md", "broken", "missing-file");
  expect("../../../etc/passwd", "broken", "missing-file");
  expect("../CONTRIBUTING.md", "broken", "missing-file");
  expect("../News.xml", "healthy");
  expect("../bundle.zip", "healthy");
  expect("../assets/doc.pdf#page=2", "unverified", "unsupported-fragment");
  expect("mailto:someone@example.org", "unverified", "unsupported-scheme");
  assert.equal(byText.get("https://cheatsheetseries.owasp.org/cheatsheets/Target.html#setext-heading").scope, "local");
});

test("index pages map to their published names", (t) => {
  const snapshot = snapshotOf(t, {
    "cheatsheets/A.md": "# A\n\n## Part\n\n[glossary](../Glossary.html#b) [old index](../Index.md#b) [home](../index.html)\n",
    "Index.md": "# Index\n\n## B\n\n[self](Index.md#b) [sheet](cheatsheets/A.md#part)\n",
    "Preface.md": "# Preface\n\n![logo](assets/logo.png) [zip](bundle.zip) [glossary](Glossary.md)\n",
    "assets/logo.png": "png",
  });
  const sheet = new Map(linksOf(snapshot, "cheatsheets/A.md").map((o) => [o.url, o]));
  assert.equal(sheet.get("../Glossary.html#b").outcome, "healthy");
  assert.equal(sheet.get("../Index.md#b").category, "missing-file", "the site publishes Index.md as Glossary");
  assert.equal(sheet.get("../index.html").outcome, "healthy");
  // The build rewrites Index.md links inside the glossary itself.
  const glossary = linksOf(snapshot, "Index.md");
  assert.deepEqual(glossary.map((o) => [o.url, o.outcome]), [
    ["Glossary.md#b", "healthy"],
    ["cheatsheets/A.md#part", "healthy"],
  ]);
  assert.ok(linksOf(snapshot, "Preface.md").every((o) => o.outcome === "healthy"));
});

test("a missing renderer is an error, never an empty extraction", (t) => {
  const root = makeRepo(t, { "cheatsheets/A.md": "# A\n" });
  const snapshot = corpus.workingTreeSnapshot(root);
  assert.throws(
    () => corpus.extractSnapshots([snapshot], path.join(root, "no-such-python")),
    /cannot run the Markdown extractor/,
  );
  const result = spawnSync(python, ["-c", "import sys; sys.exit(0)"]);
  assert.equal(result.status, 0, "the configured Python interpreter runs");
});

test("the renderer mirrors mkdocs.yml and its pins match requirements.txt", () => {
  const extractor = fs.readFileSync(path.join(repoRoot, "scripts/link_check/extract_links.py"), "utf8");
  const mkdocs = fs.readFileSync(path.join(repoRoot, "mkdocs.yml"), "utf8");
  const configured = mkdocs
    .split(/^markdown_extensions:$/m)[1]
    .split("\n")
    .map((line) => line.match(/^ {2}- ([\w.]+)/)?.[1])
    .filter(Boolean);
  const used = [...extractor.split("EXTENSIONS = [")[1].split("]")[0].matchAll(/"([\w.]+)"/g)].map((m) => m[1]);
  assert.deepEqual(used.slice(3), configured.filter((name) => name !== "toc"));
  assert.match(mkdocs, /- toc:\n\s+permalink: true/);
  assert.match(extractor, /"toc": \{"permalink": True\}/);
  assert.match(mkdocs, /emoji_index: !!python\/name:pymdownx\.emoji\.twemoji/);
  assert.match(mkdocs, /emoji_generator: !!python\/name:pymdownx\.emoji\.to_svg/);

  const pins = (file) =>
    new Map(
      fs
        .readFileSync(path.join(repoRoot, file), "utf8")
        .split("\n")
        .map((line) => line.match(/^([A-Za-z0-9_.-]+)==(\S+)/))
        .filter(Boolean)
        .map(([, name, version]) => [name.toLowerCase(), version]),
    );
  const site = pins("requirements.txt");
  for (const [name, version] of pins("scripts/link_check/requirements.txt")) {
    assert.equal(site.get(name), version, `${name} must match requirements.txt`);
  }
});

test("the site mapping mirrors Generate_Site_mkDocs.sh", () => {
  const script = fs.readFileSync(path.join(repoRoot, "scripts/Generate_Site_mkDocs.sh"), "utf8");
  const copied = new Map(
    [...script.matchAll(/^cp \.\.\/(\w+\.md) \$WORK\/cheatsheets\/(\w+\.md)$/gm)].map((m) => [m[2], m[1]]),
  );
  assert.deepEqual(new Map([...corpus.INDEX_PAGES].sort()), new Map([...copied].sort()));
  assert.match(script, /cp -r \.\.\/cheatsheets \$WORK\/cheatsheets\/cheatsheets/);
  assert.match(script, /cp -r \.\.\/assets \$WORK\/cheatsheets\/assets/);
  assert.match(script, /mv News\.xml \$WORK\/cheatsheets\/\./);
  assert.match(script, /sed -i 's\/Index\.md\/Glossary\.md\/g' \$WORK\/cheatsheets\/Glossary\.md/);
  assert.deepEqual([...corpus.GENERATED_SITE_FILES].sort(), ["News.xml", "bundle.zip"]);
});

test("only the canonical origin is local and generated aliases check canonical anchors", (t) => {
  const snapshot = snapshotOf(t, { "cheatsheets/Logging_Vocabulary_Cheat_Sheet.md": "# Logging\n\n## Overview\n" });
  const resolve = (href) => corpus.resolveLink(snapshot, "cheatsheets/Logging_Vocabulary_Cheat_Sheet.md", href);
  const base = "cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html#overview";
  assert.equal(resolve(`https://${base}`).outcome, "healthy");
  for (const href of [`http://${base}`, `https://user:pass@${base}`, `https://${base.replace('.org/', '.org:444/')}`]) {
    assert.equal(resolve(href).scope, "external", href);
  }
  for (const href of ["Application_Logging_Vocabulary_Cheat_Sheet.html", "Application_Logging_Vocabulary_Cheat_Sheet.html#overview"]) {
    const result = resolve(href);
    assert.equal(result.outcome, "healthy");
    assert.equal(result.target, "cheatsheets/Logging_Vocabulary_Cheat_Sheet.md");
  }
  assert.equal(resolve("Application_Logging_Vocabulary_Cheat_Sheet.html#absent").category, "missing-anchor");
  for (const alias of corpus.EXTERNAL_SITE_ALIASES) assert.equal(resolve(`/${alias}`).scope, "external");
});

test("alias mapping covers every generated redirect and records platform divergence", () => {
  const script = fs.readFileSync(path.join(repoRoot, "scripts/Generate_Site_mkDocs.sh"), "utf8");
  const redirects = new Map();
  for (const line of script.split("\n")) {
    const match = line.match(/redirect_from:.*?(\/cheatsheets\/[^\\"\s]+\.html).*?\$GENERATED_SITE\/([^"\s]+\.html)/);
    if (match) {
      const alias = match[1].slice(1);
      if (!redirects.has(alias)) redirects.set(alias, new Set());
      redirects.get(alias).add(match[2].replace(/\.html$/, ".md"));
    }
  }
  // macOS multi-line declarations are paired with their following target.
  const mac = [...script.matchAll(/redirect_from:.*?(\/cheatsheets\/[^\\"\s]+\.html)[\s\S]*?\$GENERATED_SITE\/([^"\s]+\.html)/g)];
  for (const [, aliasPath, target] of mac) {
    const alias = aliasPath.slice(1);
    if (!redirects.has(alias)) redirects.set(alias, new Set());
    redirects.get(alias).add(target.replace(/\.html$/, ".md"));
  }
  assert.deepEqual([...redirects.keys()].sort(), [...corpus.SITE_ALIASES.keys(), ...corpus.EXTERNAL_SITE_ALIASES].sort());
  for (const [alias, target] of corpus.SITE_ALIASES) assert.deepEqual([...redirects.get(alias)], [target]);
  assert.equal(redirects.get("cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html").size, 2);
});
