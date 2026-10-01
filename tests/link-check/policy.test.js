const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const policy = require("../../scripts/link_check/policy");

test("review dates are real completed dates and expiry is inclusive", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "exception-dates-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, "exceptions.json");
  const exception = { file: "cheatsheets/A.md", url: "B.md", category: "missing-file", reason: "Reviewed historical reference", reviewedOn: "2026-10-01", expiresOn: "2026-10-02", reference: "https://example.org/review" };
  fs.writeFileSync(file, JSON.stringify({ schemaVersion: 1, exceptions: [exception] }));
  const pair = "cheatsheets/A.md\0B.md";
  const apply = (today) => {
    const findings = [{ file: exception.file, url: exception.url, category: exception.category, outcome: "broken", new: false }];
    return policy.applyExceptions({ exceptions: policy.loadExceptions(file, today), findings, assessedPairs: new Set([pair]), presentPairs: new Set([pair]), today });
  };
  assert.equal(apply("2026-10-01")[0].state, "applied");
  assert.equal(apply("2026-10-02")[0].state, "applied");
  assert.equal(apply("2026-10-03")[0].state, "expired");
  assert.throws(() => apply("2026-09-30"), /future/);
  for (const date of ["tomorrow", "2026-02-30", "2026-99-99", "2026-1-1"]) assert.throws(() => apply(date), /YYYY-MM-DD/);
});
