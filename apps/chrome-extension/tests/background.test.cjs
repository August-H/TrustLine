const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

function worker(responses) {
  const calls = [];
  const storage = {};
  const tab = { id: 1, url: "https://ordinary.example/" };
  const noop = () => {};
  const context = vm.createContext({
    URL, AbortController, console,
    setTimeout: (fn, delay) => { if (delay <= 1000) queueMicrotask(fn); return 1; },
    clearTimeout: noop,
    fetch: async (url, options) => {
      calls.push({ url, options });
      const next = responses.shift();
      if (next instanceof Error) throw next;
      assert.ok(next, `Unexpected request: ${url}`);
      return { ok: true, json: async () => structuredClone(next) };
    },
    OffscreenCanvas: class {
      getContext() { return { scale: noop, fill: noop, getImageData: () => ({}) }; }
    },
    Path2D: class {},
    chrome: {
      runtime: { onInstalled: { addListener: noop }, onStartup: { addListener: noop },
        onMessage: { addListener: noop }, getURL: (file) => `chrome-extension://${"a".repeat(32)}/${file}` },
      tabs: { onUpdated: { addListener: noop }, onRemoved: { addListener: noop },
        get: async () => tab, update: async (_, patch) => Object.assign(tab, patch) },
      storage: {
        session: { get: async () => storage, set: async (data) => Object.assign(storage, data),
          remove: async (keys) => { for (const key of [].concat(keys)) delete storage[key]; } },
        local: { get: async () => ({ settings: { autoScan: true, blockDangerous: true } }) },
      },
      action: { setIcon: noop, setBadgeText: noop, setBadgeBackgroundColor: noop, setTitle: noop },
    },
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../background.js"), "utf8"), context);
  return { calls, context, storage, tab,
    analyze: (mode) => vm.runInContext(`analyzeUrl('https://ordinary.example/', '${mode}')`, context) };
}

test("verified database score stays 100 without a cloud request", async () => {
  const w = worker([{ verdict: "safe", score: 100, verified: true, score_source: "verified_database" }]);
  const result = await w.analyze("deep");
  assert.equal(result.score, 100);
  assert.equal(result.verified, true);
  assert.equal(w.calls.length, 1);
});

test("deep scan posts deep mode and polls the real job without replacing Jev score", async () => {
  const w = worker([
    { verdict: "suspicious", score: 73, jev_probability: 0.27, score_source: "jev",
      review: { token: "test-token", status: "pending" } },
    { status: "pending", reason: "Reviewing" },
    { status: "allow", reason: "Cloud review completed", evidence: ["Rendered page inspected"] },
  ]);
  const result = await w.analyze("deep");
  assert.equal(JSON.parse(w.calls[0].options.body).mode, "deep");
  assert.equal(w.calls[1].url, "http://127.0.0.1:8765/v1/reviews/test-token");
  assert.equal(result.review.status, "allow");
  assert.equal(result.score, 73);
  assert.equal(result.verdict, "safe");
  assert.equal(result.reasons[0], "Cloud review completed");
});

test("a cloud block overrides the verdict while preserving the URL score", async () => {
  const w = worker([{ verdict: "safe", score: 92,
    review: { status: "block", reason: "Observed a scam", evidence: [] } }]);
  const result = await w.analyze("deep");
  assert.equal(result.verdict, "dangerous");
  assert.equal(result.score, 92);
});

test("an inconclusive cloud review never becomes a safe verdict", async () => {
  const w = worker([{ verdict: "safe", score: 99,
    review: { status: "inconclusive", reason: "Cloud credentials missing", evidence: [] } }]);
  const result = await w.analyze("deep");
  assert.equal(result.verdict, "suspicious");
  assert.equal(result.review.reason, "Cloud credentials missing");
});

test("daemon failures do not generate heuristic scores or simulated deep results", async () => {
  const quick = worker([new Error("Offline")]);
  assert.equal((await quick.analyze("quick")).score, null);
  const deep = worker([new Error("Offline")]);
  await assert.rejects(deep.analyze("deep"), /Cloud review unavailable/);
  assert.equal(deep.calls.length, 1);
});

test("null and missing Jev scores stay unavailable rather than turning into zero or a default", async () => {
  for (const score of [null, undefined]) {
    const w = worker([{ verdict: "suspicious", score }]);
    assert.equal((await w.analyze("quick")).score, null);
  }
});

test("a background cloud job stores its result without an open popup", async () => {
  const w = worker([
    { score: 73, verdict: "suspicious", review: { token: "job", status: "pending" } },
    { status: "allow", reason: "Reviewed remotely", evidence: [] },
  ]);
  await vm.runInContext("scanTab(1, 'https://ordinary.example/', 'deep')", w.context);
  assert.equal(w.storage["result:1"].review.status, "allow");
  assert.equal(w.storage["result:1"].score, 73);
  assert.equal(w.storage["scan:1"], undefined);
});

test("cloud block redirects the tab to a warning with the actual target and Jev score", async () => {
  const w = worker([{ target_url: "https://original.example/", score: 92, verdict: "safe",
    review: { status: "block", reason: "Remote scam evidence", evidence: [] } }]);
  await vm.runInContext("scanTab(1, 'https://ordinary.example/', 'deep')", w.context);
  const destination = new URL(w.tab.url);
  assert.equal(destination.pathname, "/warning.html");
  assert.equal(destination.searchParams.get("url"), "https://original.example/");
  assert.equal(destination.searchParams.get("score"), "92");
  assert.equal(destination.searchParams.get("verdict"), "dangerous");
});

test("a Jev-flagged quick scan redirects the tab to the suspicious warning page", async () => {
  const w = worker([{ verdict: "dangerous", score: 5, jev_probability: 0.95, jev_status: "suspicious",
    score_source: "jev", reasons: ["Lookalike hostname"] }]);
  await vm.runInContext("scanTab(1, 'https://ordinary.example/', 'quick')", w.context);
  const destination = new URL(w.tab.url);
  assert.equal(destination.pathname, "/warning.html");
  assert.equal(destination.searchParams.get("verdict"), "suspicious");
  assert.equal(destination.searchParams.get("url"), "https://ordinary.example/");
  assert.equal(destination.searchParams.get("score"), "5");
});

test("an uncertain Jev result does not redirect", async () => {
  const w = worker([{ verdict: "suspicious", score: 50, jev_probability: 0.5, jev_status: "uncertain",
    score_source: "jev" }]);
  await vm.runInContext("scanTab(1, 'https://ordinary.example/', 'quick')", w.context);
  assert.equal(w.tab.url, "https://ordinary.example/");
});

test("a cloud approval overrides a Jev flag", async () => {
  const w = worker([{ verdict: "safe", score: 5, jev_probability: 0.95, jev_status: "suspicious",
    score_source: "jev", review: { status: "allow", reason: "Reviewed remotely", evidence: [] } }]);
  await vm.runInContext("scanTab(1, 'https://ordinary.example/', 'quick')", w.context);
  assert.equal(w.tab.url, "https://ordinary.example/");
});

test("a Jev flag never redirects away from the proxy checking page", async () => {
  const w = worker([{ target_url: "https://original.example/", verdict: "dangerous", score: 5,
    jev_probability: 0.95, jev_status: "suspicious", score_source: "jev" }]);
  w.tab.url = "https://blocked.example.com/_trustline/check/existing-token";
  await vm.runInContext(`scanTab(1, '${w.tab.url}', 'quick')`, w.context);
  assert.equal(w.tab.url, "https://blocked.example.com/_trustline/check/existing-token");
});

test("a successful Deep scan releases a previously inconclusive proxy checking tab", async () => {
  const w = worker([{ target_url: "https://original.example/article", score: 97, verdict: "safe",
    review: { status: "allow", reason: "Retried cloud review succeeded", evidence: [] } }]);
  w.tab.url = "https://blocked.example.com/_trustline/check/existing-token";
  await vm.runInContext(`scanTab(1, '${w.tab.url}', 'deep')`, w.context);
  assert.equal(w.tab.url, "https://original.example/article");
});
