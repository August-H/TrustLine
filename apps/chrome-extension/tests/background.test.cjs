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
  const listeners = {};
  const injected = [];
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
      tabs: { onUpdated: { addListener: (fn) => { listeners.updated = fn; } }, onRemoved: { addListener: noop },
        get: async () => tab, update: async (_, patch) => Object.assign(tab, patch) },
      storage: {
        session: { get: async () => storage, set: async (data) => Object.assign(storage, data),
          remove: async (keys) => { for (const key of [].concat(keys)) delete storage[key]; } },
        local: { get: async () => ({ settings: { autoScan: true, blockDangerous: true } }) },
      },
      action: { setIcon: noop, setBadgeText: noop, setBadgeBackgroundColor: noop, setTitle: noop },
      scripting: { executeScript: async (details) => { injected.push(details); return []; } },
    },
  });
  context.importScripts = (...files) => {
    for (const file of files) vm.runInContext(fs.readFileSync(path.join(__dirname, "..", file), "utf8"), context);
  };
  vm.runInContext(fs.readFileSync(path.join(__dirname, "../background.js"), "utf8"), context);
  return { calls, context, storage, tab, listeners, injected,
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

test("a cloud block caps the score in the Dangerous zone", async () => {
  const w = worker([{ verdict: "safe", score: 92,
    review: { status: "block", reason: "Observed a scam", evidence: [] } }]);
  const result = await w.analyze("deep");
  assert.equal(result.verdict, "dangerous");
  assert.equal(result.score, 39);
});

test("a completed Deep scan uses the lower of the URL and page scores", async () => {
  for (const [score, page, expected] of [[73, 0.5, 50], [40, 0.1, 40], [null, 0.25, 75], [88, null, 88]]) {
    const w = worker([{ verdict: "suspicious", score,
      review: { token: "job", status: "pending" } },
      { status: "allow", reason: "Reviewed", evidence: [], page_probability: page }]);
    assert.equal((await w.analyze("deep")).score, expected);
  }
});

test("an inconclusive cloud review never becomes a safe verdict", async () => {
  const w = worker([{ verdict: "safe", score: 99,
    review: { status: "inconclusive", reason: "Cloud credentials missing", evidence: [] } }]);
  const result = await w.analyze("deep");
  assert.equal(result.verdict, "suspicious");
  assert.equal(result.review.reason, "Cloud credentials missing");
  assert.equal(result.score, null);
  assert.equal(result.assessment, "undetermined");
});

test("daemon failures do not generate heuristic scores or simulated deep results", async () => {
  const quick = worker([new Error("Offline")]);
  assert.equal((await quick.analyze("quick")).score, null);
  const deep = worker([new Error("Offline")]);
  const result = await deep.analyze("deep");
  assert.equal(result.score, null);
  assert.equal(result.assessment, "undetermined");
  assert.equal(result.review.status, "inconclusive");
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

test("cloud block redirects the tab to a warning with the actual target and capped score", async () => {
  const w = worker([{ target_url: "https://original.example/", score: 92, verdict: "safe",
    review: { status: "block", reason: "Remote scam evidence", evidence: [] } }]);
  await vm.runInContext("scanTab(1, 'https://ordinary.example/', 'deep')", w.context);
  const destination = new URL(w.tab.url);
  assert.equal(destination.pathname, "/warning.html");
  assert.equal(destination.searchParams.get("url"), "https://original.example/");
  assert.equal(destination.searchParams.get("score"), "39");
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

function navigate(w, url = "https://ordinary.example/") {
  return vm.runInContext(`handlers.scanNavigation({ url: '${url}' }, { tab: { id: 1 } })`, w.context);
}

test("the loading screen asks for a cloud page check and waits for it", async () => {
  const w = worker([
    { verdict: "safe", score: 93, jev_probability: 0.07, jev_status: "not_flagged", score_source: "jev",
      review: { token: "nav-job", status: "pending" } },
    { status: "pending", reason: "Reviewing" },
    { status: "block", reason: "Impersonates a crypto explorer", evidence: ["Reward-voting lure"] },
  ]);
  const outcome = await navigate(w);
  assert.equal(JSON.parse(w.calls[0].options.body).mode, "navigate");
  assert.equal(w.calls[2].url, "http://127.0.0.1:8765/v1/reviews/nav-job");
  assert.equal(outcome.action, "warn");
  const warning = new URL(outcome.url);
  assert.equal(warning.searchParams.get("verdict"), "dangerous");
  assert.equal(warning.searchParams.get("score"), "39");
  assert.equal(w.storage["result:1"].review.status, "block");
});

test("a cloud approval on the loading screen lets the page open", async () => {
  const w = worker([{ verdict: "suspicious", score: 55, jev_status: "uncertain", score_source: "jev",
    review: { status: "allow", reason: "Reviewed remotely", evidence: [], page_probability: 0.2 } }]);
  const outcome = await navigate(w);
  assert.equal(outcome.action, "proceed");
  assert.equal(w.storage["result:1"].score, 55);
});

test("an inconclusive cloud check on the loading screen falls back to the address check", async () => {
  const w = worker([{ verdict: "safe", score: 90, jev_status: "not_flagged", score_source: "jev",
    reasons: ["Address looks ordinary"],
    review: { status: "inconclusive", reason: "The page could not be inspected completely.", evidence: [] } }]);
  const outcome = await navigate(w);
  assert.equal(outcome.action, "proceed");
  const result = w.storage["result:1"];
  assert.equal(result.verdict, "safe");
  assert.equal(result.score, null);
  assert.equal(result.assessment, "undetermined");
  assert.deepEqual([...result.reasons], ["The page could not be inspected completely."]);
});

test("a lost cloud job on the loading screen keeps the address verdict instead of failing", async () => {
  const w = worker([
    { verdict: "dangerous", score: 8, jev_status: "suspicious", score_source: "jev",
      review: { token: "gone", status: "pending" } },
    new Error("This cloud review is unavailable or expired"),
  ]);
  const outcome = await navigate(w);
  assert.equal(outcome.action, "warn");
  assert.equal(new URL(outcome.url).searchParams.has("score"), false);
  assert.equal(w.storage["result:1"].source, "daemon");
});

test("the hidden first check returns at once when a cloud check is still running", async () => {
  const w = worker([{ verdict: "suspicious", score: 60, jev_status: "uncertain", score_source: "jev",
    review: { token: "nav-job", status: "pending" } }]);
  const outcome = await vm.runInContext(
    "handlers.scanNavigation({ url: 'https://ordinary.example/', waitForReview: false }, { tab: { id: 1 } })", w.context);
  assert.deepEqual({ ...outcome }, { action: "review" });
  assert.equal(w.calls.length, 1);
  assert.equal(w.storage["result:1"], undefined);
});

test("a high-scoring address goes straight through on the hidden first check", async () => {
  const w = worker([{ verdict: "safe", score: 93, jev_status: "not_flagged", score_source: "jev" }]);
  const outcome = await vm.runInContext(
    "handlers.scanNavigation({ url: 'https://ordinary.example/', waitForReview: false }, { tab: { id: 1 } })", w.context);
  assert.equal(outcome.action, "proceed");
  assert.equal(outcome.url, "https://ordinary.example/");
  assert.equal(w.storage["result:1"].score, 93);
  assert.deepEqual([...w.storage.cleared], ["ordinary.example"]);
});

const UNSURE = { verdict: "safe", score: 78, jev_status: "uncertain", jev_confidence: 0.56, score_source: "jev", unsure: true,
  reasons: ["TrustLine estimates a 22.0% chance this web address is fake or misleading."] };

test("an unsure pass opens the page and shows the deep scan prompt once it loads", async () => {
  const w = worker([{ ...UNSURE }]);
  const outcome = await vm.runInContext(
    "handlers.scanNavigation({ url: 'https://ordinary.example/', waitForReview: false }, { tab: { id: 1 } })", w.context);
  assert.equal(outcome.action, "proceed");
  assert.equal(w.storage["result:1"].unsure, true);
  assert.equal(w.storage["result:1"].jevConfidence, 0.56);
  await w.listeners.updated(1, { status: "complete" }, { url: "https://www.ordinary.example/home" });
  await new Promise((r) => setImmediate(r));
  assert.equal(w.injected.length, 1);
  assert.equal(w.injected[0].target.tabId, 1);
  assert.equal(w.injected[0].func.name, "trustLineNudge");
  // Shown once: a second load of the tab does not repeat it.
  await w.listeners.updated(1, { status: "complete" }, { url: "https://ordinary.example/next" });
  await new Promise((r) => setImmediate(r));
  assert.equal(w.injected.length, 1);
});

test("the prompt is dropped if the tab ends up on a different site", async () => {
  const w = worker([{ ...UNSURE }]);
  await vm.runInContext("handlers.scanNavigation({ url: 'https://ordinary.example/' }, { tab: { id: 1 } })", w.context);
  await w.listeners.updated(1, { status: "complete" }, { url: "https://elsewhere.example/" });
  await new Promise((r) => setImmediate(r));
  assert.equal(w.injected.length, 0);
});

test("a confident pass shows no prompt", async () => {
  const w = worker([{ verdict: "safe", score: 93, jev_status: "not_flagged", score_source: "jev" }]);
  await vm.runInContext("handlers.scanNavigation({ url: 'https://ordinary.example/' }, { tab: { id: 1 } })", w.context);
  await w.listeners.updated(1, { status: "complete" }, { url: "https://ordinary.example/" });
  await new Promise((r) => setImmediate(r));
  assert.equal(w.injected.length, 0);
});

test("Click Here runs a deep scan of the tab and reports the verdict", async () => {
  const w = worker([
    { ...UNSURE, review: { token: "job", status: "pending" } },
    { status: "block", reason: "Fake wallet support page", evidence: [] },
  ]);
  const data = await vm.runInContext(
    "handlers.nudgeDeepScan({}, { tab: { id: 1, url: 'https://ordinary.example/' } })", w.context);
  assert.equal(JSON.parse(w.calls[0].options.body).mode, "deep");
  assert.equal(data.verdict, "dangerous");
  assert.equal(data.reason, "Fake wallet support page");
  assert.equal(new URL(w.tab.url).pathname, "/warning.html");
});

test("an unrecognized money site waits for the cloud and shows no prompt once it is approved", async () => {
  const w = worker([
    { ...UNSURE, score: 92, jev_confidence: 0.84, review: { token: "money-job", status: "pending" } },
    { status: "allow", reason: "Reviewed remotely", evidence: [] },
  ]);
  const outcome = await navigate(w);
  assert.equal(outcome.action, "proceed");
  assert.equal(w.storage["result:1"].unsure, false);
  await w.listeners.updated(1, { status: "complete" }, { url: "https://ordinary.example/" });
  await new Promise((r) => setImmediate(r));
  assert.equal(w.injected.length, 0);
});

test("an unrecognized financial site the cloud couldn't decide on is held on the warning page", async () => {
  const w = worker([
    { ...UNSURE, score: 93, cloud_required: true, review: { token: "money-job", status: "pending" } },
    { status: "inconclusive", reason: "The page could not be inspected completely.", evidence: [] },
  ]);
  const outcome = await navigate(w);
  assert.equal(outcome.action, "warn");
  assert.equal(new URL(outcome.url).searchParams.get("verdict"), "suspicious");
  assert.equal(w.storage["result:1"].unsure, false);
  assert.equal(w.storage["result:1"].assessment, "undetermined");
  assert.equal(w.storage["result:1"].score, null);
});

test("a failed cloud check on an unrecognized financial site also holds it", async () => {
  const w = worker([
    { ...UNSURE, score: 93, cloud_required: true, review: { token: "gone", status: "pending" } },
    new Error("This cloud review is unavailable or expired"),
  ]);
  const outcome = await navigate(w);
  assert.equal(outcome.action, "warn");
});

test("holding an unchecked financial site keeps a dangerous address verdict", async () => {
  const w = worker([
    { verdict: "dangerous", score: 11, jev_status: "suspicious", score_source: "jev", cloud_required: true,
      review: { token: "job", status: "pending" } },
    { status: "inconclusive", reason: "The remote check could not finish.", evidence: [] },
  ]);
  const outcome = await navigate(w);
  assert.equal(new URL(outcome.url).searchParams.get("verdict"), "dangerous");
  assert.equal(new URL(outcome.url).searchParams.has("score"), false);
});

test("failed deep scans discard address percentages and scores in every scan mode", async () => {
  for (const mode of ["quick", "deep", "navigate"]) {
    for (const score of [9, 99]) {
      const w = worker([{ verdict: score === 9 ? "dangerous" : "safe", score,
        score_source: "jev", jev_probability: 1 - score / 100,
        reasons: ["TrustLine estimates a 9.0% chance this web address is fake or misleading."],
        review: { status: "inconclusive", reason: "The cloud browser could not load the website.",
          evidence: [], page_probability: 0.05 } }]);
      const result = await w.analyze(mode);
      assert.equal(result.assessment, "undetermined");
      assert.equal(result.score, null);
      assert.equal(result.scoreSource, null);
      assert.doesNotMatch(result.reasons.join(" "), /%|chance/);
      w.context.testResult = result;
      const warning = new URL(vm.runInContext("warningPageUrl('https://ordinary.example/', testResult)", w.context));
      assert.equal(warning.searchParams.has("score"), false);
      assert.equal(warning.searchParams.get("review"), "inconclusive");
      assert.doesNotMatch(warning.searchParams.get("reasons"), /%|chance/);
    }
  }
});

test("a failed deep scan replaces a previously safe cached score", async () => {
  const w = worker([new Error("Offline")]);
  w.storage["result:1"] = { verdict: "safe", score: 99 };
  await vm.runInContext("scanTab(1, 'https://ordinary.example/', 'deep')", w.context);
  assert.equal(w.storage["result:1"].assessment, "undetermined");
  assert.equal(w.storage["result:1"].score, null);
});

test("the popup retains the undetermined result on its warning page", async () => {
  const w = worker([{ verdict: "dangerous", score: 9, jev_status: "suspicious", cloud_required: true,
    review: { status: "inconclusive", reason: "The website could not be reached.", evidence: [] } }]);
  const outcome = await navigate(w);
  w.tab.url = outcome.url;
  await w.listeners.updated(1, { url: outcome.url }, w.tab);
  // checkDaemon reuses the health result set by the navigation scan.
  const state = await vm.runInContext("handlers.getTabState({ tabId: 1 })", w.context);
  assert.equal(state.result.assessment, "undetermined");
  assert.equal(state.result.score, null);
  assert.equal(state.tab.domain, "ordinary.example");
  assert.equal(state.tab.scannable, false);
});
