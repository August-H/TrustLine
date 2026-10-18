"use strict";

// Shown before a navigation completes. background.js asks the daemon about the
// destination, then this page either forwards to it or hands off to the warning.

const MIN_DISPLAY_MS = 1000; // keeps instant answers from flashing the page
const STEP_INTERVAL_MS = 350;

// Preview results for `&demo=` (and for opening the page outside the extension).
const DEMO_RESULTS = {
  safe: { verdict: "safe", score: 96, reasons: [] },
  suspicious: { verdict: "suspicious", score: 52, reasons: ["Domain registered 9 days ago"] },
  dangerous: {
    verdict: "dangerous",
    score: 12,
    reasons: ["Known phishing domain", "TrustLine estimates a 91.0% chance this web address is fake or misleading."],
  },
};

const inExtension = typeof chrome !== "undefined" && Boolean(chrome.runtime?.id);

// The interception rule appends the destination unencoded (it may carry its
// own ? and &), so everything after "?url=" is the target. Hand-typed preview
// links encode it instead and can add &demo=.
function readParams() {
  const at = location.href.indexOf("?url=");
  if (at === -1) return { target: "", demo: null };
  const raw = location.href.slice(at + "?url=".length);
  if (/^https?%3A/i.test(raw)) {
    const params = new URLSearchParams(location.search);
    return { target: params.get("url") ?? "", demo: params.get("demo") };
  }
  return { target: raw, demo: null };
}

function parseTarget(text) {
  try {
    const u = new URL(text);
    return u.protocol === "http:" || u.protocol === "https:" ? u : null;
  } catch {
    return null;
  }
}

const { target, demo: demoParam } = readParams();
const parsed = parseTarget(target);
const demo = demoParam in DEMO_RESULTS ? demoParam : inExtension ? null : "safe";

/* ---------------------------------------------------------------- render */

function renderAddress() {
  const node = document.getElementById("domain");
  if (!parsed) {
    node.textContent = "an unknown site";
    return;
  }
  const host = parsed.hostname.replace(/^www\./i, "");
  const owner = ownerOf(host);
  const split = host.length - owner.length;
  node.style.setProperty("--chars", String(host.length));
  if (split > 0) {
    const ownerSpan = document.createElement("span");
    ownerSpan.className = "owner";
    ownerSpan.textContent = owner;
    node.replaceChildren(host.slice(0, split), ownerSpan);
  } else {
    node.textContent = host;
  }
  document.title = `TrustLine is checking ${host}`;
}

const progress = document.getElementById("progress");
const fill = document.getElementById("progress-fill");
const steps = [...document.querySelectorAll(".scan-step")];

function setProgress(pct) {
  fill.style.width = `${pct}%`;
  progress.setAttribute("aria-valuenow", String(Math.round(pct)));
}

// Creep towards 90% while waiting; the last stretch lands when the answer does.
let creepFrame = 0;
function creep(startedAt) {
  const elapsed = performance.now() - startedAt;
  setProgress(90 * (1 - Math.exp(-elapsed / 900)));
  creepFrame = requestAnimationFrame(() => creep(startedAt));
}

function setStep(index, state) {
  if (steps[index]) steps[index].dataset.state = state;
}

// Steps 1 and 2 tick over on a timer; step 3 finishes with the real result.
function advanceSteps() {
  setTimeout(() => {
    setStep(0, "done");
    setStep(1, "active");
  }, STEP_INTERVAL_MS);
  setTimeout(() => {
    setStep(1, "done");
    setStep(2, "active");
  }, STEP_INTERVAL_MS * 2);
}

function finish(verdict) {
  cancelAnimationFrame(creepFrame);
  steps.forEach((_, i) => setStep(i, "done"));
  document.body.dataset.result = verdict ?? "";
  setProgress(100);
}

function showFailure() {
  cancelAnimationFrame(creepFrame);
  document.getElementById("title").textContent = "TrustLine couldn't check this site";
  steps.forEach((step) => {
    if (step.dataset.state === "active") step.dataset.state = "pending";
  });
}

/* ------------------------------------------------------------------ flow */

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function demoWarningUrl(result) {
  const page = new URL("warning.html", location.href);
  page.searchParams.set("url", parsed.href);
  page.searchParams.set("verdict", result.verdict);
  page.searchParams.set("score", String(result.score));
  page.searchParams.set("reasons", JSON.stringify(result.reasons));
  page.searchParams.set("via", "scan");
  return page.href;
}

async function check() {
  if (demo) {
    await sleep(1600);
    const result = DEMO_RESULTS[demo];
    return { verdict: result.verdict, action: result.verdict === "safe" ? "proceed" : "warn",
      url: result.verdict === "safe" ? parsed.href : demoWarningUrl(result) };
  }
  const res = await chrome.runtime.sendMessage({ type: "scanNavigation", url: parsed.href });
  if (!res?.ok) throw new Error(res?.error ?? "No response from TrustLine");
  return res.data;
}

async function run() {
  renderAddress();
  if (!parsed) {
    showFailure();
    return;
  }
  const startedAt = performance.now();
  creep(startedAt);
  advanceSteps();

  let outcome;
  try {
    outcome = await check();
  } catch (err) {
    console.warn("[TrustLine]", err);
    showFailure();
    return;
  }

  const remaining = MIN_DISPLAY_MS - (performance.now() - startedAt);
  if (remaining > 0) await sleep(remaining);
  finish(outcome.verdict);
  await sleep(250); // let the bar and the last check land before leaving
  // replace(): neither this page nor a flagged site should sit in Back history.
  location.replace(outcome.url);
}

document.getElementById("cancel").addEventListener("click", () => {
  if (history.length > 1) history.back();
  else location.replace("about:blank");
});

run();
