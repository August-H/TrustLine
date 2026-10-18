"use strict";

const EXTENSION = typeof chrome !== "undefined" && Boolean(chrome.runtime?.id);

const ICONS = {
  safe: '<svg viewBox="0 0 24 24"><path d="m5 12.5 4.5 4.5L19 7.5"/></svg>',
  suspicious: '<svg viewBox="0 0 24 24"><path d="M12 6v8"/><path d="M12 18h.01"/></svg>',
  dangerous:
    '<svg viewBox="0 0 24 24"><path d="M12 2 4 5v6c0 5.1 3.4 9.4 8 11 4.6-1.6 8-5.9 8-11V5l-8-3Z"/><path d="m9.5 9.5 5 5M14.5 9.5l-5 5"/></svg>',
  idle: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M8 12h8"/></svg>',
  pending: '<svg viewBox="0 0 24 24"><path d="M21 12a9 9 0 1 1-6.2-8.56"/></svg>',
};

const VERDICT_COPY = {
  safe: ["We think ", " is safe"],
  suspicious: ["We think ", " looks suspicious"],
  dangerous: ["We think ", " is dangerous"],
};

const DEMO_RESULTS = {
  safe: {
    verdict: "safe",
    score: 92,
    reasons: ["Valid TLS certificate from a trusted issuer", "Domain registered over 10 years ago", "No known risk signals detected"],
  },
  suspicious: {
    verdict: "suspicious",
    score: 54,
    reasons: ["Domain registered 9 days ago", "Login form posts to a different origin", "Top-level domain is frequently associated with abuse"],
  },
  dangerous: {
    verdict: "dangerous",
    score: 11,
    reasons: ["Matches a known phishing kit fingerprint", "Domain impersonates a well-known brand", "Page requests payment details over an untrusted origin"],
  },
};

const $ = (id) => document.getElementById(id);
const el = {
  body: document.body,
  pill: $("daemonPill"),
  pillLabel: $("daemonLabel"),
  statusIcon: $("statusIcon"),
  verdict: $("verdict"),
  scoreValue: $("scoreValue"),
  track: $("meterTrack"),
  fill: $("meterFill"),
  signals: $("signals"),
  scanBtn: $("scanBtn"),
  scanLabel: $("scanLabel"),
  scanStatus: $("scanStatus"),
  autoScan: $("autoScan"),
  testRedirect: $("testRedirect"),
  demoSwitcher: $("demoSwitcher"),
};

const state = {
  tabId: null,
  tab: { url: "", domain: "", scannable: false },
  result: null,
  scanning: null,
  daemon: null,
  settings: { autoScan: true },
  demo: "live",
  demoScanning: false,
  error: "",
};

/* ------------------------------------------------------------ messaging */

async function send(type, payload = {}) {
  const res = await chrome.runtime.sendMessage({ type, ...payload });
  if (!res?.ok) throw new Error(res?.error || "TrustLine background did not respond");
  return res.data;
}

async function refresh() {
  if (state.tabId === null) return;
  const data = await send("getTabState", { tabId: state.tabId });
  Object.assign(state, data);
  render();
}

/* ------------------------------------------------------------ rendering */

function setVerdictText(prefix, domain, suffix) {
  const strong = document.createElement("strong");
  strong.textContent = domain;
  el.verdict.replaceChildren(document.createTextNode(prefix), strong, document.createTextNode(suffix));
}

function currentView() {
  const isDemo = state.demo !== "live";
  const domain = state.tab.domain || "example.com";
  if (isDemo) {
    return { kind: "result", result: { ...DEMO_RESULTS[state.demo], domain, source: "demo" }, scanning: state.demoScanning };
  }
  if (!state.tab.scannable) return { kind: "unscannable" };
  const scanning = state.scanning;
  if (state.result) return { kind: "result", result: state.result, scanning: scanning?.mode === "deep" };
  return { kind: "pending", scanning: scanning?.mode === "deep" };
}

function render() {
  const view = currentView();
  const status = view.kind === "result" ? view.result.verdict : "idle";
  el.body.dataset.status = status;

  // Daemon pill
  if (!state.daemon) {
    el.pill.dataset.state = "pending";
    el.pillLabel.textContent = EXTENSION ? "Connecting…" : "Standalone preview";
  } else if (state.daemon.online) {
    el.pill.dataset.state = "online";
    el.pillLabel.textContent = "Active";
    el.pill.title = `Connected to ${state.daemon.baseUrl}${state.daemon.version ? ` (v${state.daemon.version})` : ""}`;
  } else {
    el.pill.dataset.state = "mock";
    el.pillLabel.textContent = "Offline";
    el.pill.title = `Daemon unreachable at ${state.daemon.baseUrl}. No trust score is available.`;
  }

  // Status card
  el.statusIcon.classList.toggle("is-pending", view.kind === "pending");
  if (view.kind === "result") {
    const { result } = view;
    const [pre, post] = VERDICT_COPY[result.verdict];
    el.statusIcon.innerHTML = ICONS[result.verdict];
    setVerdictText(pre, result.domain, post);
  } else if (view.kind === "pending") {
    el.statusIcon.innerHTML = ICONS.pending;
    el.verdict.replaceChildren(document.createTextNode("Checking "), Object.assign(document.createElement("strong"), { textContent: state.tab.domain }), document.createTextNode("…"));
  } else {
    el.statusIcon.innerHTML = ICONS.idle;
    el.verdict.textContent = "TrustLine can't scan this page";
  }

  // Trust meter
  const score = view.kind === "result" ? view.result.score : null;
  el.scoreValue.textContent = score === null ? "--" : String(score);
  el.fill.style.width = `${score ?? 0}%`;
  el.track.setAttribute("aria-valuenow", String(score ?? 0));

  // Never show scoring formulas (e.g. "100 × (1 − …)") as if they were reasons.
  const reasons = (view.kind === "result" ? view.result.reasons ?? [] : [])
    .filter((r) => !/×|\(1\s*[−-]/.test(r));
  el.signals.hidden = reasons.length === 0;
  el.signals.replaceChildren(
    ...reasons.map((r) => Object.assign(document.createElement("li"), { textContent: r }))
  );

  // Deep scan button
  const scanning = Boolean(view.scanning);
  el.scanBtn.classList.toggle("is-scanning", scanning);
  el.scanBtn.disabled = scanning || view.kind === "unscannable";
  el.scanBtn.setAttribute("aria-busy", String(scanning));
  el.scanLabel.textContent = scanning ? "Scanning…" : "Deep scan";
  setScanTicker(scanning);
  if (!scanning) {
    const review = view.kind === "result" ? view.result.review : null;
    el.scanStatus.textContent = state.error || (review?.status === "inconclusive" ? review.reason : "");
    el.scanStatus.classList.toggle("is-error", Boolean(state.error || review?.status === "inconclusive"));
  }

  // Footer
  el.autoScan.checked = Boolean(state.settings.autoScan);
  el.testRedirect.disabled = EXTENSION && !state.tab.scannable;
  for (const btn of el.demoSwitcher.querySelectorAll("button")) {
    btn.setAttribute("aria-checked", String(btn.dataset.demo === state.demo));
  }
}

let tickerTimer = null;
let tickerStartedAt = 0;

function setScanTicker(active) {
  if (active && !tickerTimer) {
    tickerStartedAt = Date.now();
    const tick = () => {
      const elapsed = (Date.now() - tickerStartedAt) / 1000;
      el.scanStatus.classList.remove("is-error");
      el.scanStatus.textContent = `Cloud browser review in progress… ${elapsed.toFixed(1)}s`;
    };
    tick();
    tickerTimer = setInterval(tick, 100);
  } else if (!active && tickerTimer) {
    clearInterval(tickerTimer);
    tickerTimer = null;
    el.scanStatus.textContent = "";
  }
}

/* --------------------------------------------------------------- actions */

async function deepScan() {
  state.error = "";
  if (!EXTENSION) {
    state.demoScanning = true;
    render();
    await new Promise((r) => setTimeout(r, 2600));
    state.demoScanning = false;
    render();
    return;
  }
  // Preview controls never turn a real Deep scan click into a simulated scan.
  setDemo("live");
  state.scanning = { mode: "deep", startedAt: Date.now() };
  render();
  try {
    state.result = await send("scan", { tabId: state.tabId, mode: "deep" });
    await refresh();
  } catch (err) {
    state.error = `Deep scan failed: ${err.message}`;
  }
  state.scanning = null;
  render();
}

async function setAutoScan(enabled) {
  state.settings.autoScan = enabled;
  render();
  if (!EXTENSION) return;
  try {
    state.settings = await send("setSettings", { patch: { autoScan: enabled } });
  } catch (err) {
    state.error = err.message;
    render();
  }
}

async function testRedirect() {
  if (!EXTENSION) {
    state.error = "Site Report is only available inside Chrome";
    render();
    return;
  }
  try {
    await send("testRedirect", { tabId: state.tabId });
    window.close();
  } catch (err) {
    state.error = err.message;
    render();
  }
}

function setDemo(demo) {
  state.demo = demo;
  state.demoScanning = false;
  state.error = "";
  try {
    localStorage.setItem("trustline.demo", demo);
  } catch {
    /* storage unavailable; preview state just won't persist */
  }
  render();
}

/* ------------------------------------------------------------------ init */

async function init() {
  // Demo scores belong to the standalone preview, never the installed extension.
  if (EXTENSION) el.demoSwitcher.closest(".demo-row").style.display = "none";
  try {
    const saved = localStorage.getItem("trustline.demo");
    if (!EXTENSION && saved && (saved === "live" || saved in DEMO_RESULTS)) state.demo = saved;
  } catch {
    /* ignore */
  }

  el.scanBtn.addEventListener("click", deepScan);
  el.autoScan.addEventListener("change", (e) => setAutoScan(e.target.checked));
  el.testRedirect.addEventListener("click", testRedirect);
  el.demoSwitcher.addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-demo]");
    if (btn) setDemo(btn.dataset.demo);
  });

  if (!EXTENSION) {
    // Opened directly as a file or in a dev server: preview the UI with demo data.
    state.tab = { url: "https://example.com", domain: "example.com", scannable: true };
    if (state.demo === "live") state.demo = "safe";
    render();
    return;
  }

  render();
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;
  state.tabId = tab.id;

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "session") return;
    if (changes[`result:${state.tabId}`] || changes[`scan:${state.tabId}`]) refresh().catch(() => {});
  });

  try {
    await refresh();
    // Opening the popup is explicit intent, so scan even when auto-scan is off.
    if (state.tab.scannable && !state.result && !state.scanning) {
      state.result = await send("scan", { tabId: state.tabId, mode: "quick" });
      render();
    }
  } catch (err) {
    state.error = err.message;
    render();
  }
}

init();
