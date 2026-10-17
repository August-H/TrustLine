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

const DEEP_SCAN_STEPS = [
  "Fetching page content",
  "Inspecting scripts and forms",
  "Evaluating with TrustLine model",
  "Compiling verdict",
];

const $ = (id) => document.getElementById(id);
const el = {
  body: document.body,
  pill: $("daemonPill"),
  pillLabel: $("daemonLabel"),
  statusIcon: $("statusIcon"),
  verdict: $("verdict"),
  verdictMeta: $("verdictMeta"),
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

function timeAgo(ts) {
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 10) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.round(m / 60)}h ago`;
}

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
    el.pillLabel.textContent = "Daemon active";
    el.pill.title = `Connected to ${state.daemon.baseUrl}${state.daemon.version ? ` (v${state.daemon.version})` : ""}`;
  } else {
    el.pill.dataset.state = "mock";
    el.pillLabel.textContent = "Mock mode";
    el.pill.title = `Daemon unreachable at ${state.daemon.baseUrl}. Using local heuristics.`;
  }

  // Status card
  el.statusIcon.classList.toggle("is-pending", view.kind === "pending");
  if (view.kind === "result") {
    const { result } = view;
    const [pre, post] = VERDICT_COPY[result.verdict];
    el.statusIcon.innerHTML = ICONS[result.verdict];
    setVerdictText(pre, result.domain, post);
    const sourceLabel = { daemon: "TrustLine daemon", mock: "Mock analyzer", demo: "Demo preview" }[result.source] ?? "";
    const modeLabel = result.mode === "deep" ? "Deep scan" : result.source === "demo" ? "" : "Quick scan";
    const parts = [modeLabel, sourceLabel, result.scannedAt ? timeAgo(result.scannedAt) : ""].filter(Boolean);
    el.verdictMeta.textContent = parts.join(" · ");
  } else if (view.kind === "pending") {
    el.statusIcon.innerHTML = ICONS.pending;
    el.verdict.replaceChildren(document.createTextNode("Checking "), Object.assign(document.createElement("strong"), { textContent: state.tab.domain }), document.createTextNode("…"));
    el.verdictMeta.textContent = "Running quick scan";
  } else {
    el.statusIcon.innerHTML = ICONS.idle;
    el.verdict.textContent = "TrustLine can't scan this page";
    el.verdictMeta.textContent = "Open a website to see its trust score";
  }

  // Trust meter
  const score = view.kind === "result" ? view.result.score : null;
  el.scoreValue.textContent = score === null ? "--" : String(score);
  el.fill.style.width = `${score ?? 0}%`;
  el.track.setAttribute("aria-valuenow", String(score ?? 0));

  const reasons = view.kind === "result" ? view.result.reasons ?? [] : [];
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
    el.scanStatus.textContent = state.error;
    el.scanStatus.classList.toggle("is-error", Boolean(state.error));
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
      const step = DEEP_SCAN_STEPS[Math.min(DEEP_SCAN_STEPS.length - 1, Math.floor(elapsed / 0.9))];
      el.scanStatus.classList.remove("is-error");
      el.scanStatus.textContent = `${step}… ${elapsed.toFixed(1)}s`;
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
  if (state.demo !== "live" || !EXTENSION) {
    state.demoScanning = true;
    render();
    await new Promise((r) => setTimeout(r, 2600));
    state.demoScanning = false;
    render();
    return;
  }
  state.scanning = { mode: "deep", startedAt: Date.now() };
  render();
  try {
    state.result = await send("scan", { tabId: state.tabId, mode: "deep" });
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
    state.error = "Warning redirect is only available inside Chrome";
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
  try {
    const saved = localStorage.getItem("trustline.demo");
    if (saved && (saved === "live" || saved in DEMO_RESULTS)) state.demo = saved;
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
