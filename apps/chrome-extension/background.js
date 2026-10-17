/*
 * TrustLine service worker.
 *
 * Talks to the local macOS daemon over HTTP. When the daemon is unreachable it
 * falls back to a local heuristic "mock" analyzer so the UI stays usable.
 * See README.md for the daemon API contract.
 */

const CONFIG = {
  DAEMON_BASE_URL: "http://127.0.0.1:8765",
  HEALTH_TIMEOUT_MS: 1500,
  HEALTH_CACHE_MS: 10_000,
  QUICK_SCAN_TIMEOUT_MS: 8_000,
  DEEP_SCAN_TIMEOUT_MS: 90_000,
  MOCK_DEEP_SCAN_DELAY_MS: 2_800,
  RESULT_TTL_MS: 5 * 60_000,
  // Set to the hosted warning landing page (e.g. "https://trustline.app/warning").
  // When empty, the bundled warning.html is used.
  WARNING_PAGE_URL: "",
};

const VERDICTS = ["safe", "suspicious", "dangerous"];
const STATUS_COLORS = {
  safe: "#10B981",
  suspicious: "#F59E0B",
  dangerous: "#EF4444",
  idle: "#6B7280",
};
const DEFAULT_SETTINGS = { autoScan: true, blockDangerous: true };

const resultKey = (tabId) => `result:${tabId}`;
const scanKey = (tabId) => `scan:${tabId}`;

/* ------------------------------------------------------------------ utils */

function isScannableUrl(url) {
  return typeof url === "string" && /^https?:\/\//i.test(url);
}

function hostnameOf(url) {
  try {
    return new URL(url).hostname.replace(/^www\./i, "");
  } catch {
    return "";
  }
}

function verdictFromScore(score) {
  if (score >= 70) return "safe";
  if (score >= 40) return "suspicious";
  return "dangerous";
}

function clampScore(n) {
  return Math.max(0, Math.min(100, Math.round(n)));
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 5000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getSettings() {
  const { settings } = await chrome.storage.local.get("settings");
  return { ...DEFAULT_SETTINGS, ...(settings || {}) };
}

/* ----------------------------------------------------------------- daemon */

let healthCache = { checkedAt: 0, online: false, version: null };

async function checkDaemon(force = false) {
  if (!force && Date.now() - healthCache.checkedAt < CONFIG.HEALTH_CACHE_MS) {
    return healthCache;
  }
  let online = false;
  let version = null;
  try {
    const res = await fetchWithTimeout(
      `${CONFIG.DAEMON_BASE_URL}/health`,
      { method: "GET" },
      CONFIG.HEALTH_TIMEOUT_MS
    );
    if (res.ok) {
      online = true;
      const body = await res.json().catch(() => ({}));
      version = body.version ?? null;
    }
  } catch {
    online = false;
  }
  healthCache = { checkedAt: Date.now(), online, version };
  return healthCache;
}

function normalizeResult(raw, url, mode, source) {
  let score = Number(raw?.score ?? raw?.trust_score ?? raw?.trustScore);
  if (!Number.isFinite(score)) score = null;

  let verdict = String(raw?.verdict ?? raw?.status ?? "").toLowerCase();
  if (["blocked", "malicious", "danger", "unsafe"].includes(verdict)) verdict = "dangerous";
  if (["warning", "warn", "caution"].includes(verdict)) verdict = "suspicious";
  if (["ok", "trusted", "clean"].includes(verdict)) verdict = "safe";
  if (!VERDICTS.includes(verdict)) {
    verdict = score === null ? "suspicious" : verdictFromScore(score);
  }
  if (score === null) score = { safe: 85, suspicious: 55, dangerous: 15 }[verdict];

  const reasons = Array.isArray(raw?.reasons)
    ? raw.reasons.filter((r) => typeof r === "string" && r.trim()).slice(0, 6)
    : [];

  return {
    url,
    domain: hostnameOf(url),
    verdict,
    score: clampScore(score),
    reasons,
    mode,
    source,
    scannedAt: Date.now(),
  };
}

/* ------------------------------------------------------------- mock mode */

const RISKY_TLDS = new Set(["zip", "mov", "xyz", "top", "click", "gq", "tk", "ml", "cf", "work", "rest"]);
const BAIT_KEYWORDS = /(login|log-in|signin|sign-in|verify|verification|secure|account|update|wallet|confirm|banking|support-|recover)/i;

function hashString(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}

function mockAnalyze(url, mode) {
  const u = new URL(url);
  const host = u.hostname.toLowerCase();
  const isLoopback = host === "localhost" || host === "127.0.0.1" || host === "[::1]";
  const reasons = [];
  let score = 94 - (hashString(host) % 6);

  if (!isLoopback) {
    if (u.protocol === "http:") {
      score -= 18;
      reasons.push("Connection is not encrypted (HTTP)");
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      score -= 25;
      reasons.push("Site is served from a raw IP address");
    }
    if (host.includes("xn--")) {
      score -= 30;
      reasons.push("Domain uses punycode, a common look-alike trick");
    }
    if (u.username || u.password) {
      score -= 20;
      reasons.push("URL embeds credentials before the hostname");
    }
    if (host.split(".").length > 4) {
      score -= 12;
      reasons.push("Unusually deep subdomain chain");
    }
    if (BAIT_KEYWORDS.test(host)) {
      score -= 16;
      reasons.push("Domain contains credential-bait keywords");
    }
    if ((host.match(/-/g) || []).length >= 3) {
      score -= 10;
      reasons.push("Domain contains many hyphens");
    }
    if (RISKY_TLDS.has(host.split(".").pop())) {
      score -= 15;
      reasons.push("Top-level domain is frequently associated with abuse");
    }
    if (host.length > 40) {
      score -= 8;
      reasons.push("Hostname is unusually long");
    }
  }

  if (reasons.length === 0) reasons.push("No known risk signals detected");
  if (mode === "deep") reasons.push("Page content reviewed by local mock analyzer");

  return normalizeResult({ score, reasons }, url, mode, "mock");
}

/* --------------------------------------------------------------- analysis */

async function analyzeUrl(url, mode) {
  const daemon = await checkDaemon();
  if (daemon.online) {
    try {
      const res = await fetchWithTimeout(
        `${CONFIG.DAEMON_BASE_URL}/v1/analyze`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url, mode }),
        },
        mode === "deep" ? CONFIG.DEEP_SCAN_TIMEOUT_MS : CONFIG.QUICK_SCAN_TIMEOUT_MS
      );
      if (!res.ok) throw new Error(`Daemon responded with HTTP ${res.status}`);
      return normalizeResult(await res.json(), url, mode, "daemon");
    } catch (err) {
      console.warn("[TrustLine] Daemon analysis failed, using mock analyzer:", err);
      healthCache = { checkedAt: Date.now(), online: false, version: null };
    }
  }
  if (mode === "deep") await sleep(CONFIG.MOCK_DEEP_SCAN_DELAY_MS);
  return mockAnalyze(url, mode);
}

const inflight = new Map(); // tabId -> { url, mode, promise }

async function scanTab(tabId, url, mode = "quick") {
  const existing = inflight.get(tabId);
  if (existing && existing.url === url && (existing.mode === mode || existing.mode === "deep")) {
    return existing.promise;
  }

  const promise = (async () => {
    await chrome.storage.session.set({ [scanKey(tabId)]: { url, mode, startedAt: Date.now() } });
    try {
      const result = await analyzeUrl(url, mode);
      // Discard if the tab navigated elsewhere while we were scanning.
      const tab = await chrome.tabs.get(tabId).catch(() => null);
      if (!tab || tab.url !== url) return result;
      await chrome.storage.session.set({ [resultKey(tabId)]: result });
      await applyActionState(tabId, result.verdict);
      await maybeBlock(tabId, result);
      return result;
    } finally {
      await chrome.storage.session.remove(scanKey(tabId));
      if (inflight.get(tabId)?.promise === promise) inflight.delete(tabId);
    }
  })();

  inflight.set(tabId, { url, mode, promise });
  return promise;
}

/* ------------------------------------------------------- warning redirect */

async function getAllowlist() {
  const { allowlist } = await chrome.storage.session.get("allowlist");
  return Array.isArray(allowlist) ? allowlist : [];
}

function warningPageUrl(targetUrl, result, reason) {
  const base = CONFIG.WARNING_PAGE_URL || chrome.runtime.getURL("warning.html");
  const page = new URL(base);
  page.searchParams.set("url", targetUrl);
  page.searchParams.set("verdict", result?.verdict ?? "dangerous");
  if (result?.score !== undefined) page.searchParams.set("score", String(result.score));
  page.searchParams.set("reason", reason ?? result?.reasons?.[0] ?? "This site was flagged by TrustLine");
  // Full context so the warning page can render an itemized threat breakdown.
  const reasons = [...(reason ? [reason] : []), ...(result?.reasons ?? [])];
  if (reasons.length) page.searchParams.set("reasons", JSON.stringify([...new Set(reasons)]));
  if (result?.source) page.searchParams.set("source", result.source);
  if (result?.scannedAt) page.searchParams.set("ts", String(result.scannedAt));
  return page.toString();
}

async function maybeBlock(tabId, result) {
  if (result.verdict !== "dangerous") return;
  const settings = await getSettings();
  if (!settings.autoScan || !settings.blockDangerous) return;
  const allowlist = await getAllowlist();
  if (allowlist.includes(result.domain)) return;
  await chrome.tabs.update(tabId, { url: warningPageUrl(result.url, result) });
}

/* ------------------------------------------------------------ action icon */

const SHIELD_PATH = "M12 2 4 5v6c0 5.1 3.4 9.4 8 11 4.6-1.6 8-5.9 8-11V5l-8-3Z";
const iconCache = new Map();

function drawIcon(color, size) {
  const canvas = new OffscreenCanvas(size, size);
  const ctx = canvas.getContext("2d");
  ctx.scale(size / 24, size / 24);
  ctx.fillStyle = color;
  ctx.fill(new Path2D(SHIELD_PATH));
  return ctx.getImageData(0, 0, size, size);
}

function iconFor(status) {
  if (!iconCache.has(status)) {
    const color = STATUS_COLORS[status] ?? STATUS_COLORS.idle;
    iconCache.set(status, { 16: drawIcon(color, 16), 32: drawIcon(color, 32) });
  }
  return iconCache.get(status);
}

async function applyActionState(tabId, status) {
  const details = tabId === undefined ? {} : { tabId };
  try {
    await chrome.action.setIcon({ ...details, imageData: iconFor(status) });
    const badge = status === "suspicious" || status === "dangerous" ? "!" : "";
    await chrome.action.setBadgeText({ ...details, text: badge });
    if (badge) {
      await chrome.action.setBadgeBackgroundColor({ ...details, color: STATUS_COLORS[status] });
      await chrome.action.setBadgeTextColor?.({ ...details, color: "#0F1115" });
    }
    const titles = {
      safe: "TrustLine: this site looks safe",
      suspicious: "TrustLine: this site looks suspicious",
      dangerous: "TrustLine: this site looks dangerous",
      idle: "TrustLine",
    };
    await chrome.action.setTitle({ ...details, title: titles[status] ?? titles.idle });
  } catch (err) {
    // Tab may have closed between scan and icon update.
    if (!String(err?.message).includes("No tab with id")) console.warn("[TrustLine]", err);
  }
}

/* ---------------------------------------------------------------- events */

chrome.runtime.onInstalled.addListener(async () => {
  const { settings } = await chrome.storage.local.get("settings");
  await chrome.storage.local.set({ settings: { ...DEFAULT_SETTINGS, ...(settings || {}) } });
  await applyActionState(undefined, "idle");
});

chrome.runtime.onStartup.addListener(() => applyActionState(undefined, "idle"));

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    await chrome.storage.session.remove(resultKey(tabId));
    await applyActionState(tabId, "idle");
  }
  if (changeInfo.status !== "loading" || !isScannableUrl(tab.url)) return;

  const settings = await getSettings();
  if (!settings.autoScan) return;

  const { [resultKey(tabId)]: cached } = await chrome.storage.session.get(resultKey(tabId));
  if (cached && cached.url === tab.url && Date.now() - cached.scannedAt < CONFIG.RESULT_TTL_MS) {
    await applyActionState(tabId, cached.verdict);
    return;
  }
  scanTab(tabId, tab.url, "quick").catch((err) => console.warn("[TrustLine] Auto-scan failed:", err));
});

chrome.tabs.onRemoved.addListener((tabId) => {
  inflight.delete(tabId);
  chrome.storage.session.remove([resultKey(tabId), scanKey(tabId)]);
});

/* --------------------------------------------------------------- messages */

const handlers = {
  async getTabState({ tabId }) {
    const tab = await chrome.tabs.get(tabId);
    const keys = [resultKey(tabId), scanKey(tabId)];
    const stored = await chrome.storage.session.get(keys);
    const result = stored[resultKey(tabId)];
    const daemon = await checkDaemon();
    return {
      tab: { url: tab.url ?? "", domain: hostnameOf(tab.url ?? ""), scannable: isScannableUrl(tab.url) },
      result: result && result.url === tab.url ? result : null,
      scanning: stored[scanKey(tabId)] ?? null,
      daemon: { online: daemon.online, version: daemon.version, baseUrl: CONFIG.DAEMON_BASE_URL },
      settings: await getSettings(),
    };
  },

  async scan({ tabId, mode }) {
    const tab = await chrome.tabs.get(tabId);
    if (!isScannableUrl(tab.url)) throw new Error("This page can't be scanned");
    return scanTab(tabId, tab.url, mode === "deep" ? "deep" : "quick");
  },

  async setSettings({ patch }) {
    const next = { ...(await getSettings()), ...patch };
    await chrome.storage.local.set({ settings: next });
    return next;
  },

  async testRedirect({ tabId }) {
    const tab = await chrome.tabs.get(tabId);
    const { [resultKey(tabId)]: result } = await chrome.storage.session.get(resultKey(tabId));
    const target = tab.url || "https://example.com";
    const url = warningPageUrl(target, result ?? { verdict: "dangerous", score: 12 }, "Manual test triggered from the TrustLine popup");
    await chrome.tabs.update(tabId, { url });
    return { url };
  },

  async allowAndProceed({ url }, sender) {
    if (!isScannableUrl(url)) throw new Error("Invalid destination");
    const domain = hostnameOf(url);
    const allowlist = await getAllowlist();
    if (!allowlist.includes(domain)) allowlist.push(domain);
    await chrome.storage.session.set({ allowlist });
    if (sender.tab?.id !== undefined) await chrome.tabs.update(sender.tab.id, { url });
    return { domain };
  },
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const handler = handlers[message?.type];
  if (!handler) return false;
  handler(message, sender)
    .then((data) => sendResponse({ ok: true, data }))
    .catch((err) => sendResponse({ ok: false, error: err?.message ?? String(err) }));
  return true;
});
