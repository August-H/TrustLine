/*
 * TrustLine service worker.
 *
 * Talks to the local macOS daemon for verified-domain/Jev scores and
 * Cloudflare Browser Run reviews. Missing results stay unscored.
 * See README.md for the daemon API contract.
 */

const CONFIG = {
  DAEMON_BASE_URL: "http://127.0.0.1:8765",
  HEALTH_TIMEOUT_MS: 1500,
  HEALTH_CACHE_MS: 10_000,
  QUICK_SCAN_TIMEOUT_MS: 8_000,
  DEEP_SCAN_TIMEOUT_MS: 110_000,
  REVIEW_POLL_MS: 1_000,
  RESULT_TTL_MS: 5 * 60_000,
  // How long a site may load after an unconfirmed check (daemon offline, or
  // blocking turned off) before the next visit is checked again.
  NAVIGATION_PASS_MS: 60_000,
  // Set to the hosted warning landing page (e.g. "https://trustline.app/warning").
  // When empty, the bundled warning.html is used.
  WARNING_PAGE_URL: "",
};
// Served by the daemon proxy; must match REDIRECT_HOST in proxy.py.
const BLOCKED_HOST = "blocked.example.com";

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
  const suppliedScore = raw?.score;
  const score = typeof suppliedScore === "number" && Number.isFinite(suppliedScore)
    ? clampScore(suppliedScore) : null;

  let verdict = String(raw?.verdict ?? raw?.status ?? "").toLowerCase();
  if (["blocked", "malicious", "danger", "unsafe"].includes(verdict)) verdict = "dangerous";
  if (["warning", "warn", "caution"].includes(verdict)) verdict = "suspicious";
  if (["ok", "trusted", "clean"].includes(verdict)) verdict = "safe";
  if (!VERDICTS.includes(verdict)) {
    verdict = score === null ? "suspicious" : verdictFromScore(score);
  }

  const reasons = Array.isArray(raw?.reasons)
    ? raw.reasons.filter((r) => typeof r === "string" && r.trim()).slice(0, 6)
    : [];

  return {
    url,
    domain: hostnameOf(raw?.target_url || url),
    targetUrl: raw?.target_url || url,
    schemaVersion: 2,
    verified: raw?.verified === true,
    scoreSource: raw?.score_source ?? null,
    jevProbability: raw?.jev_probability ?? null,
    jevStatus: raw?.jev_status ?? null,
    review: raw?.review ?? null,
    verdict,
    score,
    reasons,
    mode,
    source,
    scannedAt: Date.now(),
  };
}

/* --------------------------------------------------------------- analysis */

async function daemonJson(path, options = {}, timeout = CONFIG.QUICK_SCAN_TIMEOUT_MS) {
  const response = await fetchWithTimeout(`${CONFIG.DAEMON_BASE_URL}${path}`, options, timeout);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Daemon responded with HTTP ${response.status}`);
  return data;
}

async function analyzeUrl(url, mode) {
  try {
    // Every explicit scan tries the daemon again, even after a cached health failure.
    const raw = await daemonJson("/v1/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, mode }),
    });
    healthCache = { checkedAt: Date.now(), online: true, version: "0.2.0" };
    const deadline = Date.now() + CONFIG.DEEP_SCAN_TIMEOUT_MS;
    while (raw.review?.status === "pending") {
      if (Date.now() >= deadline) throw new Error("Cloud review timed out. No approval was granted.");
      await sleep(CONFIG.REVIEW_POLL_MS);
      raw.review = { token: raw.review.token, ...await daemonJson(`/v1/reviews/${encodeURIComponent(raw.review.token)}`) };
    }
    if (raw.review) {
      raw.verdict = { allow: "safe", block: "dangerous" }[raw.review.status] ?? "suspicious";
      raw.reasons = [raw.review.reason, ...(raw.review.evidence ?? [])];
    }
    return normalizeResult(raw, url, mode, "daemon");
  } catch (err) {
    healthCache = { checkedAt: Date.now(), online: false, version: null };
    if (mode === "deep") throw new Error(`Cloud review unavailable: ${err.message}`);
    return normalizeResult({ verdict: "suspicious", score: null,
      reasons: ["Trust score unavailable. Start the TrustLine daemon and check its Jev configuration."] }, url, mode, "unavailable");
  }
}

const inflight = new Map(); // tabId -> { url, mode, promise }

async function scanTab(tabId, url, mode = "quick") {
  const existing = inflight.get(tabId);
  if (existing && existing.url === url && (existing.mode === mode || existing.mode === "deep")) {
    return existing.promise;
  }

  if (existing && existing.url === url) {
    await existing.promise;
    return scanTab(tabId, url, mode);
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
      // A user may retry a previously inconclusive proxy check from the popup.
      // Release that checking tab on approval even if its page stopped polling.
      const current = new URL(url);
      if (result.review?.status === "allow" && current.hostname === BLOCKED_HOST &&
          current.pathname.startsWith("/_trustline/check/") && result.targetUrl !== url) {
        await chrome.tabs.update(tabId, { url: result.targetUrl });
      }
      await maybeBlock(tabId, result);
      return result;
    } finally {
      if (inflight.get(tabId)?.promise === promise) {
        inflight.delete(tabId);
        await chrome.storage.session.remove(scanKey(tabId));
      }
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
  if (typeof result?.score === "number") page.searchParams.set("score", String(result.score));
  page.searchParams.set("reason", reason ?? result?.reasons?.[0] ?? "This site was flagged by TrustLine");
  // Full context so the warning page can render an itemized threat breakdown.
  const reasons = [...(reason ? [reason] : []), ...(result?.reasons ?? [])];
  if (reasons.length) page.searchParams.set("reasons", JSON.stringify([...new Set(reasons)]));
  if (result?.source) page.searchParams.set("source", result.source);
  if (result?.scannedAt) page.searchParams.set("ts", String(result.scannedAt));
  return page.toString();
}

async function maybeBlock(tabId, result) {
  // The proxy's checking page already holds the target; redirecting would drop its review.
  if (hostnameOf(result.url) === BLOCKED_HOST) return;
  // A completed cloud review supersedes Jev's URL judgment, as it does in the proxy.
  const jevFlagged = result.jevStatus === "suspicious" &&
    !["allow", "block"].includes(result.review?.status);
  if (!jevFlagged && result.verdict !== "dangerous") return;
  const settings = await getSettings();
  if (!settings.autoScan || !settings.blockDangerous) return;
  const allowlist = await getAllowlist();
  if (allowlist.includes(result.domain)) return;
  const shown = jevFlagged ? { ...result, verdict: "suspicious" } : result;
  await chrome.tabs.update(tabId, { url: warningPageUrl(result.targetUrl || result.url, shown) });
}

/* ------------------------------------------------- pre-navigation checks */

// A session rule sends every top-level http(s) navigation to scanning.html
// before any request reaches the site. Domains already cleared this session,
// allowlisted by the person, or given a short pass are excluded from it.
const INTERCEPT_RULE_ID = 1;
const NEVER_INTERCEPT = ["localhost", "127.0.0.1"];

async function syncInterceptRule() {
  const dnr = chrome.declarativeNetRequest;
  if (!dnr?.updateSessionRules) return;
  const settings = await getSettings();
  const { cleared = [], passes = {} } = await chrome.storage.session.get(["cleared", "passes"]);
  const now = Date.now();
  const livePasses = Object.fromEntries(Object.entries(passes).filter(([, until]) => until > now));
  if (Object.keys(livePasses).length !== Object.keys(passes).length) {
    await chrome.storage.session.set({ passes: livePasses });
  }
  const excluded = [...new Set([...NEVER_INTERCEPT, ...(await getAllowlist()), ...cleared, ...Object.keys(livePasses)])]
    .filter(Boolean);
  const addRules = settings.autoScan ? [{
    id: INTERCEPT_RULE_ID,
    priority: 1,
    action: { type: "redirect", redirect: { regexSubstitution: `${chrome.runtime.getURL("scanning.html")}?url=\\0` } },
    condition: { regexFilter: "^https?://.*", resourceTypes: ["main_frame"], excludedRequestDomains: excluded },
  }] : [];
  await dnr.updateSessionRules({ removeRuleIds: [INTERCEPT_RULE_ID], addRules });
}

// Safe verdicts clear the domain for the rest of the browser session. Anything
// else gets a short pass so forwarding to it doesn't loop back to the scanner.
async function letThrough(domain, { durable }) {
  if (durable) {
    const { cleared = [] } = await chrome.storage.session.get("cleared");
    if (!cleared.includes(domain)) await chrome.storage.session.set({ cleared: [...cleared, domain] });
  } else {
    const { passes = {} } = await chrome.storage.session.get("passes");
    await chrome.storage.session.set({ passes: { ...passes, [domain]: Date.now() + CONFIG.NAVIGATION_PASS_MS } });
    setTimeout(() => syncInterceptRule().catch(() => {}), CONFIG.NAVIGATION_PASS_MS + 1000);
  }
  await syncInterceptRule();
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
  await syncInterceptRule();
});

chrome.runtime.onStartup.addListener(async () => {
  await applyActionState(undefined, "idle");
  await syncInterceptRule();
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    // scanNavigation stores its result under the destination before forwarding;
    // keep that one so the page isn't scanned a second time.
    const { [resultKey(tabId)]: kept } = await chrome.storage.session.get(resultKey(tabId));
    if (kept?.url !== changeInfo.url) {
      await chrome.storage.session.remove(resultKey(tabId));
      await applyActionState(tabId, "idle");
    }
  }
  if (changeInfo.status !== "loading" || !isScannableUrl(tab.url)) return;

  const settings = await getSettings();
  if (!settings.autoScan) return;

  const { [resultKey(tabId)]: cached } = await chrome.storage.session.get(resultKey(tabId));
  if (cached?.schemaVersion === 2 && cached.url === tab.url && Date.now() - cached.scannedAt < CONFIG.RESULT_TTL_MS) {
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
      result: result?.schemaVersion === 2 && result.url === tab.url ? result : null,
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
    await syncInterceptRule();
    return next;
  },

  // Called by scanning.html with the destination it is holding.
  async scanNavigation({ url }, sender) {
    if (!isScannableUrl(url)) throw new Error("Invalid destination");
    const tabId = sender.tab?.id;
    const settings = await getSettings();
    const result = await analyzeUrl(url, "quick");
    if (tabId !== undefined) {
      await chrome.storage.session.set({ [resultKey(tabId)]: result });
      await applyActionState(tabId, result.verdict);
    }
    // With the daemon offline there is no verdict to act on; let the page load
    // rather than stopping every site, and check it again on the next visit.
    const checked = result.source === "daemon";
    if (checked && result.verdict !== "safe" && settings.blockDangerous) {
      const warning = new URL(warningPageUrl(url, result));
      warning.searchParams.set("via", "scan");
      return { action: "warn", verdict: result.verdict, url: warning.href };
    }
    await letThrough(hostnameOf(url), { durable: checked && result.verdict === "safe" });
    return { action: "proceed", verdict: result.verdict, url };
  },

  async testRedirect({ tabId }) {
    const tab = await chrome.tabs.get(tabId);
    const { [resultKey(tabId)]: result } = await chrome.storage.session.get(resultKey(tabId));
    const target = tab.url || "https://example.com";
    const url = warningPageUrl(target, result ?? { verdict: "dangerous", score: 12 });
    await chrome.tabs.update(tabId, { url });
    return { url };
  },

  async allowAndProceed({ url }, sender) {
    if (!isScannableUrl(url)) throw new Error("Invalid destination");
    const domain = hostnameOf(url);
    const allowlist = await getAllowlist();
    if (!allowlist.includes(domain)) allowlist.push(domain);
    await chrome.storage.session.set({ allowlist });
    await syncInterceptRule();
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
