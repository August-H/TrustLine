"use strict";

const COOLDOWN_MS = 5_000;

const params = new URLSearchParams(location.search);
const target = params.get("url") || "";
const undetermined = params.get("review") === "inconclusive";
const rawScore = params.get("score");
const score = !undetermined && rawScore && /^\d{1,3}$/.test(rawScore) ? Math.min(100, Number(rawScore)) : null;

// Same thresholds as verdictFromScore() in background.js.
function verdictFromScore(value) {
  if (value >= 70) return "safe";
  if (value >= 40) return "suspicious";
  return "dangerous";
}

// An explicit verdict wins: a cloud review can block a site whose origin score
// is high, and that must not turn the banner green. Without one, the score
// decides, and with neither the page stays on its most cautious setting.
const VERDICTS = ["safe", "suspicious", "dangerous"];
const rawVerdict = String(params.get("verdict") ?? "").toLowerCase();
const verdict = VERDICTS.includes(rawVerdict) ? rawVerdict : score === null ? "dangerous" : verdictFromScore(score);

let parsed = null;
let domain = "";
let safeTarget = "";
try {
  const u = new URL(target);
  if (u.protocol === "http:" || u.protocol === "https:") {
    parsed = u;
    domain = u.hostname.replace(/^www\./i, "");
    safeTarget = u.toString();
  }
} catch {
  /* missing or malformed target */
}

/* ------------------------------------------------------------------ utils */

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "text") node.textContent = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else node.setAttribute(key, value);
  }
  for (const child of [].concat(children)) if (child) node.append(child);
  return node;
}

function parseReasons() {
  const list = [];
  const raw = params.get("reasons");
  if (raw) {
    try {
      const decoded = JSON.parse(raw);
      if (Array.isArray(decoded)) list.push(...decoded);
    } catch {
      list.push(...raw.split("|")); // tolerate pipe-separated input
    }
  }
  const single = params.get("reason");
  if (single) list.push(single);
  const clean = list
    .filter((r) => typeof r === "string" && r.trim())
    .map((r) => plainReason(r.trim()).slice(0, 200));
  return [...new Set(clean)].slice(0, 10);
}

// Older daemons (and results cached before an update) still send the original
// technical wording; show it in the same plain English the daemon now uses.
function plainReason(text) {
  const jev = text.match(/^Jev estimates ([\d.]+%) probability of a deceptive URL origin\.?$/i);
  if (jev) return `TrustLine estimates a ${jev[1]} chance this web address is fake or misleading.`;
  if (/^This score uses URL metadata, not the website's contents\.?$/i.test(text)) {
    return "This quick check only looked at the web address, not the page itself.";
  }
  return text.replace(/^Jev score unavailable$/i, "TrustLine score unavailable");
}

/* --------------------------------------------------------- classification */

// Each rule maps a reason (from the scanner or local URL inspection) to a
// severity tag and the real-world risks it feeds.
const RULES = [
  {
    id: "lookalike",
    re: /punycode|xn--|look-?alike|homograph|typosquat|impersonat/i,
    tag: "high",
    risks: ["credential", "financial"],
  },
  {
    id: "userinfo",
    re: /embeds credentials|before the hostname/i,
    tag: "high",
    risks: ["credential"],
  },
  {
    id: "known-bad",
    re: /phish|malware|malicious|blocklist|known threat|exploit|drive-?by/i,
    tag: "high",
    risks: ["credential", "malware"],
  },
  {
    id: "payload",
    re: /download|executable|payload|\.(exe|dmg|apk|scr|msi|pkg)\b/i,
    tag: "high",
    risks: ["malware"],
  },
  {
    id: "raw-ip",
    re: /raw ip|ip address/i,
    tag: "network",
    risks: ["malware", "credential"],
  },
  {
    id: "plaintext",
    re: /not encrypted|unencrypted|\(http\)|certificate|tls|ssl/i,
    tag: "network",
    risks: ["credential", "financial"],
  },
  {
    id: "redirect",
    re: /redirect/i,
    tag: "network",
    risks: ["credential", "malware"],
  },
  {
    id: "financial-bait",
    re: /wallet|payment|billing|card|bank|crypto|invoice|refund/i,
    tag: "heuristic",
    risks: ["financial"],
  },
  {
    id: "credential-bait",
    re: /credential|bait|login|sign-?in|verify|password|account/i,
    tag: "heuristic",
    risks: ["credential"],
  },
  {
    id: "tld",
    re: /top-level domain|\btld\b|abuse/i,
    tag: "heuristic",
    risks: ["malware", "financial"],
  },
  {
    id: "structure",
    re: /hyphen|subdomain|unusually long|hostname is/i,
    tag: "heuristic",
    risks: ["credential"],
  },
  {
    id: "info",
    re: /no known risk|reviewed by|manual test|flagged by trustline/i,
    tag: "info",
    risks: [],
  },
];

const TAG_LABELS = { high: "Danger", network: "Caution", heuristic: "Warning", info: "Note" };
const TAG_ORDER = { high: 0, network: 1, heuristic: 2, info: 3 };

const fallbackRule = {
  id: "other",
  tag: "heuristic",
  risks: ["credential"],
};

function classify(text) {
  return RULES.find((r) => r.re.test(text)) ?? fallbackRule;
}

// Lightweight client-side inspection so the breakdown stays useful even when
// the scanner only passed a single reason (or none).
const RISKY_TLDS = new Set(["zip", "mov", "xyz", "top", "click", "gq", "tk", "ml", "cf", "work", "rest"]);
const BAIT_HOST = /(login|log-in|signin|sign-in|verify|verification|secure|account|update|confirm|recover)/i;
const MONEY_URL = /(wallet|payment|billing|bank|crypto|invoice|refund)/i;

function inspectUrl(u) {
  if (!u) return [];
  const host = u.hostname.toLowerCase();
  const found = [];
  if (u.protocol === "http:") found.push("Connection is not encrypted (HTTP)");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith("[")) found.push("Site is served from a raw IP address");
  if (host.includes("xn--")) found.push("Domain uses punycode, a common look-alike trick");
  if (u.username || u.password) found.push("URL embeds credentials before the hostname");
  const bait = host.match(BAIT_HOST);
  if (bait) found.push(`Domain contains credential-bait keyword "${bait[1]}"`);
  const money = (host + u.pathname).match(MONEY_URL);
  if (money) found.push(`Address references payments ("${money[1]}")`);
  if (/\.(exe|dmg|apk|scr|msi|pkg)$/i.test(u.pathname)) found.push("Link points directly at an executable download");
  if ((host.match(/-/g) || []).length >= 3) found.push("Domain contains many hyphens");
  if (host.split(".").length > 4) found.push("Unusually deep subdomain chain");
  const tld = host.split(".").pop();
  if (RISKY_TLDS.has(tld)) found.push(`Top-level domain ".${tld}" is frequently associated with abuse`);
  if (host.length > 40) found.push("Hostname is unusually long");
  return found;
}

function buildFindings() {
  if (undetermined) return [
    { text: "The deep scan could not finish. Safety is undetermined, so no probability or safety score is available.",
      rule: { tag: "info" } },
    { text: params.get("review_reason") || "TrustLine is holding this page because it could not complete the inspection.",
      rule: { tag: "info" } },
  ];
  const findings = [];
  const seen = new Set();
  for (const text of parseReasons()) {
    const rule = classify(text);
    findings.push({ text, rule });
    seen.add(rule.id);
  }
  for (const text of inspectUrl(parsed)) {
    const rule = classify(text);
    if (seen.has(rule.id)) continue;
    findings.push({ text, rule });
    seen.add(rule.id);
  }
  // Informational rows ("Manual test…", "No known risk signals…") aren't reasons; leave them out.
  const actionable = findings.filter((f) => f.rule.tag !== "info");
  // A safe verdict with no flagged reasons has nothing to explain; don't invent one.
  if (actionable.length === 0 && verdict !== "safe") {
    actionable.push({
      text: verdict === "dangerous" ? "TrustLine gave this site a very low trust score" : "TrustLine gave this site a low trust score",
      rule: fallbackRule,
    });
  }
  return actionable.sort((a, b) => TAG_ORDER[a.rule.tag] - TAG_ORDER[b.rule.tag]);
}

/* ---------------------------------------------------------------- render */

// Show the most important reasons first; the rest sit behind a button so the
// page still fits on one screen.
const VISIBLE_FINDINGS = 2;

const ICONS = {
  account: "M7 11V7a5 5 0 0 1 10 0v4M5 11h14v10H5z",
  money: "M3 6h18v12H3zM3 10h18M7 15h4",
  computer: "M3 4h18v12H3zM8 20h8M12 16v4M12 7v4M12 13.5v.01",
};

// Shown when there is no Deep scan to go on: the general risks of a flagged site.
const GENERAL_RISKS = [
  { icon: ICONS.account, tone: "risk", title: "Stolen Passwords & Accounts",
    summary: "Scammers may use fake sign-in boxes on this page to steal your passwords and lock you out of your accounts." },
  { icon: ICONS.money, tone: "risk", title: "Money & Credit Card Theft",
    summary: "This site may trick you into entering credit card or bank details to steal your money." },
  { icon: ICONS.computer, tone: "risk", title: "Computer Viruses & Scams",
    summary: "Visiting this page could install harmful software on your computer or freeze your screen with fake virus alerts." },
];

// A safe score without a Deep scan: everyday habits, not scam warnings.
const SAFE_HABITS = [
  { icon: ICONS.account, tone: "clear", title: "Signing in",
    summary: "If this site asks for a password, check the address above first and only type it if it's the site you meant to visit." },
  { icon: ICONS.money, tone: "clear", title: "Paying",
    summary: "Only enter card details on checkout pages you reached yourself, never from a pop-up or a message." },
  { icon: ICONS.computer, tone: "clear", title: "Downloads",
    summary: "Open only files you were expecting. Real sites don't ask you to install anything just to see a page." },
];

/* ------------------------------------------------------ deep scan context */

const scanMode = params.get("mode");
const review = params.get("review"); // "allow" | "block" | "inconclusive"
const pageFeatures = (() => {
  try {
    const value = JSON.parse(params.get("features") ?? "null");
    return value && typeof value === "object" ? value : null;
  } catch {
    return null;
  }
})();
// Only a finished cloud review that actually looked at the page can describe it.
const deepScanned = scanMode === "deep" && (review === "allow" || review === "block") && pageFeatures !== null;

function impersonationFound() {
  return parseReasons().some((r) => /impersonat|pretend|look-?alike|copies|fake (copy|version)/i.test(r));
}

// Plain-English cards built from what the Deep scan saw on the page.
function deepScanCards(siteLooksSafe) {
  const f = pageFeatures;
  const site = domain || "this site";
  if (siteLooksSafe) {
    return [
      f.sign_in
        ? { icon: ICONS.account, tone: f.external_form ? "risk" : "clear", title: "Sign-in looks normal",
            summary: f.external_form
              ? `${site} has a sign-in box that sends your details to a different website. Check before typing a password.`
              : `${site} has a sign-in box that keeps your details on its own site, as expected.` }
        : { icon: ICONS.account, tone: "clear", title: "No password asked for",
            summary: "TrustLine didn't see this page ask for a password or account details." },
      f.payment
        ? { icon: ICONS.money, tone: "clear", title: "Payment form looks normal",
            summary: "The page has a place for card details on its own site, and TrustLine found no tricks around it." }
        : { icon: ICONS.money, tone: "clear", title: "No payment asked for",
            summary: "Nothing TrustLine looked at asked for card or bank details." },
      f.downloads
        ? { icon: ICONS.computer, tone: "clear", title: "Has files to download",
            summary: "The page offers files to download. Open only ones you were expecting." }
        : { icon: ICONS.computer, tone: "clear", title: "No downloads",
            summary: "TrustLine didn't see any programs or files to download." },
    ];
  }
  const impersonating = impersonationFound();
  return [
    f.sign_in
      ? { icon: ICONS.account, tone: "risk", title: f.external_form ? "Sends your password elsewhere" : "Asks for your password",
          summary: f.external_form
            ? "This page asks you to sign in, then sends what you type to a different website. That's how passwords get stolen."
            : "This page asks you to sign in. On a site like this, the sign-in box may be a fake meant to steal your password." }
      : impersonating
        ? { icon: ICONS.account, tone: "risk", title: "Pretends to be someone else",
            summary: "This page copies a company you may trust, so you'll believe what it asks you to do." }
        : { icon: ICONS.account, tone: "clear", title: "No sign-in box seen",
            summary: "TrustLine didn't see a password box, but the site may ask for one on a later page." },
    f.payment
      ? { icon: ICONS.money, tone: "risk", title: f.external_form ? "Sends card details elsewhere" : "Asks for card details",
          summary: f.external_form
            ? "This page asks for card or bank details and sends them to a different website. Don't enter them."
            : "This page asks for card or bank details. Don't enter them here." }
      : { icon: ICONS.money, tone: "clear", title: "No payment form seen",
          summary: "TrustLine didn't see a payment form, but scam sites often ask for money later." },
    f.downloads
      ? { icon: ICONS.computer, tone: "risk", title: "Offers a download",
          summary: "This page offers a file to download. It could harm your computer if you open it." }
      : { icon: ICONS.computer, tone: "clear", title: "No downloads seen",
          summary: "TrustLine didn't see any files to download on this page." },
  ];
}

function riskContent() {
  const siteLooksSafe = verdict === "safe" || review === "allow";
  if (deepScanned) {
    return {
      heading: siteLooksSafe ? "What TrustLine's Deep scan found" : "What TrustLine found on this page",
      cards: deepScanCards(siteLooksSafe),
    };
  }
  if (verdict === "safe") return { heading: "Staying safe on this site", cards: SAFE_HABITS };
  return { heading: "What could happen if you continue", cards: GENERAL_RISKS };
}

function renderHeader() {
  const status = undetermined ? "undetermined" : verdict;
  document.body.dataset.status = status;
  const action = { safe: "checked", suspicious: "paused", dangerous: "blocked", undetermined: "could not check" }[status];
  document.title = domain ? `TrustLine ${action} ${domain}` : `TrustLine ${action} a site`;
  document.getElementById("title").textContent = {
    safe: "This site looks safe",
    suspicious: "This site looks suspicious",
    dangerous: "This site may be dangerous",
    undetermined: "Safety undetermined",
  }[status];
  if (undetermined) {
    document.getElementById("why-title").textContent = "The deep scan could not determine this site's safety";
    document.getElementById("override-title").textContent = "Continue without a completed scan?";
  }
}

function renderScore() {
  const section = document.getElementById("score");
  if (score === null) {
    section.hidden = true;
    return;
  }
  const zone = verdictFromScore(score);
  section.dataset.zone = zone;
  document.getElementById("score-value").textContent = String(score);
  const meter = document.getElementById("score-meter");
  meter.setAttribute("aria-valuenow", String(score));
  meter.setAttribute("aria-valuetext", `${score} out of 100, ${zone}`);
  meter.dataset.zone = zone;
  document.getElementById("score-marker").style.left = `${score}%`;
  document.getElementById("score-fill").style.width = `${score}%`;
}

/* --------------------------------------------------------------- address */

// Digits that scammers swap in for the letters they resemble.
const LOOKALIKES = { 0: "o", 1: "l", 3: "e", 5: "s" };
// ownerOf() and IP_HOST come from address.js.

function findLookalikes(host) {
  if (IP_HOST.test(host)) return [];
  const isLetter = (c) => /[a-z]/i.test(c || "");
  const hits = [];
  for (let i = 0; i < host.length; i++) {
    const c = host[i];
    if (c in LOOKALIKES && (isLetter(host[i - 1]) || isLetter(host[i + 1]))) hits.push(i);
  }
  return hits;
}

function wordAt(host, i) {
  const start = Math.max(host.lastIndexOf(".", i), host.lastIndexOf("-", i)) + 1;
  const ends = [host.indexOf(".", i), host.indexOf("-", i)].filter((n) => n !== -1);
  return host.slice(start, ends.length ? Math.min(...ends) : host.length);
}

function markedText(host, from, to, hits) {
  const nodes = [];
  let cursor = from;
  for (const i of hits) {
    if (i < from || i >= to) continue;
    if (i > cursor) nodes.push(host.slice(cursor, i));
    nodes.push(el("mark", { class: "lookalike", text: host[i] }));
    cursor = i + 1;
  }
  if (cursor < to) nodes.push(host.slice(cursor, to));
  return nodes;
}

function renderAddress() {
  const target = document.getElementById("domain");
  const notesList = document.getElementById("address-notes");
  if (!domain) {
    target.textContent = "an unknown site";
    notesList.hidden = true;
    return;
  }

  const host = domain;
  const owner = ownerOf(host);
  const split = host.length - owner.length;
  const hits = findLookalikes(host);
  target.style.setProperty("--chars", String(host.length));
  target.setAttribute("aria-label", host);

  const notes = [];
  if (split > 0) {
    target.replaceChildren(
      ...markedText(host, 0, split, hits),
      el("span", { class: "owner" }, markedText(host, split, host.length, hits))
    );
    notes.push(["This address really belongs to ", el("code", { text: owner }), ". The start can say anything."]);
  } else {
    target.replaceChildren(...markedText(host, 0, host.length, hits));
  }

  const seen = new Set();
  for (const i of hits) {
    const word = wordAt(host, i);
    const key = `${host[i]}:${word}`;
    if (seen.has(key) || seen.size >= 2) continue;
    seen.add(key);
    notes.push([
      "The ",
      el("code", { text: host[i] }),
      " in ",
      el("code", { text: word }),
      ` is a number, not the letter "${LOOKALIKES[host[i]]}".`,
    ]);
  }
  if (host.includes("xn--")) notes.push(["This address uses foreign letters that can look like ordinary ones."]);

  notesList.replaceChildren(...notes.map((parts) => el("li", {}, parts)));
  notesList.hidden = notes.length === 0;
}

/* ---------------------------------------------------------------- lists */

function renderFindings(findings) {
  const list = document.getElementById("findings");
  list.replaceChildren(
    ...findings.map(({ text, rule }, i) =>
      el("li", { class: "finding", ...(i >= VISIBLE_FINDINGS ? { hidden: "" } : {}) }, [
        el("span", { class: "tag", dataset: { tag: rule.tag }, text: TAG_LABELS[rule.tag] }),
        el("p", { class: "finding-title", text }),
      ])
    )
  );

  const more = document.getElementById("findings-more");
  const extra = findings.length - VISIBLE_FINDINGS;
  if (extra > 0) {
    more.hidden = false;
    more.textContent = `Show ${extra} more reason${extra === 1 ? "" : "s"}`;
    more.addEventListener("click", () => {
      for (const item of list.children) item.hidden = false;
      more.hidden = true;
    });
  }
}

function renderRisks() {
  if (undetermined) {
    document.querySelector(".risks-section").hidden = true;
    return;
  }
  const svgNs = "http://www.w3.org/2000/svg";
  const { heading, cards } = riskContent();
  document.getElementById("risks-title").textContent = heading;
  document.getElementById("risks").replaceChildren(
    ...cards.map((risk) => {
      const svg = document.createElementNS(svgNs, "svg");
      svg.setAttribute("viewBox", "0 0 24 24");
      svg.setAttribute("aria-hidden", "true");
      svg.classList.add("risk-icon");
      const path = document.createElementNS(svgNs, "path");
      path.setAttribute("d", risk.icon);
      svg.append(path);
      return el("li", { class: "risk", dataset: { tone: risk.tone } }, [
        el("div", { class: "risk-head" }, [svg, el("h3", { text: risk.title })]),
        el("p", { text: risk.summary }),
      ]);
    })
  );
}

/* ------------------------------------------------------------ navigation */

document.getElementById("back").addEventListener("click", () => {
  // From the scanning screen the blocked site never entered history, so one
  // step back is the page the person came from.
  const steps = params.get("via") === "scan" ? 1 : 2;
  if (history.length > steps) history.go(-steps);
  else location.replace("about:blank");
});

/* ---------------------------------------------------------- friction gate */

const ack = document.getElementById("ack");
const stepAck = document.getElementById("step-ack");
const stepVerify = document.getElementById("step-verify");
const stepProceed = document.getElementById("step-proceed");
const input = document.getElementById("confirm-host");
const hint = document.getElementById("confirm-hint");
const cooldownFill = document.getElementById("cooldown-fill");
const cooldownText = document.getElementById("cooldown-text");
const proceed = document.getElementById("proceed");

let cooldownStart = 0;
let cooldownDone = false;
let cooldownFrame = 0;

function hostMatches() {
  const typed = input.value.trim().toLowerCase();
  return Boolean(parsed) && (typed === domain.toLowerCase() || typed === parsed.hostname.toLowerCase());
}

function updateGate() {
  const acknowledged = ack.checked;
  const typed = input.value.trim();
  const match = hostMatches();

  stepAck.dataset.state = acknowledged ? "done" : "active";
  stepVerify.dataset.state = !acknowledged ? "locked" : cooldownDone && match ? "done" : "active";
  input.disabled = !acknowledged;
  input.dataset.match = !typed ? "" : match ? "yes" : "no";
  if (acknowledged && typed && !match) hint.textContent = "Doesn't match the flagged hostname yet.";
  else hint.textContent = "";

  const unlocked = acknowledged && cooldownDone && match && Boolean(safeTarget);
  stepProceed.dataset.state = unlocked ? "active" : "locked";
  proceed.disabled = !unlocked;
}

function tickCooldown() {
  const elapsed = Date.now() - cooldownStart;
  const pct = Math.min(1, elapsed / COOLDOWN_MS);
  cooldownFill.style.width = `${pct * 100}%`;
  if (pct >= 1) {
    cooldownDone = true;
    cooldownText.textContent = "";
    updateGate();
    return;
  }
  cooldownText.textContent = `Cooldown: ${Math.ceil((COOLDOWN_MS - elapsed) / 1000)}s remaining`;
  cooldownFrame = requestAnimationFrame(tickCooldown);
}

ack.addEventListener("change", () => {
  cancelAnimationFrame(cooldownFrame);
  cooldownDone = false;
  if (ack.checked) {
    cooldownStart = Date.now();
    tickCooldown();
    input.disabled = false;
    input.focus();
  } else {
    // Unchecking resets the whole gate.
    input.value = "";
    cooldownFill.style.width = "0";
    cooldownText.textContent = "";
  }
  updateGate();
});

input.addEventListener("input", updateGate);
for (const evt of ["paste", "drop"]) {
  input.addEventListener(evt, (e) => {
    e.preventDefault();
    hint.textContent = "Pasting is disabled. Type the hostname by hand.";
  });
}

proceed.addEventListener("click", async () => {
  if (proceed.disabled || !safeTarget) return;
  if (typeof chrome !== "undefined" && chrome.runtime?.id) {
    const res = await chrome.runtime.sendMessage({ type: "allowAndProceed", url: safeTarget });
    if (res?.ok) return;
  }
  location.href = safeTarget;
});

/* ------------------------------------------------------------------ init */

const findings = buildFindings();
renderHeader();
renderScore();
renderAddress();
renderFindings(findings);
renderRisks();
document.getElementById("expected-host").textContent = domain ? `Flagged: ${domain}` : "No valid destination to verify";
proceed.textContent = domain ? `Allowlist for this session & Proceed to ${domain}` : "No valid destination";
updateGate();
