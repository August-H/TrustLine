"use strict";

const COOLDOWN_MS = 5_000;

const params = new URLSearchParams(location.search);
const target = params.get("url") || "";
const verdict = params.get("verdict") === "suspicious" ? "suspicious" : "dangerous";
const rawScore = params.get("score");
const score = rawScore && /^\d{1,3}$/.test(rawScore) ? Math.min(100, Number(rawScore)) : null;

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
  const clean = list.filter((r) => typeof r === "string" && r.trim()).map((r) => r.trim().slice(0, 200));
  return [...new Set(clean)].slice(0, 10);
}

/* --------------------------------------------------------- classification */

// Each rule maps a reason (from the scanner or local URL inspection) to a
// severity tag, the real-world risks it feeds, and a plain-language explanation.
const RULES = [
  {
    id: "lookalike",
    re: /punycode|xn--|look-?alike|homograph|typosquat|impersonat/i,
    tag: "high",
    risks: ["credential", "financial"],
    detail: "The web address copies the name of a company you may trust, using letters that look almost the same.",
  },
  {
    id: "userinfo",
    re: /embeds credentials|before the hostname/i,
    tag: "high",
    risks: ["credential"],
    detail: "The link is written to hide where it really goes.",
  },
  {
    id: "known-bad",
    re: /phish|malware|malicious|blocklist|known threat|exploit|drive-?by/i,
    tag: "high",
    risks: ["credential", "malware"],
    detail: "This site is on a list of known scam or harmful websites.",
  },
  {
    id: "payload",
    re: /download|executable|payload|\.(exe|dmg|apk|scr|msi|pkg)\b/i,
    tag: "high",
    risks: ["malware"],
    detail: "This link downloads a program that could harm your computer if you open it.",
  },
  {
    id: "raw-ip",
    re: /raw ip|ip address/i,
    tag: "network",
    risks: ["malware", "credential"],
    detail: "Real companies use a normal web name, not a string of numbers. Scammers often use numbers instead.",
  },
  {
    id: "plaintext",
    re: /not encrypted|unencrypted|\(http\)|certificate|tls|ssl/i,
    tag: "network",
    risks: ["credential", "financial"],
    detail: "This connection is not private. Others could see anything you type, including passwords and card numbers.",
  },
  {
    id: "redirect",
    re: /redirect/i,
    tag: "network",
    risks: ["credential", "malware"],
    detail: "The link sends you through several other sites first, a trick used to hide scams.",
  },
  {
    id: "financial-bait",
    re: /wallet|payment|billing|card|bank|crypto|invoice|refund/i,
    tag: "heuristic",
    risks: ["financial"],
    detail: "The address mentions payments or banking, a common trick to get your card or bank details.",
  },
  {
    id: "credential-bait",
    re: /credential|bait|login|sign-?in|verify|password|account/i,
    tag: "heuristic",
    risks: ["credential"],
    detail: "Words like \"login\" or \"verify\" in an unfamiliar address are a common sign of a fake sign-in page.",
  },
  {
    id: "tld",
    re: /top-level domain|\btld\b|abuse/i,
    tag: "heuristic",
    risks: ["malware", "financial"],
    detail: "This kind of web address is cheap to set up and often used by short-lived scam sites.",
  },
  {
    id: "structure",
    re: /hyphen|subdomain|unusually long|hostname is/i,
    tag: "heuristic",
    risks: ["credential"],
    detail: "Long or oddly built addresses are used to hide a fake company name inside a real-looking one.",
  },
  {
    id: "info",
    re: /no known risk|reviewed by|manual test|flagged by trustline/i,
    tag: "info",
    risks: [],
    detail: "",
  },
];

const TAG_LABELS = { high: "Danger", network: "Caution", heuristic: "Warning", info: "Note" };
const TAG_ORDER = { high: 0, network: 1, heuristic: 2, info: 3 };

const fallbackRule = {
  id: "other",
  tag: "heuristic",
  risks: ["credential"],
  detail: "TrustLine found something about this site that matches known scams.",
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
  const actionable = findings.filter((f) => f.rule.tag !== "info");
  if (actionable.length === 0) {
    findings.push({
      text: verdict === "dangerous" ? "TrustLine gave this site a very low trust score" : "TrustLine gave this site a low trust score",
      rule: fallbackRule,
    });
  }
  return findings.sort((a, b) => TAG_ORDER[a.rule.tag] - TAG_ORDER[b.rule.tag]);
}

/* ---------------------------------------------------------------- render */

// Show the most important reasons first; the rest sit behind a button so the
// page still fits on one screen.
const VISIBLE_FINDINGS = 2;

const RISKS = [
  {
    id: "credential",
    icon: "M7 11V7a5 5 0 0 1 10 0v4M5 11h14v10H5z",
    title: "Stolen Passwords & Accounts",
    summary: "Scammers may use fake sign-in boxes on this page to steal your passwords and lock you out of your accounts.",
  },
  {
    id: "financial",
    icon: "M3 6h18v12H3zM3 10h18M7 15h4",
    title: "Money & Credit Card Theft",
    summary: "This site may trick you into entering credit card or bank details to steal your money.",
  },
  {
    id: "malware",
    icon: "M3 4h18v12H3zM8 20h8M12 16v4M12 7v4M12 13.5v.01",
    title: "Computer Viruses & Scams",
    summary: "Visiting this page could install harmful software on your computer or freeze your screen with fake virus alerts.",
  },
];

function renderHeader() {
  const paused = verdict === "suspicious";
  document.body.dataset.status = verdict;
  document.title = domain ? `TrustLine ${paused ? "paused" : "blocked"} ${domain}` : "TrustLine blocked a site";
  document.getElementById("title").textContent = paused ? "This site looks suspicious" : "This site may be dangerous";
  const lead = document.getElementById("lead");
  lead.replaceChildren(
    paused ? "TrustLine flagged this website for caution. " : "TrustLine flagged this website as dangerous. "
  );
  if (score === null) {
    lead.append(paused ? "Some things about it look like a scam." : "It looks like a scam or fake website.");
  } else {
    const rating = score < 40 ? ", which is very low" : score < 70 ? ", which is low" : "";
    lead.append("Its safety score is ", el("strong", { text: `${score} out of 100` }), `${rating}.`);
  }
}

// Zones match the verdict thresholds in background.js: under 40 dangerous, under 70 suspicious.
function renderScore() {
  const section = document.getElementById("score");
  if (score === null) {
    section.hidden = true;
    return;
  }
  const zone = score < 40 ? "dangerous" : score < 70 ? "suspicious" : "safe";
  document.getElementById("score-value").textContent = String(score);
  const meter = document.getElementById("score-meter");
  meter.setAttribute("aria-valuenow", String(score));
  meter.setAttribute("aria-valuetext", `${score} out of 100, ${zone}`);
  meter.dataset.zone = zone;
  document.getElementById("score-marker").style.left = `${score}%`;
  document.getElementById("score-fill").style.width = `${score}%`;
  document.getElementById("score-note").textContent = {
    dangerous: "Under 40 means strong signs of a scam. Most safe sites score above 70.",
    suspicious: "40 to 69 means some things look wrong. Most safe sites score above 70.",
    safe: "Most safe sites score above 70, but TrustLine found something worth checking.",
  }[zone];
}

/* --------------------------------------------------------------- address */

// Digits that scammers swap in for the letters they resemble.
const LOOKALIKES = { 0: "o", 1: "l", 3: "e", 5: "s" };
const SECOND_LEVEL = new Set(["co", "com", "org", "net", "gov", "ac", "edu"]);
const IP_HOST = /^(\d{1,3}(\.\d{1,3}){3}|\[.*\])$/;

// The registrable part of the hostname: what someone actually had to buy.
// A simple approximation of the public-suffix rules, good enough to show
// people which end of the address to read.
function ownerOf(host) {
  if (IP_HOST.test(host)) return host;
  const labels = host.split(".");
  const tld = labels.at(-1);
  const twoPart = labels.length >= 3 && tld.length === 2 && SECOND_LEVEL.has(labels.at(-2));
  return labels.slice(twoPart ? -3 : -2).join(".");
}

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
        rule.detail ? el("p", { class: "finding-detail", text: rule.detail }) : null,
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
  const svgNs = "http://www.w3.org/2000/svg";
  document.getElementById("risks").replaceChildren(
    ...RISKS.map((risk) => {
      const svg = document.createElementNS(svgNs, "svg");
      svg.setAttribute("viewBox", "0 0 24 24");
      svg.setAttribute("aria-hidden", "true");
      svg.classList.add("risk-icon");
      const path = document.createElementNS(svgNs, "path");
      path.setAttribute("d", risk.icon);
      svg.append(path);
      return el("li", { class: "risk" }, [
        el("div", { class: "risk-head" }, [svg, el("h3", { text: risk.title })]),
        el("p", { text: risk.summary }),
      ]);
    })
  );
}

/* ------------------------------------------------------------ navigation */

document.getElementById("back").addEventListener("click", () => {
  if (history.length > 2) history.go(-2);
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
  else hint.textContent = "Pasting is disabled. Type it out by hand.";

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
    cooldownText.textContent = "Cooldown complete";
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
    cooldownText.textContent = "Cooldown starts after step 1";
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
